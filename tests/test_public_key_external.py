import pytest

import pkcs11
from pkcs11 import KDF, Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.ec import (
    decode_ec_public_key,
    encode_ec_public_key,
    encode_ecdsa_signature,
    encode_named_curve_parameters,
)
from pkcs11.util.rsa import encode_rsa_public_key
from tests.conftest import IS_SOFTHSM


@pytest.mark.requires(Mechanism.RSA_PKCS)
def test_rsa(session: pkcs11.Session) -> None:
    # A key we generated earlier
    session.generate_keypair(KeyType.RSA, 1024)

    pub = session.get_key(key_type=KeyType.RSA, object_class=ObjectClass.PUBLIC_KEY)

    pub = encode_rsa_public_key(pub)

    from oscrypto.asymmetric import load_public_key, rsa_pkcs1v15_encrypt

    pub = load_public_key(pub)
    crypttext = rsa_pkcs1v15_encrypt(pub, b"Data to encrypt")

    priv = session.get_key(key_type=KeyType.RSA, object_class=ObjectClass.PRIVATE_KEY)

    plaintext = priv.decrypt(crypttext, mechanism=Mechanism.RSA_PKCS)

    assert plaintext == b"Data to encrypt"


@pytest.mark.requires(Mechanism.ECDSA_SHA1)
def test_ecdsa(session: pkcs11.Session) -> None:
    # A key we generated earlier
    session.create_domain_parameters(
        KeyType.EC,
        {
            Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1"),
        },
        local=True,
    ).generate_keypair()

    priv = session.get_key(key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY)

    signature = priv.sign(b"Data to sign", mechanism=Mechanism.ECDSA_SHA1)
    # Encode as ASN.1 for OpenSSL
    signature = encode_ecdsa_signature(signature)

    from oscrypto.asymmetric import ecdsa_verify, load_public_key

    pub = session.get_key(key_type=KeyType.EC, object_class=ObjectClass.PUBLIC_KEY)
    pub = load_public_key(encode_ec_public_key(pub))

    ecdsa_verify(pub, signature, b"Data to sign", "sha1")


@pytest.mark.requires(Mechanism.ECDH1_DERIVE)
def test_ecdh(session: pkcs11.Session) -> None:
    # A key we generated earlier
    session.create_domain_parameters(
        KeyType.EC,
        {
            Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1"),
        },
        local=True,
    ).generate_keypair()

    # Retrieve our keypair, with our public key encoded for interchange
    alice_priv = session.get_key(key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY)
    alice_pub = session.get_key(key_type=KeyType.EC, object_class=ObjectClass.PUBLIC_KEY)
    alice_pub = encode_ec_public_key(alice_pub)

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_der_public_key,
    )

    # Bob generates a keypair, with their public key encoded for
    # interchange
    bob_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_pub = bob_priv.public_key().public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )

    # Bob converts Alice's key to internal format and generates their
    # shared key
    bob_shared_key = bob_priv.exchange(
        ec.ECDH(),
        load_der_public_key(alice_pub, default_backend()),
    )

    key = alice_priv.derive_key(
        KeyType.GENERIC_SECRET,
        256,
        mechanism_param=(
            KDF.NULL,
            None,
            # N.B. it seems like SoftHSMv2 requires an EC_POINT to be
            # DER-encoded, which is not what the spec says
            decode_ec_public_key(bob_pub, encode_ec_point=IS_SOFTHSM)[Attribute.EC_POINT],
        ),
        template={
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        },
    )
    alice_shared_key = key[Attribute.VALUE]

    # We should have the same shared key
    assert bob_shared_key == alice_shared_key


@pytest.mark.requires(Mechanism.RSA_PKCS)
def test_terrible_hybrid_file_encryption_app(session: pkcs11.Session) -> None:
    # Proof of concept code only!
    import io

    from oscrypto.asymmetric import load_public_key, rsa_pkcs1v15_encrypt
    from oscrypto.symmetric import (
        aes_cbc_pkcs7_decrypt,
        aes_cbc_pkcs7_encrypt,
    )

    # A key we generated earlier
    session.generate_keypair(KeyType.RSA, 1024)

    pub = session.get_key(key_type=KeyType.RSA, object_class=ObjectClass.PUBLIC_KEY)
    pub = load_public_key(encode_rsa_public_key(pub))

    key = session.generate_random(256)
    iv = session.generate_random(128)

    source = b"This is my amazing file"

    with io.BytesIO() as dest:
        # Write a 128-byte header containing our key and our IV
        # strictly speaking we don't need to keep the IV secure but
        # we may as well.
        #
        # FIXME: Because this is RSA 1.5, we should fill the rest of the
        # frame with nonsense
        assert dest.write(rsa_pkcs1v15_encrypt(pub, key + iv)) == 128
        _, ciphertext = aes_cbc_pkcs7_encrypt(key, source, iv)
        dest.write(ciphertext)

        # Time passes
        dest.seek(0)

        # Look up our private key
        priv = session.get_key(key_type=KeyType.RSA, object_class=ObjectClass.PRIVATE_KEY)
        # Read the header
        header = dest.read(priv.key_length // 8)
        header = priv.decrypt(header, mechanism=Mechanism.RSA_PKCS)

        # The first 32 bytes is our key
        key, header = header[:32], header[32:]
        # The next 16 bytes is the IV
        iv = header[:16]
        # We can ignore the rest

        plaintext = aes_cbc_pkcs7_decrypt(key, dest.read(), iv)

    assert source == plaintext
