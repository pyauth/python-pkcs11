"""
PKCS#11 RSA Public Key Cryptography
"""

import pytest

import pkcs11
from pkcs11 import MGF, Attribute, KeyType, Mechanism, ObjectClass

pytestmark = [pytest.mark.requires(Mechanism.RSA_PKCS_KEY_PAIR_GEN)]


@pytest.fixture
def keypair(session: pkcs11.Session) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
    return session.generate_keypair(KeyType.RSA, 1024)


@pytest.mark.requires(Mechanism.RSA_PKCS)
def test_sign_pkcs_v15(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = b"00000000"

    signature = private_key.sign(data, mechanism=Mechanism.RSA_PKCS)
    assert signature is not None
    assert isinstance(signature, bytes)
    assert public_key.verify(data, signature, mechanism=Mechanism.RSA_PKCS)
    assert not public_key.verify(data, b"1234", mechanism=Mechanism.RSA_PKCS)


@pytest.mark.requires(Mechanism.SHA512_RSA_PKCS)
def test_sign_default(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = b"HELLO WORLD" * 1024

    signature = private_key.sign(data)
    assert signature is not None
    assert isinstance(signature, bytes)
    assert public_key.verify(data, signature)
    assert not public_key.verify(data, b"1234")


@pytest.mark.requires(Mechanism.SHA512_RSA_PKCS)
def test_sign_stream(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = (
        b"I" * 16,
        b"N" * 16,
        b"P" * 16,
        b"U" * 16,
        b"T" * 10,  # don't align to the blocksize
    )

    signature = private_key.sign(data)
    assert signature is not None
    assert isinstance(signature, bytes)
    assert public_key.verify(data, signature)


@pytest.mark.requires(Mechanism.RSA_PKCS_OAEP)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_key_wrap(
    session: pkcs11.Session, keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]
) -> None:
    public_key, private_key = keypair
    key = session.generate_key(
        KeyType.AES,
        128,
        template={
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        },
    )

    data = public_key.wrap_key(key)
    assert data != key[Attribute.VALUE]

    key2 = private_key.unwrap_key(
        ObjectClass.SECRET_KEY,
        KeyType.AES,
        data,
        template={
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        },
    )

    assert key[Attribute.VALUE] == key2[Attribute.VALUE]


@pytest.mark.requires(Mechanism.RSA_PKCS_OAEP)
def test_encrypt_oaep(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = b"SOME DATA"

    crypttext = public_key.encrypt(
        data,
        mechanism=Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None),
    )

    assert data != crypttext

    plaintext = private_key.decrypt(
        crypttext,
        mechanism=Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None),
    )

    assert data == plaintext


@pytest.mark.requires(Mechanism.SHA1_RSA_PKCS_PSS)
def test_sign_pss(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = b"SOME DATA"

    # These are the default params
    signature = private_key.sign(
        data,
        mechanism=Mechanism.SHA1_RSA_PKCS_PSS,
        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, 20),
    )

    assert public_key.verify(data, signature, mechanism=Mechanism.SHA1_RSA_PKCS_PSS)


@pytest.mark.requires(Mechanism.RSA_PKCS_OAEP)
def test_encrypt_too_much_data(keypair: tuple[pkcs11.PublicKey, pkcs11.PrivateKey]) -> None:
    public_key, private_key = keypair
    data = b"1234" * 128

    assert public_key.key_type == KeyType.RSA
    assert private_key.key_type == KeyType.RSA
    assert public_key.label == ""
    assert private_key.label == ""
    assert private_key.id == b""

    # You can't encrypt lots of data with RSA
    # This should ideally throw DataLen but you can't trust it
    with pytest.raises(pkcs11.PKCS11Error):
        public_key.encrypt(data)
