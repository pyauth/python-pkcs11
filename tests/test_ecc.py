"""
PKCS#11 Elliptic Curve Cryptography.
"""

import base64

import pytest

import pkcs11
from pkcs11 import KDF, Attribute, KeyType, Mechanism
from pkcs11.util.ec import (
    decode_ec_private_key,
    decode_ec_public_key,
    decode_ecdsa_signature,
    encode_ec_public_key,
    encode_named_curve_parameters,
)


@pytest.mark.requires(Mechanism.EC_KEY_PAIR_GEN)
@pytest.mark.requires(Mechanism.ECDSA)
def test_sign_ecdsa(session: pkcs11.Session) -> None:
    parameters = session.create_domain_parameters(
        KeyType.EC,
        {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
        local=True,
    )

    pub, priv = parameters.generate_keypair()

    mechanism = Mechanism.ECDSA
    data = b"HI BOB!"
    ecdsa = priv.sign(data, mechanism=mechanism)
    assert pub.verify(data, ecdsa, mechanism=mechanism)


@pytest.mark.requires(Mechanism.EC_KEY_PAIR_GEN)
@pytest.mark.requires(Mechanism.ECDH1_DERIVE)
def test_derive_key(session: pkcs11.Session) -> None:
    # DER encoded EC params from OpenSSL
    # openssl ecparam -out ec_param.der -name prime192v1
    ecparams = base64.b64decode(b"BggqhkjOPQMBAQ==")

    parameters = session.create_domain_parameters(
        KeyType.EC, {Attribute.EC_PARAMS: ecparams}, local=True
    )
    alice_pub, alice_priv = parameters.generate_keypair()
    alice_value = alice_pub[Attribute.EC_POINT]

    bob_pub, bob_priv = parameters.generate_keypair()
    bob_value = bob_pub[Attribute.EC_POINT]

    assert alice_value != bob_value

    alice_session = alice_priv.derive_key(
        KeyType.AES, 128, mechanism_param=(KDF.NULL, None, bob_value)
    )

    bob_session = bob_priv.derive_key(
        KeyType.AES, 128, mechanism_param=(KDF.NULL, None, alice_value)
    )

    iv = session.generate_random(128)
    crypttext = alice_session.encrypt("HI BOB!", mechanism_param=iv)
    plaintext = bob_session.decrypt(crypttext, mechanism_param=iv)
    assert plaintext == b"HI BOB!"


@pytest.mark.requires(Mechanism.ECDSA)
def test_import_key_params(session: pkcs11.Session) -> None:
    der = base64.b64decode("""
    MIICXDCCAc8GByqGSM49AgEwggHCAgEBME0GByqGSM49AQECQgH/////////////
    ////////////////////////////////////////////////////////////////
    /////////zCBngRCAf//////////////////////////////////////////////
    ///////////////////////////////////////8BEFRlT65YY4cmh+SmiGgtoVA
    7qLacluZsxXzuLSJkY7xCeFWGTlR7H6TexZSwL07sb8HNXPfiD0sNPHvRR/Ua1A/
    AAMVANCeiAApHLhTlsxnFzkyhKqg2mS6BIGFBADGhY4GtwQE6c2ePstmI5W0Qpxk
    gTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEY
    OSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdh
    NTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////////////////
    ////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEBA4GGAAQBMLgt
    gTFBGr0f7YrWwZsCPpLxaUQvUKvz2C6ghiFmxc2EzBgxDY+ywnmG4T++EVZhJHTP
    eIOnVRcHXXivkRe+YMQBbH/fZyqfCe41vIl39bwhqli839AAj/WoxXZuilpKaXBp
    vGbx2380UIhrec1jFjItOOg/Xp9dOecjQZK7Z0wVq1U=
    """)
    key = session.create_object(decode_ec_public_key(der))
    assert isinstance(key, pkcs11.PublicKey)

    # We should get back to identity
    assert encode_ec_public_key(key) == der


@pytest.mark.requires(Mechanism.ECDSA_SHA1)
def test_import_key_named_curve(session: pkcs11.Session) -> None:
    der = base64.b64decode("""
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa6Q5Hs+j71J1lc+VziafH+uL6603
    R8gTAphQD0iLG9Q9RgAvDQdFFpzkvXI+mEGVNRMmT/BA1OtficHcAXTdXA==
    """)
    key = session.create_object(decode_ec_public_key(der))
    assert isinstance(key, pkcs11.PublicKey)

    # Something signed with OpenSSL
    signature = base64.b64decode("""
    MEYCIQD1nDlli+uLuGX3eobKJe7PsRYkYJ4F15bjqbbB+MHewwIhAPGFRwyuFOvH
    zuj+sxXwk1CsDWN7AXbmHufOlOarXpiq
    """)
    signature = decode_ecdsa_signature(signature)

    assert key.verify(b"Data to sign", signature, mechanism=Mechanism.ECDSA_SHA1)

    # We should get back to identity
    assert encode_ec_public_key(key) == der


@pytest.mark.requires(Mechanism.ECDSA)
def test_import_key_pair(session: pkcs11.Session) -> None:
    priv = base64.b64decode("""
    MIICnAIBAQRB9JsyE7khj/d2jm5RkE9T2DKgr/y3gn4Ju+8oWfdIpurNKM4hh3Oo
    0T+ilc0BEy/SfJ5iqUxU5TocdFRpOUzfUIKgggHGMIIBwgIBATBNBgcqhkjOPQEB
    AkIB////////////////////////////////////////////////////////////
    //////////////////////////8wgZ4EQgH/////////////////////////////
    /////////////////////////////////////////////////////////ARBUZU+
    uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz
    34g9LDTx70Uf1GtQPwADFQDQnogAKRy4U5bMZxc5MoSqoNpkugSBhQQAxoWOBrcE
    BOnNnj7LZiOVtEKcZIE5BT+1Ifgor2BrTT26oUted+/nWSj+HcEnov+o3jNIs8GF
    akKb+X5+McLlvWYBGDkpaniaO8AEXIpftCx9G9mY9URJV5tEaBevvRcnPmYsl+5y
    mV70JkDFULkBP60HYTU8cIaicsJAiL6Udp/RZlACQgH/////////////////////
    //////////////////////pRhoeDvy+Wa3/MAUj3CaXQO7XJuImcR667b7cekThk
    CQIBAaGBiQOBhgAEATC4LYExQRq9H+2K1sGbAj6S8WlEL1Cr89guoIYhZsXNhMwY
    MQ2PssJ5huE/vhFWYSR0z3iDp1UXB114r5EXvmDEAWx/32cqnwnuNbyJd/W8IapY
    vN/QAI/1qMV2bopaSmlwabxm8dt/NFCIa3nNYxYyLTjoP16fXTnnI0GSu2dMFatV
    """)
    priv = session.create_object(decode_ec_private_key(priv))

    pub = base64.b64decode("""
    MIICXDCCAc8GByqGSM49AgEwggHCAgEBME0GByqGSM49AQECQgH/////////////
    ////////////////////////////////////////////////////////////////
    /////////zCBngRCAf//////////////////////////////////////////////
    ///////////////////////////////////////8BEFRlT65YY4cmh+SmiGgtoVA
    7qLacluZsxXzuLSJkY7xCeFWGTlR7H6TexZSwL07sb8HNXPfiD0sNPHvRR/Ua1A/
    AAMVANCeiAApHLhTlsxnFzkyhKqg2mS6BIGFBADGhY4GtwQE6c2ePstmI5W0Qpxk
    gTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEY
    OSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdh
    NTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////////////////
    ////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEBA4GGAAQBMLgt
    gTFBGr0f7YrWwZsCPpLxaUQvUKvz2C6ghiFmxc2EzBgxDY+ywnmG4T++EVZhJHTP
    eIOnVRcHXXivkRe+YMQBbH/fZyqfCe41vIl39bwhqli839AAj/WoxXZuilpKaXBp
    vGbx2380UIhrec1jFjItOOg/Xp9dOecjQZK7Z0wVq1U=
    """)
    pub = session.create_object(decode_ec_public_key(pub))

    signature = priv.sign(b"Example", mechanism=Mechanism.ECDSA)
    assert pub.verify(b"Example", signature, mechanism=Mechanism.ECDSA)


@pytest.mark.requires(Mechanism.EC_EDWARDS_KEY_PAIR_GEN)
@pytest.mark.requires(Mechanism.EDDSA)
def test_sign_eddsa(session: pkcs11.Session) -> None:
    parameters = session.create_domain_parameters(
        KeyType.EC_EDWARDS,
        {
            # use "Ed25519" once https://github.com/wbond/asn1crypto/pull/134
            # is merged
            Attribute.EC_PARAMS: encode_named_curve_parameters("1.3.101.112")
        },
        local=True,
    )

    pub, priv = parameters.generate_keypair()

    mechanism = Mechanism.EDDSA
    data = b"HI BOB!"
    eddsa = priv.sign(data, mechanism=mechanism)
    assert pub.verify(data, eddsa, mechanism=mechanism)
