"""
PKCS#11 DES Secret Keys
"""

import pytest

import pkcs11
from pkcs11 import KeyType, Mechanism


@pytest.mark.requires(Mechanism.DES2_KEY_GEN)
def test_generate_des2_key(session: pkcs11.Session) -> None:
    key = session.generate_key(KeyType.DES2)
    assert isinstance(key, pkcs11.SecretKey)


@pytest.mark.requires(Mechanism.DES3_KEY_GEN)
def test_generate_des3_key(session: pkcs11.Session) -> None:
    key = session.generate_key(KeyType.DES3)
    assert isinstance(key, pkcs11.SecretKey)


@pytest.mark.requires(Mechanism.DES2_KEY_GEN)
@pytest.mark.requires(Mechanism.DES3_CBC_PAD)
def test_encrypt_des2(session: pkcs11.Session) -> None:
    key = session.generate_key(KeyType.DES2)

    iv = session.generate_random(64)
    crypttext = key.encrypt("PLAIN TEXT_", mechanism_param=iv)
    plaintext = key.decrypt(crypttext, mechanism_param=iv)

    assert plaintext == b"PLAIN TEXT_"


@pytest.mark.requires(Mechanism.DES3_KEY_GEN)
@pytest.mark.requires(Mechanism.DES3_CBC_PAD)
def test_encrypt_des3(session: pkcs11.Session) -> None:
    key = session.generate_key(KeyType.DES3)

    iv = session.generate_random(64)
    crypttext = key.encrypt("PLAIN TEXT_", mechanism_param=iv)
    plaintext = key.decrypt(crypttext, mechanism_param=iv)

    assert plaintext == b"PLAIN TEXT_"
