"""
PKCS#11 Digests
"""

import hashlib

import pytest

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from tests.conftest import IS_NFAST


@pytest.mark.requires(Mechanism.SHA256)
def test_digest(session: pkcs11.Session) -> None:
    data = "THIS IS SOME DATA TO DIGEST"
    digest = session.digest(data, mechanism=Mechanism.SHA256)

    assert digest == hashlib.sha256(data.encode("utf-8")).digest()


@pytest.mark.requires(Mechanism.SHA256)
def test_digest_generator(session: pkcs11.Session) -> None:
    data = (b"This is ", b"some data ", b"to digest.")

    digest = session.digest(data, mechanism=Mechanism.SHA256)

    m = hashlib.sha256()
    for d in data:
        m.update(d)

    assert digest == m.digest()


@pytest.mark.requires(Mechanism.AES_KEY_GEN, Mechanism.SHA256)
@pytest.mark.skipif(IS_NFAST, reason="nFast can't digest keys")
def test_digest_key(session: pkcs11.Session) -> None:
    key = session.generate_key(
        KeyType.AES, 128, template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True}
    )

    digest = session.digest(key, mechanism=Mechanism.SHA256)

    assert digest == hashlib.sha256(key[Attribute.VALUE]).digest()


@pytest.mark.requires(Mechanism.AES_KEY_GEN, Mechanism.SHA256)
@pytest.mark.skipif(IS_NFAST, reason="nFast can't digest keys")
def test_digest_key_data(session: pkcs11.Session) -> None:
    key = session.generate_key(
        KeyType.AES,
        128,
        template={
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        },
    )

    data = (
        b"Some data",
        key,
    )

    digest = session.digest(data, mechanism=Mechanism.SHA256)

    m = hashlib.sha256()
    m.update(data[0])
    m.update(data[1][Attribute.VALUE])

    assert digest == m.digest()
