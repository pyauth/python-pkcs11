"""
Iterator tests
"""

import pytest

import pkcs11


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
@pytest.mark.requires(pkcs11.Mechanism.AES_CBC_PAD)
def test_partial_decrypt(session: pkcs11.Session) -> None:
    session.generate_key(pkcs11.KeyType.AES, 128, label="LOOK ME UP")

    key = session.get_key(label="LOOK ME UP")
    data = (b"1234", b"1234")

    iv = session.generate_random(128)
    encrypted_data = list(key.encrypt(data, mechanism_param=iv))

    iter1 = key.decrypt(encrypted_data, mechanism_param=iv)
    next(iter1)

    iter2 = key.decrypt(encrypted_data, mechanism_param=iv)
    with pytest.raises(pkcs11.OperationActive):
        next(iter2)


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
@pytest.mark.requires(pkcs11.Mechanism.AES_CBC_PAD)
# Ideally deleting iterator #1 would terminate the operation, but it
# currently does not.
@pytest.mark.xfail
def test_close_iterators(session: pkcs11.Session) -> None:
    session.generate_key(pkcs11.KeyType.AES, 128, label="LOOK ME UP")

    key = session.get_key(label="LOOK ME UP")
    data = (
        b"1234",
        b"1234",
    )

    iv = session.generate_random(128)
    encrypted_data = list(key.encrypt(data, mechanism_param=iv))

    iter1 = key.decrypt(encrypted_data, mechanism_param=iv)
    next(iter1)
    del iter1

    iter2 = key.decrypt(encrypted_data, mechanism_param=iv)
    next(iter2)
