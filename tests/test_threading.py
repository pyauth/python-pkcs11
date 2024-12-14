"""
PKCS#11 Thread Safety tests

Even though you have a session construct it turns out the expectation of
PKCS#11 is that you have a single session per process.
"""

import threading
import typing

import pytest

import pkcs11
from pkcs11 import SecretKey

from .conftest import IS_NFAST

pytestmark = [
    pytest.mark.skipif(IS_NFAST, reason="Deadlocks nfast ... something wrong with threading?")
]


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
@pytest.mark.requires(pkcs11.Mechanism.AES_CBC_PAD)
def test_concurrency(session: pkcs11.Session) -> None:
    # Multiplexing a session between processes
    session.generate_key(pkcs11.KeyType.AES, 128, label="LOOK ME UP")

    test_passed = [True]

    def thread_work() -> None:
        try:
            data = b"1234" * 1024 * 1024  # Multichunk files
            iv = session.generate_random(128)
            key = typing.cast(SecretKey, session.get_key(label="LOOK ME UP"))
            assert key.encrypt(data, mechanism_param=iv) is not None
        except pkcs11.PKCS11Error:
            test_passed[0] = False
            raise

    threads = [threading.Thread(target=thread_work) for _ in range(10)]

    for thread in threads:
        thread.start()

    # join each thread
    for thread in threads:
        thread.join()

    assert test_passed[0]
