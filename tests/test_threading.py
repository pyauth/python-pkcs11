"""
PKCS#11 Thread Safety tests

Even though you have a session construct it turns out the expectation of
PKCS#11 is that you have a single session per process.
"""

import os
import unittest
import threading

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11SlotTokenTests(unittest.TestCase):

    def test_concurrency(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        # PKCS#11 says 1 session per process
        with token.open(user_pin='1234') as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='LOOK ME UP')

            test_passed = [True]

            def thread_work():
                try:
                    data = b'1234' * 1024 * 1024  # Multichunk files
                    iv = session.generate_random(128)
                    key = session.get_key(label='LOOK ME UP')
                    self.assertIsNotNone(key.encrypt(data, mechanism_param=iv))
                except pkcs11.PKCS11Error:
                    test_passed[0] = False
                    raise

            threads = [
                threading.Thread(target=thread_work)
                for _ in range(10)
            ]

            for thread in threads:
                thread.start()

            # join each thread
            for thread in threads:
                thread.join()

            self.assertTrue(test_passed[0])
