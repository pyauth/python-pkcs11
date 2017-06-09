"""
PKCS#11 Thread Safety tests

Even though you have a session construct it turns out the expectation of
PKCS#11 is that you have a single session per process.
"""

import threading

import pkcs11

from . import TestCase, Not, requires


@Not.nfast  # Deadlocks nfast ... something wrong with threading?
class ThreadingTests(TestCase):

    @requires(pkcs11.Mechanism.AES_KEY_GEN, pkcs11.Mechanism.AES_CBC_PAD)
    def test_concurrency(self):
        # Multiplexing a session between processes
        self.session.generate_key(pkcs11.KeyType.AES, 128, label='LOOK ME UP')

        test_passed = [True]

        def thread_work():
            try:
                data = b'1234' * 1024 * 1024  # Multichunk files
                iv = self.session.generate_random(128)
                key = self.session.get_key(label='LOOK ME UP')
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
