"""
PKCS#11 DES Secret Keys
"""

import pkcs11
from pkcs11 import KeyType

from . import TestCase, Not


class DESTests(TestCase):

    def test_generate_des2_key(self):
        key = self.session.generate_key(KeyType.DES2)
        self.assertIsInstance(key, pkcs11.SecretKey)

    def test_generate_des3_key(self):
        key = self.session.generate_key(KeyType.DES3)
        self.assertIsInstance(key, pkcs11.SecretKey)

    def test_encrypt_des2(self):
        key = self.session.generate_key(KeyType.DES2)

        iv = self.session.generate_random(64)
        crypttext = key.encrypt('PLAIN TEXT_', mechanism_param=iv)
        plaintext = key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(plaintext, b'PLAIN TEXT_')

    def test_encrypt_des3(self):
        key = self.session.generate_key(KeyType.DES3)

        iv = self.session.generate_random(64)
        crypttext = key.encrypt('PLAIN TEXT_', mechanism_param=iv)
        plaintext = key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(plaintext, b'PLAIN TEXT_')
