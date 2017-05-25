"""
PKCS#11 Secret Keys

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import unittest

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11SecretKeyTests(unittest.TestCase):

    def test_aes_encrypt(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = b'INPUT DATA'
        iv = b'0' * 16

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            crypttext = key.encrypt(data, mechanism_param=iv)
            self.assertIsInstance(crypttext, bytes)
            self.assertNotEqual(data, crypttext)
            # We should be aligned to the block size
            self.assertEqual(len(crypttext), 16)
            # Ensure we didn't just get 16 nulls
            self.assertFalse(all(c == '\0' for c in crypttext))

            text = key.decrypt(crypttext, mechanism_param=iv)
            self.assertEqual(data, text)

    def test_aes_encrypt_stream(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )
        iv = b'0' * 16

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            cryptblocks = list(key.encrypt(data, mechanism_param=iv))

            self.assertEqual(len(cryptblocks), len(data) + 1)

            crypttext = b''.join(cryptblocks)

            self.assertNotEqual(b''.join(data), crypttext)
            # We should be aligned to the block size
            self.assertEqual(len(crypttext) % 16, 0)
            # Ensure we didn't just get 16 nulls
            self.assertFalse(all(c == '\0' for c in crypttext))

            text = b''.join(key.decrypt(cryptblocks, mechanism_param=iv))
            self.assertEqual(b''.join(data), text)

    def test_aes_encrypt_whacky_sizes(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = [
            (char * ord(char)).encode('utf-8')
            for char in 'HELLO WORLD'
        ]
        iv = b'0' * 16

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            cryptblocks = list(key.encrypt(data, mechanism_param=iv))
            textblocks = list(key.decrypt(cryptblocks, mechanism_param=iv))

            self.assertEqual(b''.join(data), b''.join(textblocks))

    def test_aes_big_string(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = b'HELLO WORLD' * 1024

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 256, store=False)
            iv = session.generate_random(128)
            crypttext = key.encrypt(data, mechanism_param=iv)
            text = key.decrypt(crypttext, mechanism_param=iv)

            self.assertEqual(text, data)

    def test_aes_sign(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = b'HELLO WORLD' * 1024

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 256, store=False)
            signature = key.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(key.verify(data, signature))
            self.assertFalse(key.verify(data, b'1234'))

    def test_aes_sign_stream(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            signature = key.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(key.verify(data, signature))
