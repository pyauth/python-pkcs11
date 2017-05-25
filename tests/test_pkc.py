"""
PKCS#11 Public Key Cryptography

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

    def test_rsa_sign(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = b'HELLO WORLD' * 1024

        with token.open(user_pin='1234') as session:
            pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 1024,
                                                 store=False)
            signature = priv.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(pub.verify(data, signature))

    def test_rsa_sign_stream(self):
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
            pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 1024,
                                                 store=False)
            signature = priv.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(pub.verify(data, signature))
