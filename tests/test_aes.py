"""
PKCS#11 AES Secret Keys
"""

import pkcs11

from . import TestCase, Is, Not


class AESTests(TestCase):

    def setUp(self):
        super().setUp()
        self.key = self.session.generate_key(pkcs11.KeyType.AES, 128)

    def test_encrypt(self):
        data = b'INPUT DATA'
        iv = b'0' * 16

        crypttext = self.key.encrypt(data, mechanism_param=iv)
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext), 16)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == '\0' for c in crypttext))

        text = self.key.decrypt(crypttext, mechanism_param=iv)
        self.assertEqual(data, text)

    def test_encrypt_stream(self):
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )
        iv = b'0' * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))

        self.assertEqual(len(cryptblocks), len(data) + 1)

        crypttext = b''.join(cryptblocks)

        self.assertNotEqual(b''.join(data), crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext) % 16, 0)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == '\0' for c in crypttext))

        text = b''.join(self.key.decrypt(cryptblocks, mechanism_param=iv))
        self.assertEqual(b''.join(data), text)

    def test_encrypt_whacky_sizes(self):
        data = [
            (char * ord(char)).encode('utf-8')
            for char in 'HELLO WORLD'
        ]
        iv = b'0' * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))
        textblocks = list(self.key.decrypt(cryptblocks, mechanism_param=iv))

        self.assertEqual(b''.join(data), b''.join(textblocks))

    def test_encrypt_big_string(self):
        data = b'HELLO WORLD' * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    def test_sign(self):
        if Is.nfast:  # SHA512_HMAC requires a special `HMAC' key on nFast
            mechanism = pkcs11.Mechanism.AES_MAC
        else:
            mechanism = None

        data = b'HELLO WORLD' * 1024

        signature = self.key.sign(data, mechanism=mechanism)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature, mechanism=mechanism))
        self.assertFalse(self.key.verify(data, b'1234', mechanism=mechanism))

    def test_sign_stream(self):
        if Is.nfast:  # SHA512_HMAC requires a special `HMAC' key on nFast
            mechanism = pkcs11.Mechanism.AES_MAC
        else:
            mechanism = None

        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )

        signature = self.key.sign(data, mechanism=mechanism)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature, mechanism=mechanism))

    @Not.softhsm2
    def test_wrap(self):
        key = self.session.generate_key(pkcs11.KeyType.AES, 128, template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.SENSITIVE: False,
        })
        data = self.key.wrap_key(key)

        key2 = self.key.unwrap_key(pkcs11.ObjectClass.SECRET_KEY,
                                   pkcs11.KeyType.AES,
                                   data, template={
                                        pkcs11.Attribute.EXTRACTABLE: True,
                                        pkcs11.Attribute.SENSITIVE: False,
                                   })

        self.assertEqual(key[pkcs11.Attribute.VALUE],
                         key2[pkcs11.Attribute.VALUE])
