"""
PKCS#11 SoftHSM v2 unit tests.

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import unittest

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11Tests(unittest.TestCase):

    def test_get_slots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()

        self.assertEqual(len(slots), 2)
        slot1, slot2 = slots

        self.assertIsInstance(slot1, pkcs11.Slot)
        self.assertEqual(slot1.flags, pkcs11.SlotFlag.TOKEN_PRESENT)

    def test_get_token(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        token = slot.get_token()

        self.assertIsInstance(token, pkcs11.Token)
        self.assertEqual(token.label, 'DEMO')
        self.assertIn(pkcs11.TokenFlag.TOKEN_INITIALIZED, token.flags)
        self.assertIn(pkcs11.TokenFlag.LOGIN_REQUIRED, token.flags)

    def test_get_mechanisms(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        mechanisms = slot.get_mechanisms()
        self.assertIn(pkcs11.Mechanism.RSA_PKCS, mechanisms)

    def test_get_tokens(self):
        lib = pkcs11.lib(LIB)

        tokens = lib.get_tokens(token_flags=pkcs11.TokenFlag.RNG)
        self.assertEqual(len(list(tokens)), 2)

        tokens = lib.get_tokens(token_label='DEMO')
        self.assertEqual(len(list(tokens)), 1)

    def test_open_session(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))

        with token.open() as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_user(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))

        with token.open(user_pin='1234') as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_so(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))

        with token.open(rw=True, so_pin='5678') as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_generate_key(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertIsInstance(key, pkcs11.EncryptMixin)

            self.assertIs(key.object_class, pkcs11.ObjectClass.SECRET_KEY)

            # Test GetAttribute
            self.assertIs(key[pkcs11.Attribute.CLASS],
                          pkcs11.ObjectClass.SECRET_KEY)
            self.assertEqual(key[pkcs11.Attribute.TOKEN], False)
            self.assertEqual(key[pkcs11.Attribute.LOCAL], True)
            self.assertEqual(key[pkcs11.Attribute.MODIFIABLE], True)
            self.assertEqual(key[pkcs11.Attribute.LABEL], '')

            # Test SetAttribute
            key[pkcs11.Attribute.LABEL] = "DEMO"

            self.assertEqual(key[pkcs11.Attribute.LABEL], "DEMO")

            # Create another key with no capabilities
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       label='MY KEY',
                                       id=b'\1\2\3\4',
                                       store=False, capabilities=0)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertNotIsInstance(key, pkcs11.EncryptMixin)

            self.assertEqual(key.label, 'MY KEY')

    def test_aes_encrypt(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))
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
        token = next(lib.get_tokens(token_label='DEMO'))
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
        token = next(lib.get_tokens(token_label='DEMO'))
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
