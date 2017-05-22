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

            # Test GetAttribute
            self.assertEqual(key[pkcs11.Attribute.TOKEN], False)
            self.assertEqual(key[pkcs11.Attribute.LOCAL], True)
            self.assertEqual(key[pkcs11.Attribute.MODIFIABLE], True)
            self.assertEqual(key[pkcs11.Attribute.LABEL], '')

            # Test SetAttribute
            key[pkcs11.Attribute.LABEL] = "DEMO"

            self.assertEqual(key[pkcs11.Attribute.LABEL], "DEMO")
