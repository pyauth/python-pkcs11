"""
PKCS#11 SoftHSM v2 unit tests.

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import unittest

import pkcs11


LIB = '/usr/local/Cellar/softhsm/2.2.0/lib/softhsm/libsofthsm2.so'


class PKCS11Tests(unittest.TestCase):

    def test_get_slots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()

        self.assertEqual(len(slots), 2)
        slot1, slot2 = slots

        self.assertIsInstance(slot1, pkcs11.Slot)
        self.assertEqual(slot1.flags, pkcs11.SlotFlags.TOKEN_PRESENT)

    def test_get_token(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        token = slot.get_token()

        self.assertIsInstance(token, pkcs11.Token)
        self.assertEqual(token.label, 'DEMO')
        self.assertIn(pkcs11.TokenFlags.TOKEN_INITIALIZED, token.flags)
        self.assertIn(pkcs11.TokenFlags.LOGIN_REQUIRED, token.flags)

    def test_get_mechanisms(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        mechanisms = slot.get_mechanisms()
        self.assertIn(pkcs11.Mechanisms.RSA_PKCS, mechanisms)

    def test_get_tokens(self):
        lib = pkcs11.lib(LIB)

        tokens = lib.get_tokens(token_flags=pkcs11.TokenFlags.RNG)
        self.assertEqual(len(list(tokens)), 2)

        tokens = lib.get_tokens(token_label='DEMO')
        self.assertEqual(len(list(tokens)), 1)

    def test_open_session(self):
        lib = pkcs11.lib(LIB)
        token = next(lib.get_tokens(token_label='DEMO'))

        with token.open() as session:
            self.assertIsInstance(session, pkcs11.Session)

