"""
PKCS#11 Slots and Tokens

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import unittest

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11SlotTokenTests(unittest.TestCase):

    def test_double_initialise(self):
        self.assertIsNotNone(pkcs11.lib(LIB))
        self.assertIsNotNone(pkcs11.lib(LIB))

    def test_double_initialise_different_libs(self):
        self.assertIsNotNone(pkcs11.lib(LIB))
        with self.assertRaises(pkcs11.AlreadyInitialized):
            pkcs11.lib('somethingelse.so')

    def test_get_slots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()

        self.assertEqual(len(slots), 2)
        slot1, slot2 = slots

        self.assertIsInstance(slot1, pkcs11.Slot)
        self.assertEqual(slot1.flags, pkcs11.SlotFlag.TOKEN_PRESENT)

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

    def test_get_token(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        token = slot.get_token()

        self.assertIsInstance(token, pkcs11.Token)
        self.assertEqual(token.label, 'DEMO')
        self.assertIn(pkcs11.TokenFlag.TOKEN_INITIALIZED, token.flags)
        self.assertIn(pkcs11.TokenFlag.LOGIN_REQUIRED, token.flags)
