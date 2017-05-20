"""
Tests
"""

import unittest

import pkcs11


LIB = '/usr/local/Cellar/softhsm/2.2.0/lib/softhsm/libsofthsm2.so'


class PKCS11Tests(unittest.TestCase):

    def test_initialize(self):
        lib = pkcs11.lib(LIB)
        print(repr(lib))
        print(lib)

    def test_get_slots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.get_slots()

        self.assertEqual(len(slots), 1)
        self.assertIsInstance(slots[0], pkcs11.Slot)

        for slot in slots:
            print(repr(slot))
            print(slot)

    def test_get_token(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        token = slot.get_token()
        self.assertIsInstance(token, pkcs11.Token)

        print(repr(token))
        print(token)

    def test_get_mechanisms(self):
        lib = pkcs11.lib(LIB)
        slot, *_ = lib.get_slots()
        print(slot.get_mechanisms())
