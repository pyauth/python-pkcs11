"""
Tests
"""

import unittest

import pkcs11


LIB = '/usr/local/Cellar/softhsm/2.2.0/lib/softhsm/libsofthsm2.so'


class PKCS11Tests(unittest.TestCase):

    def test_getInfo(self):
        lib = pkcs11.lib(LIB)
        info = lib.getInfo()
        self.assertIsInstance(info, pkcs11.Info)
        print(info)

    def test_getSlots(self):
        lib = pkcs11.lib(LIB)
        slots = lib.getSlots()

        self.assertEqual(len(slots), 1)
        self.assertIsInstance(slots[0], pkcs11.SlotInfo)

        for slot in slots:
            print(slot)
