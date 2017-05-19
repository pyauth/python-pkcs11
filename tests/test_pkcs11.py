"""
Tests
"""

import unittest

from _pkcs11_dyn_load import load

load('/usr/local/Cellar/softhsm/2.2.0/lib/softhsm/libsofthsm2.so')

import pkcs11

class PKCS11Tests(unittest.TestCase):

    def test_getInfo(self):
        lib = pkcs11.lib()
        info = lib.getInfo()
        self.assertIsInstance(info, pkcs11.Info)
        print(info)

    def test_getSlots(self):
        lib = pkcs11.lib()
        slots = lib.getSlots()

        for slot in slots:
            print(slot)
