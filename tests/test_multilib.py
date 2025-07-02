"""
PKCS#11 Slots and Tokens
"""

import os
import unittest

import pkcs11

from . import LIB


@unittest.skipUnless("PKCS11_MODULE2" in os.environ, "Requires an additional PKCS#11 module")
class MultilibTests(unittest.TestCase):
    def test_double_initialise_different_libs(self):
        lib1 = pkcs11.lib(LIB)
        lib2 = pkcs11.lib(os.environ["PKCS11_MODULE2"])
        self.assertIsNotNone(lib1)
        self.assertIsNotNone(lib2)
        self.assertIsNot(lib1, lib2)

        slots1 = lib1.get_slots()
        slots2 = lib2.get_slots()

        self.assertGreaterEqual(len(slots1), 1)
        self.assertGreaterEqual(len(slots2), 1)
