"""
Test extending enums with vendor defined mechanisms
"""

from enum import IntEnum
from unittest import TestCase

from pkcs11 import Mechanism


class VendorMechanism(IntEnum):
    X_NEW_MECHANISM = 3728959862


class VendorExtensibleEnumTests(TestCase):

    def test_known_mechanism(self):
        mech = Mechanism(0)
        self.assertIs(mech, Mechanism.RSA_PKCS_KEY_PAIR_GEN)

    def test_unknown_mechanism(self):
        mech = Mechanism(3728959861)
        self.assertEqual(mech, 3728959861)

    # def test_load_extensions(self):
    #     Mechanism.load_extension(VendorMechanism)
    #     mech = Mechanism(VendorMechanism.X_NEW_MECHANISM)
    #     self.assertEqual(mech, VendorMechanism.X_NEW_MECHANISM)
    #     self.assertEqual(str(mech), 'VendorMechanism.X_NEW_MECHANISM')
