
from unittest import TestCase

from pkcs11 import Mechanism


class VendorExtensibleEnumTests(TestCase):

    def test_known_mechanism(self):
        mech = Mechanism(0)
        self.assertIs(mech, Mechanism.RSA_PKCS_KEY_PAIR_GEN)

    def test_unknown_mechanism(self):
        mech = Mechanism(3728959861)
        self.assertEqual(mech, 3728959861)
