"""
Test nFast extension types
"""

from enum import IntEnum

from pkcs11 import Attribute, Mechanism, KeyType

from . import TestCase, Only

# From their PKCS#11 extension header
NFCK_VENDOR_NCIPHER = 0xde436972
CKA_NCIPHER = (Attribute._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
CKM_NCIPHER = (Mechanism._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
CKK_NCIPHER = (KeyType._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)


class NCMechanism(IntEnum):
    SHA224_HMAC_KEY_GEN = (CKM_NCIPHER + 0x24)
    SHA256_HMAC_KEY_GEN = (CKM_NCIPHER + 0x25)
    SHA384_HMAC_KEY_GEN = (CKM_NCIPHER + 0x26)
    SHA512_HMAC_KEY_GEN = (CKM_NCIPHER + 0x27)


@Only.nfast
class nFastTests(TestCase):

    @classmethod
    def setUpClass(cls):
        Mechanism.load_extensions(NCMechanism)

    def test_mechanisms_loaded(self):
        mechanisms = self.token.slot.get_mechanisms()
        print(mechanisms)
        self.assertIn(NCMechanism.SHA512_HMAC_KEY_GEN, mechanisms)
