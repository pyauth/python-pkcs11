"""
Test nFast extension types
"""

from enum import IntEnum

from pkcs11 import Attribute, Mechanism, KeyType

from . import TestCase, Only

NFCK_VENDOR_NCIPHER = 0xde436972
CKA_NCIPHER = (Attribute._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
CKM_NCIPHER = (Mechanism._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
CKK_NCIPHER = (KeyType._VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)


class NCMechanism(IntEnum):
    X_NC_SHA224_HMAC_KEY_GEN = (CKM_NCIPHER + 0x24)
    X_NC_SHA256_HMAC_KEY_GEN = (CKM_NCIPHER + 0x25)
    X_NC_SHA384_HMAC_KEY_GEN = (CKM_NCIPHER + 0x26)
    X_NC_SHA512_HMAC_KEY_GEN = (CKM_NCIPHER + 0x27)


@Only.nfast
class nFastTests(TestCase):

    @classmethod
    def setUpClass(cls):
        Mechanism.load_extensions(NCMechanism)

    def test_mechanisms_loaded(self):
        mechanisms = self.token.slot.get_mechanisms()
        print(mechanisms)
        self.assertIn(Mechanism.X_NC_SHA512_HMAC_KEY_GEN, mechanisms)
