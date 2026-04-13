"""
PKCS#11 attribute mapper tests.
"""

import unittest

from pkcs11 import Attribute, MechanismFlag
from pkcs11.attributes import AttributeMapper


class AttributeMapperTests(unittest.TestCase):
    def test_public_key_template_is_not_shared_between_calls(self):
        mapper = AttributeMapper()

        rsa_template = mapper.public_key_template(
            capabilities=MechanismFlag.ENCRYPT | MechanismFlag.VERIFY,
            id_=b"rsa",
            label="rsa",
            store=True,
        )
        rsa_template.update(
            {
                Attribute.PUBLIC_EXPONENT: b"\x01\x00\x01",
                Attribute.MODULUS_BITS: 4096,
            }
        )

        ec_template = mapper.public_key_template(
            capabilities=MechanismFlag.VERIFY,
            id_=b"ec",
            label="ec",
            store=False,
        )

        self.assertNotIn(Attribute.PUBLIC_EXPONENT, mapper.default_public_key_template)
        self.assertNotIn(Attribute.MODULUS_BITS, mapper.default_public_key_template)
        self.assertNotIn(Attribute.PUBLIC_EXPONENT, ec_template)
        self.assertNotIn(Attribute.MODULUS_BITS, ec_template)
        self.assertEqual(ec_template[Attribute.ID], b"ec")
        self.assertEqual(ec_template[Attribute.LABEL], "ec")
        self.assertFalse(ec_template[Attribute.TOKEN])

    def test_private_key_template_is_not_shared_between_calls(self):
        mapper = AttributeMapper()

        rsa_template = mapper.private_key_template(
            capabilities=MechanismFlag.DECRYPT | MechanismFlag.SIGN,
            id_=b"rsa",
            label="rsa",
            store=True,
        )
        rsa_template[Attribute.EXTRACTABLE] = True

        ec_template = mapper.private_key_template(
            capabilities=MechanismFlag.SIGN | MechanismFlag.DERIVE,
            id_=b"ec",
            label="ec",
            store=False,
        )

        self.assertNotIn(Attribute.EXTRACTABLE, mapper.default_private_key_template)
        self.assertNotIn(Attribute.EXTRACTABLE, ec_template)
        self.assertEqual(ec_template[Attribute.ID], b"ec")
        self.assertEqual(ec_template[Attribute.LABEL], "ec")
        self.assertFalse(ec_template[Attribute.TOKEN])
