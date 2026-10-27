import unittest

from pkcs11 import Attribute
from pkcs11._pkcs11 import template_as_attribute_list
from pkcs11.attributes import AttributeMapper


class AttributeListWithTemplateTest(unittest.TestCase):
    def test_unwrap_template_readback(self):
        template = {
            Attribute.SENSITIVE: True,
            Attribute.EXTRACTABLE: False,
            Attribute.WRAP: True,
            Attribute.UNWRAP: True,
            Attribute.UNWRAP_TEMPLATE: {Attribute.EXTRACTABLE: False},
            Attribute.LABEL: "test",
        }
        mapper = AttributeMapper()
        lst = template_as_attribute_list(template)
        self.assertEqual("test", lst.get(Attribute.LABEL, mapper))
        self.assertEqual({Attribute.EXTRACTABLE: False}, lst.get(Attribute.UNWRAP_TEMPLATE, mapper))
        self.assertEqual(template, lst.as_dict(mapper))

    def test_derive_template_readback(self):
        template = {
            Attribute.SENSITIVE: True,
            Attribute.EXTRACTABLE: False,
            Attribute.DERIVE: True,
            Attribute.DERIVE_TEMPLATE: {Attribute.EXTRACTABLE: False},
            Attribute.LABEL: "test",
        }
        mapper = AttributeMapper()
        lst = template_as_attribute_list(template)
        self.assertEqual("test", lst.get(Attribute.LABEL, mapper))
        self.assertEqual({Attribute.EXTRACTABLE: False}, lst.get(Attribute.DERIVE_TEMPLATE, mapper))
        self.assertEqual(template, lst.as_dict(mapper))

    def test_nested_template(self):
        template = {
            Attribute.SENSITIVE: True,
            Attribute.EXTRACTABLE: False,
            Attribute.DERIVE: True,
            Attribute.DERIVE_TEMPLATE: {
                Attribute.EXTRACTABLE: False,
                Attribute.DERIVE_TEMPLATE: {Attribute.EXTRACTABLE: False},
            },
            Attribute.LABEL: "test",
        }
        mapper = AttributeMapper()
        lst = template_as_attribute_list(template)
        self.assertEqual("test", lst.get(Attribute.LABEL, mapper))
        self.assertEqual(template, lst.as_dict(mapper))
