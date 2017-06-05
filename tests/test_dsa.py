"""
PKCS#11 DSA Tests
"""

import pkcs11
from pkcs11 import KeyType, Attribute

from . import TestCase


PRIME = \
    b'\x82\x92+\x10\xa6\xd4\xb5a\x02\x1a\xa2\x07Z\xc1V6\xb0%\xad\xbaF\x07'\
    b'\x18\x0f-L`\xeb\x10)\x00\xffF\x7f\xab"~u;O\xbaI\xe5\x93~y\xd7\xe5tg'\
    b'\xb8>\x90\x180E\xd1\xa0\x04YE\x8cj1'
SUBPRIME = b'\xbaD\xf5\xe2\x9fkR\xea\x0f8\xf1\xf3\xc8=Ba\xf9\xb2_w'
BASE = \
    b'\x1e\xf7\x8f+\xba{\xffJZ\xbdgk\x98\x9bE\x90[\x1e\xefgP\xa1\xd7\xcb'\
    b'\xe1\xf7U)\xd1\x9d\x18\xed;H-\x004O^6\xa9G\xf1\xac\x9d\xd2\x1e\xbf'\
    b'\xf74\xa4\xefh\xd28\x90\xa9\x99\xebsYd\xfdY'


class DSATests(TestCase):

    def test_generate_params(self):
        parameters = self.session.generate_domain_parameters(KeyType.DSA, 512)
        self.assertIsInstance(parameters, pkcs11.DomainParameters)
        self.assertEqual(parameters[Attribute.PRIME_BITS], 512)

    def test_generate_keypair_and_sign(self):
        dhparams = self.session.create_domain_parameters(KeyType.DSA, {
            Attribute.PRIME: PRIME,
            Attribute.SUBPRIME: SUBPRIME,
            Attribute.BASE: BASE,
        }, local=True)

        public, private = dhparams.generate_keypair()
        self.assertIsInstance(public, pkcs11.PublicKey)
        self.assertIsInstance(private, pkcs11.PrivateKey)

        data = 'Message to sign'
        signature = private.sign(data)
        self.assertTrue(public.verify(data, signature))
