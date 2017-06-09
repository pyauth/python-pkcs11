"""
PKCS#11 Elliptic Curve Cryptography.
"""

import base64

from pyasn1_modules.rfc3279 import prime256v1

from pkcs11 import Attribute, KeyType, KDF, Mechanism
from pkcs11.util.ec import encode_named_curve_parameters

from . import TestCase, requires


class ECCTests(TestCase):
    @requires(Mechanism.EC_KEY_PAIR_GEN, Mechanism.ECDSA)
    def test_sign_ecdsa(self):
        parameters = self.session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: encode_named_curve_parameters(prime256v1)
        }, local=True)

        pub, priv = parameters.generate_keypair()

        mechanism = Mechanism.ECDSA
        data = b'HI BOB!'
        ecdsa = priv.sign(data, mechanism=mechanism)
        self.assertTrue(pub.verify(data, ecdsa, mechanism=mechanism))

    @requires(Mechanism.EC_KEY_PAIR_GEN, Mechanism.ECDH1_DERIVE)
    def test_derive_key(self):
        # DER encoded EC params from OpenSSL
        # openssl ecparam -out ec_param.der -name prime192v1
        ecparams = base64.b64decode(b'BggqhkjOPQMBAQ==')

        parameters = self.session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: ecparams,
        }, local=True)
        alice_pub, alice_priv = parameters.generate_keypair()
        alice_value = alice_pub[Attribute.EC_POINT]

        bob_pub, bob_priv = parameters.generate_keypair()
        bob_value = bob_pub[Attribute.EC_POINT]

        self.assertNotEqual(alice_value, bob_value)

        alice_session = alice_priv.derive_key(
            KeyType.AES, 128,
            mechanism_param=(KDF.NULL, None, bob_value))

        bob_session = bob_priv.derive_key(
            KeyType.AES, 128,
            mechanism_param=(KDF.NULL, None, alice_value))

        iv = self.session.generate_random(128)
        crypttext = alice_session.encrypt('HI BOB!', mechanism_param=iv)
        plaintext = bob_session.decrypt(crypttext, mechanism_param=iv)
        self.assertEqual(plaintext, b'HI BOB!')
