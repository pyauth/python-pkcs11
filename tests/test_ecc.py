"""
PKCS#11 Elliptic Curve Cryptography.
"""

import base64

from pyasn1.codec.der import encoder
from pyasn1_modules.rfc3279 import EcpkParameters, prime256v1

from pkcs11 import Attribute, KeyType, KDF, Mechanism

from . import TestCase, Not


@Not.nfast  # No ECC on our nfast device
class ECCTests(TestCase):
    def test_sign(self):
        # Create EC_PARAMS for the named curve 'prime256v1'
        ecparams = EcpkParameters()
        ecparams['namedCurve'] = prime256v1

        parameters = self.session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: encoder.encode(ecparams),
        }, local=True)

        pub, priv = parameters.generate_keypair()

        mechanism = Mechanism.ECDSA  # SoftHSMv2 doesn't support ECDSA_SHA512
        data = b'HI BOB!'
        ecdsa = priv.sign(data, mechanism=mechanism)
        self.assertTrue(pub.verify(data, ecdsa, mechanism=mechanism))

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
