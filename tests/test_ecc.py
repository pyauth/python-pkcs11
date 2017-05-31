"""
PKCS#11 Elliptic Curve Cryptography.

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import base64
import unittest

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, KDF


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11ECCTests(unittest.TestCase):
    def test_ecc_derive_key(self):
        # DER encoded EC params from OpenSSL
        # openssl ecparam -out ec_param.der -name prime192v1
        ecparams = base64.b64decode(b'BggqhkjOPQMBAQ==')

        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            parameters = session.create_domain_parameters(KeyType.EC, {
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

            iv = session.generate_random(128)
            crypttext = alice_session.encrypt('HI BOB!', mechanism_param=iv)
            plaintext = bob_session.decrypt(crypttext, mechanism_param=iv)
            self.assertEqual(plaintext, b'HI BOB!')
