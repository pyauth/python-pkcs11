"""
PKCS#11 Public Key Cryptography

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import unittest
import struct

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11PKCTests(unittest.TestCase):

    def test_rsa_sign(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = b'HELLO WORLD' * 1024

        with token.open(user_pin='1234') as session:
            pub, priv = session.generate_keypair(KeyType.RSA, 1024,
                                                 store=False)
            signature = priv.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(pub.verify(data, signature))
            self.assertFalse(pub.verify(data, b'1234'))

    def test_rsa_sign_stream(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )

        with token.open(user_pin='1234') as session:
            pub, priv = session.generate_keypair(KeyType.RSA, 1024,
                                                 store=False)
            signature = priv.sign(data)
            self.assertIsNotNone(signature)
            self.assertIsInstance(signature, bytes)
            self.assertTrue(pub.verify(data, signature))

    def test_dh_key_derive(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            # Alice and Bob each create a Diffie-Hellman keypair from the
            # publicly available DH parameters
            #
            # E.g. RFC 3526, RFC 5114 or openssl dhparam -C 2236
            prime = [
                0x0F,0x52,0xE5,0x24,0xF5,0xFA,0x9D,0xDC,0xC6,0xAB,0xE6,0x04,
                0xE4,0x20,0x89,0x8A,0xB4,0xBF,0x27,0xB5,0x4A,0x95,0x57,0xA1,
                0x06,0xE7,0x30,0x73,0x83,0x5E,0xC9,0x23,0x11,0xED,0x42,0x45,
                0xAC,0x49,0xD3,0xE3,0xF3,0x34,0x73,0xC5,0x7D,0x00,0x3C,0x86,
                0x63,0x74,0xE0,0x75,0x97,0x84,0x1D,0x0B,0x11,0xDA,0x04,0xD0,
                0xFE,0x4F,0xB0,0x37,0xDF,0x57,0x22,0x2E,0x96,0x42,0xE0,0x7C,
                0xD7,0x5E,0x46,0x29,0xAF,0xB1,0xF4,0x81,0xAF,0xFC,0x9A,0xEF,
                0xFA,0x89,0x9E,0x0A,0xFB,0x16,0xE3,0x8F,0x01,0xA2,0xC8,0xDD,
                0xB4,0x47,0x12,0xF8,0x29,0x09,0x13,0x6E,0x9D,0xA8,0xF9,0x5D,
                0x08,0x00,0x3A,0x8C,0xA7,0xFF,0x6C,0xCF,0xE3,0x7C,0x3B,0x6B,
                0xB4,0x26,0xCC,0xDA,0x89,0x93,0x01,0x73,0xA8,0x55,0x3E,0x5B,
                0x77,0x25,0x8F,0x27,0xA3,0xF1,0xBF,0x7A,0x73,0x1F,0x85,0x96,
                0x0C,0x45,0x14,0xC1,0x06,0xB7,0x1C,0x75,0xAA,0x10,0xBC,0x86,
                0x98,0x75,0x44,0x70,0xD1,0x0F,0x20,0xF4,0xAC,0x4C,0xB3,0x88,
                0x16,0x1C,0x7E,0xA3,0x27,0xE4,0xAD,0xE1,0xA1,0x85,0x4F,0x1A,
                0x22,0x0D,0x05,0x42,0x73,0x69,0x45,0xC9,0x2F,0xF7,0xC2,0x48,
                0xE3,0xCE,0x9D,0x74,0x58,0x53,0xE7,0xA7,0x82,0x18,0xD9,0x3D,
                0xAF,0xAB,0x40,0x9F,0xAA,0x4C,0x78,0x0A,0xC3,0x24,0x2D,0xDB,
                0x12,0xA9,0x54,0xE5,0x47,0x87,0xAC,0x52,0xFE,0xE8,0x3D,0x0B,
                0x56,0xED,0x9C,0x9F,0xFF,0x39,0xE5,0xE5,0xBF,0x62,0x32,0x42,
                0x08,0xAE,0x6A,0xED,0x88,0x0E,0xB3,0x1A,0x4C,0xD3,0x08,0xE4,
                0xC4,0xAA,0x2C,0xCC,0xB1,0x37,0xA5,0xC1,0xA9,0x64,0x7E,0xEB,
                0xF9,0xD3,0xF5,0x15,0x28,0xFE,0x2E,0xE2,0x7F,0xFE,0xD9,0xB9,
                0x38,0x42,0x57,0x03,
            ]
            parameters = session.create_object({
                Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS,
                Attribute.KEY_TYPE: KeyType.DH,
                Attribute.PRIME: prime,
                Attribute.BASE: [0x2],
            })

            # Alice generate a keypair
            alice_public, alice_private = parameters.generate_keypair()
            alice_value = alice_public[Attribute.VALUE]

            # Bob generates a keypair
            bob_public, bob_private = parameters.generate_keypair()
            bob_value = bob_public[Attribute.VALUE]

            self.assertNotEqual(alice_value, bob_value)

            # Alice and Bob exchange values and an IV ...
            iv = session.generate_random(128)

            alice_session = alice_private.derive_key(
                KeyType.AES, 128, store=False,
                mechanism_param=bob_value)
            bob_session = bob_private.derive_key(
                KeyType.AES, 128, store=False,
                mechanism_param=alice_value)

            crypttext = alice_session.encrypt('HI BOB!', mechanism_param=iv)
            plaintext = bob_session.decrypt(crypttext, mechanism_param=iv)
            self.assertEqual(plaintext, b'HI BOB!')

    def test_key_wrap(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            pub, priv = session.generate_keypair(KeyType.RSA, 1024,
                                                 store=False)
            key = session.generate_key(KeyType.AES, 128,
                                       store=False,
                                       template={
                                           Attribute.EXTRACTABLE: True,
                                           Attribute.SENSITIVE: False,
                                       })

            data = pub.wrap_key(key)
            self.assertNotEqual(data, key[Attribute.VALUE])

            key2 = priv.unwrap_key(ObjectClass.SECRET_KEY,
                                   KeyType.AES,
                                   data,
                                   store=False,
                                   template={
                                           Attribute.EXTRACTABLE: True,
                                           Attribute.SENSITIVE: False,
                                   })

            self.assertEqual(key[Attribute.VALUE], key2[Attribute.VALUE])
