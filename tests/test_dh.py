"""
PKCS#11 Diffie-Hellman tests
"""

import base64

from pkcs11 import Attribute, KeyType, DomainParameters, Mechanism
from pkcs11.util.dh import (
    decode_dh_domain_parameters,
    encode_dh_domain_parameters,
    encode_dh_public_key,
)

from . import TestCase, requires, FIXME


class DHTests(TestCase):

    @requires(Mechanism.DH_PKCS_KEY_PAIR_GEN, Mechanism.DH_PKCS_DERIVE)
    @FIXME.opencryptoki  # AttributeValueInvalid when generating keypair
    def test_derive_key(self):
        # Alice and Bob each create a Diffie-Hellman keypair from the
        # publicly available DH parameters
        #
        # E.g. RFC 3526, RFC 5114 or openssl dhparam -C 2236
        prime = [
            0x0F,0x52,0xE5,0x24,0xF5,0xFA,0x9D,0xDC,0xC6,0xAB,0xE6,0x04, # noqa
            0xE4,0x20,0x89,0x8A,0xB4,0xBF,0x27,0xB5,0x4A,0x95,0x57,0xA1, # noqa
            0x06,0xE7,0x30,0x73,0x83,0x5E,0xC9,0x23,0x11,0xED,0x42,0x45, # noqa
            0xAC,0x49,0xD3,0xE3,0xF3,0x34,0x73,0xC5,0x7D,0x00,0x3C,0x86, # noqa
            0x63,0x74,0xE0,0x75,0x97,0x84,0x1D,0x0B,0x11,0xDA,0x04,0xD0, # noqa
            0xFE,0x4F,0xB0,0x37,0xDF,0x57,0x22,0x2E,0x96,0x42,0xE0,0x7C, # noqa
            0xD7,0x5E,0x46,0x29,0xAF,0xB1,0xF4,0x81,0xAF,0xFC,0x9A,0xEF, # noqa
            0xFA,0x89,0x9E,0x0A,0xFB,0x16,0xE3,0x8F,0x01,0xA2,0xC8,0xDD, # noqa
            0xB4,0x47,0x12,0xF8,0x29,0x09,0x13,0x6E,0x9D,0xA8,0xF9,0x5D, # noqa
            0x08,0x00,0x3A,0x8C,0xA7,0xFF,0x6C,0xCF,0xE3,0x7C,0x3B,0x6B, # noqa
            0xB4,0x26,0xCC,0xDA,0x89,0x93,0x01,0x73,0xA8,0x55,0x3E,0x5B, # noqa
            0x77,0x25,0x8F,0x27,0xA3,0xF1,0xBF,0x7A,0x73,0x1F,0x85,0x96, # noqa
            0x0C,0x45,0x14,0xC1,0x06,0xB7,0x1C,0x75,0xAA,0x10,0xBC,0x86, # noqa
            0x98,0x75,0x44,0x70,0xD1,0x0F,0x20,0xF4,0xAC,0x4C,0xB3,0x88, # noqa
            0x16,0x1C,0x7E,0xA3,0x27,0xE4,0xAD,0xE1,0xA1,0x85,0x4F,0x1A, # noqa
            0x22,0x0D,0x05,0x42,0x73,0x69,0x45,0xC9,0x2F,0xF7,0xC2,0x48, # noqa
            0xE3,0xCE,0x9D,0x74,0x58,0x53,0xE7,0xA7,0x82,0x18,0xD9,0x3D, # noqa
            0xAF,0xAB,0x40,0x9F,0xAA,0x4C,0x78,0x0A,0xC3,0x24,0x2D,0xDB, # noqa
            0x12,0xA9,0x54,0xE5,0x47,0x87,0xAC,0x52,0xFE,0xE8,0x3D,0x0B, # noqa
            0x56,0xED,0x9C,0x9F,0xFF,0x39,0xE5,0xE5,0xBF,0x62,0x32,0x42, # noqa
            0x08,0xAE,0x6A,0xED,0x88,0x0E,0xB3,0x1A,0x4C,0xD3,0x08,0xE4, # noqa
            0xC4,0xAA,0x2C,0xCC,0xB1,0x37,0xA5,0xC1,0xA9,0x64,0x7E,0xEB, # noqa
            0xF9,0xD3,0xF5,0x15,0x28,0xFE,0x2E,0xE2,0x7F,0xFE,0xD9,0xB9, # noqa
            0x38,0x42,0x57,0x03, # noqa
        ]
        parameters = self.session.create_domain_parameters(KeyType.DH, {
            Attribute.PRIME: prime,
            Attribute.BASE: [0x2],
        }, local=True)

        # Alice generate a keypair
        alice_public, alice_private = parameters.generate_keypair()
        alice_value = alice_public[Attribute.VALUE]

        # Bob generates a keypair
        bob_public, bob_private = parameters.generate_keypair()
        bob_value = bob_public[Attribute.VALUE]

        self.assertNotEqual(alice_value, bob_value)

        # Alice and Bob exchange values and an IV ...
        iv = self.session.generate_random(128)

        alice_session = alice_private.derive_key(
            KeyType.AES, 128,
            mechanism_param=bob_value, template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            })
        bob_session = bob_private.derive_key(
            KeyType.AES, 128,
            mechanism_param=alice_value, template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            })

        self.assertEqual(alice_session[Attribute.VALUE],
                         bob_session[Attribute.VALUE])

        crypttext = alice_session.encrypt('HI BOB!', mechanism_param=iv)
        plaintext = bob_session.decrypt(crypttext, mechanism_param=iv)
        self.assertEqual(plaintext, b'HI BOB!')

    def test_load_params(self):
        # This is RFC5114 #2
        PARAMS = base64.b64decode("""
        MIICKQKCAQEArRB+HpEjqdDWYPqnlVnFH6INZOVoO5/RtUsVl7YdCnXm+hQd+VpW
        26+aPEB7od8V6z1oijCcGA4d5rhaEnSgpm0/gVKtasISkDfJ7e/aTfjZHo/vVbc5
        S3rVt9C2wSIHyfmNEe002/bGugssi7wnvmoA4KC5xJcIs7+KMXCRiDaBKGEwvImF
        2xYC5xRBXZMwJ4Jzx94x79xzEPcSH9WgdBWYfZrcCkhtzfk6zEQyg4cxXXXhmMZB
        pIDNhqG55YfovmDmnMkosrnFIXLkEwQumyPxCw4W55djybU9z0uoCinj+3PBa451
        uX7zY+L/ox9xz53lOE5xuBwKxN/+DBDmTwKCAQEArEAy708tmuOd8wtcj/2sUGze
        vnuJmYyvdIZqCM/k/+OmgkpOELmm8N2SHwGnDEr6q3OddwDCn1LFfbF8YgqGUr5e
        kAGo1mrXwXZpEBmZAkr00CcnWsE0i7inYtBSG8mK4kcVBCLqHtQJk51U2nRgzbX2
        xrJQcXy+8YDrNBGOmNEZUppF1vg0Vm4wJeMWozDvu3eobwwasVsFGuPUKMj4rLcK
        gTcVC47rEOGD7dGZY93Z4mPkdwWJ72qiHn9fL/OBtTnM40CdE81Wavu0jWwBkYHh
        vP6UswJp7f5y/ptqpL17Wg8ccc//TBnEGOH27AF5gbwIfypwZbOEuJDTGR8r+gId
        AIAcDTTFjZP+mXF3EB+AU1pHOM68vziambNjces=
        """)

        params = self.session.create_domain_parameters(
            KeyType.DH,
            decode_dh_domain_parameters(PARAMS),
            local=True)
        self.assertIsInstance(params, DomainParameters)
        self.assertEqual(params[Attribute.PRIME][:4],
                         b'\xAD\x10\x7E\x1E')

    @requires(Mechanism.DH_PKCS_PARAMETER_GEN, Mechanism.DH_PKCS_KEY_PAIR_GEN)
    def test_generate_params(self):
        params = self.session.generate_domain_parameters(KeyType.DH, 512)
        self.assertIsInstance(params, DomainParameters)
        self.assertEqual(params[Attribute.PRIME_BITS], 512)
        self.assertEqual(len(params[Attribute.PRIME]) * 8, 512)
        encode_dh_domain_parameters(params)

        # Test encoding the public key
        public, _ = params.generate_keypair()
        encode_dh_public_key(public)
