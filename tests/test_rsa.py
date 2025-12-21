"""
PKCS#11 RSA Public Key Cryptography
"""

import unittest

import pkcs11
from pkcs11 import MGF, Attribute, KeyType, Mechanism, MechanismFlag, ObjectClass
from pkcs11.util.rsa import decode_rsa_private_key, decode_rsa_public_key

from . import FIXME, TOKEN_PIN, TestCase, requires


class RSATests(TestCase):
    @requires(Mechanism.RSA_PKCS_KEY_PAIR_GEN)
    def setUp(self):
        super().setUp()

        self.public, self.private = self.session.generate_keypair(KeyType.RSA, 1024)

    def test_key_length(self):
        self.assertEqual(1024, self.private.key_length)
        self.assertEqual(1024, self.public.key_length)

    @requires(Mechanism.RSA_PKCS)
    def test_sign_pkcs_v15(self):
        data = b"00000000"

        signature = self.private.sign(data, mechanism=Mechanism.RSA_PKCS)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature, mechanism=Mechanism.RSA_PKCS))
        self.assertFalse(self.public.verify(data, b"1234", mechanism=Mechanism.RSA_PKCS))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_with_reauthentication(self):
        public, private = self.session.generate_keypair(
            KeyType.RSA, 1024, private_template={Attribute.ALWAYS_AUTHENTICATE: True}
        )
        data = "INPUT"

        signature = private.sign(data, pin=TOKEN_PIN)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_default(self):
        data = b"HELLO WORLD" * 1024

        signature = self.private.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature))
        self.assertFalse(self.public.verify(data, b"1234"))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_stream(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        signature = self.private.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_stream_with_reauthentication(self):
        public, private = self.session.generate_keypair(
            KeyType.RSA, 1024, private_template={Attribute.ALWAYS_AUTHENTICATE: True}
        )
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        signature = private.sign(data, pin=TOKEN_PIN)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_stream_with_empty_blocks(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"",
            b"P" * 16,
            b"" * 10,
            b"U" * 16,
            b"T" * 10,
        )

        signature = self.private.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_stream_undersized_buffer(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        signature = self.private.sign(data, buffer_size=16)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_sign_stream_interrupt_releases_operation(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        def _data_with_error():
            yield data[0]
            yield data[1]
            yield data[2]
            raise ValueError

        def attempt_sign():
            self.private.sign(_data_with_error())

        self.assertRaises(ValueError, attempt_sign)
        # ...try again
        signature = self.private.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.public.verify(data, signature))

    @requires(Mechanism.SHA512_RSA_PKCS)
    def test_verify_stream_interrupt_releases_operation(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        def _data_with_error():
            yield data[0]
            yield data[1]
            yield data[2]
            raise ValueError

        signature = self.private.sign(data)

        def attempt_verify():
            self.public.verify(_data_with_error(), signature)

        self.assertRaises(ValueError, attempt_verify)
        # ...try again
        self.assertTrue(self.public.verify(data, signature))

    @requires(Mechanism.RSA_PKCS_OAEP)
    @FIXME.opencryptoki  # can't set key attributes
    def test_key_wrap(self):
        key = self.session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        data = self.public.wrap_key(key)
        self.assertNotEqual(data, key[Attribute.VALUE])

        key2 = self.private.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            data,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        self.assertEqual(key[Attribute.VALUE], key2[Attribute.VALUE])

    @requires(Mechanism.RSA_PKCS_OAEP)
    def test_encrypt_oaep(self):
        data = b"SOME DATA"

        crypttext = self.public.encrypt(
            data,
            mechanism=Mechanism.RSA_PKCS_OAEP,
            mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None),
        )

        self.assertNotEqual(data, crypttext)

        plaintext = self.private.decrypt(
            crypttext,
            mechanism=Mechanism.RSA_PKCS_OAEP,
            mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None),
        )

        self.assertEqual(data, plaintext)

    @requires(Mechanism.SHA1_RSA_PKCS_PSS)
    def test_sign_pss(self):
        data = b"SOME DATA"

        # These are the default params
        signature = self.private.sign(
            data,
            mechanism=Mechanism.SHA1_RSA_PKCS_PSS,
            mechanism_param=(Mechanism.SHA_1, MGF.SHA1, 20),
        )

        self.assertTrue(self.public.verify(data, signature, mechanism=Mechanism.SHA1_RSA_PKCS_PSS))

    @requires(Mechanism.SHA1_RSA_PKCS_PSS)
    def test_sign_pss_undersized_buffer(self):
        data = b"SOME DATA"

        signature = self.private.sign(
            data,
            mechanism=Mechanism.SHA1_RSA_PKCS_PSS,
            mechanism_param=(Mechanism.SHA_1, MGF.SHA1, 20),
            buffer_size=16,
        )

        self.assertTrue(self.public.verify(data, signature, mechanism=Mechanism.SHA1_RSA_PKCS_PSS))

    @requires(Mechanism.RSA_PKCS_OAEP)
    def test_encrypt_too_much_data(self):
        data = b"1234" * 128

        # You can't encrypt lots of data with RSA
        # This should ideally throw DataLen but you can't trust it
        with self.assertRaises(pkcs11.PKCS11Error):
            self.public.encrypt(data)


class RSAUtilTests(unittest.TestCase):
    """Tests for RSA utility functions (no HSM required)."""

    # RSA 2048-bit Private Key (PKCS#1 DER format)
    # Generated with: python3 generate_hex_for_test.py
    RSA_PRIVATE_KEY_DER = bytes.fromhex(
        "308204a40201000282010100d7765d0172639bf18e98049dcbc3e8083aa284f2"
        "64321cc105d581c0c05042fdc4222e0b91625b9ce66e770028094e5b6f2658fd"
        "8857b4290d4dc6fb62ae326948f10c554660367ad13de7b47ea8f14afc76cb08"
        "c1ea0c880a7123d708b7fad7d45577d02604e7fda235fe089d5f2abb0417cdee"
        "b4a46613cf8d0dd07bdbaf1eefafaf0b924b7893b7942925a67783a367141720"
        "e76f4fa2c476d8f6367b8b0283411f9baa0c6ac32fac82ba2428ef19fcbb7069"
        "e3f5ea382f055e42045bc30bbcf2f7b7d3a0cf7f86534ac5236cebc99ceecc34"
        "1057712f9c5102e6c8aa0c9a9e46e198ecd0f8f18d0d77511ce8403c15f5b1df"
        "7e8ef3ad7964ad18356fa4fd0203010001028201001d11c11692e25185d3a13a"
        "ee3731a53a86feaa4531b37921a9b1d6a1b4d09f59317f130b488026b0127ed0"
        "db5a8b76e0eb2c17518d7597befa268634206a342ef442615197ff1f1a8ee475"
        "406ade4c3fbbb4234c792d24a7ae10f9aee7643b19a772288a12b712bdab86f1"
        "51243a54bf8a9bd392e3185315552948b5da20178e2b8f0c5abe1a217aa596ef"
        "21460043abf2a28e3fb1255801cd5d091dbd04064eef5c540fa770a173aa68b6"
        "c4b476b241cec815be4eabffe51512926d64e2f693cfbb84d7a2c669c6f089b1"
        "0d89b1193778fe7a2cf5470805af44acddb2e679f32ae86f3050771b7dd7b150"
        "e4cd2d918796129d8b52303e4334dca6483e14575902818100f1330624abb27a"
        "818fe2eb323022c5b3e6875a5367cfb444619ef4d0567258acba48a6ffa29835"
        "05672f87334eba1e1eafc8959c0cf6fc76978d0ab40e5a007f356ba4f84fd323"
        "5ca744321cf78d67720cd3741592454d61d0bf8a0e3cc6b5bf8fa0100fffae0a"
        "f5ecb7ad27b97d4dfbff41faaac38d07975b66930b4052d1f302818100e4af0a"
        "3f405366f91be44b3492b7d3e025f896fbb97fb9bc62878ffd29ee1dcf0c73a7"
        "1baacc06d44ff9d9ba0b5c35338dfac5c5e50ed61976d2449dac573e71b5d07f"
        "c3de6c8c89e041b7b00663cdfb329749322364277d361a96993463492474ddc4"
        "99abc7269641ea6a7f9b84764c9b96d4f8a1e39fe614bb5c8ee307794f028181"
        "00864ea034193b7805df263f4b220caac403310975fa0f6954ce7b21dd44d5c5"
        "54e1220583c17939c4f97138bab432e504b7635d1399108b024a5f6a3f5ae278"
        "f65cbbc50fd3fb40ec9de3567854cc7376c977916355a0ab77353302dfecadc5"
        "9496984d796b28f1c780f9c23ca58805bdb5a47abd4dc8a11a81f5bb197fc6de"
        "4b028181008ae8ac7fc952200d975cb0360a1d31cd49235c8b219dad33fa61c0"
        "1c16d936302baf20c5d494c45d390b5aaf00f18cbb7935e7e69281d599782cb7"
        "535379574bf915e2561708b6c1958035d4edbcb8452af0ec9c5115284b8d8ecf"
        "05d6e5ac6b41b5e813345def597c46a95444224d3db1910862d2eb92984ee594"
        "8e92e75a4f0281803793f2163018e7f5c39724ad650036f2f3bd707bbc9273a2"
        "5fd579e73f8b22894aae8fc2b6445d11977fc572f31cedb23be5bcb4a51f3ba2"
        "a0d4c34d8b4eee8ea21cf3182d6ed1a548c3adfa683e515a291cec9d4694873e"
        "4ddd8ff0666fa0e3ae3e5ebcc7db78775efcd70a433648a3181afea42f31c5cb"
        "cefc72489b2a557c"
    )

    # RSA 2048-bit Public Key (PKCS#1 DER format)
    # Generated with: python3 generate_hex_for_test.py
    RSA_PUBLIC_KEY_DER = bytes.fromhex(
        "3082010a0282010100d7765d0172639bf18e98049dcbc3e8083aa284f264321c"
        "c105d581c0c05042fdc4222e0b91625b9ce66e770028094e5b6f2658fd8857b4"
        "290d4dc6fb62ae326948f10c554660367ad13de7b47ea8f14afc76cb08c1ea0c"
        "880a7123d708b7fad7d45577d02604e7fda235fe089d5f2abb0417cdeeb4a466"
        "13cf8d0dd07bdbaf1eefafaf0b924b7893b7942925a67783a367141720e76f4f"
        "a2c476d8f6367b8b0283411f9baa0c6ac32fac82ba2428ef19fcbb7069e3f5ea"
        "382f055e42045bc30bbcf2f7b7d3a0cf7f86534ac5236cebc99ceecc34105771"
        "2f9c5102e6c8aa0c9a9e46e198ecd0f8f18d0d77511ce8403c15f5b1df7e8ef3"
        "ad7964ad18356fa4fd0203010001"
    )

    def test_decode_rsa_private_key_with_capabilities(self):
        """Test decode_rsa_private_key with explicit capabilities parameter."""
        # Test with explicit capabilities
        caps = MechanismFlag.SIGN | MechanismFlag.DECRYPT
        result = decode_rsa_private_key(self.RSA_PRIVATE_KEY_DER, capabilities=caps)

        self.assertEqual(result[Attribute.CLASS], ObjectClass.PRIVATE_KEY)
        self.assertEqual(result[Attribute.KEY_TYPE], KeyType.RSA)
        self.assertTrue(result[Attribute.SIGN])
        self.assertTrue(result[Attribute.DECRYPT])
        self.assertFalse(result[Attribute.UNWRAP])

    def test_decode_rsa_public_key_with_capabilities(self):
        """Test decode_rsa_public_key with explicit capabilities parameter."""
        # Test with explicit capabilities
        caps = MechanismFlag.ENCRYPT | MechanismFlag.VERIFY
        result = decode_rsa_public_key(self.RSA_PUBLIC_KEY_DER, capabilities=caps)

        self.assertEqual(result[Attribute.CLASS], ObjectClass.PUBLIC_KEY)
        self.assertEqual(result[Attribute.KEY_TYPE], KeyType.RSA)
        self.assertTrue(result[Attribute.ENCRYPT])
        self.assertTrue(result[Attribute.VERIFY])
        self.assertFalse(result[Attribute.WRAP])
