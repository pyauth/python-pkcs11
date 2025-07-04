"""
PKCS#11 RSA Public Key Cryptography
"""

import pkcs11
from pkcs11 import MGF, Attribute, KeyType, Mechanism, ObjectClass

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
