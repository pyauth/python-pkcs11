"""
PKCS#11 AES Secret Keys
"""

from parameterized import parameterized

import pkcs11
from pkcs11 import ArgumentsBad, CTRParams, GCMParams, Mechanism, PKCS11Error

from . import FIXME, TestCase, requires


class AESTests(TestCase):
    @requires(Mechanism.AES_KEY_GEN)
    def setUp(self):
        super().setUp()
        self.key = self.session.generate_key(pkcs11.KeyType.AES, 128)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt(self):
        data = b"INPUT DATA"
        iv = b"0" * 16

        crypttext = self.key.encrypt(data, mechanism_param=iv)
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext), 16)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == "\0" for c in crypttext))

        text = self.key.decrypt(crypttext, mechanism_param=iv)
        self.assertEqual(data, text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_undersized_buffer(self):
        data = b"INPUT DATA" * 200
        iv = b"0" * 16

        crypttext = self.key.encrypt(data, mechanism_param=iv, buffer_size=32)
        text = self.key.decrypt(crypttext, mechanism_param=iv, buffer_size=32)
        self.assertEqual(data, text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_stream(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,  # don't align to the blocksize
        )
        iv = b"0" * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))

        self.assertEqual(len(cryptblocks), len(data) + 1)

        crypttext = b"".join(cryptblocks)

        self.assertNotEqual(b"".join(data), crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext) % 16, 0)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == "\0" for c in crypttext))

        text = b"".join(self.key.decrypt(cryptblocks, mechanism_param=iv))
        self.assertEqual(b"".join(data), text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_stream_interrupt_releases_operation(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )
        iv = b"0" * 16

        def _data_with_error():
            yield data[0]
            yield data[1]
            yield data[2]
            raise ValueError

        def attempt_encrypt():
            list(self.key.encrypt(_data_with_error(), mechanism_param=iv))

        self.assertRaises(ValueError, attempt_encrypt)

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))
        text = b"".join(self.key.decrypt(cryptblocks, mechanism_param=iv))
        self.assertEqual(b"".join(data), text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_stream_gc_releases_operation(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )
        iv = b"0" * 16

        attempt = self.key.encrypt(data, mechanism_param=iv)
        next(attempt)
        del attempt

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))
        text = b"".join(self.key.decrypt(cryptblocks, mechanism_param=iv))
        self.assertEqual(b"".join(data), text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_stream_undersized_buffers(self):
        data = (
            b"I" * 3189,
            b"N" * 3284,
            b"P" * 5812,
            b"U" * 2139,
            b"T" * 5851,
        )
        iv = b"0" * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv, buffer_size=256))

        self.assertEqual(len(cryptblocks), len(data) + 1)

        crypttext = b"".join(cryptblocks)

        self.assertNotEqual(b"".join(data), crypttext)
        text = b"".join(self.key.decrypt(cryptblocks, mechanism_param=iv, buffer_size=5))
        self.assertEqual(b"".join(data), text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_whacky_sizes(self):
        data = [(char * ord(char)).encode("utf-8") for char in "HELLO WORLD"]
        iv = b"0" * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))
        textblocks = list(self.key.decrypt(cryptblocks, mechanism_param=iv))

        self.assertEqual(b"".join(data), b"".join(textblocks))

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_big_string(self):
        data = b"HELLO WORLD" * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    @requires(Mechanism.AES_MAC)
    def test_sign(self):
        data = b"HELLO WORLD"

        signature = self.key.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature))
        self.assertFalse(self.key.verify(data, b"1234"))

    @requires(Mechanism.AES_MAC)
    def test_sign_stream(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,  # don't align to the blocksize
        )

        signature = self.key.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature))

    @requires(Mechanism.AES_KEY_WRAP)
    @FIXME.opencryptoki  # can't set key attributes
    def test_wrap(self):
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            128,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )
        data = self.key.wrap_key(key)

        key2 = self.key.unwrap_key(
            pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.KeyType.AES,
            data,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )

        self.assertEqual(key[pkcs11.Attribute.VALUE], key2[pkcs11.Attribute.VALUE])

    @parameterized.expand(
        [
            ("POSITIVE_128_BIT", 128, 16, TestCase.assertIsNotNone),
            ("POSITIVE_128_BIT_LONG_IV", 128, 32, TestCase.assertIsNotNone),
            ("NEGATIVE_128_BIT_BAD_IV", 128, 15, TestCase.assertIsNone),
            ("POSITIVE_256_BIT_LONG_IV", 256, 32, TestCase.assertIsNotNone),
            ("NEGATIVE_256_BIT_SHORT_IV", 256, 16, TestCase.assertIsNone),
            ("NEGATIVE_256_BIT_BAD_IV", 256, 31, TestCase.assertIsNone),
        ]
    )
    @requires(Mechanism.AES_ECB_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_derive_using_ecb_encrypt(self, test_type, test_key_length, iv_length, assert_fn):
        """Function to test AES Key Derivation using the ECB_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            key_length=test_key_length,
            capabilities=capabilities,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.DERIVE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )

        self.assertTrue(
            key is not None, "Failed to create {}-bit Master Key".format(test_key_length)
        )

        # Derive a Key from the Master Key
        iv = b"0" * iv_length
        try:
            derived_key = key.derive_key(
                pkcs11.KeyType.AES,
                key_length=test_key_length,
                capabilities=capabilities,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=iv,
                template={
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SENSITIVE: False,
                },
            )
        except (pkcs11.exceptions.MechanismParamInvalid, pkcs11.exceptions.FunctionFailed):
            derived_key = None

        assert_fn(self, derived_key, "{}-bit Key Derivation Failure".format(test_key_length))

    @parameterized.expand(
        [
            ("POSITIVE_128_BIT", 128, 16),
            ("POSITIVE_256_BIT_LONG_IV", 256, 32),
        ]
    )
    @requires(Mechanism.AES_ECB_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_encrypt_with_key_derived_using_ecb_encrypt(
        self, test_type, test_key_length, iv_length
    ):
        """Function to test Data Encryption/Decryption using a Derived AES Key.

        Function to test Data Encryption/Decryption using an AES Key
        Derived by the ECB_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            key_length=test_key_length,
            capabilities=capabilities,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.DERIVE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )

        self.assertTrue(
            key is not None, "Failed to create {}-bit Master Key".format(test_key_length)
        )

        # Derive a Key from the Master Key
        iv = b"0" * iv_length
        try:
            derived_key = key.derive_key(
                pkcs11.KeyType.AES,
                key_length=test_key_length,
                capabilities=capabilities,
                mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                mechanism_param=iv,
                template={
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SENSITIVE: False,
                },
            )
        except (pkcs11.exceptions.MechanismParamInvalid, pkcs11.exceptions.FunctionFailed):
            derived_key = None

        self.assertTrue(
            derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length)
        )

        # Test capability of Key to Encrypt/Decrypt data
        data = b"HELLO WORLD" * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    @parameterized.expand(
        [
            ("POSITIVE_128_BIT", 128, 16, 16, TestCase.assertIsNotNone),
            ("POSITIVE_128_BIT_LONG_DATA", 128, 16, 64, TestCase.assertIsNotNone),
            ("NEGATIVE_128_BIT_BAD_IV", 128, 15, 16, TestCase.assertIsNone),
            ("NEGATIVE_128_BIT_BAD_DATA", 128, 16, 31, TestCase.assertIsNone),
            ("POSITIVE_256_BIT", 256, 16, 32, TestCase.assertIsNotNone),
            ("POSITIVE_256_BIT_LONG_DATA", 256, 16, 64, TestCase.assertIsNotNone),
            ("NEGATIVE_256_BIT_BAD_IV", 256, 15, 16, TestCase.assertIsNone),
            ("NEGATIVE_256_BIT_BAD_DATA", 256, 16, 31, TestCase.assertIsNone),
            ("NEGATIVE_256_BIT_SHORT_DATA", 256, 16, 16, TestCase.assertIsNone),
        ]
    )
    @requires(Mechanism.AES_CBC_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_derive_using_cbc_encrypt(
        self, test_type, test_key_length, iv_length, data_length, assert_fn
    ):
        """Function to test AES Key Derivation using the CBC_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            key_length=test_key_length,
            capabilities=capabilities,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.DERIVE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )

        self.assertTrue(
            key is not None, "Failed to create {}-bit Master Key".format(test_key_length)
        )

        # Derive a Key from the Master Key
        iv = b"0" * iv_length
        data = b"1" * data_length
        try:
            derived_key = key.derive_key(
                pkcs11.KeyType.AES,
                key_length=test_key_length,
                capabilities=capabilities,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(iv, data),
                template={
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SENSITIVE: False,
                },
            )
        except (
            pkcs11.exceptions.MechanismParamInvalid,
            pkcs11.exceptions.FunctionFailed,
            IndexError,
        ):
            derived_key = None

        assert_fn(self, derived_key, "{}-bit Key Derivation Failure".format(test_key_length))

    @parameterized.expand(
        [
            ("POSITIVE_128_BIT", 128, 16, 16),
            ("POSITIVE_256_BIT", 256, 16, 32),
            ("POSITIVE_256_BIT_LONG_DATA", 256, 16, 64),
        ]
    )
    @requires(Mechanism.AES_CBC_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_encrypt_with_key_derived_using_cbc_encrypt(
        self, test_type, test_key_length, iv_length, data_length
    ):
        """Function to test Data Encryption/Decryption using a Derived AES Key.

        Function to test Data Encryption/Decryption using an AES Key
        Derived by the CBC_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(
            pkcs11.KeyType.AES,
            key_length=test_key_length,
            capabilities=capabilities,
            template={
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.DERIVE: True,
                pkcs11.Attribute.SENSITIVE: False,
            },
        )

        self.assertTrue(
            key is not None, "Failed to create {}-bit Master Key".format(test_key_length)
        )

        # Derive a Key from the Master Key
        iv = b"0" * iv_length
        data = b"1" * data_length
        try:
            derived_key = key.derive_key(
                pkcs11.KeyType.AES,
                key_length=test_key_length,
                capabilities=capabilities,
                mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                mechanism_param=(iv, data),
                template={
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SENSITIVE: False,
                },
            )
        except (
            pkcs11.exceptions.MechanismParamInvalid,
            pkcs11.exceptions.FunctionFailed,
            IndexError,
        ):
            derived_key = None

        self.assertTrue(
            derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length)
        )

        # Test capability of Key to Encrypt/Decrypt data
        data = b"HELLO WORLD" * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    @requires(Mechanism.AES_GCM)
    def test_encrypt_gcm(self):
        data = b"INPUT DATA"
        nonce = b"0" * 12

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce)
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce)
        )
        self.assertEqual(data, text)

    def test_gcm_nonce_size_limit(self):
        def _inst():
            return GCMParams(nonce=b"0" * 13)

        self.assertRaises(ArgumentsBad, _inst)

    @requires(Mechanism.AES_GCM)
    def test_encrypt_gcm_with_aad(self):
        data = b"INPUT DATA"
        nonce = b"0" * 12

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"foo")
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"foo")
        )
        self.assertEqual(data, text)

    @requires(Mechanism.AES_GCM)
    def test_encrypt_gcm_with_mismatching_nonces(self):
        data = b"INPUT DATA"
        nonce1 = b"0" * 12
        nonce2 = b"1" * 12

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce1, b"foo")
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        # This should be EncryptedDataInvalid, but in practice not all tokens support this
        with self.assertRaises(PKCS11Error):
            self.key.decrypt(
                crypttext, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce2, b"foo")
            )

    @requires(Mechanism.AES_GCM)
    def test_encrypt_gcm_with_mismatching_aad(self):
        data = b"INPUT DATA"
        nonce = b"0" * 12

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"foo")
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        with self.assertRaises(PKCS11Error):
            self.key.decrypt(
                crypttext, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"bar")
            )

    @requires(Mechanism.AES_GCM)
    def test_encrypt_gcm_with_custom_tag_length(self):
        data = b"INPUT DATA"
        nonce = b"0" * 12

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"foo", 120)
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(nonce, b"foo", 120)
        )
        self.assertEqual(data, text)

        # This should be EncryptedDataInvalid, but in practice not all tokens support this
        with self.assertRaises(PKCS11Error):
            text = self.key.decrypt(
                crypttext,
                mechanism=Mechanism.AES_GCM,
                mechanism_param=GCMParams(nonce, b"foo", 128),
            )

    @parameterized.expand(
        [
            (b""),
            (b"0" * 12),
            (b"0" * 15),
        ]
    )
    @requires(Mechanism.AES_CTR)
    @FIXME.opencryptoki  # opencryptoki incorrectly forces AES-CTR input to be padded
    def test_encrypt_ctr(self, nonce):
        data = b"INPUT DATA SEVERAL BLOCKS LONG SO THE COUNTER GOES UP A FEW TIMES" * 20

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce)
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce)
        )
        self.assertEqual(data, text)

    @requires(Mechanism.AES_CTR)
    def test_encrypt_ctr_exactly_padded(self):
        # let's still verify the "restricted" AES-CTR supported by opencryptoki
        data = b"PADDED INPUT DATA TO MAKE OPENCRYPTOKI HAPPY" * 16
        nonce = b"0" * 15

        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce)
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(nonce)
        )
        self.assertEqual(data, text)

    def test_ctr_nonce_size_limit(self):
        def _inst():
            return CTRParams(nonce=b"0" * 16)

        self.assertRaises(ArgumentsBad, _inst)

    @requires(Mechanism.AES_CTR)
    @FIXME.opencryptoki  # opencryptoki incorrectly forces AES-CTR input to be padded
    def test_encrypt_ctr_nonce_mismatch(self):
        data = b"INPUT DATA SEVERAL BLOCKS LONG SO THE COUNTER GOES UP A FEW TIMES" * 20
        crypttext = self.key.encrypt(
            data, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(b"0" * 12)
        )
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        text = self.key.decrypt(
            crypttext, mechanism=Mechanism.AES_CTR, mechanism_param=CTRParams(b"1" * 12)
        )
        self.assertNotEqual(data, text)
