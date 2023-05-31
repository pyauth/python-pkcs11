"""
PKCS#11 AES Secret Keys
"""

import pkcs11
from pkcs11 import Mechanism

from . import TestCase, requires, FIXME

from parameterized import parameterized

class AESTests(TestCase):

    @requires(Mechanism.AES_KEY_GEN)
    def setUp(self):
        super().setUp()
        self.key = self.session.generate_key(pkcs11.KeyType.AES, 128)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt(self):
        data = b'INPUT DATA'
        iv = b'0' * 16

        crypttext = self.key.encrypt(data, mechanism_param=iv)
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext), 16)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == '\0' for c in crypttext))

        text = self.key.decrypt(crypttext, mechanism_param=iv)
        self.assertEqual(data, text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_stream(self):
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )
        iv = b'0' * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))

        self.assertEqual(len(cryptblocks), len(data) + 1)

        crypttext = b''.join(cryptblocks)

        self.assertNotEqual(b''.join(data), crypttext)
        # We should be aligned to the block size
        self.assertEqual(len(crypttext) % 16, 0)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == '\0' for c in crypttext))

        text = b''.join(self.key.decrypt(cryptblocks, mechanism_param=iv))
        self.assertEqual(b''.join(data), text)

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_whacky_sizes(self):
        data = [
            (char * ord(char)).encode('utf-8')
            for char in 'HELLO WORLD'
        ]
        iv = b'0' * 16

        cryptblocks = list(self.key.encrypt(data, mechanism_param=iv))
        textblocks = list(self.key.decrypt(cryptblocks, mechanism_param=iv))

        self.assertEqual(b''.join(data), b''.join(textblocks))

    @requires(Mechanism.AES_CBC_PAD)
    def test_encrypt_big_string(self):
        data = b'HELLO WORLD' * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    @requires(Mechanism.AES_MAC)
    def test_sign(self):
        data = b'HELLO WORLD'

        signature = self.key.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature))
        self.assertFalse(self.key.verify(data, b'1234'))

    @requires(Mechanism.AES_MAC)
    def test_sign_stream(self):
        data = (
            b'I' * 16,
            b'N' * 16,
            b'P' * 16,
            b'U' * 16,
            b'T' * 10,  # don't align to the blocksize
        )

        signature = self.key.sign(data)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertTrue(self.key.verify(data, signature))

    @requires(Mechanism.AES_KEY_WRAP)
    @FIXME.opencryptoki  # can't set key attributes
    def test_wrap(self):
        key = self.session.generate_key(pkcs11.KeyType.AES, 128, template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.SENSITIVE: False,
        })
        data = self.key.wrap_key(key)

        key2 = self.key.unwrap_key(pkcs11.ObjectClass.SECRET_KEY,
                                   pkcs11.KeyType.AES,
                                   data, template={
                                        pkcs11.Attribute.EXTRACTABLE: True,
                                        pkcs11.Attribute.SENSITIVE: False,
                                   })

        self.assertEqual(key[pkcs11.Attribute.VALUE],
                         key2[pkcs11.Attribute.VALUE])

    @parameterized.expand([
        ("POSITIVE_128_BIT",            128, 16, TestCase.assertIsNotNone),
        ("POSITIVE_128_BIT_LONG_IV",    128, 32, TestCase.assertIsNotNone),
        ("NEGATIVE_128_BIT_BAD_IV",     128, 15, TestCase.assertIsNone),
        ("POSITIVE_256_BIT_LONG_IV",    256, 32, TestCase.assertIsNotNone),
        ("NEGATIVE_256_BIT_SHORT_IV",   256, 16, TestCase.assertIsNone),
        ("NEGATIVE_256_BIT_BAD_IV",     256, 31, TestCase.assertIsNone),
    ])
    @requires(Mechanism.AES_ECB_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_derive_using_ecb_encrypt(self, test_type, test_key_length, iv_length, assert_fn):
        """Function to test AES Key Derivation using the ECB_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                        capabilities=capabilities,
                                        template={
                                            pkcs11.Attribute.EXTRACTABLE: True,
                                            pkcs11.Attribute.DERIVE: True,
                                            pkcs11.Attribute.SENSITIVE: False,
                                        })

        self.assertTrue(key is not None, "Failed to create {}-bit Master Key".format(test_key_length))

        # Derive a Key from the Master Key
        iv = b'0' * iv_length
        try:
            derived_key = key.derive_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                         capabilities=capabilities,
                                         mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                                         mechanism_param=iv,
                                         template={
                                             pkcs11.Attribute.EXTRACTABLE: True,
                                             pkcs11.Attribute.SENSITIVE: False,
                                         })
        except (pkcs11.exceptions.MechanismParamInvalid,
                pkcs11.exceptions.FunctionFailed) as e:
            derived_key = None

        assert_fn(self, derived_key, "{}-bit Key Derivation Failure".format(test_key_length))

    @parameterized.expand([
        ("POSITIVE_128_BIT",            128, 16),
        ("POSITIVE_256_BIT_LONG_IV",    256, 32),
    ])
    @requires(Mechanism.AES_ECB_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_encrypt_with_key_derived_using_ecb_encrypt(self, test_type, test_key_length, iv_length):
        """Function to test Data Encryption/Decryption using a Derived AES Key.

        Function to test Data Encryption/Decryption using an AES Key
        Derived by the ECB_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                        capabilities=capabilities,
                                        template={
                                            pkcs11.Attribute.EXTRACTABLE: True,
                                            pkcs11.Attribute.DERIVE: True,
                                            pkcs11.Attribute.SENSITIVE: False,
                                        })

        self.assertTrue(key is not None, "Failed to create {}-bit Master Key".format(test_key_length))

        # Derive a Key from the Master Key
        iv = b'0' * iv_length
        try:
            derived_key = key.derive_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                         capabilities=capabilities,
                                         mechanism=Mechanism.AES_ECB_ENCRYPT_DATA,
                                         mechanism_param=iv,
                                         template={
                                             pkcs11.Attribute.EXTRACTABLE: True,
                                             pkcs11.Attribute.SENSITIVE: False,
                                         })
        except (pkcs11.exceptions.MechanismParamInvalid,
                pkcs11.exceptions.FunctionFailed) as e:
            derived_key = None

        self.assertTrue(derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length))

        # Test capability of Key to Encrypt/Decrypt data
        data = b'HELLO WORLD' * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

    @parameterized.expand([
        ("POSITIVE_128_BIT",            128, 16, 16, TestCase.assertIsNotNone),
        ("POSITIVE_128_BIT_LONG_DATA",  128, 16, 64, TestCase.assertIsNotNone),
        ("NEGATIVE_128_BIT_BAD_IV",     128, 15, 16, TestCase.assertIsNone),
        ("NEGATIVE_128_BIT_BAD_DATA",   128, 16, 31, TestCase.assertIsNone),
        ("POSITIVE_256_BIT",            256, 16, 32, TestCase.assertIsNotNone),
        ("POSITIVE_256_BIT_LONG_DATA",  256, 16, 64, TestCase.assertIsNotNone),
        ("NEGATIVE_256_BIT_BAD_IV",     256, 15, 16, TestCase.assertIsNone),
        ("NEGATIVE_256_BIT_BAD_DATA",   256, 16, 31, TestCase.assertIsNone),
        ("NEGATIVE_256_BIT_SHORT_DATA", 256, 16, 16, TestCase.assertIsNone),
    ])
    @requires(Mechanism.AES_CBC_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_derive_using_cbc_encrypt(self, test_type, test_key_length, iv_length, data_length, assert_fn):
        """Function to test AES Key Derivation using the CBC_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                        capabilities=capabilities,
                                        template={
                                            pkcs11.Attribute.EXTRACTABLE: True,
                                            pkcs11.Attribute.DERIVE: True,
                                            pkcs11.Attribute.SENSITIVE: False,
                                        })

        self.assertTrue(key is not None, "Failed to create {}-bit Master Key".format(test_key_length))

        # Derive a Key from the Master Key
        iv = b'0' * iv_length
        data = b'1' * data_length
        try:
            derived_key = key.derive_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                         capabilities=capabilities,
                                         mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                                         mechanism_param=(iv, data),
                                         template={
                                             pkcs11.Attribute.EXTRACTABLE: True,
                                             pkcs11.Attribute.SENSITIVE: False,
                                         })
        except (pkcs11.exceptions.MechanismParamInvalid,
                pkcs11.exceptions.FunctionFailed,
                IndexError) as e:
            derived_key = None

        assert_fn(self, derived_key, "{}-bit Key Derivation Failure".format(test_key_length))

    @parameterized.expand([
        ("POSITIVE_128_BIT",            128, 16, 16),
        ("POSITIVE_256_BIT",            256, 16, 32),
        ("POSITIVE_256_BIT_LONG_DATA",  256, 16, 64),
    ])
    @requires(Mechanism.AES_CBC_ENCRYPT_DATA)
    @FIXME.opencryptoki  # can't set key attributes
    def test_encrypt_with_key_derived_using_cbc_encrypt(self, test_type, test_key_length, iv_length, data_length):
        """Function to test Data Encryption/Decryption using a Derived AES Key.

        Function to test Data Encryption/Decryption using an AES Key
        Derived by the CBC_ENCRYPT Mechanism.

        Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
        """

        # Create the Master Key
        capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
        capabilities |= pkcs11.MechanismFlag.DERIVE
        key = self.session.generate_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                        capabilities=capabilities,
                                        template={
                                            pkcs11.Attribute.EXTRACTABLE: True,
                                            pkcs11.Attribute.DERIVE: True,
                                            pkcs11.Attribute.SENSITIVE: False,
                                        })

        self.assertTrue(key is not None, "Failed to create {}-bit Master Key".format(test_key_length))

        # Derive a Key from the Master Key
        iv = b'0' * iv_length
        data = b'1' * data_length
        try:
            derived_key = key.derive_key(pkcs11.KeyType.AES, key_length=test_key_length,
                                         capabilities=capabilities,
                                         mechanism=Mechanism.AES_CBC_ENCRYPT_DATA,
                                         mechanism_param=(iv, data),
                                         template={
                                             pkcs11.Attribute.EXTRACTABLE: True,
                                             pkcs11.Attribute.SENSITIVE: False,
                                         })
        except (pkcs11.exceptions.MechanismParamInvalid,
                pkcs11.exceptions.FunctionFailed,
                IndexError) as e:
            derived_key = None

        self.assertTrue(derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length))

        # Test capability of Key to Encrypt/Decrypt data
        data = b'HELLO WORLD' * 1024

        iv = self.session.generate_random(128)
        crypttext = self.key.encrypt(data, mechanism_param=iv)
        text = self.key.decrypt(crypttext, mechanism_param=iv)

        self.assertEqual(text, data)

class AES_CTR_Tests(TestCase):

    @requires(Mechanism.AES_KEY_GEN)
    def setUp(self):
        super().setUp()
        self.key = self.session.generate_key(pkcs11.KeyType.AES, 128)

    @requires(Mechanism.AES_CTR)
    def test_encrypt(self):
        data = b'INPUT DATA'
        ulCounterBits = 128
        cb = 16 * [0]
        params = (ulCounterBits, cb)

        crypttext = self.key.encrypt(data, mechanism_param=params, mechanism=Mechanism.AES_CTR)
        self.assertIsInstance(crypttext, bytes)
        self.assertNotEqual(data, crypttext)
        # Ensure we didn't just get 16 nulls
        self.assertFalse(all(c == '\0' for c in crypttext))

        text = self.key.decrypt(crypttext, mechanism_param=params, mechanism=Mechanism.AES_CTR)
        self.assertEqual(data, text)

    @parameterized.expand([
        ("Vector 1",
            "AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E",
            b'Single block msg'.hex(' '),
            "00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01",
            "E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8"),
        ("Vector 2",
            "7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63",
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
            "00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01",
            "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88 EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28"),
        ("Vector 3",
            "76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC",
            ("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
             "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
             "20 21 22 23"),
            "00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01",
            ("C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7"
             "45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53"
             "25 B2 07 2F")),
        ("Vector 4",
            ("16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED"
             "86 3D 06 CC FD B7 85 15"),
            b"Single block msg".hex(' '),
            "00 00 00 48 36 73 3C 14 7D 6D 93 CB 00 00 00 01",
            "4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28"),
        ("Vector 5",
            "7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C 67 8C 3D B8 E6 F6 A9 1A",
            ("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
            "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"),
            "00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 01",
            ("45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F"
             "84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00")
            ),
        ("Vector 6",
            ("02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B"
             "F5 9B 60 A7 86 D3 E0 FE"),
            ("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
             "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
             "20 21 22 23"),
            "00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 01",
            ("96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58"
             "D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88"
             "AB EE 09 35")),
        ("Vector 7",
            ("77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C"
             "6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04"),
            b"Single block msg".hex(' '),
             "00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 01",
             "14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0"),
        ("Vector 8",
            ("F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86"
             "C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84"),
            ("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
             "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"),
            "00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 01",
            ("F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9"
             "B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C"))
        ])
    @requires(Mechanism.AES_CTR)
    def test_vector(self, test_type, key, plaintext, counter_block, cryptotext):
        """https://www.ietf.org/rfc/rfc3686.txt"""
        key = self.session.create_object({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
            pkcs11.Attribute.VALUE: bytes.fromhex(key)
            })

        data = bytes.fromhex(plaintext)
        ulCounterBits = 32
        cb = bytes.fromhex(counter_block)
        params = (ulCounterBits, cb)
        crypttext = key.encrypt(data, mechanism_param=params, mechanism=Mechanism.AES_CTR)
        self.assertEqual(crypttext, bytes.fromhex(cryptotext))

