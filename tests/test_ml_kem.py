from parameterized import parameterized

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import MLKEMParameterSet

from . import TestCase, requires


class MLKEMTests(TestCase):
    @requires(Mechanism.ML_KEM_KEY_PAIR_GEN, Mechanism.ML_KEM)
    def test_generate_ml_kem_512(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_KEM,
            public_template={Attribute.PARAMETER_SET: MLKEMParameterSet.ML_KEM_512},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLKEMParameterSet.ML_KEM_512))

    @requires(Mechanism.ML_KEM_KEY_PAIR_GEN, Mechanism.ML_KEM)
    def test_generate_ml_kem_768(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_KEM,
            public_template={Attribute.PARAMETER_SET: MLKEMParameterSet.ML_KEM_768},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLKEMParameterSet.ML_KEM_768))

    @requires(Mechanism.ML_KEM_KEY_PAIR_GEN, Mechanism.ML_KEM)
    def test_generate_ml_kem_1024(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_KEM,
            public_template={Attribute.PARAMETER_SET: MLKEMParameterSet.ML_KEM_1024},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLKEMParameterSet.ML_KEM_1024))

    @parameterized.expand(
        [
            ("AES-256", 256),
            ("AES-128", 128),
        ]
    )
    @requires(Mechanism.ML_KEM_KEY_PAIR_GEN, Mechanism.ML_KEM)
    def test_encapsulate_decapsulate(self, test_type, key_length):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_KEM,
            public_template={Attribute.PARAMETER_SET: MLKEMParameterSet.ML_KEM_768},
        )

        # Encapsulate: public key produces ciphertext + shared secret key
        ciphertext, ss_enc = pub.encapsulate_key(
            KeyType.AES,
            key_length=key_length,
            store=False,
        )
        self.assertIsInstance(ciphertext, bytes)
        self.assertGreater(len(ciphertext), 0)
        self.assertIsNotNone(ss_enc)

        ss_dec = priv.decapsulate_key(
            ciphertext,
            KeyType.AES,
            store=False,
            key_length=key_length,
        )
        self.assertIsNotNone(ss_dec)

        # Verify the two shared secrets are equal by encrypting/decrypting.
        # If they differ, the AES_ECB decrypt will produce wrong output.
        plaintext = b"mlkem test data!"  # exactly 16 bytes for AES_ECB
        encrypted = ss_enc.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        recovered = ss_dec.decrypt(encrypted, mechanism=Mechanism.AES_ECB)
        self.assertEqual(plaintext, recovered)

    @requires(Mechanism.ML_KEM_KEY_PAIR_GEN, Mechanism.ML_KEM)
    def test_missing_parameter_set_raises(self):
        with self.assertRaises(pkcs11.exceptions.ArgumentsBad):
            self.session.generate_keypair(KeyType.ML_KEM)
