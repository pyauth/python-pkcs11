import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import MLDSAParameterSet

from . import TestCase, requires


class MLDSATests(TestCase):
    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_generate_ml_dsa_44(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_44},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLDSAParameterSet.ML_DSA_44))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_generate_ml_dsa_65(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_65},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLDSAParameterSet.ML_DSA_65))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_generate_ml_dsa_87(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_87},
        )
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)
        self.assertEqual(pub[Attribute.PARAMETER_SET], int(MLDSAParameterSet.ML_DSA_87))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_sign_verify(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_65},
        )
        data = b"Hello, post-quantum world!"
        sig = priv.sign(data)
        self.assertTrue(pub.verify(data, sig))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_sign_verify_wrong_data(self):
        pub, priv = self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_65},
        )
        data = b"Hello, post-quantum world!"
        sig = priv.sign(data)
        self.assertFalse(pub.verify(b"tampered data", sig))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_missing_parameter_set_raises(self):
        with self.assertRaises(pkcs11.exceptions.ArgumentsBad):
            self.session.generate_keypair(KeyType.ML_DSA)
