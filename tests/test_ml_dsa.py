import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import HedgeType, MLDSAParameterSet, SignAdditionalContext

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

    def _keypair(self):
        return self.session.generate_keypair(
            KeyType.ML_DSA,
            public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_65},
        )

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_sign_verify_context(self):
        pub, priv = self._keypair()
        data = b"Hello, post-quantum world!"
        ctx = SignAdditionalContext(context=b"python-pkcs11 test")
        sig = priv.sign(data, mechanism_param=ctx)
        self.assertTrue(pub.verify(data, sig, mechanism_param=ctx))
        # The context is part of the signed message: another context, or
        # none, must not verify.
        other = SignAdditionalContext(context=b"another context")
        self.assertFalse(pub.verify(data, sig, mechanism_param=other))
        self.assertFalse(pub.verify(data, sig))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_empty_context_matches_no_parameter(self):
        pub, priv = self._keypair()
        data = b"Hello, post-quantum world!"
        sig = priv.sign(data, mechanism_param=SignAdditionalContext())
        self.assertTrue(pub.verify(data, sig))
        sig = priv.sign(data)
        self.assertTrue(pub.verify(data, sig, mechanism_param=SignAdditionalContext(b"")))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_deterministic(self):
        pub, priv = self._keypair()
        data = b"Hello, post-quantum world!"
        param = SignAdditionalContext(hedge=HedgeType.DETERMINISTIC_REQUIRED)
        sig1 = priv.sign(data, mechanism_param=param)
        sig2 = priv.sign(data, mechanism_param=param)
        self.assertEqual(sig1, sig2)
        self.assertTrue(pub.verify(data, sig1))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_hedged(self):
        pub, priv = self._keypair()
        data = b"Hello, post-quantum world!"
        param = SignAdditionalContext(hedge=HedgeType.REQUIRED)
        sig1 = priv.sign(data, mechanism_param=param)
        sig2 = priv.sign(data, mechanism_param=param)
        self.assertNotEqual(sig1, sig2)
        self.assertTrue(pub.verify(data, sig1))
        self.assertTrue(pub.verify(data, sig2))

    @requires(Mechanism.ML_DSA_KEY_PAIR_GEN, Mechanism.ML_DSA)
    def test_wrong_parameter_type_raises(self):
        _, priv = self._keypair()
        with self.assertRaises(pkcs11.exceptions.ArgumentsBad):
            priv.sign(b"data", mechanism_param=(0, b"context"))

    def test_context_too_long_raises(self):
        with self.assertRaises(pkcs11.exceptions.ArgumentsBad):
            SignAdditionalContext(context=b"x" * 256)

    def test_hedge_must_be_hedge_type(self):
        with self.assertRaises(pkcs11.exceptions.ArgumentsBad):
            SignAdditionalContext(hedge=1)
