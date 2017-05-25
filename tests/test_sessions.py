"""
PKCS#11 Sessions

These tests assume SoftHSMv2 with a single token initialized called DEMO.
"""

import os
import unittest

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11SessionTests(unittest.TestCase):

    def test_open_session(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open() as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_user(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_so(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(rw=True, so_pin='5678') as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_generate_key(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, store=False)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertIsInstance(key, pkcs11.EncryptMixin)

            self.assertIs(key.object_class, pkcs11.ObjectClass.SECRET_KEY)

            # Test GetAttribute
            self.assertIs(key[pkcs11.Attribute.CLASS],
                          pkcs11.ObjectClass.SECRET_KEY)
            self.assertEqual(key[pkcs11.Attribute.TOKEN], False)
            self.assertEqual(key[pkcs11.Attribute.LOCAL], True)
            self.assertEqual(key[pkcs11.Attribute.MODIFIABLE], True)
            self.assertEqual(key[pkcs11.Attribute.LABEL], '')

            # Test SetAttribute
            key[pkcs11.Attribute.LABEL] = "DEMO"

            self.assertEqual(key[pkcs11.Attribute.LABEL], "DEMO")

            # Create another key with no capabilities
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       label='MY KEY',
                                       id=b'\1\2\3\4',
                                       store=False, capabilities=0)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertNotIsInstance(key, pkcs11.EncryptMixin)

            self.assertEqual(key.label, 'MY KEY')

    def test_generate_keypair(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 768,
                                                 store=False)
            self.assertIsInstance(pub, pkcs11.PublicKey)
            self.assertIsInstance(priv, pkcs11.PrivateKey)

            data = b'HELLO WORLD'
            crypttext = pub.encrypt(data)
            self.assertNotEqual(data, crypttext)
            text = priv.decrypt(crypttext)
            self.assertEqual(data, text)

    def test_get_objects(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       store=False, label='SAMPLE KEY')

            search = list(session.get_objects({
                pkcs11.Attribute.LABEL: 'SAMPLE KEY',
            }))

            self.assertEqual(len(search), 1)
            self.assertEqual(key, search[0])

    def test_create_object(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.VALUE: b'1' * 16,
            })

            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertEqual(key.key_length, 128)

    def test_destroy_object(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       store=False, label='SAMPLE KEY')
            key.destroy()

            self.assertEqual(list(session.get_objects()), [])

    def test_copy_object(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       store=False, label='SAMPLE KEY')
            new = key.copy({
                pkcs11.Attribute.LABEL: 'SOMETHING ELSE',
            })

            self.assertEqual(set(session.get_objects()), {key, new})

    def test_get_key(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='SAMPLE KEY')

            key = session.get_key(label='SAMPLE KEY',)
            self.assertIsInstance(key, pkcs11.SecretKey)
            key.encrypt(b'test', mechanism_param=b'IV' * 8)

    def test_get_key_not_found(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            with self.assertRaises(pkcs11.NoSuchKey):
                session.get_key(label='SAMPLE KEY')

    def test_get_key_vague(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='SAMPLE KEY')
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='SAMPLE KEY 2')

            with self.assertRaises(pkcs11.MultipleObjectsReturned):
                session.get_key(key_type=pkcs11.KeyType.AES)

    def test_seed_random(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open() as session:
            session.seed_random(b'12345678')

    def test_generate_random(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open() as session:
            random = session.generate_random(16 * 8)
            self.assertEqual(len(random), 16)
            # Ensure we didn't get 16 bytes of zeros
            self.assertTrue(all(c != '\0' for c in random))
