"""
PKCS#11 Sessions
"""

import pkcs11

from . import TestCase, TOKEN_PIN, Only, Not


class SessionTests(TestCase):

    with_session = False

    @Not.nfast
    def test_open_session(self):
        with self.token.open() as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_user(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            self.assertIsInstance(session, pkcs11.Session)

    @Only.softhsm2  # We don't have credentials to do this for other platforms
    def test_open_session_and_login_so(self):
        with self.token.open(rw=True, so_pin='5678') as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_generate_key(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128)
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
                                       capabilities=0)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertNotIsInstance(key, pkcs11.EncryptMixin)

            self.assertEqual(key.label, 'MY KEY')

    def test_generate_keypair(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            pub, priv = session.generate_keypair(
                pkcs11.KeyType.RSA, 1024)
            self.assertIsInstance(pub, pkcs11.PublicKey)
            self.assertIsInstance(priv, pkcs11.PrivateKey)

            data = b'HELLO WORLD'
            crypttext = pub.encrypt(data)
            self.assertNotEqual(data, crypttext)
            text = priv.decrypt(crypttext)
            self.assertEqual(data, text)

    def test_get_objects(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       label='SAMPLE KEY')

            search = list(session.get_objects({
                pkcs11.Attribute.LABEL: 'SAMPLE KEY',
            }))

            self.assertEqual(len(search), 1)
            self.assertEqual(key, search[0])

    def test_create_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.VALUE: b'1' * 16,
            })

            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertEqual(key.key_length, 128)

    @Not.nfast
    def test_destroy_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       label='SAMPLE KEY')
            key.destroy()

            self.assertEqual(list(session.get_objects()), [])

    @Only.softhsm2
    def test_copy_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128,
                                       label='SAMPLE KEY')
            new = key.copy({
                pkcs11.Attribute.LABEL: 'SOMETHING ELSE',
            })

            self.assertEqual(set(session.get_objects()), {key, new})

    def test_get_key(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 label='SAMPLE KEY')

            key = session.get_key(label='SAMPLE KEY',)
            self.assertIsInstance(key, pkcs11.SecretKey)
            key.encrypt(b'test', mechanism_param=b'IV' * 8)

    def test_get_key_not_found(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            with self.assertRaises(pkcs11.NoSuchKey):
                session.get_key(label='SAMPLE KEY')

    def test_get_key_vague(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 label='SAMPLE KEY')
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 label='SAMPLE KEY 2')

            with self.assertRaises(pkcs11.MultipleObjectsReturned):
                session.get_key(key_type=pkcs11.KeyType.AES)

    @Not.nfast
    def test_seed_random(self):
        with self.token.open() as session:
            session.seed_random(b'12345678')

    def test_generate_random(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            random = session.generate_random(16 * 8)
            self.assertEqual(len(random), 16)
            # Ensure we didn't get 16 bytes of zeros
            self.assertTrue(all(c != '\0' for c in random))
