"""
PKCS#11 Sessions
"""

import pkcs11
from pkcs11 import (
    Attribute,
    AttributeSensitive,
    AttributeTypeInvalid,
    ObjectClass,
    PKCS11Error,
)
from pkcs11.attributes import AttributeMapper, handle_bool, handle_str
from pkcs11.exceptions import PinIncorrect, PinLenRange

from . import TOKEN_PIN, TOKEN_SO_PIN, Not, Only, TestCase, requires


class SessionTests(TestCase):
    with_session = False

    @Not.nfast  # Login is required
    @Not.opencryptoki
    def test_open_session(self):
        with self.token.open() as session:
            self.assertIsInstance(session, pkcs11.Session)

    def test_open_session_and_login_user(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            self.assertIsInstance(session, pkcs11.Session)

    @Only.softhsm2  # We don't have credentials to do this for other platforms
    def test_open_session_and_login_so(self):
        with self.token.open(rw=True, so_pin=TOKEN_SO_PIN) as session:
            self.assertIsInstance(session, pkcs11.Session)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_generate_key(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertIsInstance(key, pkcs11.EncryptMixin)

            self.assertIs(key.object_class, pkcs11.ObjectClass.SECRET_KEY)

            # Test GetAttribute
            self.assertIs(key[pkcs11.Attribute.CLASS], pkcs11.ObjectClass.SECRET_KEY)
            self.assertEqual(key[pkcs11.Attribute.TOKEN], False)
            self.assertEqual(key[pkcs11.Attribute.LOCAL], True)
            self.assertEqual(key[pkcs11.Attribute.MODIFIABLE], True)
            self.assertEqual(key[pkcs11.Attribute.LABEL], "")

            # Test SetAttribute
            key[pkcs11.Attribute.LABEL] = "DEMO"

            self.assertEqual(key[pkcs11.Attribute.LABEL], "DEMO")

            # Create another key with no capabilities
            key = session.generate_key(
                pkcs11.KeyType.AES, 128, label="MY KEY", id=b"\1\2\3\4", capabilities=0
            )
            self.assertIsInstance(key, pkcs11.Object)
            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertNotIsInstance(key, pkcs11.EncryptMixin)

            self.assertEqual(key.label, "MY KEY")

    @requires(pkcs11.Mechanism.RSA_PKCS_KEY_PAIR_GEN, pkcs11.Mechanism.RSA_PKCS)
    def test_generate_keypair(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 1024)
            self.assertIsInstance(pub, pkcs11.PublicKey)
            self.assertIsInstance(priv, pkcs11.PrivateKey)

            data = b"HELLO WORLD"
            crypttext = pub.encrypt(data, mechanism=pkcs11.Mechanism.RSA_PKCS)
            self.assertNotEqual(data, crypttext)
            text = priv.decrypt(crypttext, mechanism=pkcs11.Mechanism.RSA_PKCS)
            self.assertEqual(data, text)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_get_objects(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

            search = list(
                session.get_objects(
                    {
                        pkcs11.Attribute.LABEL: "SAMPLE KEY",
                    }
                )
            )

            self.assertEqual(len(search), 1)
            self.assertEqual(key, search[0])

    def test_create_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.create_object(
                {
                    pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                    pkcs11.Attribute.VALUE: b"1" * 16,
                }
            )

            self.assertIsInstance(key, pkcs11.SecretKey)
            self.assertEqual(key.key_length, 128)

    @Not.nfast  # nFast won't destroy objects
    def test_destroy_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
            key.destroy()

            self.assertEqual(list(session.get_objects()), [])

    @Only.softhsm2
    def test_copy_object(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
            new = key.copy(
                {
                    pkcs11.Attribute.LABEL: "SOMETHING ELSE",
                }
            )

            self.assertEqual(set(session.get_objects()), {key, new})

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_get_key(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

            key = session.get_key(
                label="SAMPLE KEY",
            )
            self.assertIsInstance(key, pkcs11.SecretKey)
            key.encrypt(b"test", mechanism_param=b"IV" * 8)

    def test_get_key_not_found(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            with self.assertRaises(pkcs11.NoSuchKey):
                session.get_key(label="SAMPLE KEY")

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_get_key_vague(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
            session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY 2")

            with self.assertRaises(pkcs11.MultipleObjectsReturned):
                session.get_key(key_type=pkcs11.KeyType.AES)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_key_search_by_id(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key1 = session.generate_key(pkcs11.KeyType.AES, 128, label="KEY", id=b"1")
            key2 = session.generate_key(pkcs11.KeyType.AES, 128, label="KEY", id=b"2")
            self.assertEqual(session.get_key(id=b"1"), key1)
            self.assertEqual(session.get_key(id=b"2"), key2)
            self.assertNotEqual(session.get_key(id=b"1"), session.get_key(id=b"2"))

    @Not.nfast  # Not supported
    @Not.opencryptoki  # Not supported
    def test_seed_random(self):
        with self.token.open() as session:
            session.seed_random(b"12345678")

    def test_generate_random(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            random = session.generate_random(16 * 8)
            self.assertEqual(len(random), 16)
            # Ensure we didn't get 16 bytes of zeros
            self.assertTrue(all(c != "\0" for c in random))

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_attribute_reading_failures(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

            with self.assertRaises(AttributeSensitive):
                key.__getitem__(Attribute.VALUE)

            with self.assertRaises(AttributeTypeInvalid):
                key.__getitem__(Attribute.CERTIFICATE_TYPE)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_raise_error_if_no_result(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

            with self.assertRaises(AttributeSensitive):
                key.get_attributes([Attribute.VALUE])

            with self.assertRaises(AttributeTypeInvalid):
                key.get_attributes([Attribute.CERTIFICATE_TYPE])
            # we can't know which error code the token will choose here
            with self.assertRaises(PKCS11Error):
                key.get_attributes([Attribute.VALUE, Attribute.CERTIFICATE_TYPE])

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_partial_success_sensitive_attribute(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
            result = key.get_attributes([Attribute.LABEL, Attribute.VALUE, Attribute.CLASS])
            expected = {Attribute.LABEL: "SAMPLE KEY", Attribute.CLASS: ObjectClass.SECRET_KEY}
            self.assertDictEqual(expected, result)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_partial_success_irrelevant_attribute(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY", id=b"a")

            result = key.get_attributes(
                [Attribute.LABEL, Attribute.CERTIFICATE_TYPE, Attribute.CLASS, Attribute.ID]
            )
            expected = {
                Attribute.LABEL: "SAMPLE KEY",
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.ID: b"a",
            }
            self.assertDictEqual(expected, result)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_partial_success_with_some_empty_attrs(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="", id=b"")

            result = key.get_attributes(
                [Attribute.LABEL, Attribute.CLASS, Attribute.VALUE, Attribute.ID]
            )
            expected = {
                Attribute.LABEL: "",
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.ID: b"",
            }
            self.assertDictEqual(expected, result)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_only_empty_attrs(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="", id=b"")

            result = key.get_attributes([Attribute.LABEL, Attribute.ID])
            expected = {
                Attribute.LABEL: "",
                Attribute.ID: b"",
            }
            self.assertDictEqual(expected, result)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_bulk_attribute_empty_key_list(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

            result = key.get_attributes([])
            self.assertDictEqual({}, result)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_custom_attribute_mapper(self):
        custom_mapper = AttributeMapper()
        custom_mapper.register_handler(Attribute.ID, *handle_str)

        with self.token.open(user_pin=TOKEN_PIN, attribute_mapper=custom_mapper) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, id="SAMPLE KEY")
            id_attr = key[Attribute.ID]
            self.assertIsInstance(id_attr, str)
            self.assertEqual("SAMPLE KEY", id_attr)

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_set_unsupported_attribute(self):
        with self.token.open(user_pin=TOKEN_PIN) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, label="TEST")

            with self.assertRaises(NotImplementedError):
                key[0xDEADBEEF] = b"1234"

    @requires(pkcs11.Mechanism.AES_KEY_GEN)
    def test_treat_empty_bool_as_false(self):
        class CustomMapper(AttributeMapper):
            # contrived handler that decodes the 'ID' attribute as a bool
            def _handler(self, key):
                orig = super()._handler(key)
                if key == Attribute.ID:
                    return orig[0], handle_bool[1]
                return orig

        with self.token.open(user_pin=TOKEN_PIN, attribute_mapper=CustomMapper()) as session:
            key = session.generate_key(pkcs11.KeyType.AES, 128, id=b"")
            bool_read = key[Attribute.ID]
            self.assertIsInstance(bool_read, bool)
            self.assertFalse(bool_read, False)

    @Only.softhsm2
    def test_set_pin(self):
        old_token_pin = TOKEN_PIN
        new_token_pin = f"{TOKEN_PIN}56"

        with self.token.open(rw=True, user_pin=old_token_pin) as session:
            session.set_pin(old_token_pin, new_token_pin)

        with self.token.open(user_pin=new_token_pin) as session:
            self.assertIsInstance(session, pkcs11.Session)

        with self.token.open(rw=True, user_pin=new_token_pin) as session:
            session.set_pin(new_token_pin, old_token_pin)

        with self.token.open(user_pin=old_token_pin) as session:
            self.assertIsInstance(session, pkcs11.Session)

        with self.token.open(rw=True, user_pin=old_token_pin) as session:
            with self.assertRaises(AttributeError):
                session.set_pin(None, new_token_pin)
            with self.assertRaises(AttributeError):
                session.set_pin(old_token_pin, None)
            with self.assertRaises(PinLenRange):
                session.set_pin(old_token_pin, "")
            with self.assertRaises(PinIncorrect):
                session.set_pin("", new_token_pin)

    @Only.softhsm2
    def test_init_pin(self):
        new_token_pin = f"{TOKEN_PIN}56"

        with self.token.open(rw=True, so_pin=TOKEN_SO_PIN) as session:
            session.init_pin(new_token_pin)

        with self.token.open(rw=True, user_pin=new_token_pin) as session:
            self.assertIsInstance(session, pkcs11.Session)

        with self.token.open(rw=True, so_pin=TOKEN_SO_PIN) as session:
            session.init_pin(TOKEN_PIN)

        with self.token.open(rw=True, user_pin=TOKEN_PIN) as session:
            self.assertIsInstance(session, pkcs11.Session)

        with self.token.open(rw=True, so_pin=TOKEN_SO_PIN) as session:
            with self.assertRaises(AttributeError):
                session.init_pin(None)
            with self.assertRaises(PinLenRange):
                session.init_pin("")
