"""
PKCS#11 Sessions
"""

import pytest

import pkcs11
from tests.conftest import IS_NFAST, IS_OPENCRYPTOKI, IS_SOFTHSM


@pytest.mark.skipif(IS_NFAST or IS_OPENCRYPTOKI, reason="Login is required.")
def test_open_session(token: pkcs11.Token) -> None:
    with token.open() as session:
        assert isinstance(session, pkcs11.Session)


def test_open_session_and_login_user(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        assert isinstance(session, pkcs11.Session)


@pytest.mark.skipif(
    not IS_SOFTHSM, reason="We don't have credentials to do this for other platforms."
)
def test_open_session_and_login_so(token: pkcs11.Token, so_pin: str) -> None:
    with token.open(rw=True, so_pin=so_pin) as session:
        assert isinstance(session, pkcs11.Session)


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
def test_generate_key(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        key = session.generate_key(pkcs11.KeyType.AES, 128)
        assert isinstance(key, pkcs11.Object)
        assert isinstance(key, pkcs11.SecretKey)
        assert isinstance(key, pkcs11.EncryptMixin)

        assert key.object_class is pkcs11.ObjectClass.SECRET_KEY

        # Test GetAttribute
        assert key[pkcs11.Attribute.CLASS] is pkcs11.ObjectClass.SECRET_KEY
        assert key[pkcs11.Attribute.TOKEN] is False
        assert key[pkcs11.Attribute.LOCAL] is True
        assert key[pkcs11.Attribute.MODIFIABLE] is True
        assert key[pkcs11.Attribute.LABEL] == ""

        # Test SetAttribute
        key[pkcs11.Attribute.LABEL] = "DEMO"

        assert key[pkcs11.Attribute.LABEL] == "DEMO"

        # Create another key with no capabilities
        key = session.generate_key(
            pkcs11.KeyType.AES, 128, label="MY KEY", id=b"\1\2\3\4", capabilities=0
        )
        assert isinstance(key, pkcs11.Object)
        assert isinstance(key, pkcs11.SecretKey)
        assert not isinstance(key, pkcs11.EncryptMixin)

        assert key.label == "MY KEY"


@pytest.mark.requires(pkcs11.Mechanism.RSA_PKCS_KEY_PAIR_GEN)
@pytest.mark.requires(pkcs11.Mechanism.RSA_PKCS)
def test_generate_keypair(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 1024)
        assert isinstance(pub, pkcs11.PublicKey)
        assert isinstance(priv, pkcs11.PrivateKey)

        data = b"HELLO WORLD"
        crypttext = pub.encrypt(data, mechanism=pkcs11.Mechanism.RSA_PKCS)
        assert data != crypttext
        text = priv.decrypt(crypttext, mechanism=pkcs11.Mechanism.RSA_PKCS)
        assert data == text


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
def test_get_objects(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

        search = list(session.get_objects({pkcs11.Attribute.LABEL: "SAMPLE KEY"}))

        assert len(search) == 1
        assert key == search[0]


@pytest.mark.xfail_opencryptoki
def test_create_object(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        key = session.create_object(
            {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.VALUE: b"1" * 16,
            }
        )

        assert isinstance(key, pkcs11.SecretKey)
        assert key.key_length == 128


@pytest.mark.skipif(IS_NFAST, reason="nFast won't destroy objects.")
def test_destroy_object(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
        key.destroy()

        assert list(session.get_objects()) == []


@pytest.mark.skipif(not IS_SOFTHSM, reason="Unknown reason.")
def test_copy_object(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        key = session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
        new = key.copy(
            {
                pkcs11.Attribute.LABEL: "SOMETHING ELSE",
            }
        )

        assert set(session.get_objects()) == {key, new}


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
def test_get_key(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")

        key = session.get_key(
            label="SAMPLE KEY",
        )
        assert isinstance(key, pkcs11.SecretKey)
        key.encrypt(b"test", mechanism_param=b"IV" * 8)


def test_get_key_not_found(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        with pytest.raises(pkcs11.NoSuchKey):
            session.get_key(label="SAMPLE KEY")


@pytest.mark.requires(pkcs11.Mechanism.AES_KEY_GEN)
def test_get_key_vague(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY")
        session.generate_key(pkcs11.KeyType.AES, 128, label="SAMPLE KEY 2")

        with pytest.raises(pkcs11.MultipleObjectsReturned):
            session.get_key(key_type=pkcs11.KeyType.AES)


@pytest.mark.skipif(IS_NFAST or IS_OPENCRYPTOKI, reason="Not supported.")
def test_seed_random(token: pkcs11.Token) -> None:
    with token.open() as session:
        session.seed_random(b"12345678")


def test_generate_random(token: pkcs11.Token, pin: str) -> None:
    with token.open(user_pin=pin) as session:
        random = session.generate_random(16 * 8)
        assert len(random) == 16
        # Ensure we didn't get 16 bytes of zeros
        assert all(c != "\x00" for c in random)
