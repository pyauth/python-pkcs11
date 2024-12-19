"""
PKCS#11 AES Secret Keys
"""

import pytest

import pkcs11
from pkcs11 import Mechanism

pytestmark = [pytest.mark.requires(Mechanism.AES_KEY_GEN)]


@pytest.fixture
def key(session: pkcs11.Session) -> pkcs11.SecretKey:
    return session.generate_key(pkcs11.KeyType.AES, 128)


@pytest.mark.requires(Mechanism.AES_CBC_PAD)
def test_encrypt(key: pkcs11.SecretKey) -> None:
    data = b"INPUT DATA"
    iv = b"0" * 16

    crypttext = key.encrypt(data, mechanism_param=iv)
    assert isinstance(crypttext, bytes)
    assert data != crypttext
    # We should be aligned to the block size
    assert len(crypttext) == 16
    # Ensure we didn't just get 16 nulls
    assert all(c == "\0" for c in crypttext) is False

    text = key.decrypt(crypttext, mechanism_param=iv)
    assert data == text


@pytest.mark.requires(Mechanism.AES_CBC_PAD)
def test_encrypt_stream(key: pkcs11.SecretKey):
    data = (
        b"I" * 16,
        b"N" * 16,
        b"P" * 16,
        b"U" * 16,
        b"T" * 10,  # don't align to the blocksize
    )
    iv = b"0" * 16

    cryptblocks = list(key.encrypt(data, mechanism_param=iv))

    assert len(cryptblocks) == len(data) + 1

    crypttext = b"".join(cryptblocks)

    assert b"".join(data) != crypttext
    # We should be aligned to the block size
    assert len(crypttext) % 16 == 0
    # Ensure we didn't just get 16 nulls
    assert all(c == "\0" for c in crypttext) is False

    text = b"".join(key.decrypt(cryptblocks, mechanism_param=iv))
    assert b"".join(data) == text


@pytest.mark.requires(Mechanism.AES_CBC_PAD)
def test_encrypt_whacky_sizes(key: pkcs11.SecretKey):
    data = [(char * ord(char)).encode("utf-8") for char in "HELLO WORLD"]
    iv = b"0" * 16

    cryptblocks = list(key.encrypt(data, mechanism_param=iv))
    textblocks = list(key.decrypt(cryptblocks, mechanism_param=iv))

    assert b"".join(data) == b"".join(textblocks)


@pytest.mark.requires(Mechanism.AES_CBC_PAD)
def test_encrypt_big_string(session: pkcs11.Session, key: pkcs11.SecretKey):
    data = b"HELLO WORLD" * 1024

    iv = session.generate_random(128)
    crypttext = key.encrypt(data, mechanism_param=iv)
    text = key.decrypt(crypttext, mechanism_param=iv)

    assert text == data


@pytest.mark.requires(Mechanism.AES_MAC)
def test_sign(key: pkcs11.SecretKey):
    data = b"HELLO WORLD"

    signature = key.sign(data)
    assert isinstance(signature, bytes)
    assert key.verify(data, signature) is True
    assert key.verify(data, b"1234") is False


@pytest.mark.requires(Mechanism.AES_MAC)
def test_sign_stream(key: pkcs11.SecretKey):
    data = (
        b"I" * 16,
        b"N" * 16,
        b"P" * 16,
        b"U" * 16,
        b"T" * 10,  # don't align to the blocksize
    )

    signature = key.sign(data)
    assert isinstance(signature, bytes)
    assert key.verify(data, signature)


@pytest.mark.requires(Mechanism.AES_KEY_WRAP)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_wrap(session: pkcs11.Session, key: pkcs11.SecretKey):
    key = session.generate_key(
        pkcs11.KeyType.AES,
        128,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )
    data = key.wrap_key(key)

    key2 = key.unwrap_key(
        pkcs11.ObjectClass.SECRET_KEY,
        pkcs11.KeyType.AES,
        data,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )

    assert key[pkcs11.Attribute.VALUE] == key2[pkcs11.Attribute.VALUE]


@pytest.mark.parametrize(
    ("test_key_length", "iv_length", "is_none"),
    [
        (128, 16, False),
        (128, 32, False),
        (128, 15, True),
        (256, 32, False),
        (256, 16, True),
        (256, 31, True),
    ],
)
@pytest.mark.requires(Mechanism.AES_ECB_ENCRYPT_DATA)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_derive_using_ecb_encrypt(
    session: pkcs11.Session,
    key: pkcs11.SecretKey,
    test_key_length: int,
    iv_length: int,
    is_none: bool,
):
    """Function to test AES Key Derivation using the ECB_ENCRYPT Mechanism.

    Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
    """

    # Create the Master Key
    capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
    capabilities |= pkcs11.MechanismFlag.DERIVE
    key = session.generate_key(
        pkcs11.KeyType.AES,
        key_length=test_key_length,
        capabilities=capabilities,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.DERIVE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )

    assert key is not None, "Failed to create {}-bit Master Key".format(test_key_length)

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

    if is_none:
        assert derived_key is None, "{}-bit Key Derivation Failure".format(test_key_length)
    else:
        assert derived_key is not None, "{}-bit Key Derivation Failure".format(test_key_length)


@pytest.mark.parametrize(("test_key_length", "iv_length"), [(128, 16), (256, 32)])
@pytest.mark.requires(Mechanism.AES_ECB_ENCRYPT_DATA)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_encrypt_with_key_derived_using_ecb_encrypt(
    session: pkcs11.Session, key: pkcs11.SecretKey, test_key_length: int, iv_length: int
) -> None:
    """Function to test Data Encryption/Decryption using a Derived AES Key.

    Function to test Data Encryption/Decryption using an AES Key
    Derived by the ECB_ENCRYPT Mechanism.

    Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
    """

    # Create the Master Key
    capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
    capabilities |= pkcs11.MechanismFlag.DERIVE
    key = session.generate_key(
        pkcs11.KeyType.AES,
        key_length=test_key_length,
        capabilities=capabilities,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.DERIVE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )

    assert key is not None, "Failed to create {}-bit Master Key".format(test_key_length)

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

    assert derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length)

    # Test capability of Key to Encrypt/Decrypt data
    data = b"HELLO WORLD" * 1024

    iv = session.generate_random(128)
    crypttext = key.encrypt(data, mechanism_param=iv)
    text = key.decrypt(crypttext, mechanism_param=iv)

    assert text == data


@pytest.mark.parametrize(
    ("test_key_length", "iv_length", "data_length", "is_none"),
    [
        (128, 16, 16, False),
        (128, 16, 64, False),
        (128, 15, 16, True),
        (128, 16, 31, True),
        (256, 16, 32, False),
        (256, 16, 64, False),
        (256, 15, 16, True),
        (256, 16, 31, True),
        (256, 16, 16, True),
    ],
)
@pytest.mark.requires(Mechanism.AES_CBC_ENCRYPT_DATA)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_derive_using_cbc_encrypt(
    session: pkcs11.Session,
    key: pkcs11.SecretKey,
    test_key_length: int,
    iv_length: int,
    data_length: int,
    is_none: bool,
):
    """Function to test AES Key Derivation using the CBC_ENCRYPT Mechanism.

    Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
    """

    # Create the Master Key
    capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
    capabilities |= pkcs11.MechanismFlag.DERIVE
    key = session.generate_key(
        pkcs11.KeyType.AES,
        key_length=test_key_length,
        capabilities=capabilities,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.DERIVE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )

    assert key is not None, "Failed to create {}-bit Master Key".format(test_key_length)

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

    if is_none:
        assert derived_key is None, "{}-bit Key Derivation Failure".format(test_key_length)
    else:
        assert derived_key is not None


@pytest.mark.parametrize(
    ("test_key_length", "iv_length", "data_length"), [(128, 16, 16), (256, 16, 32), (256, 16, 64)]
)
@pytest.mark.requires(Mechanism.AES_CBC_ENCRYPT_DATA)
@pytest.mark.xfail_opencryptoki  # can't set key attributes
def test_encrypt_with_key_derived_using_cbc_encrypt(
    session: pkcs11.Session,
    key: pkcs11.SecretKey,
    test_key_length: int,
    iv_length: int,
    data_length: int,
):
    """Function to test Data Encryption/Decryption using a Derived AES Key.

    Function to test Data Encryption/Decryption using an AES Key
    Derived by the CBC_ENCRYPT Mechanism.

    Refer to Section 2.15 of http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850521
    """

    # Create the Master Key
    capabilities = pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[pkcs11.KeyType.AES]
    capabilities |= pkcs11.MechanismFlag.DERIVE
    key = session.generate_key(
        pkcs11.KeyType.AES,
        key_length=test_key_length,
        capabilities=capabilities,
        template={
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.DERIVE: True,
            pkcs11.Attribute.SENSITIVE: False,
        },
    )

    assert key is not None, "Failed to create {}-bit Master Key".format(test_key_length)

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

    assert derived_key is not None, "Failed to derive {}-bit Derived Key".format(test_key_length)

    # Test capability of Key to Encrypt/Decrypt data
    data = b"HELLO WORLD" * 1024

    iv = session.generate_random(128)
    crypttext = key.encrypt(data, mechanism_param=iv)
    text = key.decrypt(crypttext, mechanism_param=iv)

    assert text == data
