"""
Default mappings for various key types and mechanisms.

None of this is provided for in PKCS#11 and its correctness should not be
assumed.
"""

from .constants import *
from .mechanisms import *


DEFAULT_GENERATE_MECHANISMS = {
    KeyType.AES: Mechanism.AES_KEY_GEN,
    KeyType.RSA: Mechanism.RSA_PKCS_KEY_PAIR_GEN,
    KeyType.DH: Mechanism.DH_PKCS_KEY_PAIR_GEN,
}
"""
Default mechanisms for generating keys.
"""

_DEFAULT_CAPS = \
    MechanismFlag.ENCRYPT | \
    MechanismFlag.DECRYPT | \
    MechanismFlag.SIGN | \
    MechanismFlag.VERIFY | \
    MechanismFlag.WRAP | \
    MechanismFlag.UNWRAP

DEFAULT_KEY_CAPABILITIES = {
    KeyType.AES: _DEFAULT_CAPS,
    KeyType.RSA: _DEFAULT_CAPS,
    KeyType.DH: _DEFAULT_CAPS | MechanismFlag.DERIVE,
}
"""
Default capabilities for generating keys.
"""

DEFAULT_ENCRYPT_MECHANISMS = {
    KeyType.AES: Mechanism.AES_CBC_PAD,
    KeyType.RSA: Mechanism.RSA_PKCS,
}
"""
Default mechanisms for encrypt/decrypt.
"""

DEFAULT_SIGN_MECHANISMS = {
    KeyType.AES: Mechanism.SHA512_HMAC,
    KeyType.RSA: Mechanism.SHA512_RSA_PKCS,
}
"""
Default mechanisms for sign/verify.
"""

DEFAULT_WRAP_MECHANISMS = {
    KeyType.AES: Mechanism.AES_KEY_WRAP_PAD,
    KeyType.RSA: Mechanism.RSA_PKCS,
}
"""
Default mechanism for wrap/unwrap.
"""

DEFAULT_DERIVE_MECHANISMS = {
    KeyType.DH: Mechanism.DH_PKCS_DERIVE,
}
"""
Default mechanisms for key derivation
"""


# (Pack Function, Unpack Function) functions
_bool = (Struct('?').pack, lambda v: Struct('?').unpack(v)[0])
_ulong = (Struct('L').pack, lambda v: Struct('L').unpack(v)[0])
_str = (lambda s: s.encode('utf-8'), lambda b: b.decode('utf-8'))
_bytes = (bytes, bytes)
# The PKCS#11 biginteger type is considered as an array of bytes
# in network byte order.
_biginteger = _bytes


def _enum(type_):
    """Factory to pack/unpack intos into IntEnums."""
    pack, unpack = _ulong

    return (lambda v: pack(int(v)),
            lambda v: type_(unpack(v)))


ATTRIBUTE_TYPES = {
    Attribute.ALWAYS_AUTHENTICATE: _bool,
    Attribute.ALWAYS_SENSITIVE: _bool,
    Attribute.BASE: _biginteger,
    Attribute.CHECK_VALUE: _bytes,
    Attribute.CLASS: _enum(ObjectClass),
    Attribute.DECRYPT: _bool,
    Attribute.DERIVE: _bool,
    Attribute.ENCRYPT: _bool,
    Attribute.EXTRACTABLE: _bool,
    Attribute.ID: _bytes,
    Attribute.KEY_GEN_MECHANISM: _enum(Mechanism),
    Attribute.KEY_TYPE: _enum(KeyType),
    Attribute.LABEL: _str,
    Attribute.LOCAL: _bool,
    Attribute.MODIFIABLE: _bool,
    Attribute.MODULUS: _biginteger,
    Attribute.MODULUS_BITS: _ulong,
    Attribute.NEVER_EXTRACTABLE: _bool,
    Attribute.PRIME: _biginteger,
    Attribute.PRIME_BITS: _ulong,
    Attribute.PRIVATE: _bool,
    Attribute.PRIVATE_EXPONENT: _biginteger,
    Attribute.PUBLIC_EXPONENT: _biginteger,
    Attribute.SENSITIVE: _bool,
    Attribute.SIGN: _bool,
    Attribute.SIGN_RECOVER: _bool,
    Attribute.SUBPRIME: _biginteger,
    Attribute.SUBPRIME_BITS: _ulong,
    Attribute.TOKEN: _bool,
    Attribute.TRUSTED: _bool,
    Attribute.UNWRAP: _bool,
    Attribute.VALUE: _biginteger,
    Attribute.VALUE_BITS: _ulong,
    Attribute.VALUE_LEN: _ulong,
    Attribute.VERIFY: _bool,
    Attribute.VERIFY_RECOVER: _bool,
    Attribute.WRAP: _bool,
    Attribute.WRAP_WITH_TRUSTED: _bool,
}
"""
Map of attributes to (serialize, deserialize) functions.
"""
