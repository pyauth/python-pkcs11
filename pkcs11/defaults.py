"""
Default mappings for various key types and mechanisms.

None of this is provided for in PKCS#11 and its correctness should not be
assumed.
"""

from .constants import *
from .mechanisms import *


_DEFAULT_CAPS = \
    MechanismFlag.ENCRYPT | \
    MechanismFlag.DECRYPT | \
    MechanismFlag.SIGN | \
    MechanismFlag.VERIFY | \
    MechanismFlag.WRAP | \
    MechanismFlag.UNWRAP



DEFAULT_GENERATE_MECHANISMS = {
    KeyType.AES: Mechanism.AES_KEY_GEN,
    KeyType.RSA: Mechanism.RSA_PKCS_KEY_PAIR_GEN,
}
"""
Default mechanisms for generating keys.
"""

DEFAULT_KEY_CAPABILITIES = {
    KeyType.AES: _DEFAULT_CAPS,
    KeyType.RSA: _DEFAULT_CAPS,
}
"""
Default capabilities for generating keys.
"""


# (Pack Function, Unpack Function) functions
_bool = (Struct('?').pack, lambda v: Struct('?').unpack(v)[0])
_ulong = (Struct('L').pack, lambda v: Struct('L').unpack(v)[0])
_str = (lambda s: s.encode('utf-8'), lambda b: b.decode('utf-8'))
_bytes = (bytes, bytes)


def _enum(type_):
    """Factory to pack/unpack intos into IntEnums."""
    pack, unpack = _ulong

    return (lambda v: pack(int(v)),
            lambda v: type_(unpack(v)))


ATTRIBUTE_TYPES = {
    Attribute.CLASS: _enum(ObjectClass),
    Attribute.TOKEN: _bool,
    Attribute.PRIVATE: _bool,
    Attribute.LABEL: _str,
    Attribute.VALUE: _bytes,
    Attribute.TRUSTED: _bool,
    Attribute.CHECK_VALUE: _bytes,
    Attribute.KEY_TYPE: _enum(KeyType),
    Attribute.ID: _bytes,
    Attribute.SENSITIVE: _bool,
    Attribute.ENCRYPT: _bool,
    Attribute.DECRYPT: _bool,
    Attribute.WRAP: _bool,
    Attribute.UNWRAP: _bool,
    Attribute.SIGN: _bool,
    Attribute.SIGN_RECOVER: _bool,
    Attribute.VERIFY: _bool,
    Attribute.VERIFY_RECOVER: _bool,
    Attribute.DERIVE: _bool,
    Attribute.MODULUS: _bool,
    Attribute.MODULUS_BITS: _bool,
    Attribute.PUBLIC_EXPONENT: _ulong,
    Attribute.PRIVATE_EXPONENT: _ulong,
    Attribute.VALUE_BITS: _ulong,
    Attribute.VALUE_LEN: _ulong,
    Attribute.EXTRACTABLE: _bool,
    Attribute.LOCAL: _bool,
    Attribute.NEVER_EXTRACTABLE: _bool,
    Attribute.ALWAYS_SENSITIVE: _bool,
    Attribute.KEY_GEN_MECHANISM: _enum(Mechanism),
    Attribute.MODIFIABLE: _bool,
    Attribute.ALWAYS_AUTHENTICATE: _bool,
    Attribute.WRAP_WITH_TRUSTED: _bool,
}
"""
Map of attributes to (serialize, deserialize) functions.
"""
