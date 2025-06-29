"""
Default mappings for various key types and mechanisms.

None of this is provided for in PKCS#11 and its correctness should not be
assumed.
"""

from pkcs11.constants import (
    MechanismFlag,
)
from pkcs11.mechanisms import MGF, KeyType, Mechanism

DEFAULT_GENERATE_MECHANISMS = {
    KeyType.AES: Mechanism.AES_KEY_GEN,
    KeyType.DES2: Mechanism.DES2_KEY_GEN,
    KeyType.DES3: Mechanism.DES3_KEY_GEN,
    KeyType.DH: Mechanism.DH_PKCS_KEY_PAIR_GEN,
    KeyType.DSA: Mechanism.DSA_KEY_PAIR_GEN,
    KeyType.EC: Mechanism.EC_KEY_PAIR_GEN,
    KeyType.RSA: Mechanism.RSA_PKCS_KEY_PAIR_GEN,
    KeyType.X9_42_DH: Mechanism.X9_42_DH_KEY_PAIR_GEN,
    KeyType.EC_EDWARDS: Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
    KeyType.GENERIC_SECRET: Mechanism.GENERIC_SECRET_KEY_GEN,
}
"""
Default mechanisms for generating keys.
"""

_ENCRYPTION = MechanismFlag.ENCRYPT | MechanismFlag.DECRYPT
_SIGNING = MechanismFlag.SIGN | MechanismFlag.VERIFY
_WRAPPING = MechanismFlag.WRAP | MechanismFlag.UNWRAP

DEFAULT_KEY_CAPABILITIES = {
    KeyType.AES: _ENCRYPTION | _SIGNING | _WRAPPING,
    KeyType.DES2: _ENCRYPTION | _SIGNING | _WRAPPING,
    KeyType.DES3: _ENCRYPTION | _SIGNING | _WRAPPING,
    KeyType.DH: MechanismFlag.DERIVE,
    KeyType.DSA: _SIGNING,
    KeyType.EC: _SIGNING | MechanismFlag.DERIVE,
    KeyType.RSA: _ENCRYPTION | _SIGNING | _WRAPPING,
    KeyType.GENERIC_SECRET: 0,
    KeyType.EC_EDWARDS: _SIGNING,
}
"""
Default capabilities for generating keys.
"""

DEFAULT_ENCRYPT_MECHANISMS = {
    KeyType.AES: Mechanism.AES_CBC_PAD,
    KeyType.DES2: Mechanism.DES3_CBC_PAD,
    KeyType.DES3: Mechanism.DES3_CBC_PAD,
    KeyType.RSA: Mechanism.RSA_PKCS_OAEP,
}
"""
Default mechanisms for encrypt/decrypt.
"""

DEFAULT_SIGN_MECHANISMS = {
    KeyType.AES: Mechanism.AES_MAC,
    KeyType.DES2: Mechanism.DES3_MAC,
    KeyType.DES3: Mechanism.DES3_MAC,
    KeyType.DSA: Mechanism.DSA_SHA512,
    KeyType.EC: Mechanism.ECDSA_SHA512,
    KeyType.RSA: Mechanism.SHA512_RSA_PKCS,
    KeyType.EC_EDWARDS: Mechanism.EDDSA,
}
"""
Default mechanisms for sign/verify.
"""

DEFAULT_WRAP_MECHANISMS = {
    KeyType.AES: Mechanism.AES_KEY_WRAP,
    KeyType.DES2: Mechanism.DES3_ECB,
    KeyType.DES3: Mechanism.DES3_ECB,
    KeyType.RSA: Mechanism.RSA_PKCS_OAEP,
}
"""
Default mechanism for wrap/unwrap.
"""

DEFAULT_DERIVE_MECHANISMS = {
    KeyType.DH: Mechanism.DH_PKCS_DERIVE,
    KeyType.EC: Mechanism.ECDH1_DERIVE,
    KeyType.X9_42_DH: Mechanism.X9_42_DH_DERIVE,
}
"""
Default mechanisms for key derivation
"""

DEFAULT_PARAM_GENERATE_MECHANISMS = {
    KeyType.DH: Mechanism.DH_PKCS_PARAMETER_GEN,
    KeyType.DSA: Mechanism.DSA_PARAMETER_GEN,
    KeyType.X9_42_DH: Mechanism.X9_42_DH_PARAMETER_GEN,
}
"""
Default mechanisms for domain parameter generation
"""


DEFAULT_MECHANISM_PARAMS = {
    Mechanism.RSA_PKCS_OAEP: (Mechanism.SHA_1, MGF.SHA1, None),
    Mechanism.RSA_PKCS_PSS: (Mechanism.SHA_1, MGF.SHA1, 20),
}
"""
Default mechanism parameters
"""
