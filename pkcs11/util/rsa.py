"""
Key handling utilities for RSA keys (PKCS#1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asn1crypto.keys import RSAPrivateKey, RSAPublicKey

from pkcs11.constants import Attribute, MechanismFlag, ObjectClass
from pkcs11.defaults import DEFAULT_KEY_CAPABILITIES
from pkcs11.mechanisms import KeyType
from pkcs11.util import biginteger

if TYPE_CHECKING:
    from pkcs11.types import PublicKey


def decode_rsa_private_key(
    der: bytes,
    capabilities: MechanismFlag | int | None = None,
) -> dict[Attribute, Any]:
    """
    Decode a RFC2437 (PKCS#1) DER-encoded RSA private key into a dictionary of
    attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    :param bytes der: DER-encoded key
    :param MechanismFlag capabilities: Optional key capabilities
    :rtype: dict(Attribute,*)
    """
    caps: MechanismFlag | int = capabilities or DEFAULT_KEY_CAPABILITIES[KeyType.RSA]

    key = RSAPrivateKey.load(der)

    return {
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.MODULUS: biginteger(key["modulus"]),
        Attribute.PUBLIC_EXPONENT: biginteger(key["public_exponent"]),
        Attribute.PRIVATE_EXPONENT: biginteger(key["private_exponent"]),
        Attribute.PRIME_1: biginteger(key["prime1"]),
        Attribute.PRIME_2: biginteger(key["prime2"]),
        Attribute.EXPONENT_1: biginteger(key["exponent1"]),
        Attribute.EXPONENT_2: biginteger(key["exponent2"]),
        Attribute.COEFFICIENT: biginteger(key["coefficient"]),
        Attribute.DECRYPT: MechanismFlag.DECRYPT & caps != 0,
        Attribute.SIGN: MechanismFlag.SIGN & caps != 0,
        Attribute.UNWRAP: MechanismFlag.UNWRAP & caps != 0,
    }


def decode_rsa_public_key(
    der: bytes,
    capabilities: MechanismFlag | int | None = None,
) -> dict[Attribute, Any]:
    """
    Decode a RFC2437 (PKCS#1) DER-encoded RSA public key into a dictionary of
    attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    :param bytes der: DER-encoded key
    :param MechanismFlag capabilities: Optional key capabilities
    :rtype: dict(Attribute,*)
    """
    caps: MechanismFlag | int = capabilities or DEFAULT_KEY_CAPABILITIES[KeyType.RSA]

    key = RSAPublicKey.load(der)
    return {
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.MODULUS: biginteger(key["modulus"]),
        Attribute.PUBLIC_EXPONENT: biginteger(key["public_exponent"]),
        Attribute.ENCRYPT: MechanismFlag.ENCRYPT & caps != 0,
        Attribute.VERIFY: MechanismFlag.VERIFY & caps != 0,
        Attribute.WRAP: MechanismFlag.WRAP & caps != 0,
    }


def encode_rsa_public_key(key: PublicKey) -> bytes:
    """
    Encode an RSA public key into PKCS#1 DER-encoded format.

    :param PublicKey key: RSA public key
    :rtype: bytes
    """
    return RSAPublicKey(
        {
            "modulus": int.from_bytes(key[Attribute.MODULUS], byteorder="big"),
            "public_exponent": int.from_bytes(key[Attribute.PUBLIC_EXPONENT], byteorder="big"),
        }
    ).dump()
