"""
Key handling utilities for Diffie-Hellman keys.

These utilities depend on the :mod:`pyasn1` and :mod:`pyasn1_modules`.
"""

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc3279 import DomainParameters, DHPublicKey

from . import biginteger
from ..constants import Attribute
from ..exceptions import AttributeTypeInvalid


def decode_x9_42_dh_domain_parameters(der):
    """
    Decode RFC3279 (X9.42) DER-encoded Diffie-Hellman domain parameters.

    :param bytes der: DER-encoded parameters
    :rtype: dict(Attribute,*)
    """

    params, _ = decoder.decode(der, asn1Spec=DomainParameters())

    return {
        Attribute.BASE: biginteger(params['g']),
        Attribute.PRIME: biginteger(params['p']),
        Attribute.SUBPRIME: biginteger(params['q']),
    }


def encode_x9_42_dh_domain_parameters(obj):
    """
    Encode DH domain parameters into RFC 3279 (X9.42) DER-encoded format.

    Calculates the subprime if it isn't available.

    :param DomainParameters obj: domain parameters
    :rtype: bytes
    """

    asn1 = DomainParameters()
    asn1['g'] = int.from_bytes(obj[Attribute.BASE], byteorder='big')
    asn1['p'] = int.from_bytes(obj[Attribute.PRIME], byteorder='big')

    try:
        asn1['q'] = int.from_bytes(obj[Attribute.SUBPRIME], byteorder='big')
    except AttributeTypeInvalid:
        # If we don't have the subprime, calculate it.
        asn1['q'] = (asn1['p'] - 1) // 2

    return encoder.encode(asn1)


def encode_dh_public_key(key):
    """
    Encode DH public key into RFC 3279 DER-encoded format.

    :param PublicKey key: public key
    :rtype: bytes
    """

    asn1 = DHPublicKey(int.from_bytes(key[Attribute.VALUE], byteorder='big'))

    return encoder.encode(asn1)


def decode_dh_public_key(der):
    """
    Decode a DH public key from RFC 3279 DER-encoded format.

    Returns a `biginteger` encoded as bytes.

    :param bytes der: DER-encoded public key
    :rtype: bytes
    """

    asn1, _ = decoder.decode(der, asn1Spec=DHPublicKey())
    return biginteger(asn1)
