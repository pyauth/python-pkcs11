"""
Key handling utilities for Diffie-Hellman keys.

These utilities depend on the :mod:`pyasn1` and :mod:`pyasn1_modules`.
"""

from pyasn1.codec.der import decoder
from pyasn1_modules.rfc3279 import DomainParameters

from . import biginteger
from ..constants import Attribute


def decode_dh_domain_parameters(der):
    """
    Decode RFC3279 DER-encoded Diffie-Hellman domain parameters.

    :param bytes der: DER-encoded parameters
    :rtype: dict(Attribute,*)
    """

    params, _ = decoder.decode(der, asn1Spec=DomainParameters())

    return {
        Attribute.BASE: biginteger(params['g']),
        Attribute.PRIME: biginteger(params['p']),
        Attribute.SUBPRIME: biginteger(params['q']),
    }
