"""
Key handling utilities for EC keys (ANSI X.62/RFC3279).

These utilities depend on the :mod:`pyasn1` and :mod:`pyasn1_modules`.
"""

from pyasn1_modules.rfc3279 import EcpkParameters
from pyasn1.codec.der import encoder


def encode_named_curve_parameters(oid):
    """
    Return DER-encoded ANSI X.62 EC parameters for a named curve.

    Curve names are given by object identifier and can be found in
    :mod:`pyasn1_modules.rfc3279`.

    :param oid:
        Object identifier for a named curve
    :type oid: pyasn1.type.univ.ObjectIdentifier, str or tuple
    :rtype: bytes
    """
    ecParams = EcpkParameters()
    ecParams['namedCurve'] = oid
    return encoder.encode(ecParams)
