"""
Key handling utilities for EC keys (ANSI X.62/RFC3279).

These utilities depend on the :mod:`pyasn1` and :mod:`pyasn1_modules`.
"""

from ..constants import Attribute, ObjectClass
from ..mechanisms import KeyType

from pyasn1.type.univ import BitString
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc3279 import EcpkParameters, id_ecPublicKey
from pyasn1_modules import rfc3280


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


def decode_ec_public_key(der):
    """
    Decode a DER-encoded EC public key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    :param bytes der: DER-encoded key
    :rtype: dict(Attribute,*)
    """
    asn1, _ = decoder.decode(der, asn1Spec=rfc3280.SubjectPublicKeyInfo())

    assert asn1['algorithm']['algorithm'] == id_ecPublicKey, \
        "Wrong algorithm, not an EC key!"

    return {
        Attribute.KEY_TYPE: KeyType.EC,
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.EC_PARAMS: asn1['algorithm']['parameters'],
        Attribute.EC_POINT: asn1['subjectPublicKey'].asOctets(),
    }


def encode_ec_public_key(key):
    """
    Encode a DER-encoded EC public key as stored by OpenSSL.

    :param PublicKey key: RSA public key
    :rtype: bytes
    """

    asn1 = rfc3280.SubjectPublicKeyInfo()

    asn1['algorithm'] = algo = rfc3280.AlgorithmIdentifier()
    algo['algorithm'] = id_ecPublicKey
    algo['parameters'] = key[Attribute.EC_PARAMS]

    asn1['subjectPublicKey'] = \
        BitString.fromOctetString(key[Attribute.EC_POINT])

    return encoder.encode(asn1)
