"""
Certificate handling utilities for X.509 (SSL) certificates.

These utilities depend on the :mod:`pyasn1` and :mod:`pyasn1_modules`.
"""

from datetime import datetime

from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1_modules.rfc2459 import (
    Certificate,
    certificateExtensionsMap,
    id_ce_authorityKeyIdentifier,
    id_ce_subjectKeyIdentifier,
)

from ..constants import Attribute, ObjectClass, CertificateType


def _decode_x509_extension(extn):
    """Decode a X.509 extension, which is encoded as an ANY type."""
    asn_type = certificateExtensionsMap[extn['extnID']]
    octet_stream, _ = der_decoder.decode(extn['extnValue'])
    value, _ = der_decoder.decode(octet_stream, asn1Spec=asn_type)
    return value


def decode_x509_certificate(der, extended_set=False):
    """
    Decode a DER-encoded X.509 certificate into a dictionary of
    attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    Optionally pass `extended_set` to include additional attributes:
    start date, end date and key identifiers.

    :param bytes der: DER-encoded certificate
    :param extended_set: decodes more metadata about the certificate
    :rtype: dict(Attribute,*)
    """
    x509, _ = der_decoder.decode(der, asn1Spec=Certificate())
    subject = der_encoder.encode(x509['tbsCertificate']['subject'])
    issuer = der_encoder.encode(x509['tbsCertificate']['issuer'])
    serial = der_encoder.encode(x509['tbsCertificate']['serialNumber'])

    # Build a map of the extensions, maybe we can find the key identifiers
    # We're not using the certificate or checking its validity, so we don't
    # need to check critical sections
    extensions = {
        extension['extnID']: _decode_x509_extension(extension)
        for extension in x509['tbsCertificate']['extensions']
    }

    template = {
        Attribute.CLASS: ObjectClass.CERTIFICATE,
        Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
        Attribute.SUBJECT: subject,
        Attribute.ISSUER: issuer,
        Attribute.SERIAL_NUMBER: serial,
        # Yes the standard says BER
        Attribute.VALUE: ber_encoder.encode(x509),
    }

    if extended_set:
        start_date = datetime.strptime(
            str(x509['tbsCertificate']['validity']['notBefore']['utcTime']),
            '%y%m%d%H%M%SZ').date()
        end_date = datetime.strptime(
            str(x509['tbsCertificate']['validity']['notAfter']['utcTime']),
            '%y%m%d%H%M%SZ').date()

        template.update({
            Attribute.START_DATE: start_date,
            Attribute.END_DATE: end_date,
        })

        # FIXME: is this correct?
        try:
            template[Attribute.HASH_OF_SUBJECT_PUBLIC_KEY] = \
                extensions[id_ce_subjectKeyIdentifier]
        except KeyError:
            pass

        try:
            template[Attribute.HASH_OF_ISSUER_PUBLIC_KEY] = \
                extensions[id_ce_authorityKeyIdentifier]['keyIdentifier']
        except KeyError:
            pass

    return template
