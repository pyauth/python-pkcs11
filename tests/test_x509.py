"""
X.509 Certificate Tests
"""

import base64

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2459 import Certificate

import pkcs11
from pkcs11 import Attribute, ObjectClass, CertificateType

from . import TestCase


class X509Tests(TestCase):

    def test_import_certificate(self):
        cert = base64.b64decode("""
        MIIFGTCCBAGgAwIBAgISA6mw4lb59lNC1RGSf3furvsLMA0GCSqGSIb3DQEBCwUA
        MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
        ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA2MDEwNjMyMDBaFw0x
        NzA4MzAwNjMyMDBaMCYxJDAiBgNVBAMTG2J1aWxkYm90LnNxdWFyZXdlYXZlLmNv
        bS5hdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMRio46SeRO23Owi
        kGmuBp2czpeDq2D+p5c6Fzw/nPCrFkMzYvDNgufLFmQ+a69uG8SMMM/P8CGnV7U6
        z0R86bnlovEE3cpFNSvH7RW7m9+KPU2p4+fEw+navIL7IozQc3vxgKtZd4kXjbdy
        SgHAZjTybjpkB/0DA8xXU7tU6dKYQkJE6jEY6cAU4O/GQtIbzm6kjlf7QT2dsuOp
        OlWLRScz4cXPwt+tHMrLGvJohbfD7OEKTSZG6cb8pi95ojJgsekgnYvm1j0uhBt9
        swk+0its+15Z+0JUfLqENhfCMqy3S1VuoMvMUCd8maqUjemtDBv+/w8sPyAl1A07
        urOc+KkCAwEAAaOCAhswggIXMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr
        BgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU3iaawXUs
        RlrZ5ljJvNKjuj90hnIwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEw
        bwYIKwYBBQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMu
        bGV0c2VuY3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMu
        bGV0c2VuY3J5cHQub3JnLzAmBgNVHREEHzAdghtidWlsZGJvdC5zcXVhcmV3ZWF2
        ZS5jb20uYXUwgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEB
        MIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYI
        KwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGll
        ZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNl
        IHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xl
        dHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAkjJ0
        C6KAhoxGM8oKuo6IsFeYDbRCLiWTZjSA31CdQ2voca+UcsbBmXEk+JMtBS9n9ZL5
        b/Lf6zuJNHxZmpePsumx4xP5X6X2qIioEMf3EodCpAIAxOAbIeLqf1FTUjS/yMY9
        k9AI2FBxKNyWQQvis94qFtiHEExLXipSzAVe6y+a7st/3kS5eCn69skQNqCd5C30
        AeAEFDMbqN1i9gN84CusrVlxxxnNYawCExrwNhms4fA1mMcWepDkcYj8uGEofWpG
        jVzKHnBhmmmjjLOeO/mdmSYgRcZrDYxKg2hbptFWtVXiXlguezCsmwH9nrbzgUeM
        TBm97yGUC3PMJh1J6A==
        """)

        x509, *_ = decoder.decode(cert, asn1Spec=Certificate())
        subject = encoder.encode(x509['tbsCertificate']['subject'])
        issuer = encoder.encode(x509['tbsCertificate']['issuer'])
        value = encoder.encode(x509['tbsCertificate'])

        certificate = self.session.create_object({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
            Attribute.SUBJECT: subject,
            Attribute.ISSUER: issuer,
            Attribute.VALUE: value,
        })
        self.assertIsInstance(certificate, pkcs11.Certificate)
