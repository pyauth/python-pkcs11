"""
X.509 Certificate Tests
"""

import base64
import subprocess

from pyasn1.codec.der import encoder as derencoder, decoder as derdecoder
from pyasn1.codec.ber import encoder as berencoder
from pyasn1.type.univ import BitString, Null
from pyasn1_modules import rfc2459, rfc2314

import pkcs11
from pkcs11.util.rsa import (
    decode_rsa_public_key,
    encode_rsa_public_key,
)
from pkcs11.util.x509 import decode_x509_certificate
from pkcs11 import (
    Attribute,
    KeyType,
    Mechanism,
)

from . import TestCase, Not, requires


# X.509 self-signed certificate (generated with OpenSSL)
# openssl req -x509 \
#   -newkey rsa:512 \
#   -keyout key.pem \
#   -out cert.pem \
#   -days 365 \
#   -nodes
CERT = base64.b64decode("""
MIICKzCCAdWgAwIBAgIJAK3BO9rnLZd9MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwNjAyMDI0ODMyWhcNMTgwNjAyMDI0ODMyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK5z
DJiUDIutdWY8sT2O2ABKh5nmWjc4uEjNj/i5ZLQ4YlRmDL4e2vWs/GOFLVtTJKj6
rh4fj65Xo6X/5R/y+U8CAwEAAaOBpzCBpDAdBgNVHQ4EFgQU+cG240Pzz0y6igtm
hnk1+1KFv6gwdQYDVR0jBG4wbIAU+cG240Pzz0y6igtmhnk1+1KFv6ihSaRHMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGSCCQCtwTva5y2XfTAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA0EAOdvMKLrIFOYF3aVLGharY196heO0fndm39sZAXJ4PItx
n28DytHEdAoltksfJ2Ds3XAjQqcpI5eBbhIoN9Ckxg==
""")


class X509Tests(TestCase):

    def test_import_ca_certificate_easy(self):
        cert = self.session.create_object(decode_x509_certificate(CERT))
        self.assertIsInstance(cert, pkcs11.Certificate)

    @Not.nfast
    @Not.opencryptoki
    def test_import_ca_certificate(self):
        cert = self.session.create_object(
            decode_x509_certificate(CERT, extended_set=True))
        self.assertIsInstance(cert, pkcs11.Certificate)

        self.assertEqual(cert[Attribute.HASH_OF_ISSUER_PUBLIC_KEY],
                         b'\xf9\xc1\xb6\xe3\x43\xf3\xcf\x4c\xba\x8a'
                         b'\x0b\x66\x86\x79\x35\xfb\x52\x85\xbf\xa8')
        # Cert is self signed
        self.assertEqual(cert[Attribute.HASH_OF_SUBJECT_PUBLIC_KEY],
                         b'\xf9\xc1\xb6\xe3\x43\xf3\xcf\x4c\xba\x8a'
                         b'\x0b\x66\x86\x79\x35\xfb\x52\x85\xbf\xa8')

    @requires(Mechanism.SHA1_RSA_PKCS)
    def test_verify_certificate(self):
        # Warning: proof of concept code only!
        x509, *_ = derdecoder.decode(CERT, asn1Spec=rfc2459.Certificate())
        key = bytes(x509
                    ['tbsCertificate']
                    ['subjectPublicKeyInfo']
                    ['subjectPublicKey']
                    .asNumbers())
        key = self.session.create_object(decode_rsa_public_key(key))
        value = berencoder.encode(x509['tbsCertificate'])
        signature = bytes(x509['signatureValue'].asNumbers())
        mechanism = x509['signatureAlgorithm']['algorithm']

        # We could handle other mechanisms but why would we?
        assert mechanism == rfc2459.sha1WithRSAEncryption

        self.assertTrue(key.verify(value, signature,
                                   mechanism=Mechanism.SHA1_RSA_PKCS))

    @requires(Mechanism.RSA_PKCS_KEY_PAIR_GEN, Mechanism.SHA1_RSA_PKCS)
    def test_self_sign_certificate(self):
        # Warning: proof of concept code only!
        pub, priv = self.session.generate_keypair(KeyType.RSA, 1024)

        cert = rfc2459.Certificate()
        cert['tbsCertificate'] = tbs = rfc2459.TBSCertificate()
        tbs['version'] = 'v1'
        tbs['subject'] = tbs['issuer'] = rfc2459.RDNSequence()

        tbs['serialNumber'] = 0x1
        cert['signatureAlgorithm'] = tbs['signature'] = algorithm = \
            rfc2459.AlgorithmIdentifier()
        algorithm['algorithm'] = rfc2459.sha1WithRSAEncryption
        algorithm['parameters'] = Null()

        tbs['validity'] = validity = rfc2459.Validity()
        validity['notBefore'] = time = rfc2459.Time()
        time['generalTime'] = '20170101000000Z'
        validity['notAfter'] = time = rfc2459.Time()
        time['generalTime'] = '20381231000000Z'

        tbs['subjectPublicKeyInfo'] = keyinfo = rfc2459.SubjectPublicKeyInfo()
        keyinfo['algorithm'] = algorithm = rfc2459.AlgorithmIdentifier()
        algorithm['algorithm'] = rfc2459.rsaEncryption
        algorithm['parameters'] = Null()
        key = encode_rsa_public_key(pub)
        keyinfo['subjectPublicKey'] = BitString.fromOctetString(key)

        value = berencoder.encode(tbs)
        cert['signatureValue'] = BitString.fromOctetString(
            priv.sign(value,
                      mechanism=Mechanism.SHA1_RSA_PKCS))

        # Pipe our certificate to OpenSSL to verify it
        with subprocess.Popen(('openssl', 'verify'),
                              stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL) as proc:

            proc.stdin.write(b'-----BEGIN CERTIFICATE-----\n')
            proc.stdin.write(base64.encodebytes(derencoder.encode(cert)))
            proc.stdin.write(b'-----END CERTIFICATE-----\n')
            proc.stdin.close()

            self.assertEqual(proc.wait(), 0)

    @requires(Mechanism.RSA_PKCS_KEY_PAIR_GEN, Mechanism.SHA1_RSA_PKCS)
    def test_sign_csr(self):
        # Warning: proof of concept code only!
        pub, priv = self.session.generate_keypair(KeyType.RSA, 1024)

        csr = rfc2314.CertificationRequest()
        csr['certificationRequestInfo'] = info = \
            rfc2314.CertificationRequestInfo()
        info['version'] = 0
        info['subject'] = rfc2459.RDNSequence()

        attrpos = info.componentType.getPositionByName('attributes')
        attrtype = info.componentType.getTypeByPosition(attrpos)
        info['attributes'] = attrtype.clone()

        info['subjectPublicKeyInfo'] = keyinfo = rfc2459.SubjectPublicKeyInfo()
        keyinfo['algorithm'] = algorithm = rfc2459.AlgorithmIdentifier()
        algorithm['algorithm'] = rfc2459.rsaEncryption
        algorithm['parameters'] = Null()
        key = encode_rsa_public_key(pub)
        keyinfo['subjectPublicKey'] = BitString.fromOctetString(key)

        value = berencoder.encode(info)
        csr['signature'] = BitString.fromOctetString(
            priv.sign(value,
                      mechanism=Mechanism.SHA1_RSA_PKCS))
        csr['signatureAlgorithm'] = algorithm = rfc2459.AlgorithmIdentifier()
        algorithm['algorithm'] = rfc2459.sha1WithRSAEncryption
        algorithm['parameters'] = Null()

        # Pipe our CSR to OpenSSL to verify it
        with subprocess.Popen(('openssl', 'req',
                               '-inform', 'der',
                               '-noout',
                               '-verify'),
                              stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL) as proc:

            proc.stdin.write(derencoder.encode(csr))
            proc.stdin.close()

            self.assertEqual(proc.wait(), 0)
