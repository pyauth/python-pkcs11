"""
X.509 Certificate Tests
"""

import base64
import subprocess

from asn1crypto.x509 import Certificate

import pkcs11
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.dsa import decode_dsa_signature
from pkcs11.util.ec import decode_ecdsa_signature
from pkcs11.util.x509 import decode_x509_certificate, decode_x509_public_key
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
    def test_verify_certificate_rsa(self):
        # Warning: proof of concept code only!
        x509 = Certificate.load(CERT)
        key = self.session.create_object(decode_x509_public_key(CERT))
        self.assertIsInstance(key, pkcs11.PublicKey)

        value = x509['tbs_certificate'].dump()
        signature = x509.signature

        assert x509.signature_algo == 'rsassa_pkcs1v15'
        assert x509.hash_algo == 'sha1'

        self.assertTrue(key.verify(value, signature,
                                   mechanism=Mechanism.SHA1_RSA_PKCS))

    @requires(Mechanism.DSA_SHA1)
    def test_verify_certificate_dsa(self):
        # Warning: proof of concept code only!
        CERT = base64.b64decode("""
        MIIDbjCCAy6gAwIBAgIJAKPBInGiPjXNMAkGByqGSM44BAMwRTELMAkGA1UEBhMC
        QVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdp
        dHMgUHR5IEx0ZDAeFw0xNzA3MDMxMjI1MTBaFw0xOTA3MDMxMjI1MTBaMEUxCzAJ
        BgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
        dCBXaWRnaXRzIFB0eSBMdGQwggG3MIIBLAYHKoZIzjgEATCCAR8CgYEA7U0AshA/
        4MXQ3MHykoeotEoPc+OXFMJ2PHzKfbFD80UC5bloxC9kp908GG3emdqbJuCTfVUD
        sex1vEgMj1sEwilBow954zMqncu5lLBIGZKjT6tloW8sFt50sE0l+YnBvAiw9uoL
        9lBOZLKh87zWPZUuORm8lWhZEwjUnZ+3S5ECFQCNJGd68RpctgkA1kDp33NhQhev
        lQKBgQCQ6uYkvNpHMtXwyGII4JyOyStbteHjHdKfJfLNRyIEEq/E4e3Do6NGIr26
        Z7u9iBsA5/aU6gKSBrYprxY1hdR4gTRBNzSUDEzf7IX3bfRIbBhjlNBSBba5Fs0z
        /kszZbZ8XYGVxs92aWFk/1JIZ0wnToC794+juq72/TvrtvxdowOBhAACgYAjoknQ
        kRD0+x3GkbngQCU+VNspZuXboB22CU3bDGVAVhmI5N02M8NmeuN7SqqYZAlw01Ju
        rzBF7i9VW4qxBaWszMCwyozerSVjZ2JA/Qubb57v/p7F3FDHq7E33FZzgyhOimds
        rzXpVErCGJJ1oBGz5H5fvoKnQmfh0X8N/VHkZqOBpzCBpDAdBgNVHQ4EFgQUQayv
        usUnpvRgc9OtXGddqMiwm5cwdQYDVR0jBG4wbIAUQayvusUnpvRgc9OtXGddqMiw
        m5ehSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYD
        VQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQCjwSJxoj41zTAMBgNVHRME
        BTADAQH/MAkGByqGSM44BAMDLwAwLAIUNE+zTuFe01v0BRTLarPtGK8ZHHcCFB9Y
        YAwtpblAgUEdGuoAtnoEQ2tc
        """)

        x509 = Certificate.load(CERT)
        key = self.session.create_object(decode_x509_public_key(CERT))
        self.assertIsInstance(key, pkcs11.PublicKey)

        value = x509['tbs_certificate'].dump()

        assert x509.signature_algo == 'dsa'
        assert x509.hash_algo == 'sha1'

        signature = decode_dsa_signature(x509.signature)

        self.assertTrue(key.verify(value, signature,
                                   mechanism=Mechanism.DSA_SHA1))

    @requires(Mechanism.ECDSA_SHA1)
    def test_verify_certificate_ecdsa(self):
        # Warning: proof of concept code only!
        CERT = base64.b64decode("""
        MIIDGjCCAsKgAwIBAgIJAL+PbwiJUZB1MAkGByqGSM49BAEwRTELMAkGA1UEBhMC
        QVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdp
        dHMgUHR5IEx0ZDAeFw0xNzA3MDMxMTUxMTBaFw0xOTA3MDMxMTUxMTBaMEUxCzAJ
        BgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
        dCBXaWRnaXRzIFB0eSBMdGQwggFLMIIBAwYHKoZIzj0CATCB9wIBATAsBgcqhkjO
        PQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAA
        AAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQaw
        zFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEQQRrF9Hy4SxCR/i8
        5uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2
        QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAE
        royPJHkCQMq55egxmQxkFWqiz+yJx0MZP98is99SrkiK5UadFim3r3ZSt5kfh/cc
        Ccmy94BZCmihhGJ0F4eB2qOBpzCBpDAdBgNVHQ4EFgQURNXKlYGsAMItf4Ad8fkg
        Rg9ATqEwdQYDVR0jBG4wbIAURNXKlYGsAMItf4Ad8fkgRg9ATqGhSaRHMEUxCzAJ
        BgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
        dCBXaWRnaXRzIFB0eSBMdGSCCQC/j28IiVGQdTAMBgNVHRMEBTADAQH/MAkGByqG
        SM49BAEDRwAwRAIgAdJp/S9vSjS6EvRy/9zl5k2DBKGI52A3Ygsp1a96UicCIDul
        m/eL2OcGdNbzqzsC11alhemJX7Qt9GOcVqQwROIm
        """)

        x509 = Certificate.load(CERT)
        key = self.session.create_object(decode_x509_public_key(CERT))
        self.assertIsInstance(key, pkcs11.PublicKey)

        value = x509['tbs_certificate'].dump()

        assert x509.signature_algo == 'ecdsa'
        assert x509.hash_algo == 'sha1'

        signature = decode_ecdsa_signature(x509.signature)

        self.assertTrue(key.verify(value, signature,
                                   mechanism=Mechanism.ECDSA_SHA1))

    @requires(Mechanism.RSA_PKCS_KEY_PAIR_GEN, Mechanism.SHA1_RSA_PKCS)
    def test_self_sign_certificate(self):
        # Warning: proof of concept code only!
        pub, priv = self.session.generate_keypair(KeyType.RSA, 1024)

        from asn1crypto.x509 import TbsCertificate

        cert = TbsCertificate({
            'version': 'v1',
            'serial_number': 1,
            'signature': {
            },
            'issuer': {
            },
            'validity': {
            },
            'subject': {
            },
        })
        tbs['subject'] = tbs['issuer'] = rfc2459.RDNSequence()

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
