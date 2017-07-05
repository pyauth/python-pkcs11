from pkcs11 import KeyType, ObjectClass, Mechanism, Attribute
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import (
    encode_ec_public_key,
    encode_ecdsa_signature,
    encode_named_curve_parameters,
)

from . import TestCase, requires


class ExternalPublicKeyTests(TestCase):

    @requires(Mechanism.RSA_PKCS)
    def test_rsa(self):
        # A key we generated earlier
        self.session.generate_keypair(KeyType.RSA, 1024)

        pub = self.session.get_key(key_type=KeyType.RSA,
                                   object_class=ObjectClass.PUBLIC_KEY)

        pub = encode_rsa_public_key(pub)

        from oscrypto.asymmetric import load_public_key, rsa_pkcs1v15_encrypt

        pub = load_public_key(pub)
        crypttext = rsa_pkcs1v15_encrypt(pub, b'Data to encrypt')

        priv = self.session.get_key(key_type=KeyType.RSA,
                                    object_class=ObjectClass.PRIVATE_KEY)

        plaintext = priv.decrypt(crypttext, mechanism=Mechanism.RSA_PKCS)

        self.assertEqual(plaintext, b'Data to encrypt')

    @requires(Mechanism.ECDSA_SHA1)
    def test_ecdsa(self):
        from pyasn1_modules.rfc3279 import prime256v1

        # A key we generated earlier
        self.session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: encode_named_curve_parameters(prime256v1),
        }, local=True)\
            .generate_keypair()

        priv = self.session.get_key(key_type=KeyType.EC,
                                    object_class=ObjectClass.PRIVATE_KEY)

        signature = priv.sign(b'Data to sign', mechanism=Mechanism.ECDSA_SHA1)
        # Encode as ASN.1 for OpenSSL
        signature = encode_ecdsa_signature(signature)

        from oscrypto.asymmetric import load_public_key, ecdsa_verify

        pub = self.session.get_key(key_type=KeyType.EC,
                                   object_class=ObjectClass.PUBLIC_KEY)
        pub = load_public_key(encode_ec_public_key(pub))

        ecdsa_verify(pub, signature, b'Data to sign', 'sha1')

    @requires(Mechanism.RSA_PKCS)
    def test_terrible_hybrid_file_encryption_app(self):
        # Proof of concept code only!
        import io
        from oscrypto.asymmetric import load_public_key, rsa_pkcs1v15_encrypt
        from oscrypto.symmetric import (
            aes_cbc_pkcs7_encrypt,
            aes_cbc_pkcs7_decrypt,
        )

        # A key we generated earlier
        self.session.generate_keypair(KeyType.RSA, 1024)

        pub = self.session.get_key(key_type=KeyType.RSA,
                                   object_class=ObjectClass.PUBLIC_KEY)
        pub = load_public_key(encode_rsa_public_key(pub))

        key = self.session.generate_random(256)
        iv = self.session.generate_random(128)

        source = b'This is my amazing file'

        with io.BytesIO() as dest:
            # Write a 128-byte header containing our key and our IV
            # strictly speaking we don't need to keep the IV secure but
            # we may as well.
            #
            # FIXME: Because this is RSA 1.5, we should fill the rest of the
            # frame with nonsense
            self.assertEqual(dest.write(rsa_pkcs1v15_encrypt(pub, key + iv)),
                             128)
            _, ciphertext = aes_cbc_pkcs7_encrypt(key, source, iv)
            dest.write(ciphertext)

            # Time passes
            dest.seek(0)

            # Look up our private key
            priv = self.session.get_key(key_type=KeyType.RSA,
                                        object_class=ObjectClass.PRIVATE_KEY)
            # Read the header
            header = dest.read(priv.key_length // 8)
            header = priv.decrypt(header, mechanism=Mechanism.RSA_PKCS)

            # The first 32 bytes is our key
            key, header = header[:32], header[32:]
            # The next 16 bytes is the IV
            iv = header[:16]
            # We can ignore the rest

            plaintext = aes_cbc_pkcs7_decrypt(key, dest.read(), iv)

        self.assertEqual(source, plaintext)
