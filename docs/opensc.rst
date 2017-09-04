Using with SmartCard-HSM (Nitrokey HSM)
=======================================

Support for the SmartCard-HSM and Nitrokey HSM is provided through the
`OpenSC <https://github.com/OpenSC/OpenSC/wiki/PKCS11-Module>`_ project.

The device is not a cryptographic accelerator. Only key generation and the
private key operations (sign and decrypt) are supported. Public key operations
should be done by extracting the public key and working on the computer.

The following mechanisms are available:

+------------------+-----------------------+-----------------------------------+
| Cipher           | Capabilities          | Variants                          |
+==================+=======================+===================================+
| RSA (v1.5/X.509) | Decrypt, Verify, Sign | MD5, SHA1, SHA256, SHA384, SHA512 |
+------------------+-----------------------+-----------------------------------+
| ECDSA            | Sign                  | SHA1                              |
+------------------+-----------------------+-----------------------------------+
| ECDH             | Derive                | Cofactor Derive                   |
+------------------+-----------------------+-----------------------------------+

Session lifetime objects are not supported and the value of
:attr:`pkcs11.constants.Attribute.TOKEN` and the `store` keyword argument
are ignored. All objects will be stored to the device.

The following named curves are supported:

 * secp192r1 (aka prime192v1)
 * secp256r1 (aka prime256v1)
 * brainpoolP192r1
 * brainpoolP224r1
 * brainpoolP256r1
 * brainpoolP320r1
 * secp192k1
 * secp256k1 (the Bitcoin curve)

More information is available `in the Nitrokey FAQ
<https://www.nitrokey.com/documentation/frequently-asked-questions#which-algorithms-and-maximum-key-length-are-supported>`_.

Getting Started
---------------

Initialize the device with `sc-hsm-tool`, e.g.

::

    sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --label "Nitrokey"

See `the documentation
<https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#initialize-the-device>`_
for more information on the parameters.

The OpenSC PKCS #11 module is `opensc-pkcs11.so`.

Generating Keys
---------------

RSA
~~~

::

    import pkcs11

    with token.open(user_pin='1234', rw=True) as session:
        pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048,
                                             store=True,
                                             label="My RSA Keypair")

EC
~~

::

    with token.open(user_pin='1234', rw=True) as session:
        ecparams = session.create_domain_parameters(
            pkcs11.KeyType.EC, {
                pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp256r1'),
            }, local=True)

        pub, priv = ecparams.generate_keypair(store=True,
                                              label="My EC Keypair")

Exporting Public Keys for External Use
--------------------------------------

While we don't want our private keys to leave the boundary of our HSM,
we can extract the public keys for use with a cryptographic library of our
choosing. :ref:`importing-keys` has more information on functions for
exporting keys.

RSA
~~~

`PyCrypto` example:

::

    from pkcs11 import KeyType, ObjectClass, Mechanism
    from pkcs11.util.rsa import encode_rsa_public_key

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

    # Extract public key
    key = session.get_key(key_type=KeyType.RSA,
                          object_class=ObjectClass.PUBLIC_KEY)
    key = RSA.importKey(encode_rsa_public_key(key))

    # Encryption on the local machine
    cipher = PKCS1_v1_5.new(key)
    crypttext = cipher.encrypt(b'Data to encrypt')

    # Decryption in the HSM
    priv = self.session.get_key(key_type=KeyType.RSA,
                                object_class=ObjectClass.PRIVATE_KEY)

    plaintext = priv.decrypt(crypttext, mechanism=Mechanism.RSA_PKCS)

ECDSA
~~~~~

`oscrypto` example:

::

    from pkcs11 import KeyType, ObjectClass, Mechanism
    from pkcs11.util.ec import encode_ec_public_key, encode_ecdsa_signature

    from oscrypto.asymmetric import load_public_key, ecdsa_verify

    # Sign data in the HSM
    priv = self.session.get_key(key_type=KeyType.EC,
                                object_class=ObjectClass.PRIVATE_KEY)
    signature = priv.sign(b'Data to sign', mechanism=Mechanism.ECDSA_SHA1)
    # Encode as ASN.1 for interchange
    signature = encode_ecdsa_signature(signature)

    # Extract the public key
    pub = self.session.get_key(key_type=KeyType.EC,
                               object_class=ObjectClass.PUBLIC_KEY)

    # Verify the signature on the local machine
    key = load_public_key(encode_ec_public_key(pub))
    ecdsa_verify(key, signature, b'Data to sign', 'sha1')

ECDH
~~~~

Smartcard-HSM can generate a shared key via ECDH key exchange.

.. warning::

    Where possible, e.g. over networks, you should use ephemeral keys,
    to allow for perfect forward secrecy. Smartcard HSM's ECDH is only useful
    when need to repeatedly retrieve the same shared secret, e.g. encrypting
    files in a hybrid cryptosystem.

`cryptography` example:

::

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import \
        Encoding, PublicFormat, load_der_public_key

    # Retrieve our keypair, with our public key encoded for interchange
    alice_priv = self.session.get_key(key_type=KeyType.EC,
                                        object_class=ObjectClass.PRIVATE_KEY)
    alice_pub = self.session.get_key(key_type=KeyType.EC,
                                        object_class=ObjectClass.PUBLIC_KEY)
    alice_pub = encode_ec_public_key(alice_pub)

    # Bob generates a keypair, with their public key encoded for
    # interchange
    bob_priv = ec.generate_private_key(ec.SECP256R1,
                                        default_backend())
    bob_pub = bob_priv.public_key().public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )

    # Bob converts Alice's key to internal format and generates their
    # shared key
    bob_shared_key = bob_priv.exchange(
        ec.ECDH(),
        load_der_public_key(alice_pub, default_backend()),
    )

    key = alice_priv.derive_key(
        KeyType.GENERIC_SECRET, 256,
        mechanism_param=(
            KDF.NULL, None,
            # SmartcardHSM doesn't accept DER-encoded EC_POINTs for derivation
            decode_ec_public_key(bob_pub, encode_ec_point=False)
            [Attribute.EC_POINT],
        ),
    )
    alice_shared_key = key[Attribute.VALUE]

When decoding the other user's `EC_POINT` for passing into the key derivation
the standard says to pass a raw octet string (set `encode_ec_point` to False),
however some PKCS #11 implementations require a DER-encoded octet string
(i.e. the format of the :attr:`pkcs11.constants.Attribute.EC_POINT` attribute).

Encrypting Files
----------------

The device only supports asymmetric mechanisms. To do file encryption, you
will need to generate AES keys locally, which you can encrypt with your RSA
public key (this is how the Nitrokey storage key works); or by using ECDH
to generate a shared secret from a locally generated public key.

Debugging
---------

The parameter `OPENSC_DEBUG` will enable debugging of the OpenSC driver.
A higher number indicates more verbosity.

Thanks
------

Thanks to Nitrokey for their support of open software and
sending a Nitrokey HSM to test with `python-pkcs11`.
