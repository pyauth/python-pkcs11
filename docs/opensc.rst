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
                pkcs11.Attribute: pkcs11.util.ec.encode_named_curve_parameters('prime256v1'),
            }, local=True)

        pub, priv = ecparams.generate_keypair(store=True,
                                              label="My EC Keypair")

Exporting Public Keys for External Use
--------------------------------------

While we don't want our private keys to leave the boundary of our HSM,
we can extract the public keys for use with a cryptographic library of our
choosing.

RSA
~~~

PyCrypto example:

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


Debugging
---------

The parameter `OPENSC_DEBUG` will enable debugging of the OpenSC driver.
A higher number indicates more verbosity.
