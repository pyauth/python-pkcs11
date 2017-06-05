Applied PKCS #11
================

`PKCS <https://en.wikipedia.org/wiki/PKCS>`_ #11 is the name given to a
standard defining an API for cryptographic hardware. While it was developed by
RSA, as part of a suite of standards, the standard is not exclusive to RSA
ciphers and is meant to cover a wide range of cryptographic possibilities.
PKCS #11 is most closely related to Java's JCE and Microsoft's CAPI.

.. contents:: Section Contents
    :depth: 2
    :local:

Concepts in PKCS #11
--------------------

Slots and Tokens
~~~~~~~~~~~~~~~~

A `slot` originally referred to a single card slot on a smartcard device that
could accept a `token`. A token was a smartcard that contained secure,
encrypted keys and certificates. You would insert your smartcard (token) into
the slot, and use its contents to do cryptographic operations.

Nowadays the distinction is more blurry. Many USB-key HSMs appear as a single
slot containing a hardwired single token (their internal storage). Server
devices often make use of software tokens (`softcards`), which appear as
slots within PKCS #11, but no physical device exists. These devices can
also feature physical slots and `accelerator slots`.

.. seealso::

    Slots have :attr:`pkcs11.Slot.flags` which can tell you something about
    what kind of slot this is.

Tokens are secured with a passphrase (PIN). Not all implementations use
pins in their underlying implementation, but these are required for PKCS#11.
Some implementations let you control the behaviour of their PKCS #11 module
in ways not specified by the specification through environment variables
(e.g. default token pins).

.. note::

    The PKCS #11 library is running within your process, using your memory,
    etc. It may talk to a daemon to access the underlying hardware, or it
    may be talking directly.

    Environment variables set on your process can be used to configure
    the behaviour of the library, check the documentation for your device.

Finding Tokens
^^^^^^^^^^^^^^

Tokens are identified by a label or serial number.

You can retrieve all tokens matching search parameters:

::

    for slot in lib.get_slots():
        token = slot.get_token()
        # Check the parameters
        if token.label == '...':
            break

::

    for token in lib.get_tokens(token_label='smartcard'):
        print(token)

Retrieving a single token has a shortcut function:

::

    try:
        lib.get_token(token_label='smartcard')
    except NoSuchToken:
        pass
    except MultipleTokensReturned:
        pass


Mechanisms and Capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Different devices support different cryptographic operations. In PKCS #11
mechanisms refer to the combination of cipher (e.g. AES), hash function
(e.g. SHA512) and block mode (e.g. CBC). Mechanisms also exist for generating
keys, and deriving keys and parameters.

The capabilities of a mechanism indicate what types of operations can be
carried out with the mechanism, e.g. encryption, signing, key generation.

Not all devices support all mechanisms. Some may support non-standard
mechanisms. Not all devices support the same capabilities for mechanisms
or same key lengths. This information can be retrieved via
:meth:`pkcs11.Slot.get_mechanisms` and :meth:`pkcs11.Slot.get_mechanism_info`
or from your device documentation.

Some mechanisms require `mechanism parameters`. These are used to provide
additional context to the mechanism that does not form part of the key.
Examples of mechanism parameters are initialisation vectors for block
modes, salts, key derivation functions, and other party's shared secrets (for
Diffie-Hellman).

.. seealso::

    The :class:`pkcs11.mechanisms.Mechanism` type includes information
    on the required parameters for common mechanisms.
    A complete list of `current mechanisms
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html>`_
    and `historical mechanisms
    <http://docs.oasis-open.org/pkcs11/pkcs11-hist/v2.40/errata01/os/pkcs11-hist-v2.40-errata01-os-complete.html>`_
    includes the mechanism parameters and input requirements for each
    mechanism.

Objects and Attributes
~~~~~~~~~~~~~~~~~~~~~~

An object is a piece of cryptographic information stored on a `token`.
Objects have a `class` (e.g. private key) which is exposed in `python-pkcs11`
as a Python class. They also have a number of other attributes depending on
their class.

There are three main classes of object:

* keys (symmetric secret keys and asymmetric public and private keys);
* domain parameters (storing the parameters used to generate keys); and
* certificates (e.g. `X.509 <https://en.wikipedia.org/wiki/X.509>`_
  certificates).

.. note::

    Irregardless of the PKCS #11 specification, not all devices reliably
    handle all object attributes. They can also have different defaults.
    `python-pkcs11` tries to abstract that as much as possible to enable
    writing portable code.

.. seealso::

    :class:`pkcs11.constants.Attribute` describes the available attributes
    and their Python types.

    **biginteger**

    One type is handled specially: `biginteger`, an arbitrarily long integer
    in network byte order. Although Python can handle arbitrarily long
    integers, many other systems cannot and pass these types around as
    byte arrays, and more often than not, that is an easier form to
    handle them in.

    `biginteger` attributes can be specified as :class:`bytes`,
    :class:`bytearray` or an iterable of byte-sized integers.

    If you do have integers, you can convert them to :class:`bytes` using
    :func:`pkcs11.util.biginteger`.

Finding Objects
^^^^^^^^^^^^^^^

Objects can be found on a `token` using their attributes. Usually an `ID`
or `LABEL`.

::

    for obj in session.get_objects({
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.LABEL: 'aes256',
    }):
        print(obj)

Finding a specific key is so common there's a shortcut function:

::

    try:
        key = session.get_key(label='aes256')
    except NoSuchKey:
        pass
    except MultipleObjectsReturned:
        pass

Keys
~~~~

There are three classes of key objects:

* symmetric secret keys;
* asymmetric public keys; and
* asymmetric private keys.

The following attributes can be set for keys:

.. glossary::

    PRIVATE
        Private objects can only be accessed by logged in sessions.

    LOCAL
        This key was generated on the device.

    EXTRACTABLE
        The key can be extracted from the HSM.

    SENSITIVE
        The key is sensitive and cannot be removed from the device in
        clear text.

    ALWAYS_SENSITIVE
        The key has never not been `SENSITIVE`.

    NEVER_EXTRACTABLE
        The key has never been `EXTRACTABLE`.

    ALWAYS_AUTHENTICATE
        The key requires authentication every time it's used.

.. note::

    Keys should be generated on the HSM rather than imported.
    Generally only public keys should not be `PRIVATE` and `SENSITIVE`.
    Allowing private keys to be accessed defeats the purpose of securing your
    keys in a HSM. `python-pkcs11` sets meaningful defaults.

Domain Parameters
~~~~~~~~~~~~~~~~~

Domain parameters are the parameters used to generate cryptographic keys (e.g.
the name of the elliptic curve being used). They are public information.
Obscuring the domain parameters does not increase the security of a
cryptosystem. Typically the domain parameters form part of a protocol
specification, and RFCs exist giving pre-agreed, named domain parameters for
cryptosystems.

In `python-pkcs11` domain parameters can either be stored as an object in your
HSM, or loaded via some other mechanism (e.g. in your code) and used
directly without creating a HSM object.

.. seealso::

    OpenSSL can be used to generate unique or named domain parameters for
    `Diffie-Hellman <https://wiki.openssl.org/index.php/Manual:Dhparam(1)>`_,
    `DSA <https://wiki.openssl.org/index.php/Manual:Dsaparam(1)>`_ and
    `EC <https://wiki.openssl.org/index.php/Manual:Ecparam(1)>`_.

    :mod:`pkcs11.util` includes modules for creating and decoding
    domain parameters.

Sessions
~~~~~~~~

Accessing a token is done by opening a session. Sessions can be public or
logged in. Only a logged in session can access objects marked as `private`.
Depending on your device, some functions may also be unavailable.

.. warning::

    It is important to close sessions when you are finished with them.
    Some devices will leak resources if sessions aren't closed.

    Where possible you should use sessions via a context manager.

Concepts related to PKCS #11
----------------------------

Binary Formats and Padding
~~~~~~~~~~~~~~~~~~~~~~~~~~

PKCS #11 is `protocol agnostic` and does not define or implement any codecs for
the storing of enciphered data, keys, initialisation vectors, etc. outside the
HSM. [1]_ For example, CBC mechanisms will not include the initialization
vector. You must choose a storage/transmission format that suits your
requirements.

Some mechanisms require input data to be `padded` to a certain block size.
Standardized `PAD` variants of many mechanisms exist based on upstream
specifications. For other mechanisms PKCS #11 does not define any specific
algorithms, and you must choose one that suits your requirements.

.. seealso::

    Lots of standards exist for the storing and transmission of cryptographic
    data. If you're not implementing a specific protocol, there may still be
    an RFC standard with a Python implementation to ensure people can
    understand your binary data in the future.

    See also:

    * `RFC 5652 (Cryptographic Message Standard) (supercedes PKCS #7)
      <https://tools.ietf.org/html/rfc5652>`_

.. [1] It does define types for data `inside` the HSM, e.g. attribute
       data types and binary formats (e.g. EC parameters, X.509 certificates).

PKCS #15
~~~~~~~~

PKCS #15 defines a standard for storing cryptographic objects within the
HSM device to enable interoperability between devices and tokens. PKCS #15
is often referenced in conjunction with PKCS #11 as the storage format
used on the `tokens`.

ASN.1, DER, BER
~~~~~~~~~~~~~~~

ASN.1 is a data model for storing structured information. DER and BER
are binary representations of that data model which are used extensively in
cryptography, e.g. for storing RSA key objects, X.509 certificates and
elliptic curve information.

Accessing ASN.1 encoded objects is mostly left to packages other than
`python-pkcs11`, however :mod:`pkcs11.util` does include some utilities to
encode and decode objects where required for working with PKCS #11 itself
(e.g. converting PKCS #1 encoded RSA keys into PKCS #11 objects and
generating parameters for elliptic curves).

PEM
~~~

`PEM <https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail>`_ is
a standard for handling cryptographic objects. It is a base64 encoded version
of the binary DER object. The label indicates the type of object, and thus
what ASN.1 model to use. `python-pkcs11` does not include PEM parsing,
you should include another package if required.

Getting a Session
-----------------

Given a PKCS #11 library (`.so`) that is stored in the environment as
`PKCS11_MODULE`.

To open a read-only session on a token named `smartcard`:

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='smartcard')

    with token.open() as session:
        print(session)

To open a user session with the passphrase/pin `secret`:

::

    with token.open(user_pin='secret') as session:
        print(session)

To open a read/write session:

::

    with token.open(rw=True, user_pin='secret') as session:
        print(session)

.. seealso::

    :meth:`pkcs11.Token.open` has more options for opening the session.

Generating Keys
---------------

Keys can either live for the lifetime of the `session` or be stored on the
token. Storing keys requires a read only session.

To store keys pass `store=True`. When storing keys it is recommended to set
a `label` or `id`, so you can find the key again.

Symmetric Keys
~~~~~~~~~~~~~~

AES
^^^

AES keys can be generated by specifying the key length:

::

    from pkcs11 import KeyType

    key = session.generate_key(KeyType.AES, 256)

Generally AES keys are considered secret. However if you're using your HSM
to generate keys for use with local AES (e.g. in hybrid encryption systems).
You can do the following:

::

    from pkcs11 import KeyType, Attribute

    key = session.generate_key(KeyType.AES, 256, template={
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: True,
    })
    # This is the secret key
    print(key[Attribute.VALUE])

.. glossary::

    VALUE
        Secret key (as `biginteger`).

Asymmetric Keypairs
~~~~~~~~~~~~~~~~~~~

RSA
^^^

RSA keypairs can be generated by specifying the length of the modulus:

::

    from pkcs11 import KeyType

    public, private = session.generate_keypair(KeyType.RSA, 2048)

The default public exponent is `65537`. You can specify an alternative:

::

    from pkcs11 import KeyType, Attribute

    public, private = session.generate_keypair(KeyType.RSA, 2048,
                                               public_template={Attribute.PUBLIC_EXPONENT: ...})
    # This is the public key
    print(public[Attribute.MODULUS])
    print(public[Attribute.PUBLIC_EXPONENT])

The public key has two parameters:

.. glossary::

    MODULUS
        Key modulus (as `biginteger`).

    PUBLIC_EXPONENT
        Public exponent (as `biginteger`).

These can be exported as RFC 2437 (PKCS #1) DER-encoded binary using
:func:`pkcs11.util.rsa.encode_rsa_public_key`.

From Domain Parameters
~~~~~~~~~~~~~~~~~~~~~~

.. note::

    Choosing domain parameters is not covered in this document. Domain
    parameters are often either specified by the requirements you are
    implementing for, or have a standard implementation to derive quality
    parameters. Some domain parameters (e.g. choice of elliptic curve)
    can drastically weaken the cryptosystem.

Diffie-Hellman
^^^^^^^^^^^^^^

Diffie-Hellman key pairs require several domain parameters, specified as
`bigintegers`.  There are two forms of Diffie-Hellman domain parameters: PKCS
#3 and X9.42.

.. glossary::

    BASE
        The prime base (g) (as `biginteger`).

    PRIME
        The prime modulus (p) (as `biginteger`).

    SUBPRIME
        (X9.42 only) The subprime (q) (as `biginteger`).

::

    from pkcs11 import Attribute

    parameters = session.create_domain_parameters(KeyType.DH, {
        Attribute.PRIME: b'prime...',
        Attribute.BASE: b'base...',
    }, local=True)

    public, private = parameters.generate_keypair()

`RFC 3279 <https://tools.ietf.org/html/rfc3279#section-2.3.3>`_ defines a
standard ASN.1 encoding for DH parameters, which can be loaded with
:func:`pkcs11.util.dh.decode_x9_42_dh_domain_parameters`:

::

    params = session.create_domain_parameters(
        KeyType.X9_42_DH,
        decode_x9_42_dh_domain_parameters(b'DER-encoded parameters'),
        local=True)


If supported, unique domain parameters can also be generated for a given
`PRIME` length (e.g. 512 bits) with
:meth:`pkcs11.Session.generate_domain_parameters`:

::

    params = session.generate_domain_parameters(KeyType.DH, 512)

X9.42 format domain parameters can be encoded back to their RFC 3279 format
with :func:`pkcs11.util.dh.encode_x9_42_dh_domain_parameters`.

Key pairs can be generated from the domain parameters:

::

    public, private = parameters.generate_keypair()
    # This is the public key
    print(public[Attribute.VALUE])

The public key has a single important attribute:

.. glossary::

    VALUE
        Public key (as biginteger).

This can be encoded in RFC 3279 format with
:func:`pkcs11.util.dh.encode_dh_public_key`.

Elliptic Curve
^^^^^^^^^^^^^^

Elliptic curves require a domain parameter describing the curve. Curves can
be described in two ways:

* As named curves; or
* As a complete set of parameters.

Not all devices support both specifications.
Both specifications are specified using the same `attribute`.

.. glossary::

    EC_PARAMS
        Curve parameters (as DER-encoded X9.62 bytes).

::

    from pkcs11 import Attribute


    parameters = session.create_domain_parameters(KeyType.EC,
        Attribute.EC_PARAMS: b'DER-encoded X9.62 parameters ...',
    }, local=True)

    public, private = parameters.generate_keypair()


Named curves (e.g. `prime256v1`) can be specified like this:

::

    from pkcs11 import Attribute
    from pkcs11.util.ec import encode_named_curve_parameters
    from pyasn1_modules.rfc3279 import prime256v1


    parameters = session.create_domain_parameters(KeyType.EC, {
        Attribute.EC_PARAMS: encode_named_curve_parameters(prime256v1)
    }, local=True)

Key pairs can be generated from the domain parameters:

::

    public, private = parameters.generate_keypair()
    # This is the public key
    print(public[Attribute.EC_POINT])

The public key as a single important attribute:

.. glossary::

    EC_POINT
        Public key (as X9.62 DER-encoded bytes).

Encryption/Decryption
---------------------

AES
~~~

The `AES <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>`_ cipher
requires you to specify a block mode as part of the `mechanism`.

The default block mode is `CBC with PKCS padding
<http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850490>`_,
which can handle data not padded to the block size and requires you to
supply an initialisation vector of 128-bits of good random.

A number of other mechanisms are available:

+-------------+-----+----------------+---------------------------------+
| Mechanism   | IV  | Input Size     | Notes                           |
+=============+=====+================+=================================+
| AES_ECB     | No  | 128-bit blocks | Only suitable for key-wrapping. |
|             |     |                | Identical blocks encrypt        |
|             |     |                | identically!                    |
+-------------+-----+----------------+---------------------------------+
| AES_CBC     | Yes | 128-bit blocks |                                 |
+-------------+-----+----------------+---------------------------------+
| AES_CBC_PAD | Yes | Any            | Default mechanism               |
+-------------+-----+----------------+---------------------------------+
| AES_OFB     | Yes | Any            |                                 |
+-------------+-----+----------------+---------------------------------+
| AES_CFB_*   | Yes | Any            | 3 modes: AES_CFB8, AES_CFB64,   |
|             |     |                | and AES_CFB128.                 |
+-------------+-----+----------------+---------------------------------+
| AES_CTS     | Yes | >= 128-bit     |                                 |
+-------------+-----+----------------+---------------------------------+
| AES_CTR     | Not currently supported [2]_                           |
+-------------+                                                        |
| AES_GCM     |                                                        |
+-------------+                                                        |
| AES_CGM     |                                                        |
+-------------+--------------------------------------------------------+

.. [2] AES encryption with multiple mechanism parameters not currently
       implemented due to lack of hardware supporting these mechanisms.

.. warning:: **Initialisation vectors**

    An initialization vector (IV) or starting variable (SV) is data that is
    used by several modes to randomize the encryption and hence to produce
    distinct ciphertexts even if the same plaintext is encrypted multiple
    times.

    An initialization vector has different security requirements than a key, so
    the IV usually does not need to be secret. However, in most cases, it is
    important that an initialization vector is never reused under the same key.
    For CBC and CFB, reusing an IV leaks some information about the first block
    of plaintext, and about any common prefix shared by the two messages. For
    OFB and CTR, reusing an IV completely destroys security.

    In CBC mode, the IV must, in addition, be unpredictable at encryption time;
    in particular, the (previously) common practice of re-using the last
    ciphertext block of a message as the IV for the next message is insecure.

    We recommend using :meth:`pkcs11.Session.generate_random` to create a
    quality IV.

A simple example:

::

    # Given an AES key `key`
    iv = session.generate_random(128)
    ciphertext = key.encrypt(plaintext, mechanism_param=iv)

    plaintext = key.decrypt(ciphertext, mechanism_param=iv)

Or using an alternative mechanism:

::

    from pkcs11 import Mechanism

    iv = session.generate_random(128)
    ciphertext = key.encrypt(plaintext,
                             mechanism=Mechanism.AES_OFB,
                             mechanism_param=iv)

Large amounts of data can be passed as a generator:

::

    buffer_size = 8192
    with \\
            open(file_in, 'rb') as input_, \\
            open(file_out, 'wb') as output:

        # A generator yielding chunks of the file
        chunks = iter(lambda: input_.read(buffer_size), '')

        for chunk in key.encrypt(chunks,
                                 mechanism_param=iv,
                                 buffer_size=buffer_size):
            output.write(chunk)

.. note::

    These mechanisms do not store the IV. You must store the IV yourself,
    e.g. on the front of the ciphertext. It is safe to store an IV in the
    clear.

RSA
~~~

The default RSA cipher is `PKCS #1 v1.5
<http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850410>`_

A number of other mechanisms are available:

+-----------------------+------------+-------------------------+-----------------------+
| Mechanism             | Parameters | Input Length            | Notes                 |
+=======================+============+=========================+=======================+
| RSA_PKCS              | None       | <= key length - 11      | Default mechanism     |
+-----------------------+------------+-------------------------+-----------------------+
| RSA_PKCS_OAEP         | Not currently supported                                      |
+-----------------------+------------+-------------------------+-----------------------+
| RSA_X_509             | None       | key length              | Raw mode. No padding. |
+-----------------------+------------+-------------------------+-----------------------+
| RSA_PKCS_TPM_1_1      | None       | <= key length - 11 - 5  | See TCPA TPM          |
|                       |            |                         | Specification Version |
|                       |            |                         | 1.1b                  |
+-----------------------+------------+-------------------------+-----------------------+
| RSA_PKCS_OAEP_TPM_1_1 | Not currently supported                                      |
+-----------------------+--------------------------------------------------------------+

A simple example:

::

    # Given an RSA key pair `public, private`
    ciphertext = public.encrypt(plaintext)

    plaintext = private.decrypt(ciphertext)

Signing/Verifying
-----------------

Signing and verification mechanisms require two components:

* the cipher; and
* the hashing function.

Raw versions for some mechanisms also exist. These require you to do your
own hashing outside of PKCS #11.

Signing functions typically work on a finite length of data, so the signing
of large amounts of data requires hashing with a secure one-way hash function.

AES
~~~

A `MAC` is required for signing with AES. The default mechanism is
`SHA512_HMAC` (aka HMAC-SHA512).

A number of other hashing functions and MACs are available depending on
your implementation.

::

    # Given a secret key, `key`
    signature = key.sign(data)

    assert key.verify(data, signature)

RSA
~~~

The default signing and verification mechanism for RSA is `RSA_SHA512_PKCS`.

Other mechanisms are available:

+-------------------+-------------------------------------------+
| Mechanism         | Notes                                     |
+===================+===========================================+
| RSA_PKCS          | No hashing. Supply your own.              |
+-------------------+-------------------------------------------+
| SHA*_RSA_PKCS     | SHAx message digesting.                   |
+-------------------+-------------------------------------------+
| RSA_PKCS_PSS      | Not currently implemented.                |
+-------------------+                                           |
| SHA*_RSA_PKCS_PSS |                                           |
+-------------------+-------------------------------------------+
| RSA_9796          | ISO/IES 9796 RSA signing.                 |
+-------------------+-------------------------------------------+
| RSA_X_509         | X.509 (raw) RSA signing.                  |
+-------------------+-------------------------------------------+
| RSA_X9_31         | X9.31 RSA signing.                        |
+-------------------+-------------------------------------------+

::

    # Given a private key `private`
    signature = private.sign(data)

    # Given a public key `public`
    assert public.verify(data, signature)

ECDSA
~~~~~

The default signing and verification mechanism for ECDSA is `ECDSA_SHA512`.

Other mechanisms are available:

+------------+-------------------------------------------+
| Mechanism  | Notes                                     |
+============+===========================================+
| ECDSA      | No hashing. Input truncated to 1024 bits. |
+------------+-------------------------------------------+
| ECDSA_SHA* | ECDSA with SHAx message digesting.        |
+------------+-------------------------------------------+

::

    # Given a private key `private`
    signature = private.sign(data)

    # Given a public key `public`
    assert public.verify(data, signature)

Wrapping/Unwrapping
-------------------

The expectation when using HSMs is that secret and private keys never leave
the secure boundary of the HSM. However, there is a use case for transmitting
secret and private keys over insecure mediums. We can do this using key
wrapping.

Key wrapping is similar to encryption and decryption except instead of turning
plaintext into crypttext it turns key objects into crypttext and vice versa.

Keys must be marked as `EXTRACTABLE` to remove them from the HSM, even wrapped.

AES
~~~

The key we're wrapping can be any sensitive key, either a secret key or
a private key. In this example we're extracting an AES secret key:

::

    # Given two secret keys, `key1` and `key2`, we can extract an encrypted
    # version of `key2`
    crypttext = key1.wrap_key(key2)

Wrapping doesn't store any parameters about the keys. We must supply those
to import the key.

::

    key = key1.unwrap_key(ObjectClass.SECRET_KEY, KeyType.AES, crypttext)

RSA
~~~

The key we're wrapping can be any sensitive key, either a secret key or
a private key. In this example we're extracting an AES secret key:

::

    # Given a public key, `public`, and a secret key `key`, we can extract an
    encrypted version of `key`
    crypttext = public.wrap_key(key)

Wrapping doesn't store any parameters about the keys. We must supply those
to import the key.

::

    # Given a private key, `private`, matching `public` above we can decrypt
    # and import `key`.
    key = private.unwrap_key(ObjectClass.SECRET_KEY, KeyType.AES, crypttext)

Deriving Shared Keys
--------------------

Diffie-Hellman
~~~~~~~~~~~~~~

DH lets us derive a shared key using shared domain parameters, our private
key and the other party's public key, which is passed as a mechanism parameter.

The default DH derivation mechanism is `DH_PKCS_DERIVE`, which uses the
algorithm described in PKCS #3.

.. note::

    Other DH derivation mechanisms including X9.42 derivation are not currently
    supported.

::

    # Given our DH private key `private` and the other party's public key
    # `other_public`
    key = private.derive_key(
        KeyType.AES, 128,
        mechanism_param=other_public)

If the other user's public key was encoded using RFC 3279, we can decode this
with :func:`pkcs11.util.dh.decode_dh_public_key`:

::

    from pkcs11.util.dh import decode_dh_public_key

    key = private.derive_key(
        KeyType.AES, 128,
        mechanism_param=decode_dh_public_key(encoded_public_key))

And we can encode our public key for them using
:func:`pkcs11.util.dh.encode_dh_public_key`:

::

    from pkcs11.util.dh import encode_dh_public_key

    # Given our DH public key `public`
    encoded_public_key = encode_dh_public_key(public)

The shared derived key can now be used for any appropriate mechanism.

If you want to extract the shared key from the HSM, you can mark the key
as `EXTRACTABLE`:

::

    key = private.derive_key(
        KeyType.AES, 128,
        mechanism_param=other_public,
        template={
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
    # This is our shared secret key
    print(key[Attribute.VALUE])


EC Diffie-Hellman
~~~~~~~~~~~~~~~~~

ECDH is supported using the `ECDH1_DERIVE` mechanism,
similar to plain DH, except that the mechanism parameter
is a tuple consisting of 3 parameters:

* a key derivation function (KDF);
* a shared value; and
* the other user's public key.

The supported KDFs vary from device to device, check your HSM documentation.
For :attr:`pkcs11.mechanisms.KDF.NULL` (the most widely supported KDF), the
shared value must be `None`.

.. note::

    Other ECDH derivation mechanisms including co-factor derivation and MQV
    derivation are not currently supported.

::

    from pkcs11 import KeyType, KDF

    # Given our DH private key `private` and the other party's public key
    # `other_public`
    key = private.derive_key(
        KeyType.AES, 128,
        mechanism_param=(KDF.NULL, None, other_public))

If you want to extract the shared key from the HSM, you can mark the key
as `EXTRACTABLE`:

::

    key = private.derive_key(
        KeyType.AES, 128,
        mechanism_param=(KDF.NULL, None, other_public),
        template={
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
    # This is our shared secret key
    print(key[Attribute.VALUE])

Digesting and Hashing
---------------------

PKCS #11 exposes the ability to hash or digest data via a number of mechanisms.
For performance reasons, this is rarely done in the HSM, and is usually done
in your process. There are unlikely any advantages to using this functionality
over :mod:`hashlib`.

To digest a message (e.g. with SHA-256):

::

    from pkcs11 import Mechanism

    digest = session.digest(data, mechanism=Mechanism.SHA256)

You can also pass an iterable of data:

::
    with open(file_in, 'rb') as input_:
        # A generator yielding chunks of the file
        chunks = iter(lambda: input_.read(buffer_size), '')
        digest = session.digest(chunks, mechanism=Mechanism.SHA512)


Certificates
------------

Certificates can be stored in the HSM as objects.  PKCS#11 is limited in its
handling of certificates, and does not provide features like parsing of X.509
etc. These should be handled in an external library. PKCS#11 will not set
attributes on the certificate based on the `VALUE` and these must be specified
when creating the object.

X.509
~~~~~

:func:`pkcs11.util.x509.decode_x509_certificate` can be used to decode
X.509 certificates for storage in the HSM:

::

    from pkcs11.util.x509 import decode_x509_certificate

    cert = self.session.create_object(decode_x509_certificate(b'DER encoded X.509 cert...'))

The following attributes are defined:

.. glossary::

    VALUE
        The certificate (BER-encoded binary in X.509 format)

    SUBJECT
        The certificate subject (DER-encoded X.509 distinguished name)

    ISSUER
        The certificate issuer (DER-encoded X.509 distinguished name)

    SERIAL
        The certificate serial (DER-encoded integer)

Additionally an extended set of attributes may be imported if your HSM supports
it:

.. glossary::

    START_DATE
        The certificate start date (notBefore)

    END_DATE
        The certificate end date (notAfter)

    HASH_OF_SUBJECT_PUBLIC_KEY
        The identifier of the subject's public key (bytes)

    HASH_OF_ISSUER_PUBLIC_KEY
        The identifier of the issuer's public key (bytes)