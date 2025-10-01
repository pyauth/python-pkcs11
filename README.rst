.. image:: https://travis-ci.org/danni/python-pkcs11.svg?branch=master
    :target: https://travis-ci.org/danni/python-pkcs11

Python PKCS#11 - High Level Wrapper API
=======================================

A high level, "more Pythonic" interface to the PKCS#11 (Cryptoki) standard
to support HSM and Smartcard devices in Python.

The interface is designed to follow the logical structure of a HSM, with
useful defaults for obscurely documented parameters. Many APIs will optionally
accept iterables and act as generators, allowing you to stream large data
blocks for symmetric encryption.

python-pkcs11 also includes numerous utility functions to convert between PKCS
#11 data structures and common interchange formats including PKCS #1 and X.509.

python-pkcs11 is fully documented and has a full integration test suite for all
features.

Historically, this project used to run continuous integration tests against several
HSM platforms, but this test setup has not been maintained over time. Currently,
the integration tests in GitHub Actions use SoftHSMv2 as a baseline.
We also test against ``opencryptoki`` in CI. If you would like
to contribute some CI setup with additional PKCS#11 implementations or actual HSMs,
let's chat!

Source: https://github.com/pyauth/python-pkcs11

Documentation: http://python-pkcs11.readthedocs.io/en/latest/

Getting Started
---------------

Install from Pip:

::

    pip install python-pkcs11


Or build from source:

::

    python -m build .

Or using ``uv``:

::

   uv build

Assuming your PKCS#11 library is set as `PKCS11_MODULE` and contains a
token named `DEMO`:

AES
~~~

::

    import pkcs11

    # Initialise our PKCS#11 library
    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate an AES key in this session
        key = session.generate_key(pkcs11.KeyType.AES, 256)

        # Get an initialisation vector
        iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
        # Encrypt our data
        crypttext = key.encrypt(data, mechanism_param=iv)

3DES
~~~~

::

    import pkcs11

    # Initialise our PKCS#11 library
    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate a DES key in this session
        key = session.generate_key(pkcs11.KeyType.DES3)

        # Get an initialisation vector
        iv = session.generate_random(64)  # DES blocks are fixed at 64 bits
        # Encrypt our data
        crypttext = key.encrypt(data, mechanism_param=iv)

RSA
~~~

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate an RSA keypair in this session
        pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048)

        # Encrypt as one block
        crypttext = pub.encrypt(data)

DSA
~~~

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate an DSA keypair in this session
        pub, priv = session.generate_keypair(pkcs11.KeyType.DSA, 1024)

        # Sign
        signature = priv.sign(data)

ECDSA
~~~~~

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate an EC keypair in this session from a named curve
        ecparams = session.create_domain_parameters(
            pkcs11.KeyType.EC, {
                pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp256r1'),
            }, local=True)
        pub, priv = ecparams.generate_keypair()

        # Sign
        signature = priv.sign(data)

Diffie-Hellman
~~~~~~~~~~~~~~

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    with token.open() as session:
        # Given shared Diffie-Hellman parameters
        parameters = session.create_domain_parameters(pkcs11.KeyType.DH, {
            pkcs11.Attribute.PRIME: prime,  # Diffie-Hellman parameters
            pkcs11.Attribute.BASE: base,
        })

        # Generate a DH key pair from the public parameters
        public, private = parameters.generate_keypair()

        # Share the public half of it with our other party.
        _network_.write(public[Attribute.VALUE])
        # And get their shared value
        other_value = _network_.read()

        # Derive a shared session key with perfect forward secrecy
        session_key = private.derive_key(
            pkcs11.KeyType.AES, 128,
            mechanism_param=other_value)


Elliptic-Curve Diffie-Hellman
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    import pkcs11

    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    with token.open() as session:
        # Given DER encocded EC parameters, e.g. from
        #    openssl ecparam -outform der -name <named curve>
        parameters = session.create_domain_parameters(pkcs11.KeyType.EC, {
            pkcs11.Attribute.EC_PARAMS: ecparams,
        })

        # Generate a DH key pair from the public parameters
        public, private = parameters.generate_keypair()

        # Share the public half of it with our other party.
        _network_.write(public[pkcs11.Attribute.EC_POINT])
        # And get their shared value
        other_value = _network_.read()

        # Derive a shared session key
        session_key = private.derive_key(
            pkcs11.KeyType.AES, 128,
            mechanism_param=(pkcs11.KDF.NULL, None, other_value))

Raw Data Objects
~~~~~~~~~~~~~~~~~~

This can be useful for storing symmetric encryption keys and the like. Be sure to set the Attribute PRIVATE to True, otherwise the Objects will be readable even without Pin login.

import os, pkcs11

    lib = pkcs11.lib(os.environ["PKCS11_MODULE"])
    token = lib.get_token(token_label="DEMO")

    demoapp = "python-pkcs11 demo"
    demolabel = "testobject"
    demodata = "Hello World!".encode("ascii")

    with token.open(user_pin="1111") as session:

        #write data into an object
        session.create_object(
            attrs={
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.DATA,
                pkcs11.Attribute.APPLICATION: demoapp,
                pkcs11.Attribute.LABEL: demolabel,
                pkcs11.Attribute.VALUE: demodata,
                pkcs11.Attribute.TOKEN: True
            })

        #retrieve an object
        objectfilter = {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.DATA,
                pkcs11.Attribute.LABEL: demolabel
        }

        #objects are not uniquely identified by their attributes
        #the result might be a list of multiple objects with "demolabel"
        objects = list(session.get_objects(attrs=objectfilter))
        print(objects)

        #extract information from an object
        print(objects[-1][pkcs11.Attribute.VALUE])

        #change an object
        objects[-1][pkcs11.Attribute.VALUE] = "testdata".encode("ascii")
        print(objects[-1][pkcs11.Attribute.VALUE])


Tested Compatibility
--------------------

+------------------------------+--------------+-----------------+--------------+-------------------+
| Functionality                | SoftHSMv2    | Thales nCipher  | Opencryptoki | OpenSC (Nitrokey) |
+==============================+==============+=================+==============+===================+
| Get Slots/Tokens             | Works        | Works           | Works        | Works             |
+------------------------------+--------------+-----------------+--------------+-------------------+
| Get Mechanisms               | Works        | Works           | Works        | Works             |
+------------------------------+--------------+-----------------+--------------+-------------------+
| Initialize token             | Not implemented                                                   |
+------------------------------+-------------------------------------------------------------------+
| Slot events                  | Not implemented                                                   |
+------------------------------+-------------------------------------------------------------------+
| Alternative authentication   | Not implemented                                                   |
| path                         |                                                                   |
+------------------------------+-------------------------------------------------------------------+
| `Always authenticate` keys   | Not implemented                                                   |
+-------------+----------------+--------------+-----------------+--------------+-------------------+
| Create/Copy | Keys           | Works        | Works           | Errors       | Create            |
|             +----------------+--------------+-----------------+--------------+-------------------+
|             | Certificates   | Caveats [1]_ | Caveats [1]_    | Caveats [1]_ | ?                 |
|             +----------------+--------------+-----------------+--------------+-------------------+
|             | Domain Params  | Caveats [1]_ | Caveats [1]_    | ?            | N/A               |
+-------------+----------------+--------------+-----------------+--------------+-------------------+
| Destroy Object               | Works        | N/A             | Works        | Works             |
+------------------------------+--------------+-----------------+--------------+-------------------+
| Generate Random              | Works        | Works           | Works        | Works             |
+------------------------------+--------------+-----------------+--------------+-------------------+
| Seed Random                  | Works        | N/A             | N/A          | N/A               |
+------------------------------+--------------+-----------------+--------------+-------------------+
| Digest (Data & Keys)         | Works        | Caveats [2]_    | Works        | Works             |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| AES    | Generate key        | Works        | Works           | Works        | N/A               |
|        +---------------------+--------------+-----------------+--------------+                   |
|        | Encrypt/Decrypt     | Works        | Works           | Works        |                   |
|        +---------------------+--------------+-----------------+--------------+                   |
|        | Wrap/Unwrap         | ? [3]_       | Works           | Errors       |                   |
|        +---------------------+--------------+-----------------+--------------+                   |
|        | Sign/Verify         | Works        | Works [4]_      | N/A          |                   |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| DES2/  | Generate key        | Works        | Works           | Works        | N/A               |
| DES3   +---------------------+--------------+-----------------+--------------+                   |
|        | Encrypt/Decrypt     | Works        | Works           | Works        |                   |
|        +---------------------+--------------+-----------------+--------------+                   |
|        | Wrap/Unwrap         | ?            | ?               | ?            |                   |
|        +---------------------+--------------+-----------------+--------------+                   |
|        | Sign/Verify         | ?            | ?               | ?            |                   |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| RSA    | Generate key pair   | Works        | Works           | Works        | Works [4]_ [8]_   |
|        +---------------------+--------------+-----------------+--------------+-------------------+
|        | Encrypt/Decrypt     | Works        | Works           | Works        | Decrypt only [9]_ |
|        +---------------------+--------------+-----------------+--------------+-------------------+
|        | Wrap/Unwrap         | Works        | Works           | Works        | N/A               |
|        +---------------------+--------------+-----------------+--------------+-------------------+
|        | Sign/Verify         | Works        | Works           | Works        | Works             |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| DSA    | Generate parameters | Works        | Error           | N/A          | N/A               |
|        +---------------------+--------------+-----------------+              |                   |
|        | Generate key pair   | Works        | Caveats [5]_    |              |                   |
|        +---------------------+--------------+-----------------+              |                   |
|        | Sign/Verify         | Works        | Works [4]_      |              |                   |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| DH     | Generate parameters | Works        | N/A             | N/A          | N/A               |
|        +---------------------+--------------+-----------------+              |                   |
|        | Generate key pair   | Works        | Caveats [6]_    |              |                   |
|        +---------------------+--------------+-----------------+              |                   |
|        | Derive Key          | Works        | Caveats [7]_    |              |                   |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| EC     | Generate key pair   | Caveats [6]_ | ? [3]_          | N/A          | Works             |
|        +---------------------+--------------+-----------------+              +-------------------+
|        | Sign/Verify (ECDSA) | Works [4]_   | ? [3]_          |              | Sign only [9]_    |
|        +---------------------+--------------+-----------------+              +-------------------+
|        | Derive key (ECDH)   | Works        | ? [3]_          |              | ?                 |
+--------+---------------------+--------------+-----------------+--------------+-------------------+
| Proprietary extensions       | N/A          | Not implemented | N/A          | N/A               |
+------------------------------+--------------+-----------------+--------------+-------------------+

.. [1] Device supports limited set of attributes.
.. [2] Digesting keys is not supported.
.. [3] Untested: requires support in device.
.. [4] Default mechanism not supported, must specify a mechanism.
.. [5] From existing domain parameters.
.. [6] Local domain parameters only.
.. [7] Generates security warnings about the derived key.
.. [8] `store` parameter is ignored, all keys are stored.
.. [9] Encryption/verify not supported, extract the public key

Python version:

* >= 3.9

PKCS#11 versions:

* 2.11
* 2.20
* 2.40
* 3.1

Feel free to send pull requests for any functionality that's not exposed. The
code is designed to be readable and expose the PKCS #11 spec in a
straight-forward way.

If you want your device supported, get in touch!

More info on PKCS #11
---------------------

The latest version of the PKCS #11 spec is available from OASIS:

http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html

You should also consult the documentation for your PKCS #11 implementation.
Many implementations expose additional vendor options configurable in your
environment, including alternative features, modes and debugging
information.

License
-------

MIT License

Copyright (c) 2017 Danielle Madeley and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
