Python PKCS#11 - High Level Wrapper API
=======================================

A high level, "more Pythonic" interface to the PKCS#11 (Cryptoki) standard
to support HSM and Smartcard devices in Python.

The interface is designed to follow the logical structure of a HSM, with
useful defaults for obscurely documented parameters. Many APIs will optionally
accept iterables and act as generators, allowing you to stream large data
blocks in a straightforward way.

Source: https://github.com/danni/python-pkcs11

Documentation: http://python-pkcs11.readthedocs.io/en/latest/

Getting Started
---------------

Install from Pip:

::

    pip install python-pkcs11


Or build from source:

::

    python setup.py build

Assuming your PKCS#11 library is set as `PKCS_MODULE` and contains a
token named `DEMO`:

::

    import pkcs11

    # Initialise our PKCS#11 library
    lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
    token = lib.get_token(token_label='DEMO')

    data = b'INPUT DATA'

    # Open a session on our token
    with token.open(user_pin='1234') as session:
        # Generate an AES key in this session
        key = session.generate_key(pkcs11.KeyType.AES, 256, store=False)

        # Get an initialisation vector
        iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
        # Encrypt our data
        crypttext = key.encrypt(data, mechanism_param=iv)

Tested Compatibility
--------------------

Things that should almost certainly work.

PKCS#11 version:

* 2.4

Libraries:

* SoftHSMv2
* Thales nCipher (Security World)

Mechanisms:

* AES
* RSA

Operations:

* Encrypt
* Decrypt
* Generate Key
* Generate Keypair

Feel free to send pull requests for any functionality that's not exposed. The
code is designed to be readable and expose the PKCS#11 spec in a
straight-forward way.

More info on PKCS#11
--------------------

The latest version of the PKCS#11 spec is available from OASIS:

http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html

You should also consult the documentation for your PKCS#11 implementation.
Many implementations expose additional vendor options configurable in your
environment, including alternative features, modes and debugging
information.

License
-------

MIT License

Copyright (c) 2017 Danielle Madeley

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
