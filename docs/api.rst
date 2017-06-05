API Reference
=============

.. contents:: Section Contents
    :depth: 2
    :local:

Classes
-------

.. automodule:: pkcs11
    :members:
    :exclude-members: lib

    .. class:: lib(so)

        Initialises the PKCS#11 library.

        Only one PKCS#11 library can be initialised.

        :param str so: Path to the PKCS#11 library to initialise.
        
        .. method:: get_slots(token_present=False)

            Returns a list of PKCS#11 device slots known to this library.

            :param token_present: If true, will limit the results to
                slots with a token present.

            :rtype: list(Slot)

        .. method:: get_tokens(token_label=None, token_serial=None, token_flags=None, slot_flags=None, mechanisms=None)

            Generator yielding PKCS#11 tokens matching the provided parameters.

            See also :meth:`get_token`.

            :param str token_label: Optional token label.
            :param bytes token_serial: Optional token serial.
            :param TokenFlag token_flags: Optional bitwise token flags.
            :param SlotFlag slot_flags: Optional bitwise slot flags.
            :param iter(Mechanism) mechanisms: Optional required mechanisms.

            :rtype: iter(Token)

        .. method:: get_token(token_label=None, token_serial=None, token_flags=None, slot_flags=None, mechanisms=None)

            Returns a single token or raises either
            :class:`pkcs11.exceptions.NoSuchToken` or
            :class:`pkcs11.exceptions.MultipleTokensReturned`.

            See also :meth:`get_tokens`.

            :param str token_label: Optional token label.
            :param bytes token_serial: Optional token serial.
            :param TokenFlag token_flags: Optional bitwise token flags.
            :param SlotFlag slot_flags: Optional bitwise slot flags.
            :param iter(Mechanism) mechanisms: Optional required mechanisms.

            :rtype: Token

        .. attribute:: cryptoki_version

            PKCS#11 Cryptoki standard version (:class:`tuple`).

        .. attribute:: manufacturer_id

            Library vendor's name (:class:`str`).

        .. attribute:: library_description

            Description of the vendor's library (:class:`str`).

        .. attribute:: library_version

            Vendor's library version (:class:`tuple`).


    .. autoclass:: Slot()
        :members:
        :inherited-members:


    .. autoclass:: Token()
        :members:
        :inherited-members:

    .. autoclass:: Session()
        :members:
        :inherited-members:


    Token Objects
    ~~~~~~~~~~~~~

    The following classes relate to :class:`Object` objects on the
    :class:`Token`.

    .. autoclass:: Object()
        :members:
        :inherited-members:

    .. autoclass:: Key(Object)
        :members:

    .. autoclass:: SecretKey(Key)
        :members:

    .. autoclass:: PublicKey(Key)
        :members:

    .. autoclass:: PrivateKey(Key)
        :members:

    .. autoclass:: DomainParameters(Object)
        :members:

    .. autoclass:: Certificate(Object)
        :members:

    Object Capabilities
    ~~~~~~~~~~~~~~~~~~~

    Capability mixins for :class:`Object` objects.

    .. autoclass:: EncryptMixin()
        :members:

    .. autoclass:: DecryptMixin()
        :members:

    .. autoclass:: SignMixin()
        :members:

    .. autoclass:: VerifyMixin()
        :members:

    .. autoclass:: WrapMixin()
        :members:

    .. autoclass:: UnwrapMixin()
        :members:

    .. autoclass:: DeriveMixin()
        :members:


Constants
---------

.. automodule:: pkcs11.constants
    :members:
    :inherited-members:
    :undoc-members:


Key Types & Mechanisms
----------------------

.. automodule:: pkcs11.mechanisms
    :members:
    :inherited-members:
    :undoc-members:

.. autoclass:: pkcs11.MechanismInfo()
    :members:
    :inherited-members:


Exceptions
----------

.. automodule:: pkcs11.exceptions
    :members:
    :undoc-members:


Utilities
---------

General Utilities
~~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util
    :members:
    :undoc-members:

RSA Key Utilities
~~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util.rsa
    :members:
    :undoc-members:

DSA Key Utilities
~~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util.dsa
    :members:
    :undoc-members:

DH Key Utilities
~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util.dh
    :members:
    :undoc-members:

EC Key Utilities
~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util.ec
    :members:
    :undoc-members:

X.509 Certificate Utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: pkcs11.util.x509
    :members:
    :undoc-members:
