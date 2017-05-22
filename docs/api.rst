API Reference
=============

.. toctree::
    :maxdepth: 2

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

            :param str token_label: Optional token label.
            :param bytes token_serial: Optional token serial.
            :param TokenFlag token_flags: Optional bitwise token flags.
            :param SlotFlag slot_flags: Optional bitwise slot flags.
            :param iterable(Mechanism) mechanisms: Optional required mechanisms.

            :rtype: iter(Token)

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

    The following classes relate to :class:`Object`s on the :class:`Token`:

    .. autoclass:: Object()
        :members:
        :inherited-members:

    .. autoclass:: SecretKey()
        :members:

    .. autoclass:: EncryptMixin()
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


Exceptions
----------

.. automodule:: pkcs11.exceptions
    :members:
    :undoc-members:
