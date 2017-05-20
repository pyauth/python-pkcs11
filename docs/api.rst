API Reference
=============

.. toctree::
    :maxdepth: 2

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

    .. autoclass:: Slot()
        :members:
        :inherited-members:


    .. autoclass:: Token()
        :members:
        :inherited-members:

Mechanisms
----------

.. autoclass:: pkcs11.Mechanisms
    :members:
    :inherited-members:
    :undoc-members:


Exceptions
----------

.. automodule:: pkcs11.exceptions
    :members:
    :exclude-members: PKCS11Error
    :undoc-members:

    .. autoexception:: PKCS11Error
