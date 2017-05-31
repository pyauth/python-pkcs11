"""
Type wrangling utility functions.
"""

from _pkcs11_defn cimport *

from .constants import *
from .mechanisms import *


cdef CK_BYTE_buffer(length):
    """Make a buffer for `length` CK_BYTEs."""
    return array(shape=(length,), itemsize=sizeof(CK_BYTE), format='B')


cdef CK_ULONG_buffer(length):
    """Make a buffer for `length` CK_ULONGs."""
    return array(shape=(length,), itemsize=sizeof(CK_ULONG), format='L')


cdef CK_MECHANISM _make_CK_MECHANISM(key_type, default_map,
                                     mechanism=None, param=None) except *:
    """Build a CK_MECHANISM."""

    if mechanism is None:
        try:
            mechanism = default_map[key_type]
        except KeyError:
            raise ArgumentsBad("No default mechanism for this key type. "
                                "Please specify `mechanism`.")

    if not isinstance(mechanism, Mechanism):
        raise ArgumentsBad("`mechanism` must be a Mechanism.")

    cdef CK_MECHANISM mech
    mech.mechanism = mechanism.value

    if param is None:
        mech.pParameter = NULL
        mech.ulParameterLen = 0

    elif isinstance(param, bytes):
        mech.pParameter = <CK_CHAR *> param
        mech.ulParameterLen = len(param)

    else:
        raise ArgumentsBad("Unexpected argument to mechanism_param")

    return mech


cdef bytes _pack_attribute(key, value):
    """Pack a Attribute value into a bytes array."""

    try:
        pack, _ = ATTRIBUTE_TYPES[key]
        return pack(value)
    except KeyError:
        raise NotImplementedError("Can't pack this %s. "
                                  "Expand ATTRIBUTE_TYPES!" % key)


cdef _unpack_attributes(key, value):
    """Unpack a Attribute bytes array into a Python value."""

    try:
        _, unpack = ATTRIBUTE_TYPES[key]
        return unpack(bytes(value))
    except KeyError:
        raise NotImplementedError("Can't unpack this %s. "
                                  "Expand ATTRIBUTE_TYPES!" % key)
