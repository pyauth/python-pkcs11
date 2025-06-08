"""
Type wrangling utility functions.
"""
from cython.view cimport array

from defaults import *
from ._pkcs11_defn cimport *


cdef inline CK_BYTE_buffer(length):
    """Make a buffer for `length` CK_BYTEs."""
    return array(shape=(length,), itemsize=sizeof(CK_BYTE), format='B')


cdef inline CK_ULONG_buffer(length):
    """Make a buffer for `length` CK_ULONGs."""
    return array(shape=(length,), itemsize=sizeof(CK_ULONG), format='L')


cdef inline bytes _pack_attribute(key, value):
    """Pack a Attribute value into a bytes array."""

    try:
        pack, _ = ATTRIBUTE_TYPES[key]
        return pack(value)
    except KeyError:
        raise NotImplementedError("Can't pack this %s. "
                                  "Expand ATTRIBUTE_TYPES!" % key)


cdef inline _unpack_attributes(key, value):
    """Unpack a Attribute bytes array into a Python value."""

    try:
        _, unpack = ATTRIBUTE_TYPES[key]
        return unpack(bytes(value))
    except KeyError:
        raise NotImplementedError("Can't unpack this %s. "
                                  "Expand ATTRIBUTE_TYPES!" % key)
