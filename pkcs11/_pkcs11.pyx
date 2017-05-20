"""
High-level Python PKCS#11 Wrapper.

Ensure your library is loaded before import this module.
"""

from cython.view cimport array

from _pkcs11_defn cimport *
from . import types
from .exceptions import *
from .mechanisms import *


ERROR_MAP = {
    CKR_ARGUMENTS_BAD: ArgumentsBad,
    CKR_BUFFER_TOO_SMALL: MemoryError,
    CKR_CRYPTOKI_NOT_INITIALIZED: NotInitialized,
    CKR_DEVICE_ERROR: DeviceError,
    CKR_DEVICE_MEMORY: DeviceMemory,
    CKR_DEVICE_REMOVED: DeviceRemoved,
    CKR_FUNCTION_FAILED: FunctionFailed,
    CKR_GENERAL_ERROR: GeneralError,
    CKR_HOST_MEMORY: HostMemory,
    CKR_SLOT_ID_INVALID: SlotIDInvalid,
    CKR_TOKEN_NOT_PRESENT: TokenNotPresent,
    CKR_TOKEN_NOT_RECOGNIZED: TokenNotRecognised,
}


cdef str _CK_UTF8CHAR_to_str(bytes data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: any byte past 31 appears to be bogus, is this my fault
    # or SoftHSM?
    return data[:31].decode('utf-8').rstrip()


cdef tuple _CK_VERSION_to_tuple(CK_VERSION data):
    """Convert CK_VERSION to tuple."""
    return (data.major, data.minor)


def _CK_MECHANISM_TYPE_to_enum(mechanism):
    try:
        return Mechanisms(mechanism)
    except ValueError:
        return mechanism


cdef void assertRV(CK_RV rv):
    """Check for an acceptable RV value."""
    if rv != CK_RV.CKR_OK:
        raise ERROR_MAP.get(rv, PKCS11Error)()


class Slot(types.Slot):
    def __init__(self, lib, slotID, **kwargs):
        self._lib = lib
        self.slotID = slotID
        super().__init__(**kwargs)

    def get_token(self):
        cdef CK_TOKEN_INFO info

        assertRV(C_GetTokenInfo(self.slotID, &info))

        return Token(self, **info)

    def get_mechanisms(self):
        cdef CK_ULONG count

        assertRV(C_GetMechanismList(self.slotID, NULL, &count))

        cdef CK_MECHANISM_TYPE [:] mechanisms = \
            array(shape=(count,),
                  itemsize=sizeof(CK_MECHANISM_TYPE),
                  format='L')

        assertRV(C_GetMechanismList(self.slotID, &mechanisms[0], &count))

        return set(map(_CK_MECHANISM_TYPE_to_enum, mechanisms))


class Token(types.Token):
    pass


cdef class lib:

    cdef str manufacturerID
    cdef str libraryDescription
    cdef tuple cryptokiVersion
    cdef tuple libraryVersion

    def __cinit__(self):
        assertRV(C_Initialize(NULL))

    def __init__(self):
        cdef CK_INFO info

        assertRV(C_GetInfo(&info))

        self.manufacturerID = _CK_UTF8CHAR_to_str(info.manufacturerID)
        self.libraryDescription = _CK_UTF8CHAR_to_str(info.libraryDescription)
        self.cryptokiVersion = _CK_VERSION_to_tuple(info.cryptokiVersion)
        self.libraryVersion = _CK_VERSION_to_tuple(info.libraryVersion)

    def __str__(self):
        return '\n'.join((
            "Manufacturer ID: %s" % self.manufacturerID,
            "Library Description: %s" % self.libraryDescription,
            "Cryptoki Version: %s.%s" % self.cryptokiVersion,
            "Library Version: %s.%s" % self.libraryVersion,
        ))

    def get_slots(self, token_present=False):
        cdef CK_ULONG count

        assertRV(C_GetSlotList(token_present, NULL, &count))

        cdef CK_ULONG [:] slotIDs = array(shape=(count,),
                                          itemsize=sizeof(CK_ULONG),
                                          format='L')

        assertRV(C_GetSlotList(token_present, &slotIDs[0], &count))

        cdef CK_SLOT_INFO info
        slots = []

        for slotID in slotIDs:
            assertRV(C_GetSlotInfo(slotID, &info))
            slots.append(Slot(self, slotID, **info))

        return slots

    def __dealloc__(self):
        assertRV(C_Finalize(NULL))
