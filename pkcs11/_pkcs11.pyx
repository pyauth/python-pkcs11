"""
High-level Python PKCS#11 Wrapper.

Ensure your library is loaded before import this module.
See pkcs11._loader.load() or pkcs11.lib().

Most class here inherit from pkcs11.types, which provides easier introspection
for Sphinx/Jedi/etc, as this module is not importable without having the
library loaded.
"""

from cython.view cimport array

from _pkcs11_defn cimport *
from . import types
from .exceptions import *
from .mechanisms import *
from .types import _CK_UTF8CHAR_to_str


# Map from return codes to Python exceptions.
ERROR_MAP = {
    CK_RV.CKR_ARGUMENTS_BAD: ArgumentsBad,
    CK_RV.CKR_BUFFER_TOO_SMALL: MemoryError,
    CK_RV.CKR_CRYPTOKI_NOT_INITIALIZED: NotInitialized,
    CK_RV.CKR_DEVICE_ERROR: DeviceError,
    CK_RV.CKR_DEVICE_MEMORY: DeviceMemory,
    CK_RV.CKR_DEVICE_REMOVED: DeviceRemoved,
    CK_RV.CKR_FUNCTION_FAILED: FunctionFailed,
    CK_RV.CKR_GENERAL_ERROR: GeneralError,
    CK_RV.CKR_HOST_MEMORY: HostMemory,
    CK_RV.CKR_SESSION_CLOSED: SessionClosed,
    CK_RV.CKR_SESSION_COUNT: SessionCount,
    CK_RV.CKR_SESSION_HANDLE_INVALID: SessionHandleInvalid,
    CK_RV.CKR_SESSION_PARALLEL_NOT_SUPPORTED: RuntimeError,
    CK_RV.CKR_SESSION_READ_WRITE_SO_EXISTS: SessionReadWriteSOExists,
    CK_RV.CKR_SLOT_ID_INVALID: SlotIDInvalid,
    CK_RV.CKR_TOKEN_NOT_PRESENT: TokenNotPresent,
    CK_RV.CKR_TOKEN_NOT_RECOGNIZED: TokenNotRecognised,
    CK_RV.CKR_TOKEN_WRITE_PROTECTED: TokenWriteProtected,
}


cdef tuple _CK_VERSION_to_tuple(CK_VERSION data):
    """Convert CK_VERSION to tuple."""
    return (data.major, data.minor)


def _CK_MECHANISM_TYPE_to_enum(mechanism):
    """Convert CK_MECHANISM_TYPE to enum or be okay."""
    try:
        return Mechanisms(mechanism)
    except ValueError:
        return mechanism


cpdef void assertRV(CK_RV rv):
    """Check for an acceptable RV value or thrown an exception."""
    if rv != CK_RV.CKR_OK:
        raise ERROR_MAP.get(rv, PKCS11Error)()


class Slot(types.Slot):
    """Extend Slot with implementation."""

    def get_token(self):
        cdef CK_TOKEN_INFO info

        assertRV(C_GetTokenInfo(self.slot_id, &info))

        return Token(self, **info)

    def get_mechanisms(self):
        cdef CK_ULONG count

        assertRV(C_GetMechanismList(self.slot_id, NULL, &count))

        cdef CK_MECHANISM_TYPE [:] mechanisms = \
            array(shape=(count,),
                  itemsize=sizeof(CK_MECHANISM_TYPE),
                  format='L')

        assertRV(C_GetMechanismList(self.slot_id, &mechanisms[0], &count))

        return set(map(_CK_MECHANISM_TYPE_to_enum, mechanisms))


class Token(types.Token):
    """Extend Token with implementation."""

    def open(self, rw=False, user_pin=None, so_pin=None):
        cdef CK_SESSION_HANDLE handle
        cdef CK_FLAGS flags = CKF_SERIAL_SESSION

        if rw:
            flags |= CKF_RW_SESSION

        assertRV(C_OpenSession(self.slot.slot_id, flags, NULL, NULL, &handle))

        return Session(self, handle)


class Session(types.Session):
    """Extend Session with implementation."""

    def close(self):
        assertRV(C_CloseSession(self._handle))


cdef class lib:
    """
    Main entry point.

    This class needs to be defined cdef, so it can't shadow a class in
    pkcs11.types.
    """

    cdef str so
    cdef str manufacturer_id
    cdef str library_description
    cdef tuple cryptoki_version
    cdef tuple library_version

    def __cinit__(self):
        assertRV(C_Initialize(NULL))

    def __init__(self, so):
        self.so = so

        cdef CK_INFO info

        assertRV(C_GetInfo(&info))

        self.manufacturer_id = _CK_UTF8CHAR_to_str(info.manufacturerID)
        self.library_description = _CK_UTF8CHAR_to_str(info.libraryDescription)
        self.cryptoki_version = _CK_VERSION_to_tuple(info.cryptokiVersion)
        self.library_version = _CK_VERSION_to_tuple(info.libraryVersion)

    def __str__(self):
        return '\n'.join((
            "Library: %s" % self.so,
            "Manufacturer ID: %s" % self.manufacturer_id,
            "Library Description: %s" % self.library_description,
            "Cryptoki Version: %s.%s" % self.cryptoki_version,
            "Library Version: %s.%s" % self.library_version,
        ))

    def __repr__(self):
        return '<pkcs11.lib ({so})>'.format(
            so=self.so)

    def get_slots(self, token_present=False):
        """Get all slots."""

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

    def get_tokens(self,
                   token_label=None,
                   token_serial=None,
                   token_flags=None,
                   slot_flags=None,
                   mechanisms=None):
        """Search for a token matching the parameters."""

        for slot in self.get_slots():
            token = slot.get_token()
            token_mechanisms = slot.get_mechanisms()

            try:
                if token_label is not None and \
                        token.label != token_label:
                    continue

                if token_serial is not None and \
                        token.serial != token_serial:
                    continue

                if token_flags is not None and \
                        not token.flags & token_flags:
                    continue

                if slot_flags is not None and \
                        not slot.flags & slot_flags:
                    continue

                if mechanisms is not None and \
                        set(mechanisms) not in token_mechanisms:
                    continue

                yield token
            except PKCS11Error:
                continue

    def __dealloc__(self):
        assertRV(C_Finalize(NULL))
