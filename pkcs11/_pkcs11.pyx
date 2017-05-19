"""
High-level Python PKCS#11 Wrapper.

Ensure your library is loaded before import this module.
"""

from cython.view cimport array

from _pkcs11_defn cimport *
from .types import *


cdef void assertRV(CK_RV rv):
    """Check for an acceptable RV value."""
    if rv != CK_RV.CKR_OK:
        raise PKCSError(rv)


cdef class lib:
    """
    Main entrypoint. Call methods on here.
    """

    def __cinit__(self):
        assertRV(C_Initialize(NULL))

    def getInfo(self):
        """
        Returns info about our PKCS#11 library.
        """
        cdef CK_INFO info

        assertRV(C_GetInfo(&info))

        return Info(**info)

    def getSlots(self, tokenPresent=False):
        """
        Returns information about our configured slots.
        """

        cdef CK_ULONG count

        assertRV(C_GetSlotList(tokenPresent, NULL, &count))

        cdef CK_ULONG [:] slotIDs = array(shape=(count,),
                                          itemsize=sizeof(CK_ULONG),
                                          format='L')

        assertRV(C_GetSlotList(tokenPresent, &slotIDs[0], &count))

        cdef CK_SLOT_INFO info
        slots = []

        for slotID in slotIDs:
            assertRV(C_GetSlotInfo(slotID, &info))
            slots.append(SlotInfo(**info))

        return slots

    def __dealloc__(self):
        assertRV(C_Finalize(NULL))


cdef class Session:

    pass
