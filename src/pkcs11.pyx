"""
High-level Python PKCS#11 Wrapper.

Ensure your library is loaded before import this module.
"""

from cython.view cimport array

from _pkcs11 cimport *


class PKCSError(Exception):
    pass


cdef _CK_UTF8CHAR_to_str(data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: the last couple of bytes are sometimes bogus, is this me
    # or SoftHSM?
    return data[:-1].decode('utf-8').rstrip()


cdef _CK_VERSION_to_tuple(data):
    """Convert CK_VERSION to tuple."""
    return (data['major'], data['minor'])


cdef class Info:
    """
    getInfo return type
    """
    cdef str manufacturerID
    cdef str libraryDescription
    cdef tuple cryptokiVersion
    cdef tuple libraryVersion

    def __init__(self,
                 manufacturerID=None,
                 libraryDescription=None,
                 cryptokiVersion=None,
                 libraryVersion=None,
                 **kwargs):
        self.manufacturerID = _CK_UTF8CHAR_to_str(manufacturerID)
        self.libraryDescription = _CK_UTF8CHAR_to_str(libraryDescription)
        self.cryptokiVersion = _CK_VERSION_to_tuple(cryptokiVersion)
        self.libraryVersion = _CK_VERSION_to_tuple(libraryVersion)

    def __str__(self):
        return '\n'.join((
            "Manufacturer ID: %s" % self.manufacturerID,
            "Library Description: %s" % self.libraryDescription,
            "Cryptoki Version: %s.%s" % self.cryptokiVersion,
            "Library Version: %s.%s" % self.libraryVersion,
        ))


cdef class SlotInfo:
    """
    getSlotInfo return type
    """

    cdef str slotDescription
    cdef str manufacturerID
    cdef tuple hardwareVersion
    cdef tuple firmwareVersion

    def __init__(self,
                 slotDescription=None,
                 manufacturerID=None,
                 hardwareVersion=None,
                 firmwareVersion=None,
                 **kwargs):
        self.slotDescription = _CK_UTF8CHAR_to_str(slotDescription)
        self.manufacturerID = _CK_UTF8CHAR_to_str(manufacturerID)
        self.hardwareVersion = _CK_VERSION_to_tuple(hardwareVersion)
        self.firmwareVersion = _CK_VERSION_to_tuple(firmwareVersion)

    def __str__(self):
        return '\n'.join((
            "Slot Description: %s" % self.slotDescription,
            "Manufacturer ID: %s" % self.manufacturerID,
            "Hardware Version: %s.%s" % self.hardwareVersion,
            "Firmware Version: %s.%s" % self.firmwareVersion,
        ))


cdef class lib:
    """
    Main entrypoint. Call methods on here.
    """

    def __cinit__(self):
        C_Initialize(NULL)

    def getInfo(self):
        """
        Returns info about our PKCS#11 library.
        """
        cdef CK_INFO info

        rv = C_GetInfo(&info)
        if rv != CK_RV.CKR_OK:
            raise PKCSError(rv)

        return Info(**info)

    def getSlots(self, tokenPresent=False):
        """
        Returns information about our configured slots.
        """

        cdef CK_ULONG count

        rv = C_GetSlotList(tokenPresent, NULL, &count)
        if rv != CK_RV.CKR_OK:
            raise PKCSError(rv)

        cdef CK_ULONG [:] slotIDs = array(shape=(count,),
                                          itemsize=sizeof(CK_ULONG),
                                          format='L')

        rv = C_GetSlotList(tokenPresent, &slotIDs[0], &count)
        if rv != CK_RV.CKR_OK:
            raise PKCSError(rv)

        cdef CK_SLOT_INFO info
        slots = []

        for slotID in slotIDs:
            rv = C_GetSlotInfo(slotID, &info)
            if rv != CK_RV.CKR_OK:
                raise PKCSError(rv)
            slots.append(SlotInfo(**info))

        return slots

    def __dealloc__(self):
        C_Finalize(NULL)


cdef class Session:

    pass
