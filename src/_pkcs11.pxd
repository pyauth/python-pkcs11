"""
Definitions imported from PKCS11 C headers.
"""

cdef extern from 'extern/pkcs11.h':

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef unsigned long int CK_ULONG;
    ctypedef CK_ULONG CK_FLAGS

    ctypedef CK_ULONG CK_SLOT_ID

    ctypedef enum CK_RV:
        CKR_OK,

    ctypedef struct CK_VERSION:
        CK_BYTE major
        CK_BYTE minor

    ctypedef struct CK_INFO:
        CK_VERSION cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags

        CK_UTF8CHAR libraryDescription[32]
        CK_VERSION libraryVersion;

    ctypedef struct CK_SLOT_INFO:
        CK_UTF8CHAR   slotDescription[64];
        CK_UTF8CHAR   manufacturerID[32];
        CK_FLAGS      flags;

        CK_VERSION    hardwareVersion;
        CK_VERSION    firmwareVersion;

    CK_RV C_Initialize(void *)
    CK_RV C_Finalize(void *)
    CK_RV C_GetInfo(CK_INFO *info)
    CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                        CK_SLOT_ID *slotList,
                        CK_ULONG *count)
    CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                        CK_SLOT_INFO *info)
