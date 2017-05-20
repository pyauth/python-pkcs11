"""
Definitions imported from PKCS11 C headers.
"""

cdef extern from '../extern/pkcs11.h':

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef char CK_CHAR
    ctypedef unsigned long int CK_ULONG;
    ctypedef CK_ULONG CK_FLAGS

    ctypedef CK_ULONG CK_SLOT_ID
    ctypedef CK_ULONG CK_MECHANISM_TYPE

    ctypedef enum CK_RV:
        CKR_ARGUMENTS_BAD,
        CKR_BUFFER_TOO_SMALL,
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_MEMORY,
        CKR_DEVICE_REMOVED,
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
        CKR_HOST_MEMORY,
        CKR_OK,
        CKR_SLOT_ID_INVALID,
        CKR_TOKEN_NOT_PRESENT,
        CKR_TOKEN_NOT_RECOGNIZED,

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
        CK_UTF8CHAR slotDescription[64];
        CK_UTF8CHAR manufacturerID[32];
        CK_FLAGS flags;

        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;

    ctypedef struct CK_TOKEN_INFO:
        CK_UTF8CHAR   label[32]
        CK_UTF8CHAR   manufacturerID[32]
        CK_UTF8CHAR   model[16]
        CK_CHAR       serialNumber[16]
        CK_FLAGS      flags

        CK_ULONG      ulMaxSessionCount
        CK_ULONG      ulSessionCount
        CK_ULONG      ulMaxRwSessionCount
        CK_ULONG      ulRwSessionCount
        CK_ULONG      ulMaxPinLen
        CK_ULONG      ulMinPinLen
        CK_ULONG      ulTotalPublicMemory
        CK_ULONG      ulFreePublicMemory
        CK_ULONG      ulTotalPrivateMemory
        CK_ULONG      ulFreePrivateMemory
        CK_VERSION    hardwareVersion
        CK_VERSION    firmwareVersion
        CK_CHAR       utcTime[16]


    CK_RV C_Initialize(void *)
    CK_RV C_Finalize(void *)
    CK_RV C_GetInfo(CK_INFO *info)
    CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                        CK_SLOT_ID *slotList,
                        CK_ULONG *count)

    CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                        CK_SLOT_INFO *info)
    CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
                         CK_TOKEN_INFO *info)
    CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                             CK_MECHANISM_TYPE *mechanismList,
                             CK_ULONG *count)
