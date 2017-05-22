"""
High-level Python PKCS#11 Wrapper.

Ensure your library is loaded before import this module.
See pkcs11._loader.load() or pkcs11.lib().

Most class here inherit from pkcs11.types, which provides easier introspection
for Sphinx/Jedi/etc, as this module is not importable without having the
library loaded.
"""

from cython.view cimport array
from cpython.mem cimport PyMem_Malloc, PyMem_Free

from _pkcs11_defn cimport *
from . import types
from .exceptions import *
from .constants import *
from .mechanisms import *
from .types import _CK_UTF8CHAR_to_str


# Map from return codes to Python exceptions.
ERROR_MAP = {
    CKR_ARGUMENTS_BAD: ArgumentsBad,
    CKR_BUFFER_TOO_SMALL: MemoryError("Buffer was too small. Should never see this."),
    CKR_CRYPTOKI_NOT_INITIALIZED: RuntimeError("Initialisation error. Should never see this"),
    CKR_DEVICE_ERROR: DeviceError,
    CKR_DEVICE_MEMORY: DeviceMemory,
    CKR_DEVICE_REMOVED: DeviceRemoved,
    CKR_FUNCTION_CANCELED: FunctionCancelled,
    CKR_FUNCTION_FAILED: FunctionFailed,
    CKR_GENERAL_ERROR: GeneralError,
    CKR_HOST_MEMORY: HostMemory,
    CKR_OPERATION_NOT_INITIALIZED: OperationNotInitialized,
    CKR_PIN_INCORRECT: PinIncorrect,
    CKR_PIN_LOCKED: PinLocked,
    CKR_SESSION_CLOSED: SessionClosed,
    CKR_SESSION_COUNT: SessionCount,
    CKR_SESSION_HANDLE_INVALID: SessionHandleInvalid,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED: RuntimeError("Parallel not supported. Should never see this."),
    CKR_SESSION_READ_ONLY: SessionReadOnly,
    CKR_SESSION_READ_ONLY_EXISTS: SessionReadOnlyExists,
    CKR_SESSION_READ_WRITE_SO_EXISTS: SessionReadWriteSOExists,
    CKR_TEMPLATE_INCOMPLETE: TemplateIncomplete,
    CKR_TEMPLATE_INCONSISTENT: TemplateInconsistent,
    CKR_SLOT_ID_INVALID: SlotIDInvalid,
    CKR_TOKEN_NOT_PRESENT: TokenNotPresent,
    CKR_TOKEN_NOT_RECOGNIZED: TokenNotRecognised,
    CKR_TOKEN_WRITE_PROTECTED: TokenWriteProtected,
    CKR_USER_ALREADY_LOGGED_IN: UserAlreadyLoggedIn,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN: AnotherUserAlreadyLoggedIn,
    CKR_USER_PIN_NOT_INITIALIZED: UserPinNotInitialized,
    CKR_USER_TOO_MANY_TYPES: UserTooManyTypes,
    CKR_USER_TYPE_INVALID: RuntimeError("User type invalid. Should never see this."),
}


cdef tuple _CK_VERSION_to_tuple(CK_VERSION data):
    """Convert CK_VERSION to tuple."""
    return (data.major, data.minor)


def _CK_MECHANISM_TYPE_to_enum(mechanism):
    """Convert CK_MECHANISM_TYPE to enum or be okay."""
    try:
        return Mechanism(mechanism)
    except ValueError:
        return mechanism


cdef CK_MECHANISM _make_CK_MECHANISM(key_type,
                                     mechanism=None, param=b'') except *:
    """Build a CK_MECHANISM."""

    if mechanism is None:
        try:
            mechanism = DEFAULT_GENERATE_MECHANISMS[key_type]
        except KeyError:
            raise ArgumentsBad("No default mechanism for this key type. "
                                "Please specify `mechanism`.")

    if not isinstance(mechanism, Mechanism):
        raise ArgumentsBad("`mechanism` must be a Mechanism.")

    cdef CK_MECHANISM mech
    mech.mechanism = mechanism.value
    mech.pParameter = <CK_CHAR *> param
    mech.ulParameterLen = len(param)

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


cpdef void assertRV(CK_RV rv) except *:
    """Check for an acceptable RV value or thrown an exception."""
    if rv != CKR_OK:
        raise ERROR_MAP.get(rv,
                            PKCS11Error("Unmapped error code %s" % hex(rv)))


cdef class AttributeList:
    """
    A list of CK_ATTRIBUTE objects.
    """

    cdef dict attrs
    """Python representation of the data."""
    cdef CK_ATTRIBUTE *data
    """CK_ATTRIBUTE * representation of the data."""
    cdef size_t count
    """Length of `data`."""

    cdef _values

    def __cinit__(self, attrs):
        self.attrs = dict(attrs)
        self.count = count = len(attrs)

        self.data = <CK_ATTRIBUTE *> PyMem_Malloc(count * sizeof(CK_ATTRIBUTE))
        if not self.data:
            raise MemoryError()

        # Turn the values into bytes and store them so we have pointers
        # to them.
        self._values = [
            _pack_attribute(key, value)
            for key, value in self.attrs.items()
        ]

        for index, (key, value) in enumerate(zip(attrs.keys(), self._values)):
            self.data[index].type = key
            self.data[index].pValue = <CK_CHAR *> value
            self.data[index].ulValueLen = len(value)

    def __dealloc__(self):
        PyMem_Free(self.data)


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
        cdef CK_USER_TYPE user_type

        if rw:
            flags |= CKF_RW_SESSION

        if user_pin is not None and so_pin is not None:
            raise ArgumentsBad("Set either `user_pin` or `so_pin`")
        elif user_pin is not None:
            pin = user_pin.encode('utf-8')
            user_type = CKU_USER
        elif so_pin is not None:
            pin = so_pin.encode('utf-8')
            user_type = CKU_SO
        else:
            pin = None
            user_type = UserType.NOBODY

        assertRV(C_OpenSession(self.slot.slot_id, flags, NULL, NULL, &handle))

        if pin is not None:
            assertRV(C_Login(handle, user_type, pin, len(pin)))

        return Session(self, handle, rw=rw, user_type=user_type)


class Session(types.Session):
    """Extend Session with implementation."""

    def close(self):
        if self.user_type is not UserType.NOBODY:
            assertRV(C_Logout(self._handle))

        assertRV(C_CloseSession(self._handle))

    def generate_key(self, key_type, key_length,
                     id=None, label=None,
                     store=True, capabilities=None,
                     mechanism=None, mechanism_params=b'',
                     template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        cdef CK_MECHANISM mech = \
            _make_CK_MECHANISM(key_type, mechanism, mechanism_params)
        cdef CK_OBJECT_HANDLE key

        # Build attributes
        template_ = {
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            Attribute.VALUE_LEN: key_length // 8,
        }
        template_.update(template or {})
        attrs = AttributeList(template_)

        assertRV(C_GenerateKey(self._handle,
                               &mech,
                               attrs.data, attrs.count,
                               &key))

        return Object(self, key)


class Object(types.Object):
    """Expand Object with an implementation."""

    def __getitem__(self, key):
        cdef CK_ATTRIBUTE template
        template.type = key
        template.pValue = NULL

        # Find out the attribute size
        assertRV(C_GetAttributeValue(self.session._handle, self._handle,
                                     &template, 1))

        if template.ulValueLen == 0:
            return _unpack_attributes(key, b'')

        # Put a buffer of the right length in place
        cdef CK_CHAR [:] value = array(shape=(template.ulValueLen,),
                                       itemsize=sizeof(CK_CHAR),
                                       format='B')
        template.pValue = <CK_CHAR *> &value[0]

        # Request the value
        assertRV(C_GetAttributeValue(self.session._handle, self._handle,
                                     &template, 1))

        return _unpack_attributes(key, value)

    def __setitem__(self, key, value):
        value = _pack_attribute(key, value)

        cdef CK_ATTRIBUTE template
        template.type = key
        template.pValue = <CK_CHAR *> value
        template.ulValueLen = len(value)

        assertRV(C_SetAttributeValue(self.session._handle, self._handle,
                                     &template, 1))



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
