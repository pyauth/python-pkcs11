#cython: language_level=3
#coverage#cython: linetrace=True
"""
High-level Python PKCS#11 Wrapper.

Most class here inherit from pkcs11.types, which provides easier introspection
for Sphinx/Jedi/etc, as this module is not importable without having the
library loaded.
"""

from __future__ import (absolute_import, unicode_literals,
                        print_function, division)

from threading import RLock

from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.string cimport memcpy

from pkcs11 import types
from pkcs11.attributes import AttributeMapper
from pkcs11.defaults import *
from pkcs11.exceptions import *
from pkcs11.constants import *
from pkcs11.mechanisms import *
from pkcs11.types import (
    _CK_UTF8CHAR_to_str,
    _CK_VERSION_to_tuple,
    _CK_MECHANISM_TYPE_to_enum,
    PROTECTED_AUTH,
)


cdef class lib(HasFuncList)

cdef class HasFuncList:
    cdef CK_FUNCTION_LIST *funclist

    def __cinit__(self, *args, **kwargs):
        self.funclist = NULL


cdef assertRV(rv) with gil:
    """Check for an acceptable RV value or thrown an exception."""
    if rv == CKR_OK:
        return
    raise map_rv_to_error(rv)


cdef class AttributeList:
    """
    A list of CK_ATTRIBUTE objects.
    """

    cdef CK_ATTRIBUTE *data
    """CK_ATTRIBUTE * representation of the data."""
    cdef CK_ULONG count
    """Length of `data`."""

    def __cinit__(self, attrs):
        self.data = NULL
        self.count = 0

    @staticmethod
    cdef AttributeList from_owned_pointer(CK_ATTRIBUTE * data, CK_ULONG count):
        cdef AttributeList lst = AttributeList.__new__(AttributeList, ())
        lst.data = data
        lst.count = count
        return lst

    @staticmethod
    cdef AttributeList from_template(dict template, object attribute_mapper):
        cdef AttributeList lst = AttributeList.__new__(AttributeList, ())

        lst.count = count = <CK_ULONG> len(template)

        lst.data = <CK_ATTRIBUTE *> PyMem_Malloc(count * sizeof(CK_ATTRIBUTE))
        if lst.data is NULL:
            raise MemoryError()

        cdef bytes value_bytes
        cdef CK_CHAR * value_ptr
        cdef Py_ssize_t value_len
        for index, (key, value) in enumerate(template.items()):
            lst.data[index].type = key
            value_bytes = attribute_mapper.pack_attribute(key, value)
            value_len = len(value_bytes)
            # copy the result into a pointer that we manage, for consistency with the other init method
            value_ptr = <CK_CHAR *> PyMem_Malloc(value_len)
            if value_ptr is NULL:
                raise MemoryError()
            memcpy(value_ptr, <CK_CHAR *> value_bytes, <size_t> value_len)
            lst.data[index].pValue = <CK_CHAR *> value_ptr
            lst.data[index].ulValueLen = <CK_ULONG> value_len

        return lst

    def __init__(self, attrs):
        raise TypeError

    cdef at_index(self, CK_ULONG index, object attribute_mapper):
        cdef CK_ATTRIBUTE * attr
        if index < self.count:
            attr = &self.data[index]
            return attribute_mapper.unpack_attributes(
                attr.type,
                PyBytes_FromStringAndSize(<char *> attr.pValue, <Py_ssize_t> attr.ulValueLen)
            )
        else:
            raise IndexError()

    def as_dict(self, attribute_mapper):
        cdef CK_ATTRIBUTE * attr
        result = {}
        for index in range(self.count):
            attr = &self.data[index]
            result[attr.type] = self.at_index(index, attribute_mapper)
        return result

    def get(self, item, attribute_mapper):
        cdef CK_ULONG index = 0
        cdef CK_ATTRIBUTE_TYPE key = item
        for index in range(self.count):
            if self.data[index].type == key:
                return self.at_index(index, attribute_mapper)
        raise KeyError(item)

    def __dealloc__(self):
        cdef CK_ULONG index = 0
        if self.data is not NULL:
            for index in range(self.count):
                PyMem_Free(self.data[index].pValue)
            PyMem_Free(self.data)


cdef class MechanismWithParam:
    """
    Python wrapper for a Mechanism with its parameter
    """

    cdef CK_MECHANISM *data
    """The mechanism."""
    cdef void *param
    """Reference to a pointer we might need to free."""
    cdef object _python_param
    """
    Hold a reference to the original parameter object so it doesn't get
    GC'd before this one.
    """

    def __cinit__(self, *args):
        self.data = <CK_MECHANISM *> PyMem_Malloc(sizeof(CK_MECHANISM))
        self.param = NULL
        self._python_param = None

    def __init__(self, key_type, mapping, mechanism=None, param=None):
        self._python_param = param
        if mechanism is None:
            try:
                mechanism = mapping[key_type]
            except KeyError:
                raise ArgumentsBad("No default mechanism for this key type. "
                                    "Please specify `mechanism`.")

        if not isinstance(mechanism, Mechanism):
            raise ArgumentsBad("`mechanism` must be a Mechanism.")
        # Possible types of parameters we might need to allocate
        # These are used to make assigning to the object we malloc() easier
        # FIXME: is there a better way to do this?
        cdef CK_RSA_PKCS_OAEP_PARAMS *oaep_params
        cdef CK_RSA_PKCS_PSS_PARAMS *pss_params
        cdef CK_EDDSA_PARAMS *eddsa_params
        cdef CK_ECDH1_DERIVE_PARAMS *ecdh1_params
        cdef CK_KEY_DERIVATION_STRING_DATA *aes_ecb_params
        cdef CK_AES_CBC_ENCRYPT_DATA_PARAMS *aes_cbc_params
        cdef CK_GCM_PARAMS *gcm_params
        cdef CK_AES_CTR_PARAMS *aes_ctr_params

        # Unpack mechanism parameters

        if mechanism == Mechanism.AES_ECB_ENCRYPT_DATA:
            paramlen = sizeof(CK_KEY_DERIVATION_STRING_DATA)
            self.param = aes_ecb_params = \
                <CK_KEY_DERIVATION_STRING_DATA *> PyMem_Malloc(paramlen)
            aes_ecb_params.pData = <CK_BYTE *> param
            aes_ecb_params.ulLen = <CK_ULONG> len(param)

        elif isinstance(param, bytes):
            # Note: this is an escape hatch of sorts that can be used to provide parameters for
            #  unsupported algorithms in raw binary form.
            # We include it at this point in the chain for forwards compatibility reasons:
            #  if at a later point, "first class" support for the unsupported mechanism is added
            #  to the library, existing code that used this "raw mode" workaround will keep working
            #  because this branch takes priority.
            #
            # The parameter convention for AES_ECB_ENCRYPT_DATA predates this ordering decision,
            #  so it takes precedence over this branch for backwards compatibility.
            self.data.pParameter = <CK_BYTE *> param
            paramlen =  len(param)

        elif mechanism == Mechanism.RSA_PKCS_OAEP:
            paramlen = sizeof(CK_RSA_PKCS_OAEP_PARAMS)
            self.param = oaep_params = \
                <CK_RSA_PKCS_OAEP_PARAMS *> PyMem_Malloc(paramlen)

            oaep_params.source = CKZ_DATA_SPECIFIED

            if param is None:
                param = DEFAULT_MECHANISM_PARAMS[mechanism]

            (oaep_params.hashAlg, oaep_params.mgf, source_data) = param

            if source_data is None:
                oaep_params.pSourceData = NULL
                oaep_params.ulSourceDataLen = <CK_ULONG> 0
            else:
                oaep_params.pSourceData = <CK_BYTE *> source_data
                oaep_params.ulSourceDataLen = <CK_ULONG> len(source_data)

        elif mechanism in (Mechanism.RSA_PKCS_PSS,
                           Mechanism.SHA1_RSA_PKCS_PSS,
                           Mechanism.SHA224_RSA_PKCS_PSS,
                           Mechanism.SHA256_RSA_PKCS_PSS,
                           Mechanism.SHA384_RSA_PKCS_PSS,
                           Mechanism.SHA512_RSA_PKCS_PSS):
            paramlen = sizeof(CK_RSA_PKCS_PSS_PARAMS)
            self.param = pss_params = \
                <CK_RSA_PKCS_PSS_PARAMS *> PyMem_Malloc(paramlen)

            if param is None:
                # All PSS mechanisms have the same defaults
                param = DEFAULT_MECHANISM_PARAMS[Mechanism.RSA_PKCS_PSS]

            (pss_params.hashAlg, pss_params.mgf, pss_params.sLen) = param

        elif mechanism == Mechanism.EDDSA and param is not None:
            paramlen = sizeof(CK_EDDSA_PARAMS)
            self.param = eddsa_params = \
                <CK_EDDSA_PARAMS *> PyMem_Malloc(paramlen)
            (eddsa_params.phFlag, context_data) = param
            if context_data is None:
                eddsa_params.pContextData = NULL
                eddsa_params.ulContextDataLen = 0
            else:
                eddsa_params.pContextData = context_data
                eddsa_params.ulContextDataLen = <CK_ULONG> len(context_data)

        elif mechanism in (
                Mechanism.ECDH1_DERIVE,
                Mechanism.ECDH1_COFACTOR_DERIVE):
            paramlen = sizeof(CK_ECDH1_DERIVE_PARAMS)
            self.param = ecdh1_params = \
                <CK_ECDH1_DERIVE_PARAMS *> PyMem_Malloc(paramlen)

            (ecdh1_params.kdf, shared_data, public_data) = param

            if shared_data is None:
                ecdh1_params.pSharedData = NULL
                ecdh1_params.ulSharedDataLen = 0
            else:
                ecdh1_params.pSharedData = shared_data
                ecdh1_params.ulSharedDataLen = <CK_ULONG> len(shared_data)

            ecdh1_params.pPublicData = public_data
            ecdh1_params.ulPublicDataLen = <CK_ULONG> len(public_data)

        elif mechanism == Mechanism.AES_CBC_ENCRYPT_DATA:
            paramlen = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)
            self.param = aes_cbc_params = \
                    <CK_AES_CBC_ENCRYPT_DATA_PARAMS *> PyMem_Malloc(paramlen)
            (iv, data) = param
            aes_cbc_params.iv = iv[:16]
            aes_cbc_params.pData = <CK_BYTE *> data
            aes_cbc_params.length = <CK_ULONG> len(data)

        elif mechanism == Mechanism.AES_GCM:
            paramlen = sizeof(CK_GCM_PARAMS)
            if not isinstance(param, GCMParams):
                raise TypeError
            self.param = gcm_params = <CK_GCM_PARAMS *> PyMem_Malloc(paramlen)
            gcm_params.pIv = <CK_BYTE *> param.nonce
            gcm_params.ulIvLen = <CK_ULONG> len(param.nonce)
            gcm_params.ulIvBits = <CK_ULONG> len(param.nonce) * 8
            if param.aad is not None:
                gcm_params.pAAD = <CK_BYTE *> param.aad
                gcm_params.ulAADLen = <CK_ULONG> len(param.aad)
            else:
                gcm_params.pAAD = NULL
                gcm_params.ulAADLen = 0
            gcm_params.ulTagBits = <CK_ULONG> param.tag_bits

        elif mechanism == Mechanism.AES_CTR:
            paramlen = sizeof(CK_AES_CTR_PARAMS)
            self.param = aes_ctr_params = <CK_AES_CTR_PARAMS *> PyMem_Malloc(paramlen)
            # use a wrapper type to not break the forwards compat rule for params specified as `bytes`
            if not isinstance(param, CTRParams):
                raise TypeError
            aes_ctr_params.ulCounterBits = (16 - len(param.nonce)) * 8
            aes_ctr_params.cb = param.nonce + b"\x00" * (15 - len(param.nonce)) + b"\x01"

        elif param is None:
            self.data.pParameter = NULL
            paramlen = 0

        else:
            raise ArgumentsBad("Unexpected argument to mechanism_param")

        self.data.mechanism = mechanism
        self.data.ulParameterLen = <CK_ULONG> paramlen

        if self.param != NULL:
            self.data.pParameter = self.param

    def __dealloc__(self):
        PyMem_Free(self.data)
        PyMem_Free(self.param)


cdef class Slot(HasFuncList, types.Slot):
    """Extend Slot with implementation."""

    cdef readonly CK_SLOT_ID slot_id
    cdef readonly str slot_description
    cdef readonly str manufacturer_id
    cdef CK_FLAGS slot_flags
    cdef CK_VERSION _hw_version
    cdef CK_VERSION _fw_version
    cdef CK_VERSION _cryptoki_version

    @staticmethod
    cdef Slot make(CK_FUNCTION_LIST *funclist, CK_SLOT_ID slot_id, CK_SLOT_INFO info, CK_VERSION cryptoki_version):
        description = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Slot slot = Slot.__new__(Slot)
        slot.funclist = funclist

        slot.slot_id = slot_id
        slot.slot_description = _CK_UTF8CHAR_to_str(description)
        slot.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        slot._hw_version = info.hardwareVersion
        slot._fw_version = info.firmwareVersion
        slot._cryptoki_version = cryptoki_version
        slot.slot_flags = info.flags
        return slot

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this slot (:class:`SlotFlag`)."""
        return SlotFlag(self.slot_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._fw_version)

    @property
    def cryptoki_version(self):
        """PKCS#11 (cryptoki) API version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._cryptoki_version)

    def get_token(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_TOKEN_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetTokenInfo(slot_id, &info)
        assertRV(retval)

        return Token.make(self, info)

    def get_mechanisms(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, NULL, &count)
        assertRV(retval)

        if count == 0:
            return set()

        cdef CK_MECHANISM_TYPE [:] mechanisms = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, &mechanisms[0], &count)
        assertRV(retval)

        return set(map(_CK_MECHANISM_TYPE_to_enum, mechanisms))

    def get_mechanism_info(self, mechanism):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_MECHANISM_TYPE mech_type = mechanism
        cdef CK_MECHANISM_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismInfo(slot_id, mech_type, &info)
        assertRV(retval)

        return types.MechanismInfo(self, mechanism, **info)

    def _identity(self):
        return Slot.__name__, self.slot_id

    def __str__(self):
        return "\n".join(
            (
                "Slot Description: %s" % self.slot_description,
                "Manufacturer ID: %s" % self.manufacturer_id,
                "Hardware Version: %s.%s" % self.hardware_version,
                "Firmware Version: %s.%s" % self.firmware_version,
                "Flags: %s" % self.flags,
            )
        )

    def __repr__(self):
        return "<{klass} (slotID={slot_id} flags={flags})>".format(
            klass=type(self).__name__, slot_id=self.slot_id, flags=str(self.flags)
        )


cdef class Token(HasFuncList, types.Token):
    """Extend Token with implementation."""

    cdef readonly Slot slot
    cdef readonly str label
    cdef readonly bytes serial
    cdef readonly str manufacturer_id
    cdef readonly str model
    cdef CK_FLAGS token_flags
    cdef CK_VERSION _hw_version
    cdef CK_VERSION _fw_version

    @staticmethod
    cdef Token make(Slot slot, CK_TOKEN_INFO info):
        label = info.label[:sizeof(info.label)]
        serial_number = info.serialNumber[:sizeof(info.serialNumber)]
        model = info.model[:sizeof(info.model)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Token token = Token.__new__(Token)
        token.funclist = slot.funclist
        token.slot = slot
        token.label = _CK_UTF8CHAR_to_str(label)
        token.serial = serial_number.rstrip()
        token.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        token.model = _CK_UTF8CHAR_to_str(model)
        token._hw_version = info.hardwareVersion
        token._fw_version = info.firmwareVersion
        token.token_flags = info.flags
        return token

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this token (:class:`TokenFlag`)."""
        return TokenFlag(self.token_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._fw_version)

    def open(
            self,
            rw=False,
            user_pin=None,
            so_pin=None,
            user_type=None,
            attribute_mapper=None,
            cancel_strategy=CancelStrategy.DEFAULT
    ):
        cdef CK_SLOT_ID slot_id = self.slot.slot_id
        cdef CK_SESSION_HANDLE handle
        cdef CK_FLAGS flags = CKF_SERIAL_SESSION
        cdef CK_USER_TYPE final_user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval
        cdef CK_USER_TYPE c_user_type

        if rw:
            flags |= CKF_RW_SESSION

        if user_pin is not None and so_pin is not None:
            raise ArgumentsBad("Set either `user_pin` or `so_pin`")
        elif user_pin is PROTECTED_AUTH:
            pin = None
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is PROTECTED_AUTH:
            pin = None
            c_user_type = CKU_SO
        elif user_pin is not None:
            pin = user_pin.encode('utf-8')
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is not None:
            pin = so_pin.encode('utf-8')
            c_user_type = CKU_SO
        else:
            pin = None
            c_user_type = CKU_USER_NOBODY

        with nogil:
            retval = self.funclist.C_OpenSession(slot_id, flags, NULL, NULL, &handle)
        assertRV(retval)

        if so_pin is PROTECTED_AUTH or user_pin is PROTECTED_AUTH:
            if self.flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH:
                with nogil:
                    retval = self.funclist.C_Login(handle, c_user_type, NULL, 0)
                assertRV(retval)
            else:
                raise ArgumentsBad("Protected authentication is not supported by loaded module")
        elif pin is not None:
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)

            with nogil:
                retval = self.funclist.C_Login(handle, c_user_type, pin_data, pin_length)
            assertRV(retval)

        return Session.make(
            self, handle,
            rw=<bint> rw,
            user_type=c_user_type,
            mapper=attribute_mapper or AttributeMapper(),
            cancel_strategy=<unsigned int> cancel_strategy
        )

    def __str__(self):
        return self.label

    def _identity(self):
        return Token.__name__, self.slot

    def __repr__(self):
        return "<{klass} (label='{label}' serial={serial} flags={flags})>".format(
            klass=type(self).__name__, label=self.label, serial=self.serial, flags=str(self.flags)
        )


cdef class OperationContext:
    cdef Session session
    cdef bint active

    def __cinit__(self, session, *args, **kwargs):
        self.session = session
        self.active = False

    def __init__(self, session):
        pass

    def __enter__(self):
        self.session.operation_lock.acquire()
        self.active = True
        self._initiate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._finalize(silent=False)

    cdef _handle_final_retval(self, CK_RV retval) with gil:
        self.active = False
        self.session.operation_lock.release()
        assertRV(retval)

    cdef _operation_aware_assert(self, CK_RV retval) with gil:
        if retval != CKR_BUFFER_TOO_SMALL and retval != CKR_OK:
            # This is an error that terminated the operation
            # We flag the operation as completed on our end as well.
            # This is useful to track because there's no way to cleanly cancel
            # cryptographic operations in PCKS#11 2.x.
            self._handle_final_retval(retval)

    def _initiate(self):
        raise NotImplementedError

    def _finalize(self, silent=False):
        if self.active:
            self.active = False
            self.session.operation_lock.release()

    def __del__(self):
        self._finalize()


cdef class OperationWithBinaryOutput(OperationContext):

    cdef MechanismWithParam mech

    cdef CK_ULONG buffer_size
    cdef CK_ULONG buffer_data_length
    cdef CK_BYTE [:] output_buf

    @staticmethod
    cdef OperationWithBinaryOutput _setup(
            type cls,
            Session session,
            MechanismWithParam mech,
            CK_ULONG buffer_size
    ) with gil:
        cdef OperationWithBinaryOutput op = cls.__new__(cls, session)
        op.mech = mech
        if buffer_size > 0:
            op.output_buf = CK_BYTE_buffer(buffer_size)
        op.buffer_size = buffer_size
        return op

    cdef resize_buffer(self, CK_ULONG length):
        self.output_buf = CK_BYTE_buffer(length)
        self.buffer_size = length

    cdef inline bytes current_output(self):
        return bytes(self.output_buf[:self.buffer_data_length])

    cdef CK_RV update_resizing_output(
            self,
            OperationUpdateWithResult op_update,
            CK_BYTE *data,
            CK_ULONG data_len,
    ) with gil:

        cdef CK_ULONG length = self.buffer_size
        cdef CK_BYTE *output_buf_loc = &self.output_buf[0]
        cdef CK_RV retval

        with nogil:
            retval = op_update(
                self.session.handle, data, data_len, NULL, &length
            )

        if retval != CKR_OK:
            return retval

        if length > self.buffer_size:
            self.resize_buffer(length)
            output_buf_loc = &self.output_buf[0]

        with nogil:
            retval = op_update(
                self.session.handle, data, data_len, output_buf_loc, &length
            )
        self.buffer_data_length = length
        return retval

    cdef CK_RV execute_resizing_output(self, OperationWithResult op) with gil:

        cdef CK_ULONG length = self.buffer_size
        cdef CK_BYTE *output_buf_loc = &self.output_buf[0]
        cdef CK_RV retval

        with nogil:
            retval = op(self.session.handle, NULL, &length)

        if retval != CKR_OK:
            return retval

        if length > self.buffer_size:
            self.resize_buffer(length)
            output_buf_loc = &self.output_buf[0]


        with nogil:
            retval = op(self.session.handle, output_buf_loc, &length)
        self.buffer_data_length = length
        return retval

    cdef bytes process_fully(
            self,
            OperationUpdateWithResult op,
            CK_BYTE *data,
            CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval = self.update_resizing_output(op, data, data_len)
        self._handle_final_retval(retval)
        return self.current_output()

    cdef bytes update_with_result(
            self, OperationUpdateWithResult op, CK_BYTE *data, CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval = self.update_resizing_output(op, data, data_len)
        self._operation_aware_assert(retval)
        return self.current_output()

    cdef update_no_output(
            self, OperationUpdate op, CK_BYTE *data, CK_ULONG data_len
    ) with gil:
        cdef CK_RV retval
        with nogil:
            retval = op(self.session.handle, data, data_len)
        self._operation_aware_assert(retval)

    cdef bytes finish_with_output(self, OperationWithResult op_final) with gil:
        cdef CK_RV retval = self.execute_resizing_output(op_final)
        self._handle_final_retval(retval)
        return self.current_output()


cdef class SearchIter(OperationContext):
    """Iterate a search for objects on a session."""

    cdef AttributeList template
    cdef CK_ULONG batch_size

    def __init__(self, session, attrs, batch_size):
        cdef Session _session = session
        cdef AttributeList template = _session.make_attribute_list(attrs)
        self.template = template
        self.batch_size = batch_size
        super().__init__(_session)

    def __iter__(self):
        return self

    def _batch_iter(self, results, count):
        for ix in range(count):
            yield make_object(self.session, results[ix])

    def __next__(self):
        """Get the next batch of objects."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj
        cdef CK_ULONG count
        cdef CK_RV retval

        cdef CK_OBJECT_HANDLE [:] results = CK_ULONG_buffer(self.batch_size)

        with nogil:
            retval = self.session.funclist.C_FindObjects(handle, &results[0], self.batch_size, &count)
        assertRV(retval)

        if count == 0:
            self._finalize()
            raise StopIteration()
        else:
            return self._batch_iter(results, count)

    def _initiate(self):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_ATTRIBUTE *attr_data = self.template.data
        cdef CK_ULONG attr_count = self.template.count
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_FindObjectsInit(handle, attr_data, attr_count)
        assertRV(retval)

    def _finalize(self, silent=False):
        """Finish the operation."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_RV retval

        if self.active:
            with nogil:
                retval = self.session.funclist.C_FindObjectsFinal(handle)
            if not silent:
                self._handle_final_retval(retval)


cdef class DigestOperation(OperationWithBinaryOutput):

    @staticmethod
    cdef DigestOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_ULONG buffer_size
    ) with gil:
        cdef DigestOperation op = <DigestOperation> OperationWithBinaryOutput._setup(
            DigestOperation, session, mech, buffer_size
        )
        return op

    def _initiate(self):
        cdef CK_RV retval
        with nogil:
            retval = self.session.funclist.C_DigestInit(self.session.handle, self.mech.data)
        self._operation_aware_assert(retval)

    cdef bytes digest_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        cdef Session session = self.session
        return self.process_fully(session.funclist.C_Digest, data, data_len)

    cdef void update_digest(self, CK_BYTE *data, CK_ULONG data_len):
        self.update_no_output(self.session.funclist.C_DigestUpdate, data, data_len)

    cdef void update_digest_with_key(self, CK_OBJECT_HANDLE key):
        cdef Session session = self.session
        with nogil:
            retval = session.funclist.C_DigestKey(session.handle, key)
        self._operation_aware_assert(retval)

    def ingest_chunks(self, chunks):
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_OBJECT_HANDLE key

        for chunk in chunks:
            if not chunk:
                continue
            if isinstance(chunk, types.Key):
                key = chunk.handle
                self.update_digest_with_key(key)
            else:
                data_ptr = chunk
                data_len = <CK_ULONG> len(chunk)
                self.update_digest(data_ptr, data_len)

    cdef bytes finish(self):
        return self.finish_with_output(self.session.funclist.C_DigestFinal)

    def _finalize(self, silent=False):
        cdef Session session = self.session
        if self.active:
            self.execute_resizing_output(session.funclist.C_DigestFinal)
        super()._finalize(silent=silent)


def merge_templates(default_template, *user_templates):
    template = default_template.copy()

    for user_template in user_templates:
        if user_template is not None:
            template.update(user_template)

    return {
        key: value
        for key, value in template.items()
        if value is not DEFAULT
    }


cdef class Session(HasFuncList, types.Session):
    """Extend Session with implementation."""

    cdef readonly CK_SESSION_HANDLE handle
    cdef readonly Token token
    cdef readonly bint rw
    cdef CK_USER_TYPE _user_type
    cdef object operation_lock
    cdef object attribute_mapper
    cdef unsigned int cancel_strategy

    @staticmethod
    cdef Session make(
            Token token,
            CK_SESSION_HANDLE handle,
            bint rw,
            CK_USER_TYPE user_type,
            object mapper,
            unsigned int cancel_strategy
    ):
        cdef Session session = Session.__new__(Session)

        session.funclist = token.funclist
        session.token = token

        session.handle = handle
        # Big operation lock prevents other threads from entering/reentering
        # operations. If the same thread enters the lock, they will get a
        # Cryptoki warning
        session.operation_lock = RLock()

        session.rw = rw
        session._user_type = user_type
        session.attribute_mapper = mapper
        session.cancel_strategy = cancel_strategy
        return session

    def __init__(self):
        raise TypeError

    def _identity(self):
        return Session.__name__, self.token, self.handle

    @property
    def user_type(self):
        """User type for this session (:class:`pkcs11.constants.UserType`)."""
        return UserType(self._user_type)

    def close(self):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_RV retval

        if self.user_type != UserType.NOBODY:
            with nogil:
                retval = self.funclist.C_Logout(handle)
            assertRV(retval)

        with nogil:
            retval = self.funclist.C_CloseSession(handle)
        assertRV(retval)

    def get_objects(self, attrs=None, batch_size=10):
        with SearchIter(self, attrs or {}, batch_size) as op:
            for batch in op:
                yield from batch

    def reaffirm_credentials(self, pin):
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length

        pin = pin.encode('utf-8')
        pin_data = pin
        pin_length = <CK_ULONG> len(pin)
        user_type = CKU_CONTEXT_SPECIFIC

        with nogil:
            retval = self.funclist.C_Login(self.handle, user_type, pin_data, pin_length)
        assertRV(retval)

    def create_object(self, attrs):
        template = self.make_attribute_list(attrs)

        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_CreateObject(handle, attr_data, attr_count, &new)
        assertRV(retval)

        return make_object(self, new)

    def create_domain_parameters(self, key_type, attrs,
                                 local=False, store=False):
        if local and store:
            raise ArgumentsBad("Cannot set both `local` and `store`")

        attrs = dict(attrs)
        attrs[Attribute.CLASS] = ObjectClass.DOMAIN_PARAMETERS
        attrs[Attribute.KEY_TYPE] = key_type
        attrs[Attribute.TOKEN] = store

        if local:
            return LocalDomainParameters(self, attrs)
        else:
            return self.create_object(attrs)

    def generate_domain_parameters(self, key_type, param_length, store=False,
                                   mechanism=None, mechanism_param=None,
                                   template=None):
        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(param_length, int):
            raise ArgumentsBad("`param_length` is the length in bits.")

        mech = MechanismWithParam(
            key_type, DEFAULT_PARAM_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        template_ = {
            Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS,
            Attribute.TOKEN: store,
            Attribute.PRIME_BITS: param_length,
        }
        attrs = self.make_attribute_list(merge_templates(template_, template))

        return self.generate_key_from_attrs(attrs, mech)

    cdef AttributeList make_attribute_list(self, template):
        return AttributeList.from_template(dict(template), self.attribute_mapper)

    def generate_key(self, key_type, key_length=None,
                     id=None, label=None,
                     store=False, capabilities=None,
                     mechanism=None, mechanism_param=None,
                     template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        template_ = self.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        # Build attributes
        if key_type not in (KeyType.DES2, KeyType.DES3, KeyType.GOST28147, KeyType.SEED):
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes

        attrs = self.make_attribute_list(merge_templates(template_, template))

        return self.generate_key_from_attrs(attrs, mech)

    cdef object generate_key_from_attrs(
            self, AttributeList attrs, MechanismWithParam mech
    ):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key

        with nogil:
            retval = self.funclist.C_GenerateKey(handle, mech_data, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(self, key)


    def _generate_keypair(self, key_type, key_length=None,
                          id=None, label=None,
                          store=False, capabilities=None,
                          mechanism=None, mechanism_param=None,
                          public_template=None, private_template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        public_template_ = self.attribute_mapper.public_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )

        if key_type is KeyType.RSA:
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            # Some PKCS#11 implementations don't default this, it makes sense
            # to do it here
            public_template_.update({
                Attribute.PUBLIC_EXPONENT: b'\1\0\1',
                Attribute.MODULUS_BITS: key_length,
            })

        public_attrs = self.make_attribute_list(merge_templates(public_template_, public_template))

        private_template_ = self.attribute_mapper.private_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )
        private_attrs = self.make_attribute_list(merge_templates(private_template_, private_template))
        return self.generate_keypair_from_attrs(public_attrs, private_attrs, mech)

    cdef tuple generate_keypair_from_attrs(
            self,
            AttributeList public_attrs,
            AttributeList private_attrs,
            MechanismWithParam mech
    ):

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *public_attr_data = public_attrs.data
        cdef CK_ULONG public_attr_count = public_attrs.count
        cdef CK_ATTRIBUTE *private_attr_data = private_attrs.data
        cdef CK_ULONG private_attr_count = private_attrs.count
        cdef CK_OBJECT_HANDLE public_key
        cdef CK_OBJECT_HANDLE private_key
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateKeyPair(handle, mech_data, public_attr_data, public_attr_count, private_attr_data, private_attr_count, &public_key, &private_key)
        assertRV(retval)

        return (make_object(self, public_key),
                make_object(self, private_key))

    def seed_random(self, seed):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_BYTE *seed_data = seed
        cdef CK_ULONG seed_len = <CK_ULONG> len(seed)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_SeedRandom(handle, seed_data, seed_len)
        assertRV(retval)

    def generate_random(self, nbits):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_ULONG length = nbits // 8
        cdef CK_CHAR [:] random = CK_BYTE_buffer(length)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateRandom(handle, &random[0], length)
        assertRV(retval)

        return bytes(random)

    def __digest_operation(self, mechanism, mechanism_param):
        mech = MechanismWithParam(
            None, {},
            mechanism, mechanism_param)
        return DigestOperation.setup(self, mech, 1024)

    def _digest(self, data, mechanism=None, mechanism_param=None):
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_RV retval

        cdef DigestOperation op =  self.__digest_operation(mechanism, mechanism_param)
        with op:
            return op.digest_process_fully(data_ptr, data_len)

    def _digest_generator(self, data, mechanism=None, mechanism_param=None):

        cdef DigestOperation op = self.__digest_operation(mechanism, mechanism_param)
        with op:
            op.ingest_chunks(data)
            return op.finish()

    def set_pin(self, old_pin, new_pin):
        cdef CK_ULONG old_pin_length
        cdef CK_ULONG new_pin_length
        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_UTF8CHAR *old_pin_data
        cdef CK_UTF8CHAR *new_pin_data
        cdef CK_RV retval

        pin_old = old_pin.encode('utf-8')
        pin_new = new_pin.encode('utf-8')

        old_pin_data = pin_old
        new_pin_data = pin_new
        old_pin_length = len(pin_old)
        new_pin_length = len(pin_new)

        with nogil:
            retval = self.funclist.C_SetPIN(handle, old_pin_data, old_pin_length, new_pin_data, new_pin_length)
        assertRV(retval)

    def init_pin(self, pin):
        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        pin = pin.encode('utf-8')

        pin_data = pin
        pin_length = len(pin)

        with nogil:
            retval = self.funclist.C_InitPIN(handle, pin_data, pin_length)
        assertRV(retval)

cdef class ObjectHandleWrapper(HasFuncList):
    """
    Class implementing generic operations on PKCS#11 objects.
    """

    cdef readonly Session session
    cdef readonly CK_OBJECT_HANDLE handle

    @staticmethod
    cdef ObjectHandleWrapper wrap(Session session, CK_OBJECT_HANDLE handle):
        cdef ObjectHandleWrapper obj = ObjectHandleWrapper.__new__(ObjectHandleWrapper)
        obj.funclist = session.funclist
        obj.session = session
        obj.handle = handle
        return obj

    def __init__(self):
        raise TypeError

    cdef AttributeList get_attribute_list(self, CK_ATTRIBUTE_TYPE * keys, CK_ULONG total) with gil:
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ULONG ix = 0
        cdef CK_ULONG retrievable = 0
        cdef CK_ATTRIBUTE *tpl = <CK_ATTRIBUTE *> PyMem_Malloc(total * sizeof(CK_ATTRIBUTE))
        cdef CK_RV retval

        for ix in range(total):
            tpl[ix].type = keys[ix]
            tpl[ix].pValue = NULL
            tpl[ix].ulValueLen = <CK_ULONG> 0

        with nogil:
            retval = self.funclist.C_GetAttributeValue(handle, obj, tpl, total)

        for ix in range(total):
            if tpl[ix].ulValueLen != CK_UNAVAILABLE_INFORMATION:
                # overwrite the template at position 'retrievable' in the buffer
                tpl[retrievable].type = tpl[ix].type
                tpl[retrievable].pValue = PyMem_Malloc(tpl[ix].ulValueLen)
                if tpl[retrievable].pValue is NULL:
                    raise MemoryError()
                tpl[retrievable].ulValueLen = tpl[ix].ulValueLen
                retrievable += 1
            # The spec prohibits returning CK_UNAVAILABLE_INFORMATION
            #  together with CKR_OK, but some tokens do that anyway.
            #  Let's be defensive and map that to a proper error,
            if tpl[ix].ulValueLen == CK_UNAVAILABLE_INFORMATION and retval == CKR_OK:
                retval = CKR_FUNCTION_FAILED
                break

        # when this gets GC'd, the __dealloc__ will clean up our buffers
        result = AttributeList.from_owned_pointer(tpl, retrievable)
        if retrievable:
            with nogil:
                retval = self.funclist.C_GetAttributeValue(handle, obj, tpl, retrievable)
            for ix in range(retrievable):
                # Ensure the data returned from the token is sane
                if tpl[ix].ulValueLen == CK_UNAVAILABLE_INFORMATION or tpl[ix].pValue is NULL:
                    retval = CKR_FUNCTION_FAILED
                    break
        assertRV(retval)
        return result


    def __getitem__(self, key):
        cdef CK_ATTRIBUTE_TYPE key_t = key
        return self.get_attribute_list(&key_t, 1).at_index(0, self.session.attribute_mapper)

    def __setitem__(self, key, value):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE template
        cdef CK_RV retval

        value = self.session.attribute_mapper.pack_attribute(key, value)

        template.type = key
        template.pValue = <CK_CHAR *> value
        template.ulValueLen = <CK_ULONG>len(value)

        with nogil:
            retval = self.funclist.C_SetAttributeValue(handle, obj, &template, 1)
        assertRV(retval)

    def destroy(self):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_DestroyObject(handle, obj)
        assertRV(retval)

    def copy(self, attrs):
        template = self.session.make_attribute_list(attrs)

        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new_obj
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_CopyObject(handle, obj, attr_data, attr_count, &new_obj)
        assertRV(retval)
        return new_obj

    def identity(self):
        return ObjectHandleWrapper.__name__, self.session, self.handle


class Object(types.Object):
    """Expand Object with an implementation."""

    def __init__(self, wrapper: ObjectHandleWrapper):
        self.wrapper = wrapper

    def __getitem__(self, item):
        return self.wrapper[item]

    def __setitem__(self, key, value):
        self.wrapper[key] = value

    def get_attributes(self, keys):
        cdef ObjectHandleWrapper wrapper = self.wrapper
        cdef CK_ULONG total = len(keys)

        if not total:
            return {}

        cdef CK_ATTRIBUTE_TYPE * key_ptr = <CK_ATTRIBUTE_TYPE *> PyMem_Malloc(total * sizeof(CK_ATTRIBUTE_TYPE))
        cdef CK_ULONG ix = 0
        for ix, key in enumerate(keys):
            key_ptr[ix] = <CK_ATTRIBUTE_TYPE> key

        try:
            result = wrapper.get_attribute_list(key_ptr, total).as_dict(wrapper.session.attribute_mapper)
        finally:
            PyMem_Free(key_ptr)
        return result

    @property
    def session(self):
        return self.wrapper.session

    @property
    def handle(self):
        return self.wrapper.handle

    def copy(self, attrs):
        new_obj = self.wrapper.copy(attrs)
        return make_object(self.wrapper.session, new_obj)

    def destroy(self):
        self.wrapper.destroy()

    def _identity(self):
        return Object.__name__, self.wrapper.identity()


cdef object make_object(Session session, CK_OBJECT_HANDLE handle) with gil:
    """
    Make an object with the right bases for its class and capabilities.
    """
    wrapper = ObjectHandleWrapper.wrap(session, handle)

    cdef CK_ATTRIBUTE_TYPE[8] attr_keys = [
        Attribute.CLASS,
        Attribute.ENCRYPT,
        Attribute.DECRYPT,
        Attribute.SIGN,
        Attribute.VERIFY,
        Attribute.WRAP,
        Attribute.UNWRAP,
        Attribute.DERIVE
    ]

    try:
        # Determine a list of base classes to manufacture our class with
        try:
            attributes = wrapper.get_attribute_list(&attr_keys[0], 8)
        except PKCS11Error:
            # retry fetching the flags one by one, some tokens do not implement error handling
            # on bulk fetches correctly.
            attributes = {}
            for key in attr_keys:
                try:
                    attributes[key] = wrapper[key]
                except (AttributeTypeInvalid, AttributeSensitive, FunctionFailed):
                    continue

        object_class = attributes.get(Attribute.CLASS, session.attribute_mapper)
        bases = (_CLASS_MAP[object_class],)

        # Build a list of mixins for this new class
        for attribute, mixin in (
                (Attribute.ENCRYPT, EncryptMixin),
                (Attribute.DECRYPT, DecryptMixin),
                (Attribute.SIGN, SignMixin),
                (Attribute.VERIFY, VerifyMixin),
                (Attribute.WRAP, WrapMixin),
                (Attribute.UNWRAP, UnwrapMixin),
                (Attribute.DERIVE, DeriveMixin),
        ):
            try:
                if attributes.get(attribute, session.attribute_mapper):
                    bases += (mixin,)
            except KeyError:
                pass

        bases += (Object,)

        # Manufacture a class with the right capabilities.
        klass = type(bases[0].__name__, bases, {})

        return klass(wrapper)

    except KeyError:
        return Object(wrapper)


class SecretKey(types.SecretKey):
    pass


class PublicKey(types.PublicKey):
    pass


class PrivateKey(types.PrivateKey):
    pass


class GenerateWithParametersMixin(types.DomainParameters):
    def generate_keypair(self,
                         id=None, label=None,
                         store=False, capabilities=None,
                         mechanism=None, mechanism_param=None,
                         public_template=None, private_template=None):

        cdef Session session = self.session
        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[self.key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_GENERATE_MECHANISMS, mechanism, mechanism_param)

        # Build attributes
        public_template_ = session.attribute_mapper.public_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )

        # Copy in our domain parameters.
        # Not all parameters are appropriate for all domains.
        try:
            public_template_.update(
                self.get_attributes(
                    (
                        Attribute.BASE,
                        Attribute.PRIME,
                        Attribute.SUBPRIME,
                        Attribute.EC_PARAMS,
                    )
                )
            )
        except (AttributeTypeInvalid, FunctionFailed):
            pass

        public_attrs = session.make_attribute_list(merge_templates(public_template_, public_template))

        private_template_ = session.attribute_mapper.private_key_template(
            id_=id, label=label, store=store, capabilities=capabilities,
        )
        private_attrs = session.make_attribute_list(merge_templates(private_template_, private_template))

        return session.generate_keypair_from_attrs(public_attrs, private_attrs, mech)


class LocalDomainParameters(GenerateWithParametersMixin, types.LocalDomainParameters):
    pass

class StoredDomainParameters(GenerateWithParametersMixin):
    pass

class Certificate(types.Certificate):
    pass


cdef class KeyOperation(OperationWithBinaryOutput):
    cdef CK_OBJECT_HANDLE key
    cdef KeyOperationInit op_init

    @staticmethod
    cdef KeyOperation _common_key_setup(
            type cls,
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:

        cdef KeyOperation op = <KeyOperation> OperationWithBinaryOutput._setup(
            cls, session, mech, buffer_size
        )
        op.key = key
        return op

    def unclean_shutdown(self):
        """
        Shutdown implementation for 2.x PKCS#11 modules that don't support shutdown signalling
        """
        raise NotImplementedError

    def _initiate(self):
        cdef CK_RV retval
        with nogil:
            retval = self.op_init(self.session.handle, self.mech.data, self.key)
        self._operation_aware_assert(retval)

    def _cancel_operation(self, silent):
        cdef CK_RV retval
        if self.session.cancel_strategy == CancelStrategy.CANCEL_WITH_INIT:
            # cancel the operation if still active
            # This is a PKCS#11 3.x feature
            with nogil:
                retval = self.op_init(self.session.handle, NULL, self.key)
            if retval == CKR_OPERATION_CANCEL_FAILED and not silent:
                raise PKCS11Error("Failed to cancel operation")
        else:
            # No official cancel protocol in v2.x of the standard
            # Try the poor man's way by making a hail-mary call to C_XYZFinish() and ignoring the response
            self.unclean_shutdown()

    def _finalize(self, silent=False):
        if self.active:
            self._cancel_operation(silent)
        super()._finalize(silent=silent)


cdef class DataCryptOperation(KeyOperation):

    cdef OperationUpdateWithResult op_update
    cdef OperationWithResult op_final
    cdef OperationUpdateWithResult op_full

    @staticmethod
    cdef DataCryptOperation setup_encrypt(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataCryptOperation op = <DataCryptOperation> KeyOperation._common_key_setup(
            DataCryptOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_EncryptInit
        op.op_update = session.funclist.C_EncryptUpdate
        op.op_final = session.funclist.C_EncryptFinal
        op.op_full = session.funclist.C_Encrypt
        return op

    @staticmethod
    cdef DataCryptOperation setup_decrypt(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataCryptOperation op = <DataCryptOperation> KeyOperation._common_key_setup(
            DataCryptOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_DecryptInit
        op.op_update = session.funclist.C_DecryptUpdate
        op.op_final = session.funclist.C_DecryptFinal
        op.op_full = session.funclist.C_Decrypt
        return op

    cdef bytes crypt_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        return self.process_fully(self.op_full, data, data_len)

    cdef bytes finish(self) with gil:
        return self.finish_with_output(self.op_final)

    def unclean_shutdown(self):
        self.execute_resizing_output(self.op_final)

    def update_chunks(self, chunks):
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len

        for chunk in chunks:
            if not chunk:
                continue
            data_ptr = chunk
            data_len = <CK_ULONG> len(chunk)
            yield self.update_with_result(self.op_update, data_ptr, data_len)


class EncryptMixin(types.EncryptMixin):
    """Expand EncryptMixin with an implementation."""

    def __encrypt_operation(self, mechanism, mechanism_param, buffer_size):

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)

        return DataCryptOperation.setup_encrypt(self.session, mech, self.handle, buffer_size)

    def _encrypt(self, data, mechanism=None, mechanism_param=None, buffer_size=8192):
        """
        Non chunking encrypt. Needed for some mechanisms.
        """
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)

        cdef DataCryptOperation op = self.__encrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            return op.crypt_process_fully(data, data_len)


    def _encrypt_generator(self, data,
                           mechanism=None, mechanism_param=None,
                           buffer_size=8192):
        """
        Do chunked encryption.
        """
        cdef DataCryptOperation op = self.__encrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            yield from op.update_chunks(data)
            yield op.finish()


class DecryptMixin(types.DecryptMixin):
    """Expand DecryptMixin with an implementation."""

    def __decrypt_operation(self, mechanism, mechanism_param, buffer_size):

        mech = MechanismWithParam(self.key_type, DEFAULT_ENCRYPT_MECHANISMS, mechanism, mechanism_param)

        return DataCryptOperation.setup_decrypt(self.session, mech, self.handle, buffer_size)

    def _decrypt(self, data, mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):
        """Non chunking decrypt."""
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)

        cdef DataCryptOperation op = self.__decrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            return op.crypt_process_fully(data, data_len)


    def _decrypt_generator(self, data,
                           mechanism=None, mechanism_param=None, pin=None,
                           buffer_size=8192):
        """
        Chunking decrypt.
        """
        cdef Session session = self.session

        cdef DataCryptOperation op = self.__decrypt_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            yield from op.update_chunks(data)
            yield op.finish()


cdef class SignOrVerifyOperation(KeyOperation):
    cdef OperationUpdate op_update

    def ingest_chunks(self, chunks):
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len

        for chunk in chunks:
            if not chunk:
                continue
            data_ptr = chunk
            data_len = <CK_ULONG> len(chunk)
            self.update_no_output(self.op_update, data_ptr, data_len)


cdef class DataSignOperation(SignOrVerifyOperation):

    @staticmethod
    cdef DataSignOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key,
            CK_ULONG buffer_size
    ) with gil:
        cdef DataSignOperation op = <DataSignOperation> KeyOperation._common_key_setup(
            DataSignOperation, session, mech, key, buffer_size
        )
        op.op_init = session.funclist.C_SignInit
        op.op_update = session.funclist.C_SignUpdate
        return op

    cdef bytes sign_process_fully(self, CK_BYTE *data, CK_ULONG data_len) with gil:
        cdef Session session = self.session
        return self.process_fully(session.funclist.C_Sign, data, data_len)

    cdef bytes finish(self) with gil:
        cdef Session session = self.session
        return self.finish_with_output(session.funclist.C_SignFinal)

    def unclean_shutdown(self):
        cdef Session session = self.session
        self.execute_resizing_output(session.funclist.C_SignFinal)


class SignMixin(types.SignMixin):
    """Expand SignMixin with an implementation."""

    def __sign_operation(self, mechanism, mechanism_param, buffer_size):
        mech = MechanismWithParam(self.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        return DataSignOperation.setup(self.session, mech, self.handle, buffer_size)

    def _sign(self, data,
              mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):
        cdef Session session = self.session
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef DataSignOperation op = self.__sign_operation(mechanism, mechanism_param, buffer_size)

        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            return op.sign_process_fully(data, data_len)

    def _sign_generator(self, data,
                        mechanism=None, mechanism_param=None, pin=None, buffer_size=8192):

        cdef Session session = self.session
        cdef DataSignOperation op = self.__sign_operation(mechanism, mechanism_param, buffer_size)
        with op:
            if pin is not None:
                session.reaffirm_credentials(pin)
            op.ingest_chunks(data)
            return op.finish()


cdef class DataVerifyOperation(SignOrVerifyOperation):

    @staticmethod
    cdef DataVerifyOperation setup(
            Session session,
            MechanismWithParam mech,
            CK_OBJECT_HANDLE key
    ) with gil:
        cdef DataVerifyOperation op = <DataVerifyOperation> KeyOperation._common_key_setup(
            DataVerifyOperation, session, mech, key, 0
        )
        op.op_init = session.funclist.C_VerifyInit
        op.op_update = session.funclist.C_VerifyUpdate
        return op

    cdef verify_process_fully(
        self,
        CK_BYTE *data,
        CK_ULONG data_len,
        CK_BYTE *sig,
        CK_ULONG sig_len,
    ) with gil:
        cdef Session session = self.session
        cdef CK_RV retval
        with nogil:
            retval = session.funclist.C_Verify(session.handle, data, data_len, sig, sig_len)
        self._handle_final_retval(retval)

    cdef finish(self, CK_BYTE *sig, CK_ULONG sig_len) with gil:
        cdef Session session = self.session
        cdef CK_RV retval
        with nogil:
            retval = session.funclist.C_VerifyFinal(session.handle, sig, sig_len)
        self._handle_final_retval(retval)

    def unclean_shutdown(self):
        cdef Session session = self.session
        cdef CK_BYTE dummy = 0
        with nogil:
            session.funclist.C_VerifyFinal(session.handle, &dummy, 0)


class VerifyMixin(types.VerifyMixin):
    """Expand VerifyMixin with an implementation."""

    def __verify_operation(self, mechanism, mechanism_param):
        mech = MechanismWithParam(self.key_type, DEFAULT_SIGN_MECHANISMS, mechanism, mechanism_param)
        return DataVerifyOperation.setup(self.session, mech, self.handle)

    def _verify(self, data, signature,
                mechanism=None, mechanism_param=None):

        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef DataVerifyOperation op = self.__verify_operation(mechanism, mechanism_param)

        with op:
            op.verify_process_fully(data_ptr, data_len, sig_ptr, sig_len)

    def _verify_generator(self, data, signature,
                          mechanism=None, mechanism_param=None):

        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef DataVerifyOperation op = self.__verify_operation(mechanism, mechanism_param)

        with op:
            op.ingest_chunks(data)
            return op.finish(sig_ptr, sig_len)


class WrapMixin(types.WrapMixin):
    """Expand WrapMixin with an implementation."""

    def wrap_key(self, key,
                 mechanism=None, mechanism_param=None):

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE wrapping_key = self.handle
        cdef CK_OBJECT_HANDLE key_to_wrap = key.handle
        cdef CK_ULONG length
        cdef CK_RV retval

        # Find out how many bytes we need to allocate
        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, NULL, &length)
        assertRV(retval)

        cdef CK_BYTE [:] data = CK_BYTE_buffer(length)

        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, &data[0], &length)
        assertRV(retval)

        return bytes(data[:length])


class UnwrapMixin(types.UnwrapMixin):
    """Expand UnwrapMixin with an implementation."""

    def unwrap_key(self, object_class, key_type, key_data,
                   id=None, label=None,
                   mechanism=None, mechanism_param=None,
                   store=False, capabilities=None,
                   template=None):

        if not isinstance(object_class, ObjectClass):
            raise ArgumentsBad("`object_class` must be ObjectClass.")

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(self.key_type, DEFAULT_WRAP_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        # Build attributes
        template_ = session.attribute_mapper.generic_key_template(
            {
                Attribute.CLASS: object_class,
                Attribute.KEY_TYPE: key_type,
            },
            id_=id,
            label=label,
            store=store,
            capabilities=capabilities,
        )
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE unwrapping_key = self.handle
        cdef CK_BYTE *wrapped_key_ptr = key_data
        cdef CK_ULONG wrapped_key_len = <CK_ULONG> len(key_data)
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_UnwrapKey(session.handle, mech_data, unwrapping_key, wrapped_key_ptr, wrapped_key_len, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)


class DeriveMixin(types.DeriveMixin):
    """Expand DeriveMixin with an implementation."""

    def derive_key(self, key_type, key_length,
                   id=None, label=None,
                   store=False, capabilities=None,
                   mechanism=None, mechanism_param=None,
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

        mech = MechanismWithParam(self.key_type, DEFAULT_DERIVE_MECHANISMS, mechanism, mechanism_param)

        cdef Session session = self.session

        template_ = session.attribute_mapper.secret_key_template(
            capabilities=capabilities, id_=id, label=label, store=store,
        )
        template_[Attribute.KEY_TYPE] = key_type
        template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes
        cdef AttributeList attrs = session.make_attribute_list(merge_templates(template_, template))
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE src_key = self.handle
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_DeriveKey(session.handle, mech_data, src_key, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)


_CLASS_MAP = {
    ObjectClass.SECRET_KEY: SecretKey,
    ObjectClass.PUBLIC_KEY: PublicKey,
    ObjectClass.PRIVATE_KEY: PrivateKey,
    ObjectClass.DOMAIN_PARAMETERS: StoredDomainParameters,
    ObjectClass.CERTIFICATE: Certificate,
}

cdef extern from "../extern/load_module.c":
    ctypedef struct P11_HANDLE:
        void *get_function_list_ptr

    object p11_error()
    P11_HANDLE* p11_open(object path_str)
    int p11_close(P11_HANDLE* handle)


cdef class lib(HasFuncList):
    """
    Main entry point.

    This class needs to be defined cdef, so it can't shadow a class in
    pkcs11.types.
    """

    cdef readonly str so
    cdef readonly str manufacturer_id
    cdef readonly str library_description
    cdef readonly bint initialized
    cdef CK_VERSION _cryptoki_version
    cdef CK_VERSION _library_version
    cdef P11_HANDLE *_p11_handle

    cdef _load_pkcs11_lib(self, so) with gil:
        """Load a PKCS#11 library, and extract function calls.

        This method will dynamically load a PKCS11 library, and attempt to
        resolve the symbol 'C_GetFunctionList()'. Once found, the entry point
        is called to populate an internal table of function pointers.

        This is a private method, and must never be called directly.
        Called when a new lib class is instantiated.

        :param so: the path to a valid PKCS#11 library
        :type so: str
        :raises: PKCS11Error
        :rtype: None
        """

        # to keep a pointer to the C_GetFunctionList address returned by dlsym()
        cdef C_GetFunctionList_ptr populate_function_list
        cdef CK_RV retval

        cdef P11_HANDLE *handle = p11_open(so)
        if handle == NULL:
            err = <str> p11_error()
            if err:
                raise PKCS11Error(f"OS exception while loading {so}: {err}")
            else:
                raise PKCS11Error(f"Unknown exception while loading {so}")
        populate_function_list = <C_GetFunctionList_ptr> handle.get_function_list_ptr
        self._p11_handle = handle

        assertRV(populate_function_list(&self.funclist))

    def __cinit__(self, so):
        cdef CK_RV retval
        self._p11_handle = NULL
        self._load_pkcs11_lib(so)
        self.initialized = False
        # at this point, _funclist contains all function pointers to the library

    cpdef initialize(self):
        cdef CK_RV retval
        if self.funclist != NULL and not self.initialized:
            with nogil:
                retval = self.funclist.C_Initialize(NULL)
            assertRV(retval)
            self.initialized = True

    cdef CK_RV _finalize(self):
        cdef CK_RV retval = CKR_OK
        if self.funclist != NULL and self.initialized:
            retval = self.funclist.C_Finalize(NULL)
            self.initialized = False
        return retval

    def finalize(self):
        assertRV(self._finalize())

    def reinitialize(self):
        if self.funclist != NULL:
            self.finalize()
            self.initialize()

    def __init__(self, so):
        self.so = so
        cdef CK_INFO info
        cdef CK_RV retval

        self.initialize()

        with nogil:
            retval = self.funclist.C_GetInfo(&info)
        assertRV(retval)

        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]
        libraryDescription = info.libraryDescription[:sizeof(info.libraryDescription)]

        self.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturerID)
        self.library_description = _CK_UTF8CHAR_to_str(libraryDescription)
        self._cryptoki_version = info.cryptokiVersion
        self._library_version = info.libraryVersion

    @property
    def library_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._library_version)

    @property
    def cryptoki_version(self):
        """PKCS#11 (cryptoki) API version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self._cryptoki_version)

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

        cdef CK_BBOOL present = token_present
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetSlotList(present, NULL, &count)
        assertRV(retval)

        if count == 0:
            return []

        cdef CK_SLOT_ID [:] slot_list = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetSlotList(present, &slot_list[0], &count)
        assertRV(retval)

        cdef CK_SLOT_ID slot_id
        cdef CK_SLOT_INFO info

        slots = []

        for slot_id in slot_list:
            with nogil:
                retval = self.funclist.C_GetSlotInfo(slot_id, &info)
            assertRV(retval)

            slots.append(
                Slot.make(self.funclist, slot_id, info, self._cryptoki_version)
            )

        return slots


    def get_tokens(self,
                   token_label=None,
                   token_serial=None,
                   token_flags=None,
                   slot_flags=None,
                   mechanisms=None):
        """Search for a token matching the parameters."""

        for slot in self.get_slots():
            try:
                token = slot.get_token()
                token_mechanisms = slot.get_mechanisms()

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
            except (TokenNotPresent, TokenNotRecognised):
                continue

    def get_token(self, **kwargs):
        """Get a single token."""
        iterator = self.get_tokens(**kwargs)

        try:
            token = next(iterator)
        except StopIteration:
            raise NoSuchToken("No token matching %s" % kwargs)

        try:
            next(iterator)
            raise MultipleTokensReturned(
                "More than 1 token matches %s" % kwargs)
        except StopIteration:
            return token

    def wait_for_slot_event(self, blocking=True):
        cdef CK_SLOT_ID slot_id
        cdef CK_FLAGS flag = 0
        cdef CK_RV retval

        if not blocking:
            flag |= CKF_DONT_BLOCK

        with nogil:
            retval = self.funclist.C_WaitForSlotEvent(flag, &slot_id, NULL)
        assertRV(retval)

        cdef CK_SLOT_INFO info

        with nogil:
            retval = self.funclist.C_GetSlotInfo(slot_id, &info)
        assertRV(retval)

        slotDescription = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]

        return Slot(self, slot_id, slotDescription, manufacturerID,
                 info.hardwareVersion, info.firmwareVersion, info.flags)

    def unload(self):
        self._finalize()
        self.funclist = NULL
        if self._p11_handle != NULL:
            p11_close(self._p11_handle)
            self._p11_handle = NULL

    def __dealloc__(self):
        self.unload()
