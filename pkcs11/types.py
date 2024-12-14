"""
Types for high level PKCS#11 wrapper.

This module provides stubs that are overrideen in pkcs11._pkcs11.
"""

import types
import typing
from binascii import hexlify
from collections.abc import Iterable, Iterator
from functools import cached_property
from threading import RLock
from typing import Any, Literal, Optional, Protocol, TypedDict, TypeVar, Union, overload

from pkcs11.constants import Attribute, MechanismFlag, ObjectClass, SlotFlag, TokenFlag, UserType
from pkcs11.exceptions import (
    ArgumentsBad,
    AttributeTypeInvalid,
    MultipleObjectsReturned,
    NoSuchKey,
    SignatureInvalid,
    SignatureLenRange,
)
from pkcs11.mechanisms import KeyType, Mechanism

PROTECTED_AUTH = object()
"""Indicate the pin should be supplied via an external mechanism (e.g. pin pad)"""

# Using typing.Self with Python 3.11
Self = TypeVar("Self", bound="Object")
AttributeDict = dict[Attribute, Union[bytes, bool, str, list[int], ObjectClass, KeyType]]


class VersionDict(TypedDict):
    major: str
    minor: str


def _CK_UTF8CHAR_to_str(data: bytes) -> str:
    """Convert CK_UTF8CHAR to string."""
    return data.rstrip(b"\0").decode("utf-8").rstrip()


def _CK_VERSION_to_tuple(data: VersionDict) -> tuple[str, str]:
    """Convert CK_VERSION to tuple."""
    return (data["major"], data["minor"])


def _CK_MECHANISM_TYPE_to_enum(mechanism: int) -> Union[Mechanism, int]:
    """Convert CK_MECHANISM_TYPE to enum or be okay."""
    try:
        return Mechanism(mechanism)
    except ValueError:
        return mechanism


class Library(Protocol):
    so: str
    manufacturer_id: str
    library_description: str
    cryptoki_version: str
    library_version: str

    def __init__(self, so: str) -> None: ...

    def __str__(self) -> str: ...

    def __repr__(self) -> str: ...

    def get_slots(self, token_present: bool = False) -> list["Slot"]: ...

    def get_tokens(
        self,
        token_label: Optional[str] = None,
        token_serial: Optional[bytes] = None,
        token_flags: Optional[TokenFlag] = None,
        slot_flags: Optional[SlotFlag] = None,
        mechanisms: Optional[set[Mechanism]] = None,
    ) -> Iterator["Token"]: ...

    def get_token(
        self,
        token_label: Optional[str] = None,
        token_serial: Optional[bytes] = None,
        token_flags: Optional[TokenFlag] = None,
        slot_flags: Optional[SlotFlag] = None,
        mechanisms: Optional[set[Mechanism]] = None,
    ) -> "Token": ...

    def reinitialize(self) -> None: ...


class MechanismInfo:
    """
    Information about a mechanism.

    See :meth:`pkcs11.Slot.get_mechanism_info`.
    """

    def __init__(
        self,
        slot: "Slot",
        mechanism: Mechanism,
        ulMinKeySize: Optional[int] = None,
        ulMaxKeySize: Optional[int] = None,
        flags: Optional[int] = None,
    ):
        self.slot = slot
        """:class:`pkcs11.Slot` this information is for."""
        self.mechanism = mechanism
        """:class:`pkcs11.mechanisms.Mechanism` this information is for."""
        self.min_key_length = ulMinKeySize
        """Minimum key length in bits (:class:`int`)."""
        self.max_key_length = ulMaxKeySize
        """Maximum key length in bits (:class:`int`)."""
        self.flags = MechanismFlag(flags)  # type: ignore[arg-type]
        """Mechanism capabilities (:class:`pkcs11.constants.MechanismFlag`)."""

    def __str__(self) -> str:
        return "\n".join(
            (
                "Supported key lengths: [%s, %s]" % (self.min_key_length, self.max_key_length),
                "Flags: %s" % self.flags,
            )
        )

    def __repr__(self) -> str:
        return "<{klass} (mechanism={mechanism}, flags={flags})>".format(
            klass=type(self).__name__, mechanism=str(self.mechanism), flags=str(self.flags)
        )


class Slot:
    """
    A PKCS#11 device slot.

    This object represents a physical or software slot exposed by PKCS#11.
    A slot has hardware capabilities, e.g. supported mechanisms and may has
    a physical or software :class:`Token` installed.
    """

    def __init__(
        self,
        lib: Library,
        slot_id: int,
        slotDescription: bytes,
        manufacturerID: bytes,
        hardwareVersion: VersionDict,
        firmwareVersion: VersionDict,
        flags: int,
    ) -> None:
        self._lib = lib  # Hold a reference to the lib to prevent gc

        self.slot_id = slot_id
        """Slot identifier (opaque)."""
        self.slot_description = _CK_UTF8CHAR_to_str(slotDescription)
        """Slot name (:class:`str`)."""
        self.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturerID)
        """Slot/device manufacturer's name (:class:`str`)."""
        self.hardware_version = _CK_VERSION_to_tuple(hardwareVersion)
        """Hardware version (:class:`tuple`)."""
        self.firmware_version = _CK_VERSION_to_tuple(firmwareVersion)
        """Firmware version (:class:`tuple`)."""
        self.flags = SlotFlag(flags)
        """Capabilities of this slot (:class:`SlotFlag`)."""

    def get_token(self) -> "Token":
        """
        Returns the token loaded into this slot.

        :rtype: Token
        """
        raise NotImplementedError()

    def get_mechanisms(self) -> set[Mechanism]:
        """
        Returns the mechanisms supported by this device.

        :rtype: set(Mechanism)
        """
        raise NotImplementedError()

    def get_mechanism_info(self, mechanism: Mechanism) -> MechanismInfo:
        """
        Returns information about the mechanism.

        :param Mechanism mechanism: mechanism to learn about
        :rtype: MechanismInfo
        """
        raise NotImplementedError()

    def __eq__(self, other: Any) -> bool:
        return self.slot_id == other.slot_id  # type: ignore[no-any-return]

    def __str__(self) -> str:
        return "\n".join(
            (
                "Slot Description: %s" % self.slot_description,
                "Manufacturer ID: %s" % self.manufacturer_id,
                "Hardware Version: %s.%s" % self.hardware_version,
                "Firmware Version: %s.%s" % self.firmware_version,
                "Flags: %s" % self.flags,
            )
        )

    def __repr__(self) -> str:
        return "<{klass} (slotID={slot_id} flags={flags})>".format(
            klass=type(self).__name__, slot_id=self.slot_id, flags=str(self.flags)
        )


class Token:
    """
    A PKCS#11 token.

    A token can be physically installed in a :class:`Slot`, or a software
    token, depending on your PKCS#11 library.
    """

    def __init__(
        self,
        slot: Slot,
        label: bytes,
        serialNumber: bytes,
        model: bytes,
        manufacturerID: bytes,
        hardwareVersion: VersionDict,
        firmwareVersion: VersionDict,
        flags: int,
    ) -> None:
        self.slot = slot
        """The :class:`Slot` this token is installed in."""
        self.label = _CK_UTF8CHAR_to_str(label)
        """Label of this token (:class:`str`)."""
        self.serial = serialNumber.rstrip()
        """Serial number of this token (:class:`bytes`)."""
        self.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturerID)
        """Manufacturer ID."""
        self.model = _CK_UTF8CHAR_to_str(model)
        """Model name."""
        self.hardware_version = _CK_VERSION_to_tuple(hardwareVersion)
        """Hardware version (:class:`tuple`)."""
        self.firmware_version = _CK_VERSION_to_tuple(firmwareVersion)
        """Firmware version (:class:`tuple`)."""
        self.flags = TokenFlag(flags)
        """Capabilities of this token (:class:`pkcs11.flags.TokenFlag`)."""

    def __eq__(self, other: Any) -> bool:
        return self.slot == other.slot  # type: ignore[no-any-return]

    def open(
        self,
        rw: bool = False,
        user_pin: Optional[str] = None,
        so_pin: Optional[str] = None,
        user_type: Optional[UserType] = None,
    ) -> "Session":
        """
        Open a session on the token and optionally log in as a user or
        security officer (pass one of `user_pin` or `so_pin`). Pass PROTECTED_AUTH to
        indicate the pin should be supplied via an external mechanism (e.g. pin pad).

        Can be used as a context manager or close with :meth:`Session.close`.

        ::

            with token.open() as session:

                print(session)

        :param rw: True to create a read/write session.
        :param bytes user_pin: Authenticate to this session as a user.
        :param bytes so_pin: Authenticate to this session as a
            security officer.
        :param user_type: Sets the userType parameter to C_Login.
            Allows for vendor-defined values. Defaults to UserType.SO if
            so_pin is set, otherwise UserType.USER.

        :rtype: Session
        """
        raise NotImplementedError()

    def __str__(self) -> str:
        return self.label

    def __repr__(self) -> str:
        return "<{klass} (label='{label!r}' serial={serial!r} flags={flags})>".format(
            klass=type(self).__name__, label=self.label, serial=self.serial, flags=str(self.flags)
        )


class Session:
    """
    A PKCS#11 :class:`Token` session.

    A session is required to do nearly all operations on a token including
    encryption/signing/keygen etc.

    Create a session using :meth:`Token.open`. Sessions can be used as a
    context manager or closed with :meth:`close`.
    """

    def __init__(
        self, token: Token, handle: int, rw: bool = False, user_type: UserType = UserType.NOBODY
    ) -> None:
        self.token = token
        """:class:`Token` this session is on."""

        self._handle = handle
        # Big operation lock prevents other threads from entering/reentering
        # operations. If the same thread enters the lock, they will get a
        # Cryptoki warning
        self._operation_lock = RLock()

        self.rw = rw
        """True if this is a read/write session."""
        self.user_type = user_type
        """User type for this session (:class:`pkcs11.constants.UserType`)."""

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(self, type(other))
            and self.token == other.token
            and self._handle == other._handle
        )

    def __hash__(self) -> int:
        return hash(self._handle)

    def __enter__(self) -> "Session":
        return self

    def __exit__(
        self, type_: type[Exception], value: Exception, traceback: types.TracebackType
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the session."""
        raise NotImplementedError()

    @typing.overload
    def get_key(
        self,
        object_class: Literal[ObjectClass.PRIVATE_KEY],
        key_type: Optional[KeyType] = None,
        label: Optional[str] = None,
        id: Optional[bytes] = None,
    ) -> "PrivateKey": ...

    @typing.overload
    def get_key(
        self,
        object_class: Literal[ObjectClass.PUBLIC_KEY],
        key_type: Optional[KeyType] = None,
        label: Optional[str] = None,
        id: Optional[bytes] = None,
    ) -> "PublicKey": ...

    @typing.overload
    def get_key(
        self,
        object_class: Literal[ObjectClass.SECRET_KEY],
        key_type: Optional[KeyType] = None,
        label: Optional[str] = None,
        id: Optional[bytes] = None,
    ) -> "SecretKey": ...

    @typing.overload
    def get_key(
        self,
        object_class: Optional[ObjectClass] = None,
        key_type: Optional[KeyType] = None,
        label: Optional[str] = None,
        id: Optional[bytes] = None,
    ) -> "Key": ...

    def get_key(
        self,
        object_class: Optional[ObjectClass] = None,
        key_type: Optional[KeyType] = None,
        label: Optional[str] = None,
        id: Optional[bytes] = None,
    ) -> "Key":
        """
        Search for a key with any of `key_type`, `label` and/or `id`.

        Returns a single key or throws :class:`pkcs11.exceptions.NoSuchKey` or
        :class:`pkcs11.exceptions.MultipleObjectsReturned`.

        This is a simplified version of :meth:`get_objects`, which allows
        searching for any object.

        :param ObjectClass object_class: Optional object class.
        :param KeyType key_type: Optional key type.
        :param str label: Optional key label.
        :param bytes id: Optional key id.

        :rtype: Key
        """

        if object_class is None and key_type is None and label is None and id is None:
            raise ArgumentsBad("Must specify at least one search parameter.")

        attrs: AttributeDict = {}

        if object_class is not None:
            attrs[Attribute.CLASS] = object_class

        if key_type is not None:
            attrs[Attribute.KEY_TYPE] = key_type

        if label is not None:
            attrs[Attribute.LABEL] = label

        if id is not None:
            attrs[Attribute.ID] = id

        iterator: Iterator[Key] = typing.cast(Iterator[Key], self.get_objects(attrs))

        try:
            try:
                key = next(iterator)
            except StopIteration as ex:
                raise NoSuchKey("No key matching %s" % attrs) from ex

            try:
                next(iterator)
                raise MultipleObjectsReturned("More than 1 key matches %s" % attrs)
            except StopIteration:
                return key
        finally:
            # Force finalizing SearchIter rather than waiting for garbage
            # collection, so that we release the operation lock.
            iterator._finalize()  # type: ignore[attr-defined]

    def get_objects(self, attrs: Optional[AttributeDict] = None) -> Iterator["Object"]:
        """
        Search for objects matching `attrs`. Returns a generator.

        ::

            for obj in session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.LABEL: 'MY LABEL',
            }):

                print(obj)

        This is the more generic version of :meth:`get_key`.

        :param dict(Attribute,*) attrs: Attributes to search for.

        :rtype: iter(Object)
        """
        raise NotImplementedError()

    def create_object(self, attrs: AttributeDict) -> "Object":
        """
        Create a new object on the :class:`Token`. This is a low-level
        interface to create any type of object and can be used for importing
        data onto the Token.

        ::

            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.VALUE: b'SUPER SECRET KEY',
            })

        For generating keys see :meth:`generate_key` or
        :meth:`generate_keypair`.
        For importing keys see :ref:`importing-keys`.

        Requires a read/write session, unless the object is not to be
        stored. To permanently store the object in the HSM add **pkcs.Attribute.TOKEN: True**,
        see :meth:`pkcs11.Attribute` for more available object attributes.

        :param dict(Attribute,*) attrs: attributes of the object to create
        :rtype: Object
        """
        raise NotImplementedError()

    def create_domain_parameters(
        self,
        key_type: KeyType,
        attrs: AttributeDict,
        local: bool = False,
        store: bool = False,
    ) -> "DomainParameters":
        """
        Create a domain parameters object from known parameters.

        Domain parameters are used for key generation of key types such
        as DH, DSA and EC.

        You can also generate new parameters using
        :meth:`generate_domain_parameters`.

        The `local` parameter creates a Python object that is not created on
        the HSM (its object handle will be unset). This is useful if you only
        need the domain parameters to create another object, and do not need a
        real PKCS #11 object in the session.

        .. warning::

            Domain parameters have no id or labels. Storing them is possible
            but be aware they may be difficult to retrieve.

        :param KeyType key_type: Key type these parameters are for
        :param dict(Attribute,*) attrs: Domain parameters
            (specific tp `key_type`)
        :param local: if True, do not transfer parameters to the HSM.
        :param store: if True, store these parameters permanently in the HSM.
        :rtype: DomainParameters
        """

        raise NotImplementedError()

    def generate_domain_parameters(
        self,
        key_type: KeyType,
        param_length: int,
        store: bool = False,
        mechanism: Optional[Mechanism] = None,
        mechanism_param: Optional[tuple[Any, ...]] = None,
        template: Optional[AttributeDict] = None,
    ) -> "DomainParameters":
        """
        Generate domain parameters.

        See :meth:`create_domain_parameters` for creating domain parameter
        objects from known parameters.

        See :meth:`generate_key` for documentation on mechanisms and templates.

        .. warning::

            Domain parameters have no id or labels. Storing them is possible
            but be aware they may be difficult to retrieve.

        :param KeyType key_type: Key type these parameters are for
        :param int params_length: Size of the parameters (e.g. prime length)
            in bits.
        :param store: Store these parameters in the HSM
        :param Mechanism mechanism: Optional generation mechanism (or default)
        :param bytes mechanism_param: Optional mechanism parameter.
        :param dict(Attribute,*) template: Optional additional attributes.
        :rtype: DomainParameters
        """

        raise NotImplementedError()

    def generate_key(
        self,
        key_type: KeyType,
        key_length: Optional[int] = None,
        id: Optional[bytes] = None,
        label: Optional[str] = None,
        store: bool = False,
        capabilities: Optional[MechanismFlag] = None,
        mechanism: Optional[Mechanism] = None,
        mechanism_param: Optional[tuple[Any, ...]] = None,
        template: Optional[AttributeDict] = None,
    ) -> "SecretKey":
        """
        Generate a single key (e.g. AES, DES).

        Keys should set at least `id` or `label`.

        An appropriate `mechanism` will be chosen for `key_type`
        (see :attr:`DEFAULT_GENERATE_MECHANISMS`) or this can be overridden.
        Similarly for the `capabilities` (see
        :attr:`DEFAULT_KEY_CAPABILITIES`).

        The `template` will extend the default template used to make the
        key.

        Possible mechanisms and template attributes are defined by `PKCS #11
        <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.
        Invalid mechanisms or attributes should raise
        :exc:`pkcs11.exceptions.MechanismInvalid` and
        :exc:`pkcs11.exceptions.AttributeTypeInvalid` respectively.

        :param KeyType key_type: Key type (e.g. KeyType.AES)
        :param int key_length: Key length in bits (e.g. 256).
        :param bytes id: Key identifier.
        :param str label: Key label.
        :param store: Store key on token (requires R/W session).
        :param MechanismFlag capabilities: Key capabilities (or default).
        :param Mechanism mechanism: Generation mechanism (or default).
        :param bytes mechanism_param: Optional vector to the mechanism.
        :param dict(Attribute,*) template: Additional attributes.

        :rtype: SecretKey
        """
        raise NotImplementedError()

    def _generate_keypair(
        self, key_type: KeyType, key_length: Optional[int] = None, **kwargs: Any
    ) -> tuple["PublicKey", "PrivateKey"]:
        raise NotImplementedError()

    def generate_keypair(
        self, key_type: KeyType, key_length: Optional[int] = None, **kwargs: Any
    ) -> tuple["PublicKey", "PrivateKey"]:
        """
        Generate a asymmetric keypair (e.g. RSA).

        See :meth:`generate_key` for more information.

        :param KeyType key_type: Key type (e.g. KeyType.DSA)
        :param int key_length: Key length in bits (e.g. 256).
        :param bytes id: Key identifier.
        :param str label: Key label.
        :param bool store: Store key on token (requires R/W session).
        :param MechanismFlag capabilities: Key capabilities (or default).
        :param Mechanism mechanism: Generation mechanism (or default).
        :param bytes mechanism_param: Optional vector to the mechanism.
        :param dict(Attribute,*) private_template: Additional attributes for private key.
        :param dict(Attribute,*) public_template: Additional attributes for public key.

        :rtype: (PublicKey, PrivateKey)
        """
        if key_type is KeyType.DSA:
            if key_length is None:
                raise ArgumentsBad("Must specify `key_length`")

            params = self.generate_domain_parameters(key_type, key_length)

            return params.generate_keypair(**kwargs)
        else:
            return self._generate_keypair(key_type, key_length=key_length, **kwargs)

    def seed_random(self, seed: bytes) -> None:
        """
        Mix additional seed material into the RNG (if supported).

        :param bytes seed: Bytes of random to seed.
        """
        raise NotImplementedError()

    def generate_random(self, nbits: int) -> bytes:
        """
        Generate `length` bits of random or pseudo-random data (if supported).

        :param int nbits: Number of bits to generate.
        :rtype: bytes
        """
        raise NotImplementedError()

    def _digest(self, data: bytes, **kwargs: Any) -> bytes:
        raise NotImplementedError()

    def _digest_generator(
        self,
        data: Union[tuple[Union[bytes, "Key"], ...], Iterator[Union[bytes, "Key"]]],
        **kwargs: Any,
    ) -> bytes:
        raise NotImplementedError()

    def digest(
        self,
        data: Union[
            str, bytes, "Key", tuple[Union[bytes, "Key"], ...], Iterator[Union[bytes, "Key"]]
        ],
        **kwargs: Any,
    ) -> bytes:
        """
        Digest `data` using `mechanism`.

        `data` can be a single value or an iterator.

        :class:`Key` objects can also be digested, optionally interspersed
        with :class:`bytes`.

        :param data: Data to digest
        :type data: str, bytes, Key or iter(bytes, Key)
        :param Mechanism mechanism: digest mechanism
        :param bytes mechanism_param: optional mechanism parameter

        :rtype: bytes
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode("utf-8")

        if isinstance(data, bytes):
            return self._digest(data, **kwargs)

        elif isinstance(data, Key):
            data = (data,)

        return self._digest_generator(data, **kwargs)


class Object:
    """
    A PKCS#11 object residing on a :class:`Token`.

    Objects implement :meth:`__getitem__` and :meth:`__setitem__` to
    retrieve :class:`pkcs11.constants.Attribute` values on the object.
    Valid attributes for an object are given in `PKCS #11
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.
    Invalid attributes should raise
    :exc:`pkcs11.exceptions.AttributeTypeInvalid`.
    """

    object_class: ObjectClass
    """:class:`pkcs11.constants.ObjectClass` of this Object."""

    def __init__(self, session: Session, handle: Optional[int]) -> None:
        self.session = session
        """:class:`Session` this object is valid for."""
        self._handle = handle

    def __eq__(self, other: Any) -> bool:
        return self.session == other.session and self._handle == other._handle  # type: ignore[no-any-return]

    def __hash__(self) -> int:
        return hash((self.session, self._handle))

    if typing.TYPE_CHECKING:

        def __getitem__(self, item: Attribute) -> Any: ...

        def __setitem__(self, key: Attribute, value: Any) -> None: ...

    def copy(self: Self, attrs: AttributeDict) -> Self:
        """
        Make a copy of the object with new attributes `attrs`.

        Requires a read/write session, unless the object is not to be
        stored.

        ::

            new = key.copy({
                Attribute.LABEL: 'MY NEW KEY',
            })

        Certain objects may not be copied. Calling :meth:`copy` on such
        objects will result in an exception.

        :param dict(Attribute,*) attrs: attributes for the new :class:`Object`
        :rtype: Object
        """
        raise NotImplementedError()

    def destroy(self) -> None:
        """
        Destroy the object.

        Requires a read/write session, unless the object is not stored.

        Certain objects may not be destroyed. Calling :meth:`destroy` on such
        objects will result in an exception.

        The :class:`Object` is no longer valid.
        """
        raise NotImplementedError()


class EncryptMixin(Object):
    """
    This :class:`Object` supports the encrypt capability.
    """

    def _encrypt(self, data: bytes, buffer_size: int = 8192, **kwargs: Any) -> bytes:
        raise NotImplementedError

    def _encrypt_generator(
        self, data: Iterable[bytes], buffer_size: int = 8192, **kwargs: Any
    ) -> Iterator[bytes]:
        raise NotImplementedError

    @overload
    def encrypt(self, data: Union[str, bytes], buffer_size: int = 8192, **kwargs: Any) -> bytes: ...

    @overload
    def encrypt(
        self, data: Union[Iterable[bytes]], buffer_size: int = 8192, **kwargs: Any
    ) -> Iterator[bytes]: ...

    def encrypt(
        self, data: Union[str, bytes, Iterable[bytes]], buffer_size: int = 8192, **kwargs: Any
    ) -> Union[bytes, Iterator[bytes]]:
        """
        Encrypt some `data`.

        Data can be either :class:`str` or :class:`bytes`, in which case it
        will return :class:`bytes`; or an iterable of :class:`bytes` in
        which case it will return a generator yielding :class:`bytes`
        (be aware, more chunks will be output than input).

        If you do not specify `mechanism` then the default from
        :attr:`DEFAULT_ENCRYPT_MECHANISMS` will be used. If an iterable
        is passed and the mechanism chosen does not support handling data
        in chunks, an exception will be raised.

        Some mechanisms (including the default CBC mechanisms) require
        additional parameters, e.g. an initialisation vector [#]_, to
        the mechanism.  Pass this as `mechanism_param`.
        Documentation of these parameters is given specified in `PKCS #11
        <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.

        When passing an iterable for data
        `buffer_size` must be sufficient to store the working buffer. An
        integer number of blocks and greater than or equal to the largest
        input chunk is recommended.

        The returned generator obtains a lock on the :class:`Session`
        to prevent other threads from starting a simultaneous operation.
        The lock is released when you consume/destroy the generator.
        See :ref:`concurrency`.

        .. warning::

            It's not currently possible to cancel an encryption operation
            by deleting the generator. You must consume the generator to
            complete the operation.

        An example of streaming a file is as follows:

        ::

            def encrypt_file(file_in, file_out, buffer_size=8192):

                with \\
                        open(file_in, 'rb') as input_, \\
                        open(file_out, 'wb') as output:

                    chunks = iter(lambda: input_.read(buffer_size), '')

                    for chunk in key.encrypt(chunks,
                                             mechanism_param=iv,
                                             buffer_size=buffer_size):
                        output.write(chunk)

        :param data: data to encrypt
        :type data: str, bytes or iter(bytes)
        :param Mechanism mechanism: optional encryption mechanism
            (or None for default)
        :param bytes mechanism_param: optional mechanism parameter
            (e.g. initialisation vector).
        :param int buffer_size: size of the working buffer (for generators)

        :rtype: bytes or iter(bytes)

        .. [#] The initialisation vector should contain quality random,
            e.g. from :meth:`Session.generate_random`.
            This method will not return the value of the initialisation
            vector as part of the encryption. You must store that yourself.
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode("utf-8")

        if isinstance(data, bytes):
            return self._encrypt(data, **kwargs)

        else:
            return self._encrypt_generator(data, buffer_size=buffer_size, **kwargs)


class VerifyMixin(Object):
    """
    This :class:`Object` supports the verify capability.
    """

    def _verify(self, data: bytes, signature: bytes, **kwargs: Any) -> bool:
        raise NotImplementedError

    def _verify_generator(self, data: Iterable[bytes], signature: bytes, **kwargs: Any) -> bool:
        raise NotImplementedError

    def verify(
        self, data: Union[str, bytes, Iterable[bytes]], signature: bytes, **kwargs: Any
    ) -> bool:
        """
        Verify some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        Returns True if `signature` is valid for `data`.

        For DSA and ECDSA keys, PKCS #11 expects the two parameters (r & s)
        as two concatenated `biginteger` of the same length. To convert these
        from other formats, such as the format used by OpenSSL, use
        :func:`pkcs11.util.dsa.decode_dsa_signature` or
        :func:`pkcs11.util.ec.decode_ecdsa_signature`.

        :param data: data to sign
        :type data: str, bytes or iter(bytes)
        :param bytes signature: signature
        :param Mechanism mechanism: optional signing mechanism
        :param bytes mechanism_param: optional mechanism parameter

        :rtype: bool
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode("utf-8")

        try:
            if isinstance(data, bytes):
                self._verify(data, signature, **kwargs)
            else:
                self._verify_generator(data, signature, **kwargs)

            return True

        except (SignatureInvalid, SignatureLenRange):
            return False


class DomainParameters(Object):
    """
    PKCS#11 Domain Parameters.

    Used to store domain parameters as part of the key generation step, e.g.
    in DSA and Diffie-Hellman.
    """

    def __init__(
        self, session: Session, handle: Optional[int], params: Optional[AttributeDict] = None
    ):
        super().__init__(session, handle)
        self.params = params

    def __getitem__(self, key: Attribute) -> Any:
        if self._handle is None:
            try:
                return self.params[key]  # type: ignore[index]  # seems to be handled somehow?
            except KeyError as ex:
                raise AttributeTypeInvalid from ex
        else:
            return super().__getitem__(key)

    def __setitem__(self, key: Attribute, value: Any) -> None:
        if self._handle is None:
            self.params[key] = value  # type: ignore[index]  # seems to be handled somehow?
        else:
            super().__setitem__(key, value)

    @cached_property
    def key_type(self) -> KeyType:
        """
        Key type (:class:`pkcs11.mechanisms.KeyType`) these parameters
        can be used to generate.
        """
        return self[Attribute.KEY_TYPE]  # type: ignore[no-any-return]

    def generate_keypair(
        self,
        id: Optional[bytes] = None,
        label: Optional[str] = None,
        store: bool = False,
        capabilities: Optional[MechanismFlag] = None,
        mechanism: Optional[Mechanism] = None,
        mechanism_param: Optional[tuple[Any, ...]] = None,
        public_template: Optional[AttributeDict] = None,
        private_template: Optional[AttributeDict] = None,
    ) -> tuple["PublicKey", "PrivateKey"]:
        """
        Generate a key pair from these domain parameters (e.g. for
        Diffie-Hellman.

        See :meth:`Session.generate_key` for more information.

        :param bytes id: Key identifier.
        :param str label: Key label.
        :param store: Store key on token (requires R/W session).
        :param MechanismFlag capabilities: Key capabilities (or default).
        :param Mechanism mechanism: Generation mechanism (or default).
        :param bytes mechanism_param: Optional vector to the mechanism.
        :param dict(Attribute,*) template: Additional attributes.

        :rtype: (PublicKey, PrivateKey)
        """
        raise NotImplementedError()


class DecryptMixin(Object):
    """
    This :class:`Object` supports the decrypt capability.
    """

    def _decrypt(self, data: bytes, buffer_size: int = 8192, **kwargs: Any) -> bytes:
        raise NotImplementedError

    def _decrypt_generator(
        self, data: Union[Iterable[int], Iterable[bytes]], buffer_size: int = 8192, **kwargs: Any
    ) -> Iterator[bytes]:
        raise NotImplementedError

    @typing.overload
    def decrypt(self, data: bytes, buffer_size: int = 8192, **kwargs: Any) -> bytes: ...

    @typing.overload
    def decrypt(
        self, data: Union[Iterable[int], Iterable[bytes]], buffer_size: int = 8192, **kwargs: Any
    ) -> Iterator[bytes]: ...

    def decrypt(
        self,
        data: Union[bytes, Iterable[bytes], Iterable[int]],
        buffer_size: int = 8192,
        **kwargs: Any,
    ) -> Union[bytes, Iterator[bytes]]:
        """
        Decrypt some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        :param data: data to decrypt
        :type data: bytes or iter(bytes)
        :param Mechanism mechanism: optional encryption mechanism
            (or None for default).
        :param bytes mechanism_param: optional mechanism parameter
            (e.g. initialisation vector).
        :param pin: optional user pin for keys that require it (e.g. YubiKey)
        :param int buffer_size: size of the working buffer (for generators).

        :rtype: bytes or iter(bytes)
        """

        # If we're not an iterable, call into our generator with an iterable
        # version and join the result at the end.
        if isinstance(data, bytes):
            return self._decrypt(data, **kwargs)

        else:
            return self._decrypt_generator(data, buffer_size=buffer_size, **kwargs)


class SignMixin(Object):
    """
    This :class:`Object` supports the sign capability.
    """

    def _sign(self, data: bytes, **kwargs: Any) -> bytes:
        raise NotImplementedError

    # NOTE: Unlike other mixins, sign_generator() also returns bytes and not an iterator
    def _sign_generator(self, data: Iterable[bytes], **kwargs: Any) -> bytes:
        raise NotImplementedError

    def sign(self, data: Union[str, bytes, Iterable[bytes]], **kwargs: Any) -> bytes:
        """
        Sign some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        For DSA and ECDSA keys, PKCS #11 outputs the two parameters (r & s)
        as two concatenated `biginteger` of the same length. To convert these
        into other formats, such as the format used by OpenSSL, use
        :func:`pkcs11.util.dsa.encode_dsa_signature` or
        :func:`pkcs11.util.ec.encode_ecdsa_signature`.

        :param data: data to sign
        :type data: str, bytes or iter(bytes)
        :param Mechanism mechanism: optional signing mechanism
        :param bytes mechanism_param: optional mechanism parameter
        :param pin: optional user pin for keys that require it (e.g. YubiKey)

        :rtype: bytes
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode("utf-8")

        if isinstance(data, bytes):
            return self._sign(data, **kwargs)

        else:
            return self._sign_generator(data, **kwargs)


class WrapMixin(Object):
    """
    This :class:`Object` supports the wrap capability.
    """

    def wrap_key(
        self,
        key: "Key",
        mechanism: Optional[Mechanism] = None,
        mechanism_param: Optional[tuple[Any, ...]] = None,
    ) -> bytes:
        """
        Use this key to wrap (i.e. encrypt) `key` for export. Returns
        an encrypted version of `key`.

        `key` must have :attr:`Attribute.EXTRACTABLE` = True.

        :param Key key: key to export
        :param Mechanism mechanism: wrapping mechanism (or None for default).
        :param bytes mechanism_param: mechanism parameter (if required)

        :rtype: bytes
        """
        raise NotImplementedError()


class UnwrapMixin(Object):
    """
    This :class:`Object` supports the unwrap capability.
    """

    def unwrap_key(
        self,
        object_class: ObjectClass,
        key_type: KeyType,
        key_data: bytes,
        id: Optional[bytes] = None,
        label: Optional[bytes] = None,
        mechanism: Optional["Key"] = None,
        mechanism_param: Optional[tuple[Any, ...]] = None,
        store: bool = False,
        capabilities: Optional[MechanismFlag] = None,
        template: Optional[AttributeDict] = None,
    ) -> "Key":
        """
        Use this key to unwrap (i.e. decrypt) and import `key_data`.

        See :class:`Session.generate_key` for more information.

        :param ObjectClass object_class: Object class to import as
        :param KeyType key_type: Key type (e.g. KeyType.AES)
        :param bytes key_data: Encrypted key to unwrap
        :param bytes id: Key identifier.
        :param str label: Key label.
        :param store: Store key on token (requires R/W session).
        :param MechanismFlag capabilities: Key capabilities (or default).
        :param Mechanism mechanism: Generation mechanism (or default).
        :param bytes mechanism_param: Optional vector to the mechanism.
        :param dict(Attribute,*) template: Additional attributes.

        :rtype: Key
        """
        raise NotImplementedError()


class DeriveMixin(Object):
    """
    This :class:`Object` supports the derive capability.
    """

    def derive_key(
        self,
        key_type: KeyType,
        key_length: int,
        id: Optional[bytes] = None,
        label: Optional[bytes] = None,
        store: bool = False,
        capabilities: Optional[MechanismFlag] = None,
        mechanism: Optional[Mechanism] = None,
        mechanism_param: Optional[Union[bytes, tuple[Any, ...]]] = None,
        template: Optional[AttributeDict] = None,
    ) -> "SecretKey":
        """
        Derive a new key from this key. Used to create session
        keys from a PKCS key exchange.

        Typically the mechanism, e.g. Diffie-Hellman, requires you
        to specify the other party's piece of shared information as
        the `mechanism_param`.  Some mechanisms require a tuple of data (see
        :class:`pkcs11.mechanisms.Mechanism`).

        See :class:`Session.generate_key` for more documentation on key
        generation.

        Diffie-Hellman example:

        ::

            # Diffie-Hellman domain parameters
            # e.g. from RFC 3526, RFC 5114 or `openssl dhparam`
            prime = [0xFF, ...]
            base = [0x02]

            parameters = session.create_domain_parameters(KeyType.DH, {
                Attribute.PRIME: prime,
                Attribute.BASE: base,
            }, local=True)

            # Alice generates a DH key pair from the public
            # Diffie-Hellman parameters
            public, private = parameters.generate_keypair()
            alices_value = public[Attribute.VALUE]

            # Bob generates a DH key pair from the same parameters.

            # Alice exchanges public values with Bob...
            # She sends `alices_value` and receives `bobs_value`.
            # (Assuming Alice is doing AES CBC, she also needs to send an IV)

            # Alice generates a session key with Bob's public value
            # Bob will generate the same session key using Alice's value.
            session_key = private.derive_key(
                KeyType.AES, 128,
                mechanism_param=bobs_value)

        Elliptic-Curve Diffie-Hellman example:

        ::

            # DER encoded EC params, e.g. from OpenSSL
            # openssl ecparam -outform der -name prime192v1 | base64
            #
            # Check what EC parameters the module supports with
            # slot.get_module_info()
            parameters = session.create_domain_parameters(KeyType.EC, {
                Attribute.EC_PARAMS: b'...',
            }, local=True)

            # Alice generates a EC key pair, and gets her public value
            public, private = parameters.generate_keypair()
            alices_value = public[Attribute.EC_POINT]

            # Bob generates a DH key pair from the same parameters.

            # Alice exchanges public values with Bob...
            # She sends `alices_value` and receives `bobs_value`.

            # Alice generates a session key with Bob's public value
            # Bob will generate the same session key using Alice's value.
            session_key = private.derive_key(
                KeyType.AES, 128,
                mechanism_param=(KDF.NULL, None, bobs_value))

        :param KeyType key_type: Key type (e.g. KeyType.AES)
        :param int key_length: Key length in bits (e.g. 256).
        :param bytes id: Key identifier.
        :param str label: Key label.
        :param store: Store key on token (requires R/W session).
        :param MechanismFlag capabilities: Key capabilities (or default).
        :param Mechanism mechanism: Generation mechanism (or default).
        :param bytes mechanism_param: Optional vector to the mechanism.
        :param dict(Attribute,*) template: Additional attributes.

        :rtype: SecretKey
        """
        raise NotImplementedError()


class Key(Object):
    """Base class for all key :class:`Object` types."""

    @cached_property
    def id(self) -> bytes:
        """Key id (:class:`bytes`)."""
        return self[Attribute.ID]  # type: ignore[no-any-return]

    @cached_property
    def label(self) -> str:
        """Key label (:class:`str`)."""
        return self[Attribute.LABEL]  # type: ignore[no-any-return]

    @property
    def key_length(self) -> int:
        raise NotImplementedError()

    @cached_property
    def key_type(self) -> KeyType:
        """Key type (:class:`pkcs11.mechanisms.KeyType`)."""
        return self[Attribute.KEY_TYPE]  # type: ignore[no-any-return]

    @cached_property
    def _key_description(self) -> str:
        """A description of the key."""
        try:
            return "%s-bit %s" % (self.key_length, self.key_type.name)
        except AttributeTypeInvalid:
            return self.key_type.name

    def __repr__(self) -> str:
        return "<%s label='%s' id='%s' %s>" % (
            type(self).__name__,
            self.label,
            hexlify(self.id).decode("ascii"),
            self._key_description,
        )


class SecretKey(
    DecryptMixin, DeriveMixin, EncryptMixin, SignMixin, UnwrapMixin, VerifyMixin, WrapMixin, Key
):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.SECRET_KEY` object
    (symmetric encryption key).
    """

    object_class = ObjectClass.SECRET_KEY

    @cached_property
    def key_length(self) -> int:
        """Key length in bits."""
        return self[Attribute.VALUE_LEN] * 8  # type: ignore[no-any-return]


class PublicKey(EncryptMixin, VerifyMixin, WrapMixin, Key):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.PUBLIC_KEY` object
    (asymmetric public key).

    RSA private keys can be imported and exported from PKCS#1 DER-encoding
    using :func:`pkcs11.util.rsa.decode_rsa_public_key` and
    :func:`pkcs11.util.rsa.encode_rsa_public_key` respectively.
    """

    object_class = ObjectClass.PUBLIC_KEY

    @cached_property
    def key_length(self) -> int:
        """Key length in bits."""
        return self[Attribute.MODULUS_BITS]  # type: ignore[no-any-return]


class PrivateKey(DecryptMixin, DeriveMixin, SignMixin, UnwrapMixin, Key):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.PRIVATE_KEY` object
    (asymmetric private key).

    RSA private keys can be imported from PKCS#1 DER-encoding using
    :func:`pkcs11.util.rsa.decode_rsa_private_key`.

    .. warning::

        Private keys imported directly, rather than unwrapped from a trusted
        private key should be considered insecure.
    """

    object_class = ObjectClass.PRIVATE_KEY

    @cached_property
    def key_length(self) -> int:
        """Key length in bits."""
        return len(self[Attribute.MODULUS]) * 8


class Certificate(Object):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.CERTIFICATE` object.

    PKCS#11 is limited in its handling of certificates, and does not
    provide features like parsing of X.509 etc. These should be handled in
    an external library. PKCS#11 will not set attributes on the certificate
    based on the `VALUE`.

    :func:`pkcs11.util.x509.decode_x509_certificate` will extract attributes
    from a certificate to create the object.
    """

    object_class = ObjectClass.CERTIFICATE

    @cached_property
    def certificate_type(self) -> int:  # TODO: Unclear if this is a KeyType or some othe renum
        """
        The type of certificate.

        :rtype: CertificateType
        """
        return self[Attribute.CERTIFICATE_TYPE]  # type: ignore[no-any-return]
