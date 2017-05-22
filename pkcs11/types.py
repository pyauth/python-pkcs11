"""
Types for high level PKCS#11 wrapper.

This module provides stubs that are overrideen in pkcs11._pkcs11.
"""

from binascii import hexlify

from .constants import *
from .mechanisms import *


def _CK_UTF8CHAR_to_str(data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: the last couple of bytes are sometimes bogus, is this me
    # or SoftHSM?
    return data[:31].decode('utf-8').rstrip()


def _CK_VERSION_to_tuple(data):
    """Convert CK_VERSION to tuple."""
    return (data['major'], data['minor'])


def _CK_MECHANISM_TYPE_to_enum(mechanism):
    """Convert CK_MECHANISM_TYPE to enum or be okay."""
    try:
        return Mechanism(mechanism)
    except ValueError:
        return mechanism


class Slot:
    """
    A PKCS#11 device slot.

    This object represents a physical or software slot exposed by PKCS#11.
    A slot has hardware capabilities, e.g. supported mechanisms and may has
    a physical or software :class:`Token` installed.
    """

    def __init__(self, lib, slot_id,
                 slotDescription=None,
                 manufacturerID=None,
                 hardwareVersion=None,
                 firmwareVersion=None,
                 flags=None,
                 **kwargs):

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

    def get_token(self):
        """
        Returns the token loaded into this slot.

        :rtype: Token
        """
        raise NotImplementedError()

    def get_mechanisms(self):
        """
        Returns the mechanisms supported by this device.

        :rtype: set(Mechanism)
        """
        raise NotImplementedError()

    def __eq__(self, other):
        return self.slot_id == other.slot_id

    def __str__(self):
        return '\n'.join((
            "Slot Description: %s" % self.slot_description,
            "Manufacturer ID: %s" % self.manufacturer_id,
            "Hardware Version: %s.%s" % self.hardware_version,
            "Firmware Version: %s.%s" % self.firmware_version,
            "Flags: %s" % self.flags,
        ))

    def __repr__(self):
        return '<{klass} (slotID={slot_id} flags={flags})>'.format(
            klass=type(self).__name__,
            slot_id=self.slot_id,
            flags=str(self.flags))


class Token:
    """
    A PKCS#11 token.

    A token can be physically installed in a :class:`Slot`, or a software
    token, depending on your PKCS#11 library.
    """

    def __init__(self, slot,
                 label=None, serial=None, flags=None,
                 **kwargs):

        self.slot = slot
        """The :class:`Slot` this token is installed in."""
        self.label = _CK_UTF8CHAR_to_str(label)
        """Label of this token (:class:`str`)."""
        self.serial = serial
        """Serial number of this token (:class:`bytes`)."""
        self.flags = TokenFlag(flags)
        """Capabilities of this token (:class:`pkcs11.flags.TokenFlag`)."""

    def __eq__(self, other):
        return self.slot == other.slot

    def open(self, rw=False, user_pin=None, so_pin=None):
        """
        Open a session on the token and optionally log in as a user or
        security officer (pass one of `user_pin` or `so_pin`).

        Can be used as a context manager or close with :meth:`Session.close`.

        ::

            with token.open() as session:

                print(session)

        :param rw: True to create a read/write session.
        :param bytes user_pin: Authenticate to this session as a user.
        :param bytes so_pin: Authenticate to this session as a
            security officer.

        :rtype: Session
        """
        raise NotImplementedError()

    def __str__(self):
        return self.label

    def __repr__(self):
        return "<{klass} (label='{label}' serial={serial} flags={flags})>"\
            .format(klass=type(self).__name__,
                    label=self.label,
                    serial=self.serial,
                    flags=str(self.flags))


class Session:
    """
    A PKCS#11 :class:`Token` session.

    A session is required to do nearly all operations on a token including
    encryption/signing/keygen etc.

    Create a session using :meth:`Token.open`. Sessions can be used as a
    context manager or closed with :meth:`close`.
    """

    def __init__(self, token, handle, rw=False, user_type=UserType.NOBODY):
        self.token = token
        """:class:`Token` this session is on."""

        self._handle = handle
        self.rw = rw
        """True if this is a read/write session."""
        self.user_type = user_type
        """User type for this session (:class:`pkcs11.constants.UserType`)."""

    def __eq__(self, other):
        return self.token == other.token and \
            self._handle == other._handle

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.close()

    def close(self):
        """Close the session."""
        raise NotImplementedError()

    def get_objects(self, attrs):
        """
        Search for objects matching `attrs`.

        ::

            for obj in session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.LABEL: 'MY LABEL',
            }):

                print(obj)

        :param dict(Attribute,*) attrs: Attributes to search for.

        :rtype: iter(Object)
        """
        raise NotImplementedError()

    def generate_key(self, key_type, key_length,
                     id=None, label=None,
                     store=True, capabilities=None,
                     mechanism=None, mechanism_param=b'',
                     template=None):
        """
        Generate a single key (e.g. AES, DES).

        Keys should set at least `id` or `label`.

        An appropriate `mechanism` will be chosen for `key_type`
        (see :attr:`DEFAULT_GENERATE_MECHANISMS`) or this can be overridden.
        Similarly the `capabilities` (see :attr:`DEFAULT_KEY_CAPABILITIES`).

        The `template` will extend the default template used to make the
        key.

        :param KeyType key_type: Key type (e.g. KeyType.AES)
        :param int key_length: Key length in bits (e.g. 256).
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


class Object:
    """
    A PKCS#11 object residing on a :class:`Token`.

    Objects implement :meth:`__getitem__` and :meth:`__setitem__` to
    retrieve :class:`pkcs11.constants.Attribute` values on the object.
    """

    object_class = None
    """:class:`pkcs11.constants.ObjectClass` of this Object."""

    def __init__(self, session, handle):
        self.session = session
        """:class:`Session` this object is valid for."""
        self._handle = handle

    def __eq__(self, other):
        return self.session == other.session and \
            self._handle == other._handle

    def destroy(self):
        """
        Destroy the object.

        Requires a R/W session.
        """
        raise NotImplementedError()


class Key(Object):
    """Base class for all key :class:`Object` types."""

    @property
    def id(self):
        """Key id (:class:`bytes`)."""
        return self[Attribute.ID]

    @property
    def label(self):
        """Key label (:class:`str`)."""
        return self[Attribute.LABEL]

    @property
    def key_type(self):
        """Key type (:class:`pkcs11.mechanisms.KeyType`)."""
        return self[Attribute.KEY_TYPE]

    def __repr__(self):
        return "<%s label='%s' id='%s' %s-bit %s>" % (
            type(self).__name__,
            self.label,
            hexlify(self.id).decode('ascii'),
            self.key_length,
            self.key_type.name)


class SecretKey(Key):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.SECRET_KEY` object
    (symmetric encryption key).
    """

    object_class = ObjectClass.SECRET_KEY

    @property
    def key_length(self):
        """Key length in bits."""
        return self[Attribute.VALUE_LEN] * 8


class EncryptMixin(Object):
    """
    This :class:`Object` supports the encrypt capability.
    """

    def _encrypt(self, data, mechanism=None, mechanism_param=b''):
        raise NotImplementedError()

    def encrypt(self, data, **kwargs):
        """
        Encrypt some `data`.

        Data can be either :class:`str` or :class:`bytes`, in which case it
        will return :class:`bytes`; or an iterable of :class:`bytes` in
        which case it will return a generator yielding :class:`bytes`
        (be aware, more chunks will be output than input).

        If you do not specify `mechanism` then the default from
        :attr:`DEFAULT_ENCRYPT_MECHANISMS` will be used.

        Some mechanisms (including the default CBC mechanisms) require an
        initialisation vector (of key length) to set the initial state of
        the mechanism.  Pass this as `mechanism_param`. The initialisation
        vector should contain quality random. This method will not return
        the value of the initialisation parameter.

        `buffer_size` must be sufficient to store the working buffer. An
        integer number of blocks and greater than or equal to the largest
        input chunk is recommended.

        :param data: data to encrypt
        :type data: str, bytes or iter(bytes)
        :param Mechanism mechanism: optional encryption mechanism
            (or None for default)
        :param bytes mechanism_param: optional mechanism parameter
            (e.g. initialisation vector).
        :param int buffer_size: size of the working buffer (default 1024).

        :rtype: bytes or iter(bytes)
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode('utf-8')

        # If we're not an iterable, recurse into ourselves with an iterable
        # version and join the result at the end.
        if isinstance(data, bytes):
            return b''.join(self._encrypt((data,), **kwargs))

        else:
            return self._encrypt(data, **kwargs)


class DecryptMixin(Object):
    """
    This :class:`Object` supports the decrypt capability.
    """

    def _decrypt(self, data, mechanism=None, mechanism_param=b''):
        raise NotImplementedError()

    def decrypt(self, data, **kwargs):
        """
        Decrypt some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        :param data: data to decrypt
        :type data: bytes or iter(bytes)
        :param Mechanism mechanism: optional encryption mechanism
            (or None for default).
        :param bytes mechanism_param: optional mechanism parameter
            (e.g. initialisation vector).
        :param int buffer_size: size of the working buffer (default 1024).

        :rtype: bytes or iter(bytes)
        """

        # If we're not an iterable, recurse into ourselves with an iterable
        # version and join the result at the end.
        if isinstance(data, bytes):
            return b''.join(self._decrypt((data,), **kwargs))

        else:
            return self._decrypt(data, **kwargs)


class SignMixin(Object):
    pass


class VerifyMixin(Object):
    pass


class WrapMixin(Object):
    pass


class UnwrapMixin(Object):
    pass
