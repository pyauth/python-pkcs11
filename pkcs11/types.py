"""
Types for high level PKCS#11 wrapper.

This module provides stubs that are overrideen in pkcs11._pkcs11.
"""

from threading import RLock
from binascii import hexlify

from .constants import *
from .mechanisms import *
from .exceptions import *


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
        # Big operation lock prevents other threads from entering/reentering
        # operations. If the same thread enters the lock, they will get a
        # Cryptoki warning
        self._operation_lock = RLock()

        self.rw = rw
        """True if this is a read/write session."""
        self.user_type = user_type
        """User type for this session (:class:`pkcs11.constants.UserType`)."""

    def __eq__(self, other):
        return self.token == other.token and \
            self._handle == other._handle

    def __hash__(self):
        return hash(self._handle)

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.close()

    def close(self):
        """Close the session."""
        raise NotImplementedError()

    def get_key(self, object_class=None, key_type=None, label=None, id=None):
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

        if object_class is None and \
                key_type is None and \
                label is None \
                and id is None:
            raise ArgumentsBad("Must specify at least one search parameter.")

        attrs = {}

        if object_class is not None:
            attrs[Attribute.CLASS] = object_class

        if key_type is not None:
            attrs[Attribute.KEY_TYPE] = key_type

        if label is not None:
            attrs[Attribute.LABEL] = label

        if id is not None:
            attrs[Attribute.ID] = id

        iterator = self.get_objects(attrs)

        try:
            try:
                key = next(iterator)
            except StopIteration:
                raise NoSuchKey("No key matching %s" % attrs)

            try:
                next(iterator)
                raise MultipleObjectsReturned("More than 1 key matches %s" %
                                              attrs)
            except StopIteration:
                return key
        finally:
            # Force finalizing SearchIter rather than waiting for garbage
            # collection, so that we release the operation lock.
            iterator._finalize()

    def get_objects(self, attrs=None):
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

    def create_object(self, attrs):
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
        For importing keys see :meth:`import_key`.

        Requires a read/write session, unless the object is not to be
        stored.

        :param dict(Attribute,*) attrs: attributes of the object to create
        :rtype: Object
        """
        raise NotImplementedError()

    def generate_key(self, key_type, key_length,
                     id=None, label=None,
                     store=True, capabilities=None,
                     mechanism=None, mechanism_param=None,
                     template=None):
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

    def generate_keypair(self, key_type, key_length,
                         id=None, label=None,
                         store=True, capabilities=None,
                         mechanism=None, mechanism_param=None,
                         public_template=None, private_template=None):
        """
        Generate a asymmetric keypair (e.g. RSA).

        See :meth:`generate_key` for more information.

        :param KeyType key_type: Key type (e.g. KeyType.AES)
        :param int key_length: Key length in bits (e.g. 256).
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

    def seed_random(self, seed):
        """
        Mix additional seed material into the RNG (if supported).

        :param bytes seed: Bytes of random to seed.
        """
        raise NotImplementedError()

    def generate_random(self, nbits):
        """
        Generate `length` bits of random or pseudo-random data (if supported).

        :param int nbits: Number of bits to generate.
        :rtype: bytes
        """
        raise NotImplementedError()


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

    object_class = None
    """:class:`pkcs11.constants.ObjectClass` of this Object."""

    def __init__(self, session, handle):
        self.session = session
        """:class:`Session` this object is valid for."""
        self._handle = handle

    def __eq__(self, other):
        return self.session == other.session and \
            self._handle == other._handle

    def __hash__(self):
        return hash((self.session, self._handle))

    def copy(self, attrs):
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

    def destroy(self):
        """
        Destroy the object.

        Requires a read/write session, unless the object is not stored.

        Certain objects may not be destroyed. Calling :meth:`destroy` on such
        objects will result in an exception.

        The :class:`Object` is no longer valid.
        """
        raise NotImplementedError()


class DomainParameters(Object):
    """
    PKCS#11 Domain Parameters.

    Used to store domain parameters as part of the key generation step, e.g.
    in DSA and Diffie-Hellman.
    """

    @property
    def key_type(self):
        """
        Key type (:class:`pkcs11.mechanisms.KeyType`) these parameters
        can be used to generate.
        """
        return self[Attribute.KEY_TYPE]

    def generate_keypair(self, id=None, label=None,
                         store=False, capabilities=None,
                         mechanism=None, mechanism_param=None,
                         public_template=None, private_template=None):
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


class PublicKey(Key):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.PUBLIC_KEY` object
    (asymmetric public key).
    """

    object_class = ObjectClass.PUBLIC_KEY

    @property
    def key_length(self):
        """Key length in bits."""
        return self[Attribute.MODULUS_BITS]


class PrivateKey(Key):
    """
    A PKCS#11 :attr:`pkcs11.constants.ObjectClass.PRIVATE_KEY` object
    (asymmetric private key).
    """

    object_class = ObjectClass.PRIVATE_KEY

    @property
    def key_length(self):
        """Key length in bits."""
        return len(self[Attribute.MODULUS]) * 8


class EncryptMixin(Object):
    """
    This :class:`Object` supports the encrypt capability.
    """

    def encrypt(self, data, buffer_size=8192, **kwargs):
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
        Documentation of these parameters is given specified in
        `PKCS #11 <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.

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
            data = data.encode('utf-8')

        if isinstance(data, bytes):
            return self._encrypt(data, **kwargs)

        else:
            return self._encrypt_generator(data,
                                           buffer_size=buffer_size, **kwargs)


class DecryptMixin(Object):
    """
    This :class:`Object` supports the decrypt capability.
    """

    def decrypt(self, data, buffer_size=8192, **kwargs):
        """
        Decrypt some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        :param data: data to decrypt
        :type data: bytes or iter(bytes)
        :param Mechanism mechanism: optional encryption mechanism
            (or None for default).
        :param bytes mechanism_param: optional mechanism parameter
            (e.g. initialisation vector).
        :param int buffer_size: size of the working buffer (for generators).

        :rtype: bytes or iter(bytes)
        """

        # If we're not an iterable, call into our generator with an iterable
        # version and join the result at the end.
        if isinstance(data, bytes):
            return self._decrypt(data, **kwargs)

        else:
            return self._decrypt_generator(data,
                                           buffer_size=buffer_size, **kwargs)


class SignMixin(Object):
    """
    This :class:`Object` supports the sign capability.
    """

    def sign(self, data, **kwargs):
        """
        Sign some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        :param data: data to sign
        :type data: str, bytes or iter(bytes)
        :param Mechanism mechanism: optional signing mechanism
        :param bytes mechanism_param: optional mechanism parameter

        :rtype: bytes
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode('utf-8')

        if isinstance(data, bytes):
            return self._sign(data, **kwargs)

        else:
            return self._sign_generator(data, **kwargs)


class VerifyMixin(Object):
    """
    This :class:`Object` supports the verify capability.
    """

    def verify(self, data, signature, **kwargs):
        """
        Verify some `data`.

        See :meth:`EncryptMixin.encrypt` for more information.

        Returns True if `signature` is valid for `data`.

        :param data: data to sign
        :type data: str, bytes or iter(bytes)
        :param bytes signature: signature
        :param Mechanism mechanism: optional signing mechanism
        :param bytes mechanism_param: optional mechanism parameter

        :rtype: bool
        """

        # If data is a string, encode it now as UTF-8.
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            if isinstance(data, bytes):
                self._verify(data, signature, **kwargs)
            else:
                self._verify_generator(data, signature, **kwargs)

            return True

        except (SignatureInvalid, SignatureLenRange):
            return False


class WrapMixin(Object):
    """
    This :class:`Object` supports the wrap capability.
    """

    def wrap_key(self, key,
                 mechanism=None, mechanism_param=None):
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

    def unwrap_key(self, object_class, key_type, key_data,
                   id=None, label=None,
                   mechanism=None, mechanism_param=None,
                   store=False, capabilities=None,
                   template=None):
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

    def derive_key(self, key_type, key_length,
                   id=None, label=None,
                   store=False, capabilities=None,
                   mechanism=None, mechanism_param=None,
                   template=None):
        """
        Derive a new key from this key. Used to create session
        keys from a PKCS key exchange.

        Typically the mechanism, e.g. Diffie-Hellman, requires you
        to specify the other party's piece of shared information as
        the `mechanism_param`.

        See :class:`Session.generate_key` for more documentation on key
        generation.

        ::

            # Diffie-Hellman domain parameters
            # e.g. from RFC 3526, RFC 5114 or `openssl dhparam`
            prime = [0xFF, ...]
            base = [0x02]

            parameters = session.create_object({
                Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS,
                Attribute.KEY_TYPE: KeyType.DH,
                Attribute.PRIME: prime,
                Attribute.BASE: base,
            })

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
