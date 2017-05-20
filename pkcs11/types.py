"""
Types for high level PKCS#11 wrapper.

This module provides stubs that are overrideen in pkcs11._pkcs11.
"""

import enum


def _CK_UTF8CHAR_to_str(data):
    """Convert CK_UTF8CHAR to string."""
    # FIXME: the last couple of bytes are sometimes bogus, is this me
    # or SoftHSM?
    return data[:31].decode('utf-8').rstrip()


def _CK_VERSION_to_tuple(data):
    """Convert CK_VERSION to tuple."""
    return (data['major'], data['minor'])


@enum.unique
class SlotFlags(enum.IntFlag):
    """:class:`Slot` flags."""

    TOKEN_PRESENT    = 0x00000001
    """A token is there (N.B. some hardware known not to set this.)"""
    REMOVABLE_DEVICE = 0x00000002
    """Removable devices."""
    HW_SLOT          = 0x00000004
    """Hardware slot."""


@enum.unique
class TokenFlags(enum.IntFlag):
    """:class:`Token` flags."""

    RNG                   = 0x00000001
    """Has random number generator."""
    WRITE_PROTECTED       = 0x00000002
    """Token is write protected."""
    LOGIN_REQUIRED        = 0x00000004
    """User must login."""
    USER_PIN_INITIALIZED  = 0x00000008
    """Normal user's pin is set."""

    RESTORE_KEY_NOT_NEEDED = 0x00000020
    """
    If it is set, that means that *every* time the state of cryptographic
    operations of a session is successfully saved, all keys needed to continue
    those operations are stored in the state.
    """

    CLOCK_ON_TOKEN        = 0x00000040
    """
    If it is set, that means that the token has some sort of clock.  The time
    on that clock is returned in the token info structure.
    """

    PROTECTED_AUTHENTICATION_PATH = 0x00000100
    """
    If it is set, that means that there is some way for the user to login
    without sending a PIN through the Cryptoki library itself.
    """

    DUAL_CRYPTO_OPERATIONS = 0x00000200
    """
    If it is true, that means that a single session with the token can perform
    dual simultaneous cryptographic operations (digest and encrypt; decrypt and
    digest; sign and encrypt; and decrypt and sign).
    """

    TOKEN_INITIALIZED = 0x00000400
    """
    If it is true, the token has been initialized using C_InitializeToken or an
    equivalent mechanism outside the scope of PKCS #11.  Calling
    C_InitializeToken when this flag is set will cause the token to be
    reinitialized.
    """

    USER_PIN_COUNT_LOW = 0x00010000
    """
    If it is true, an incorrect user login PIN has been entered at least once
    since the last successful authentication.
    """

    USER_PIN_FINAL_TRY = 0x00020000
    """
    If it is true, supplying an incorrect user PIN will it to become locked.
    """

    USER_PIN_LOCKED = 0x00040000
    """
    If it is true, the user PIN has been locked. User login to the token is not
    possible.
    """

    USER_PIN_TO_BE_CHANGED = 0x00080000
    """
    If it is true, the user PIN value is the default value set by token
    initialization or manufacturing, or the PIN has been expired by the card.
    """

    SO_PIN_COUNT_LOW = 0x00100000
    """
    If it is true, an incorrect SO (security officer) login PIN has been
    entered at least once since the last successful authentication.
    """

    SO_PIN_FINAL_TRY = 0x00200000
    """
    If it is true, supplying an incorrect SO (security officer) PIN will it to
    become locked.
    """

    SO_PIN_LOCKED = 0x00400000
    """
    If it is true, the SO (security officer) PIN has been locked. SO login to
    the token is not possible.
    """

    SO_PIN_TO_BE_CHANGED = 0x00800000
    """
    If it is true, the SO PIN value is the default value set by token
    initialization or manufacturing, or the PIN has been expired by the card.
    """

    ERROR_STATE = 0x01000000


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
        self.flags = SlotFlags(flags)
        """Capabilities of this slot (:class:`SlotFlags`)."""

    def get_token(self):
        """
        Returns the token loaded into this slot.

        :rtype: Token
        """
        raise NotImplementedError()

    def get_mechanisms(self):
        """
        Returns the mechanisms supported by this device.

        :rtype: set(Mechanisms)
        """
        raise NotImplementedError()

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
        self.flags = TokenFlags(flags)
        """Capabilities of this token (:class:`TokenFlags`)."""

    def open(self, rw=False, user_pin=None, so_pin=None):
        """
        Open a session on the token.

        Can be used as a context manager.

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

    def __init__(self, token, handle):
        self.token = token
        """:class:`Token` this session is on."""

        self._handle = handle

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.close()

    def close(self):
        """Close the session."""
        raise NotImplementedError()
