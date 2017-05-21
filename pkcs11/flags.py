"""
These are equivalent to the CKF_* flags from the Cryptoki standard but grouped
by purpose.

See the Python :class:`IntFlag` documentation for more information on how to
use these classes.
"""

try:
    from enum import IntFlag, unique
except ImportError:
    from aenum import IntFlag, unique


@unique
class SlotFlags(IntFlag):
    """:class:`Slot` flags."""

    TOKEN_PRESENT    = 0x00000001
    """A token is there (N.B. some hardware known not to set this.)"""
    REMOVABLE_DEVICE = 0x00000002
    """Removable devices."""
    HW_SLOT          = 0x00000004
    """Hardware slot."""


@unique
class TokenFlags(IntFlag):
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


