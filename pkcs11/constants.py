"""
PKCS#11 constants.

See the Python :mod:`enum` documentation for more information on how to
use these classes.
"""

from struct import Struct

try:
    from enum import IntEnum, IntFlag, unique
except ImportError:
    from aenum import IntEnum, IntFlag, unique


@unique
class UserType(IntEnum):
    """PKCS#11 user types."""

    NOBODY = 999
    """
    Not officially in the PKCS#11 spec. Used to represent a session that is not
    logged in.
    """
    SO = 0
    """Security officer."""
    USER = 1


class ObjectClass(IntEnum):
    """
    PKCS#11 :class:`Object` class.

    This is the type of object we have.
    """
    DATA              = 0x00000000
    CERTIFICATE       = 0x00000001
    PUBLIC_KEY        = 0x00000002
    """See :class:`pkcs11.PublicKey`."""
    PRIVATE_KEY       = 0x00000003
    """See :class:`pkcs11.PrivateKey`."""
    SECRET_KEY        = 0x00000004
    """See :class:`pkcs11.SecretKey`."""
    HW_FEATURE        = 0x00000005
    DOMAIN_PARAMETERS = 0x00000006
    MECHANISM         = 0x00000007
    OTP_KEY           = 0x00000008

    VENDOR_DEFINED    = 0x80000000

    def __repr__(self):
        return '<ObjectClass.%s>' % self.name


class Attribute(IntEnum):
    """
    PKCS#11 object attributes.

    Not all attributes are relevant to all objects.
    Relevant attributes for each object type are given in
    `PKCS #11 <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_.
    """

    CLASS              = 0x00000000
    """Object type (:class:`ObjectClass`)."""
    TOKEN              = 0x00000001
    """
    If True object will be stored to token.
    Otherwise has session lifetime (:class:`bool`).
    """
    PRIVATE            = 0x00000002
    """
    True if user must be authenticated to access this object (:class:`bool`).
    """
    LABEL              = 0x00000003
    """Object label (:class:`str`)."""
    APPLICATION        = 0x00000010
    VALUE              = 0x00000011
    """Object value. May be `SENSITIVE` (:class:`bytes`)."""
    OBJECT_ID          = 0x00000012
    CERTIFICATE_TYPE   = 0x00000080
    ISSUER             = 0x00000081
    SERIAL_NUMBER      = 0x00000082
    AC_ISSUER          = 0x00000083
    OWNER              = 0x00000084
    ATTR_TYPES         = 0x00000085
    TRUSTED            = 0x00000086
    """
    This key can be used to wrap keys with `WRAP_WITH_TRUSTED` set
    (:class:`bool`).
    """
    CERTIFICATE_CATEGORY        = 0x00000087
    JAVA_MIDP_SECURITY_DOMAIN   = 0x00000088
    URL                         = 0x00000089
    HASH_OF_SUBJECT_PUBLIC_KEY  = 0x0000008A
    HASH_OF_ISSUER_PUBLIC_KEY   = 0x0000008B
    CHECK_VALUE                 = 0x00000090
    """`VALUE` checksum. Key Check Value (:class:`bytes`)."""

    KEY_TYPE            = 0x00000100
    """Key type (:class:`KeyType`)."""
    SUBJECT             = 0x00000101
    ID                  = 0x00000102
    """Key ID (bytes)."""
    SENSITIVE           = 0x00000103
    """
    Sensitive attributes cannot be retrieved from the HSM
    (e.g. `VALUE` or `PRIVATE_EXPONENT`) (:class:`bool`).
    """
    ENCRYPT             = 0x00000104
    """Key supports encryption (:class:`bool`)."""
    DECRYPT             = 0x00000105
    """Key supports decryption (:class:`bool`)."""
    WRAP                = 0x00000106
    """Key supports wrapping (:class:`bool`)."""
    UNWRAP              = 0x00000107
    """Key supports unwrapping (:class:`bool`)."""
    SIGN                = 0x00000108
    """Key supports signing (:class:`bool`)."""
    SIGN_RECOVER        = 0x00000109
    VERIFY              = 0x0000010A
    """Key supports signature verification (:class:`bool`)."""
    VERIFY_RECOVER      = 0x0000010B
    DERIVE              = 0x0000010C
    """Key supports key derivation (:class:`bool`)."""
    START_DATE          = 0x00000110
    """Start date for the object's validity."""
    END_DATE            = 0x00000111
    """End date for the object's validity."""
    MODULUS             = 0x00000120
    """RSA private key modulus (n)."""
    MODULUS_BITS        = 0x00000121
    """
    RSA private key modulus length. Use this for private key generation
    (:class:`int`).
    """
    PUBLIC_EXPONENT     = 0x00000122
    """RSA public exponent (e)."""
    PRIVATE_EXPONENT    = 0x00000123
    """RSA private exponent (d)."""
    PRIME_1             = 0x00000124
    """RSA private key prime #1 (p). May not be stored."""
    PRIME_2             = 0x00000125
    """RSA private key prime #2 (q). May not be stored."""
    EXPONENT_1          = 0x00000126
    """RSA private key exponent #1 (d mod p-1). May not be stored."""
    EXPONENT_2          = 0x00000127
    """RSA private key exponent #2 (d mod q-1). May not be stored."""
    COEFFICIENT         = 0x00000128
    """RSA private key CRT coefficient (q^-1 mod p). May not be stored."""
    PRIME               = 0x00000130
    SUBPRIME            = 0x00000131
    BASE                = 0x00000132

    PRIME_BITS          = 0x00000133
    SUBPRIME_BITS       = 0x00000134

    VALUE_BITS          = 0x00000160
    VALUE_LEN           = 0x00000161
    """
    `VALUE` length in bytes. Use this for secret key generation
    (:class:`int`).
    """
    EXTRACTABLE         = 0x00000162
    """Key can be extracted wrapped."""
    LOCAL               = 0x00000163
    """True if generated on the token, False if imported."""
    NEVER_EXTRACTABLE   = 0x00000164
    """`EXTRACTABLE` has always been False."""
    ALWAYS_SENSITIVE    = 0x00000165
    """`SENSITIVE` has always been True."""
    KEY_GEN_MECHANISM   = 0x00000166
    """Key generation mechanism (:class:`pkcs11.mechanisms.Mechanism`)."""

    MODIFIABLE          = 0x00000170
    """Object can be modified (:class:`bool`)."""

    ECDSA_PARAMS        = 0x00000180
    EC_PARAMS           = 0x00000180

    EC_POINT            = 0x00000181

    SECONDARY_AUTH      = 0x00000200
    AUTH_PIN_FLAGS      = 0x00000201

    ALWAYS_AUTHENTICATE       = 0x00000202
    """
    User has to provide pin with each use (sign or decrypt) (:class:`bool`).
    """

    WRAP_WITH_TRUSTED         = 0x00000210
    """Key can only be wrapped with a `TRUSTED` key."""
    # WRAP_TEMPLATE       = (CKF_ARRAY_ATTRIBUTE|0x00000211)
    # UNWRAP_TEMPLATE     = (CKF_ARRAY_ATTRIBUTE|0x00000212)
    # DERIVE_TEMPLATE     = (CKF_ARRAY_ATTRIBUTE|0x00000213)

    OTP_FORMAT                = 0x00000220
    OTP_LENGTH                = 0x00000221
    OTP_TIME_INTERVAL         = 0x00000222
    OTP_USER_FRIENDLY_MODE    = 0x00000223
    OTP_CHALLENGE_REQUIREMENT = 0x00000224
    OTP_TIME_REQUIREMENT      = 0x00000225
    OTP_COUNTER_REQUIREMENT   = 0x00000226
    OTP_PIN_REQUIREMENT       = 0x00000227
    OTP_COUNTER               = 0x0000022E
    OTP_TIME                  = 0x0000022F
    OTP_USER_IDENTIFIER       = 0x0000022A
    OTP_SERVICE_IDENTIFIER    = 0x0000022B
    OTP_SERVICE_LOGO          = 0x0000022C
    OTP_SERVICE_LOGO_TYPE     = 0x0000022D

    GOSTR3410_PARAMS          = 0x00000250
    GOSTR3411_PARAMS          = 0x00000251
    GOST28147_PARAMS          = 0x00000252

    HW_FEATURE_TYPE           = 0x00000300
    RESET_ON_INIT             = 0x00000301
    HAS_RESET                 = 0x00000302

    PIXEL_X                   = 0x00000400
    PIXEL_Y                   = 0x00000401
    RESOLUTION                = 0x00000402
    CHAR_ROWS                 = 0x00000403
    CHAR_COLUMNS              = 0x00000404
    COLOR                     = 0x00000405
    BITS_PER_PIXEL            = 0x00000406
    CHAR_SETS                 = 0x00000480
    ENCODING_METHODS          = 0x00000481
    MIME_TYPES                = 0x00000482
    MECHANISM_TYPE            = 0x00000500
    REQUIRED_CMS_ATTRIBUTES   = 0x00000501
    DEFAULT_CMS_ATTRIBUTES    = 0x00000502
    SUPPORTED_CMS_ATTRIBUTES  = 0x00000503
    # ALLOWED_MECHANISMS        = (CKF_ARRAY_ATTRIBUTE|0x00000600)

    VENDOR_DEFINED            = 0x80000000

    def __repr__(self):
        return '<Attribute.%s>' % self.name


@unique
class MechanismFlag(IntFlag):
    """
    Describes the capabilities of a :class:`pkcs11.mechanisms.Mechanism`
    or :class:`pkcs11.Object`.

    Some objects and mechanisms are symmetric (i.e. can be used for encryption
    and decryption), some are asymmetric (e.g. public key cryptography).
    """
    ENCRYPT           = 0x00000100
    """Can be used for encryption."""
    DECRYPT           = 0x00000200
    """Can be used for decryption."""
    DIGEST            = 0x00000400
    """Can make a message digest (hash)."""
    SIGN              = 0x00000800
    """Can calculate digital signature."""
    SIGN_RECOVER      = 0x00001000
    VERIFY            = 0x00002000
    """Can verify digital signature."""
    VERIFY_RECOVER    = 0x00004000
    GENERATE          = 0x00008000
    """Can generate key/object."""
    GENERATE_KEY_PAIR = 0x00010000
    """Can generate key pair."""
    WRAP              = 0x00020000
    """Can wrap a key for export."""
    UNWRAP            = 0x00040000
    """Can unwrap a key for import."""
    DERIVE            = 0x00080000
    """Can derive a key from another key."""


@unique
class SlotFlag(IntFlag):
    """:class:`pkcs11.Slot` flags."""

    TOKEN_PRESENT    = 0x00000001
    """A token is there (N.B. some hardware known not to set this.)"""
    REMOVABLE_DEVICE = 0x00000002
    """Removable devices."""
    HW_SLOT          = 0x00000004
    """Hardware slot."""


@unique
class TokenFlag(IntFlag):
    """:class:`pkcs11.Token` flags."""

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
