"""
PKCS#11 Exceptions
"""

class PKCS11Error(RuntimeError):
    """
    Base exception for all PKCS#11 exceptions.
    """


class AnotherUserAlreadyLoggedIn(PKCS11Error):
    pass


class ArgumentsBad(PKCS11Error):
    pass


class DeviceError(PKCS11Error):
    pass


class DeviceMemory(PKCS11Error):
    pass


class DeviceRemoved(PKCS11Error):
    pass


class FunctionCancelled(PKCS11Error):
    pass


class FunctionFailed(PKCS11Error):
    pass


class GeneralError(PKCS11Error):
    pass


class HostMemory(PKCS11Error):
    pass


class MechanismInvalid(PKCS11Error):
    pass


class OperationNotInitialized(PKCS11Error):
    pass


class SessionClosed(PKCS11Error):
    pass


class SessionCount(PKCS11Error):
    """
    An attempt to open a session which does not succeed because there are too
    many existing sessions.
    """


class SessionHandleInvalid(PKCS11Error):
    """
    The session handle was invalid. This is usually caused by using an
    old session object that is not known to PKCS#11.
    """


class SessionReadOnly(PKCS11Error):
    pass


class SessionReadOnlyExists(PKCS11Error):
    pass


class SessionReadWriteSOExists(PKCS11Error):
    """
    If the application calling :meth:`Token.open` already has a R/W SO
    session open with the token, then any attempt to open a R/O session with
    the token fails with this exception.
    """


class PinIncorrect(PKCS11Error):
    pass


class PinLocked(PKCS11Error):
    pass


class SlotIDInvalid(PKCS11Error):
    pass


class TemplateIncomplete(PKCS11Error):
    pass


class TemplateInconsistent(PKCS11Error):
    pass


class TokenNotPresent(PKCS11Error):
    pass


class TokenNotRecognised(PKCS11Error):
    pass


class TokenWriteProtected(PKCS11Error):
    pass


class UserAlreadyLoggedIn(PKCS11Error):
    pass


class UserPinNotInitialized(PKCS11Error):
    pass


class UserTooManyTypes(PKCS11Error):
    pass
