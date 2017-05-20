"""
PKCS#11 Exceptions
"""

class PKCS11Error(RuntimeError):
    pass


class NotInitialized(PKCS11Error):
    pass


class DeviceError(PKCS11Error):
    pass


class DeviceMemory(PKCS11Error):
    pass


class DeviceRemoved(PKCS11Error):
    pass


class FunctionFailed(PKCS11Error):
    pass


class HostMemory(PKCS11Error):
    pass


class GeneralError(PKCS11Error):
    pass


class SlotIDInvalid(PKCS11Error):
    pass


class TokenNotPresent(PKCS11Error):
    pass


class TokenNotRecognised(PKCS11Error):
    pass


class ArgumentsBad(PKCS11Error):
    pass
