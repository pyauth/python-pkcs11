"""
:mod:`pkcs11` defines a high-level, "Pythonic" interface to PKCS#11.
"""

import typing

from pkcs11.constants import (
    Attribute,
    CertificateType,
    MechanismFlag,
    ObjectClass,
    SlotFlag,
    TokenFlag,
    UserType,
)
from pkcs11.exceptions import *  # noqa: F403
from pkcs11.mechanisms import KDF, MGF, KeyType, Mechanism
from pkcs11.types import (
    Certificate,
    DomainParameters,
    Library,
    MechanismInfo,
    PrivateKey,
    PublicKey,
    SecretKey,
    Session,
    Slot,
    Token,
)
from pkcs11.util import dh, dsa, ec, rsa, x509

_so = None
_lib = None


def lib(so: str) -> Library:
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.
    """
    global _lib
    global _so

    if _lib:
        if _so != so:
            raise AlreadyInitialized("Already initialized with %s" % so)  # noqa: F405
        else:
            return _lib

    from . import _pkcs11  # type: ignore[attr-defined]

    _lib = typing.cast(Library, _pkcs11.lib(so))
    _so = so

    return _lib


__all__ = [
    "KDF",
    "MGF",
    "Attribute",
    "Certificate",
    "CertificateType",
    "DomainParameters",
    "KeyType",
    "Library",
    "Mechanism",
    "MechanismFlag",
    "MechanismInfo",
    "ObjectClass",
    "PrivateKey",
    "PublicKey",
    "SecretKey",
    "Session",
    "Slot",
    "SlotFlag",
    "Token",
    "TokenFlag",
    "UserType",
    "dh",
    "dsa",
    "ec",
    "lib",
    "rsa",
    "x509",
]
