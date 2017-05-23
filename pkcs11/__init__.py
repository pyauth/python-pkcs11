"""
:mod:`pkcs11` defines a high-level, "Pythonic" interface to PKCS#11.
"""

from .constants import *
from .exceptions import *
from .mechanisms import *
from .types import *


_so = None
_lib = None


def lib(so):
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.
    """
    global _lib
    global _so

    if _lib:
        if _so != so:
            raise AlreadyInitialized("Already initialized with %s" % so)
        else:
            return _lib

    # Initialise ourselves now
    from ._loader import load
    load(so)

    from . import _pkcs11

    _lib = _pkcs11.lib(so)
    _so = so

    return _lib
