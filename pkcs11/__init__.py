"""
:mod:`pkcs11` defines a high-level, "Pythonic" interface to PKCS#11.
"""

from .constants import *
from .exceptions import *
from .mechanisms import *
from .types import *


def lib(so):
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.
    """

    from ._loader import load
    load(so)

    from . import _pkcs11

    return _pkcs11.lib(so)
