"""
High-level Python PKCS#11 Wrapper.
"""

from .types import *
from .exceptions import *
from .mechanisms import *


def lib(so):
    """
    Returns a PKCS#11 library.
    """

    from ._loader import load
    load(so)

    from . import _pkcs11

    return _pkcs11.lib()
