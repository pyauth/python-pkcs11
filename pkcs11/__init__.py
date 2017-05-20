"""
High-level Python PKCS#11 Wrapper.
"""

from .types import *
from .exceptions import *
from .mechanisms import *


def lib(so):
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.
    """

    from ._loader import load
    load(so)

    from . import _pkcs11

    return _pkcs11.lib()
