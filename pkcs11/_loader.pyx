"""
Handle dynamic loading of the library.
"""

from posix cimport dlfcn


def load(so):
    """Load the library."""

    handle = dlfcn.dlopen(so.encode('utf-8'),
                          dlfcn.RTLD_LAZY | dlfcn.RTLD_GLOBAL)

    if handle == NULL:
        raise RuntimeError(dlfcn.dlerror())
