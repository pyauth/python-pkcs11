"""
setup.py
"""

from distutils.core import setup
from distutils.extension import Extension

from Cython.Build import cythonize

ext_modules = [
    Extension('_pkcs11_dyn_load',
              sources=[
                  'src/_pkcs11_dyn_load.pyx',
              ],
    ),
    Extension('pkcs11',
              sources=[
                  'src/pkcs11.pyx',
              ],
              define_macros=[
                  # These are required to build the PKCS11 headers
                  #
                  # They vary based on OS. See extern/pkcs11.h
                  ('CK_PTR', '*'),
                  ('CK_DEFINE_FUNCTION(returnType, name)', 'returnType name'),
                  ('CK_DECLARE_FUNCTION(returnType, name)', 'returnType name'),
                  ('CK_DECLARE_FUNCTION_POINTER(returnType, name)', 'returnType (* name)'),
                  ('CK_CALLBACK_FUNCTION(returnType, name)', 'returnType (* name)'),
              ],
    ),
]


setup(
    ext_modules=cythonize(ext_modules),
)
