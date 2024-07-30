# Add cython extension module to build configuration.
#
# See also: https://setuptools.pypa.io/en/latest/userguide/ext_modules.html

from setuptools import Extension, setup
import platform

libraries = []

# if compiling using MSVC, we need to link against user32 library
if platform.system() == "Windows":
    libraries.append("user32")


setup(
    ext_modules=[
        Extension(
            name="pkcs11._pkcs11",
            sources=[
                "pkcs11/_pkcs11.pyx",
            ],
            libraries=libraries,
        ),
    ],
)
