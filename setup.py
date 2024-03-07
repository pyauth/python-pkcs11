#!/usr/bin/env python3

"""
Installation file. 
"""

import sys

from setuptools import Extension, find_packages, setup


def get_libraries(ls: bool = False) -> tuple|list:
    """
    Check the OS and return link to user32 if OS is Windows. 

    Args:
        `ls` (bool, optional): Indicate if it should return a list or not. Defaults to False.

    Returns:
        tuple|list: Return user32 in the selected format.
    """
    if sys.platform == 'win32':
        if ls is True:
            return ['user32', ]
        else:
            return ('user32', )
    else:
        if ls is True:
            return []
        else:
            return ()
        
try:
    setup(
        packages=find_packages(exclude=['tests']),
        include_package_data=True,
        ext_modules=[Extension(name = "pkcs11._pkcs11",
                               sources = ["pkcs11/_pkcs11.pyx"],
                               libraries = get_libraries())],
        test_suite = 'tests'
    )
except:
    setup(
        packages=find_packages(exclude=['tests']),
        include_package_data=True,
        ext_modules=[Extension(name = "pkcs11._pkcs11",
                               sources = ["pkcs11/_pkcs11.pyx"],
                               libraries = get_libraries(ls=True))],
        test_suite = 'tests'
    )