#!/usr/bin/env python
"""
setup.py
"""

from setuptools import setup, find_packages
from setuptools.extension import Extension
import platform

# if compiling using MSVC, we need to link against user32 library
if platform.system() == 'Windows':
    libraries = ('user32',)
else:
    libraries = ()

if __name__ == '__main__':
    with \
            open('requirements.in') as requirements, \
            open('README.rst') as readme:

        ext_modules = [
            Extension('pkcs11._pkcs11',
                    sources=[
                        'pkcs11/_pkcs11.pyx',
                    ],
                    libraries=libraries,
            ),
        ]

        setup(
            name='python-pkcs11',
            description='PKCS#11 (Cryptoki) support for Python',
            use_scm_version=True,
            author='Danielle Madeley',
            author_email='danielle@madeley.id.au',
            url='https://github.com/danni/python-pkcs11',
            long_description=readme.read(),
            classifiers=[
                'License :: OSI Approved :: MIT License',
                'Programming Language :: Python',
                'Programming Language :: Python :: 3',
                'Programming Language :: Python :: 3.5',
                'Programming Language :: Python :: 3.6',
                'Programming Language :: Python :: 3.7',
                'Programming Language :: Python :: 3.8',
                'Topic :: Security :: Cryptography',
            ],

            packages=find_packages(exclude=['tests']),
            include_package_data=True,
            ext_modules=ext_modules,

            install_requires=requirements.readlines(),
            setup_requires=[
                'cython',
                'setuptools >= 18.0',
                'setuptools_scm',
            ],

            test_suite='tests',
        )
