"""
setup.py
"""

from setuptools import setup, find_packages
from setuptools.extension import Extension

from Cython.Build import cythonize

if __name__ == '__main__':
    with \
            open('requirements.in') as requirements, \
            open('README.rst') as readme:

        ext_modules = [
            Extension('pkcs11._loader',
                    sources=[
                        'pkcs11/_loader.pyx',
                    ],
            ),
            Extension('pkcs11._pkcs11',
                    sources=[
                        'pkcs11/_pkcs11.pyx',
                        'pkcs11/_errors.pyx',
                        'pkcs11/_utils.pyx',
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
            setup_requires=['setuptools_scm'],

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
                'Topic :: Security :: Cryptography',
            ],

            packages=find_packages(exclude=['tests']),
            include_package_data=True,
            ext_modules=cythonize(ext_modules),

            install_requires=requirements.readlines(),
            test_suite='tests',
        )
