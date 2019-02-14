"""
PKCS#11 Tests

The following environment variables will influence the behaviour of test cases:
 - PKCS11_MODULE, mandatory, points to the library/DLL to use for testing
 - PKCS11_TOKEN_LABEL, mandatory, contains the token label
 - PKCS11_TOKEN_PIN, optional (default is None), contains the PIN/passphrase of the token
 - PKCS11_TOKEN_SO_PIN, optional (default is same as PKCS11_TOKEN_PIN), security officer PIN
 - OPENSSL_PATH, optional, path to openssl executable (i.e. the folder that contains it)

"""

import os
import shutil
import unittest
from functools import wraps
from warnings import warn

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


try:
    TOKEN = os.environ['PKCS11_TOKEN_LABEL']
except KeyError:
    raise RuntimeError("Must define `PKCS11_TOKEN_LABEL' to run tests.")

TOKEN_PIN = os.environ.get('PKCS11_TOKEN_PIN')  # Can be None
if TOKEN_PIN is None:
    warn("`PKCS11_TOKEN_PIN' env variable is unset.")

TOKEN_SO_PIN = os.environ.get('PKCS11_TOKEN_SO_PIN')
if TOKEN_SO_PIN is None:
    TOKEN_SO_PIN = TOKEN_PIN
    warn("`PKCS11_TOKEN_SO_PIN' env variable is unset. Using value from `PKCS11_TOKEN_PIN'")

OPENSSL = shutil.which('openssl', path=os.environ.get('OPENSSL_PATH'))
if OPENSSL is None:
    warn("Path to OpenSSL not found. Please adjust `PATH' or define `OPENSSL_PATH'")


class TestCase(unittest.TestCase):
    """Base test case, optionally creates a token and a session."""

    with_token = True
    """Creates a token for this test case."""
    with_session = True
    """Creates a session for this test case."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lib = lib = pkcs11.lib(LIB)

        if cls.with_token or cls.with_session:
            cls.token = lib.get_token(token_label=TOKEN)

    def setUp(self):
        super().setUp()

        if self.with_session:
            self.session = self.token.open(user_pin=TOKEN_PIN)

    def tearDown(self):
        if self.with_session:
            self.session.close()

        super().tearDown()


def requires(*mechanisms):
    """
    Decorates a function or class as requiring mechanisms, else they are
    skipped.
    """

    def check_requirements(self):
        """Determine what, if any, required mechanisms are unavailable."""
        unavailable = set(mechanisms) - self.token.slot.get_mechanisms()

        if unavailable:
            raise unittest.SkipTest("Requires %s"
                                    % ', '.join(map(str, unavailable)))

    def inner(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            check_requirements(self)

            return func(self, *args, **kwargs)

        return wrapper

    return inner


def xfail(condition):
    """Mark a test that's expected to fail for a given condition."""

    def inner(func):
        if condition:
            return unittest.expectedFailure(func)

        else:
            return func

    return inner


class Is:
    """
    Test what device we're using.
    """
    # trick: str.endswith() can accept tuples,
    # see https://stackoverflow.com/questions/18351951/check-if-string-ends-with-one-of-the-strings-from-a-list
    softhsm2 = LIB.lower().endswith(('libsofthsm2.so', 'libsofthsm2.dylib', 'softhsm2.dll', 'softhsm2-x64.dll')) 
    nfast = LIB.lower().endswith(('libcknfast.so', 'cknfast.dll'))
    opencryptoki = LIB.endswith('libopencryptoki.so')
    travis = os.environ.get('TRAVIS') == 'true'


class Avail:
    """
    Test if a resource is available
    """
    # openssl is searched across the exec path. Optionally, OPENSSL_PATH env variable can be defined
    # in case there is no direct path to it (i.e. PATH does not point to it)
    openssl = OPENSSL is not None

class Only:
    """
    Limit tests to given conditions
    """
    softhsm2 = unittest.skipUnless(Is.softhsm2, "SoftHSMv2 only")
    openssl = unittest.skipUnless(Avail.openssl, "openssl not found in the path")

class Not:
    """
    Ignore tests for given devices
    """

    softhsm2 = unittest.skipIf(Is.softhsm2, "Not supported by SoftHSMv2")
    nfast = unittest.skipIf(Is.nfast, "Not supported by nFast")
    opencryptoki = unittest.skipIf(Is.opencryptoki,
                                   "Not supported by OpenCryptoki")


class FIXME:
    """
    Tests is broken on this platform.
    """

    softhsm2 = xfail(Is.softhsm2)
    nfast = xfail(Is.nfast)
    opencryptoki = xfail(Is.opencryptoki)
    travis = xfail(Is.travis)
