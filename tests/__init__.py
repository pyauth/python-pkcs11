"""
PKCS#11 Tests
"""

import os
import unittest
from functools import wraps

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


try:
    TOKEN = os.environ['PKCS11_TOKEN_LABEL']
    TOKEN_PIN = os.environ.get('PKCS11_TOKEN_PIN')  # Can be None
except KeyError:
    raise RuntimeError("Must define `PKCS11_TOKEN_LABEL` to run tests.")


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
    softhsm2 = LIB.endswith('libsofthsm2.so')
    nfast = LIB.endswith('libcknfast.so')
    opencryptoki = LIB.endswith('libopencryptoki.so')


class Only:
    """
    Limit tests to given devices
    """

    softhsm2 = unittest.skipUnless(Is.softhsm2, "SoftHSMv2 only")


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
