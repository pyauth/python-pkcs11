"""
PKCS#11 Tests
"""

import os
import unittest

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

    def setUp(self):
        super().setUp()
        self.lib = lib = pkcs11.lib(LIB)

        if self.with_token or self.with_session:
            self.token = token = lib.get_token(token_label=TOKEN)

        if self.with_session:
            self.session = token.open(user_pin=TOKEN_PIN)

    def tearDown(self):
        if self.with_session:
            self.session.close()

        super().tearDown()


class Is:
    """
    Test what device we're using.
    """
    softhsm2 = LIB.endswith('libsofthsm2.so')
    nfast = LIB.endswith('libcknfast.so')


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
