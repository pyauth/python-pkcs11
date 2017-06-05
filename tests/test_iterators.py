"""
Iterator tests
"""

import unittest

import pkcs11

from . import TestCase


class IteratorTests(TestCase):

    def test_partial_decrypt(self):
        self.session.generate_key(pkcs11.KeyType.AES, 128,
                                  label='LOOK ME UP')

        key = self.session.get_key(label='LOOK ME UP')
        data = (
            b'1234',
            b'1234',
        )

        iv = self.session.generate_random(128)
        encrypted_data = list(key.encrypt(data, mechanism_param=iv))

        iter1 = key.decrypt(encrypted_data, mechanism_param=iv)
        next(iter1)

        with self.assertRaises(pkcs11.OperationActive):
            iter2 = key.decrypt(encrypted_data, mechanism_param=iv)
            next(iter2)

    # Ideally deleting iterator #1 would terminate the operation, but it
    # currently does not.
    @unittest.expectedFailure
    def test_close_iterators(self):
        self.session.generate_key(pkcs11.KeyType.AES, 128,
                                  label='LOOK ME UP')

        key = self.session.get_key(label='LOOK ME UP')
        data = (
            b'1234',
            b'1234',
        )

        iv = self.session.generate_random(128)
        encrypted_data = list(key.encrypt(data, mechanism_param=iv))

        iter1 = key.decrypt(encrypted_data, mechanism_param=iv)
        next(iter1)
        del iter1

        iter2 = key.decrypt(encrypted_data, mechanism_param=iv)
        next(iter2)
