import os
import unittest

import pkcs11


try:
    LIB = os.environ['PKCS11_MODULE']
except KeyError:
    raise RuntimeError("Must define `PKCS11_MODULE' to run tests.")


class PKCS11SessionTests(unittest.TestCase):

    def test_partial_decrypt(self):
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='LOOK ME UP')

            key = session.get_key(label='LOOK ME UP')
            data = (
                b'1234',
                b'1234',
            )

            iv = session.generate_random(128)
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
        lib = pkcs11.lib(LIB)
        token = lib.get_token(token_label='DEMO')

        with token.open(user_pin='1234') as session:
            session.generate_key(pkcs11.KeyType.AES, 128,
                                 store=False, label='LOOK ME UP')

            key = session.get_key(label='LOOK ME UP')
            data = (
                b'1234',
                b'1234',
            )

            iv = session.generate_random(128)
            encrypted_data = list(key.encrypt(data, mechanism_param=iv))

            iter1 = key.decrypt(encrypted_data, mechanism_param=iv)
            next(iter1)
            del iter1

            iter2 = key.decrypt(encrypted_data, mechanism_param=iv)
            next(iter2)
