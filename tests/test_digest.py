"""
PKCS#11 Digests
"""

import hashlib

from pkcs11 import Mechanism

from . import TestCase


class DigestTests(TestCase):

    def test_digest(self):
        data = 'THIS IS SOME DATA TO DIGEST'
        digest = self.session.digest(data, mechanism=Mechanism.SHA256)

        self.assertEqual(digest,
                         hashlib.sha256(data.encode('utf-8')).digest())

    def test_digest_generator(self):
        data = (
            b'This is ',
            b'some data ',
            b'to digest.',
        )

        digest = self.session.digest(data, mechanism=Mechanism.SHA256)

        m = hashlib.sha256()
        for d in data:
            m.update(d)

        self.assertEqual(digest, m.digest())
