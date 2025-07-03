"""
PKCS#11 Digests
"""

import hashlib

from pkcs11 import Attribute, KeyType, Mechanism

from . import Not, TestCase, requires


class DigestTests(TestCase):
    @requires(Mechanism.SHA256)
    def test_digest(self):
        data = "THIS IS SOME DATA TO DIGEST"
        digest = self.session.digest(data, mechanism=Mechanism.SHA256)

        self.assertEqual(digest, hashlib.sha256(data.encode("utf-8")).digest())

    @requires(Mechanism.SHA256)
    def test_digest_generator(self):
        data = (
            b"This is ",
            b"some data ",
            b"to digest.",
        )

        digest = self.session.digest(data, mechanism=Mechanism.SHA256)

        m = hashlib.sha256()
        for d in data:
            m.update(d)

        self.assertEqual(digest, m.digest())

    @requires(Mechanism.AES_KEY_GEN, Mechanism.SHA256)
    @Not.nfast  # nFast can't digest keys
    def test_digest_key(self):
        key = self.session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )

        digest = self.session.digest(key, mechanism=Mechanism.SHA256)

        self.assertEqual(digest, hashlib.sha256(key[Attribute.VALUE]).digest())

    @requires(Mechanism.AES_KEY_GEN, Mechanism.SHA256)
    @Not.nfast  # nFast can't digest keys
    def test_digest_key_data(self):
        key = self.session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )

        data = (
            b"Some data",
            key,
        )

        digest = self.session.digest(data, mechanism=Mechanism.SHA256)

        m = hashlib.sha256()
        m.update(data[0])
        m.update(data[1][Attribute.VALUE])

        self.assertEqual(digest, m.digest())

    @requires(Mechanism.SHA256)
    def test_digest_stream_interrupt_releases_operation(self):
        data = (
            b"I" * 16,
            b"N" * 16,
            b"P" * 16,
            b"U" * 16,
            b"T" * 10,
        )

        def _data_with_error():
            yield data[0]
            yield data[1]
            yield data[2]
            raise ValueError

        def attempt_digest():
            self.session.digest(_data_with_error(), mechanism=Mechanism.SHA256)

        self.assertRaises(ValueError, attempt_digest)
        # ...try again
        digest = self.session.digest(data, mechanism=Mechanism.SHA256)
        m = hashlib.sha256()
        for d in data:
            m.update(d)
        self.assertEqual(digest, m.digest())
