.. _concurrency:

Concurrency
===========

PKCS#11 is able to be accessed from multiple threads. The specification
recommends setting a flag to enable access from multiple threads, however
due to the existence of the
`global interpreter lock <https://docs.python.org/3/c-api/init.html#thread-state-and-the-global-interpreter-lock>`_
preventing concurrent execution of Python threads, you will not be preempted
inside a single PKCS#11 call and so the flag has not been set to maximise
compatibility with PKCS#11 implementations.

Most of the calls exposed in our API make a single call into PKCS#11, however,
multi-step calls, such as searching for objects, encryption,
decryption, etc. can be preempted as control is returned to the interpreter
(e.g. by generators). The :class:`pkcs11.Session` class includes a
reenterant lock (:class:`threading.RLock`)
to control access to these multi-step operations, and prevent threads from
interfering with each other.

.. warning::

    Libraries that monkeypatch Python, such as `gevent`, may be supported,
    but are not currently being tested.

The lock is not released until the iterator is consumed (or garbage collected).
However, if you do not consume the iterator, you will never complete the
action and further actions will raise
:class:`pkcs11.exceptions.OperationActive` (cancelling iterators is not
currently supported).

Reenterant Sessions
-------------------

Thread safety aside, a number of PKCS#11 libraries do not support the same
token being logged in from simultaneous sessions (within the same process),
and so it can be advantageous to use a single session across multiple threads.
Sessions can often live for a very long time, but failing to close a session
may leak resources into your memory space, HSM daemon or HSM hardware.

A simple reference counting reenterant session object can be used.

::

    import logging
    import threading

    import pkcs11


    LOCK = threading.Lock()
    LIB = pkcs11.lib(settings.PKCS11_MODULE)


    class Session(object):
        """Reenterant session wrapper."""

        session = None
        refcount = 0

        @classmethod
        def acquire(cls):
            with LOCK:
                if cls.refcount == 0:
                    token = LIB.get_token(token_label=settings.PKCS11_TOKEN)
                    cls.session = token.open(user_pin=settings.PKCS11_TOKEN_PASSPHRASE)

                cls.refcount += 1
                return cls.session

        @classmethod
        def release(cls):
            with LOCK:
                cls.refcount -= 1

                if cls.refcount == 0:
                    cls.session.close()
                    cls.session = None

        def __enter__(self):
            return self.acquire()

        def __exit__(self, type_, value, traceback):
            self.release()

The multi-step locking primitives in the :class:`pkcs11.Session` should
allow you to operate safely.
