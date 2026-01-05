from __future__ import annotations

from typing import SupportsInt


def biginteger(value: SupportsInt) -> bytes:
    """
    Returns a PKCS#11 biginteger bytestream from a Python integer or
    similar type (e.g. :class:`asn1crypto.core.Integer`).

    :param int value: Value
    :rtype: bytes
    """

    value_int = int(value)  # In case it's a asn1 type or similar

    return value_int.to_bytes((value_int.bit_length() + 7) // 8, byteorder="big")
