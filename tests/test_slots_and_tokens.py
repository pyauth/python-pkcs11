"""
PKCS#11 Slots and Tokens
"""

import pytest

import pkcs11
from tests.conftest import IS_NFAST, IS_OPENCRYPTOKI, IS_SOFTHSM, LIB_PATH


def test_double_initialise() -> None:
    assert pkcs11.lib(LIB_PATH) is not None
    assert pkcs11.lib(LIB_PATH) is not None


def test_double_initialise_different_libs() -> None:
    assert pkcs11.lib(LIB_PATH) is not None
    with pytest.raises(pkcs11.AlreadyInitialized):
        pkcs11.lib("somethingelse.so")


@pytest.mark.skipif(not IS_SOFTHSM, reason="Only supported on SoftHSMv2.")
@pytest.mark.usefixtures("softhsm_token")
def test_get_slots() -> None:
    lib = pkcs11.lib(LIB_PATH)
    slots = lib.get_slots()
    print(slots)

    assert len(slots) == 2
    slot1, slot2 = slots

    assert isinstance(slot1, pkcs11.Slot)
    assert slot1.flags == pkcs11.SlotFlag.TOKEN_PRESENT


def test_get_mechanisms() -> None:
    lib = pkcs11.lib(LIB_PATH)
    slot, *_ = lib.get_slots()
    mechanisms = slot.get_mechanisms()
    assert pkcs11.Mechanism.RSA_PKCS in mechanisms


def test_get_mechanism_info() -> None:
    lib = pkcs11.lib(LIB_PATH)
    slot, *_ = lib.get_slots()
    info = slot.get_mechanism_info(pkcs11.Mechanism.RSA_PKCS_OAEP)
    assert isinstance(info, pkcs11.MechanismInfo)


@pytest.mark.skipif(IS_NFAST or IS_OPENCRYPTOKI, reason="EC not supported.")
def test_get_mechanism_info_ec() -> None:
    lib = pkcs11.lib(LIB_PATH)
    slot, *_ = lib.get_slots()
    info = slot.get_mechanism_info(pkcs11.Mechanism.EC_KEY_PAIR_GEN)
    assert isinstance(info, pkcs11.MechanismInfo)
    assert pkcs11.MechanismFlag.EC_NAMEDCURVE in info.flags


@pytest.mark.skipif(not IS_SOFTHSM, reason="Only supported on SoftHSMv2.")
def test_get_tokens(softhsm_token: pkcs11.Token) -> None:
    lib = pkcs11.lib(LIB_PATH)

    tokens = list(lib.get_tokens(token_flags=pkcs11.TokenFlag.RNG))
    print(tokens)
    assert len(list(tokens)) == 2

    tokens = lib.get_tokens(token_label=softhsm_token.label)
    assert len(list(tokens)) == 1


@pytest.mark.skipif(not IS_SOFTHSM, reason="Only supported on SoftHSMv2.")
def test_get_token(token: pkcs11.Token) -> None:
    lib = pkcs11.lib(LIB_PATH)
    slot, *_ = lib.get_slots()
    actual_token = slot.get_token()

    assert isinstance(actual_token, pkcs11.Token)
    assert actual_token.label == token.label
    assert pkcs11.TokenFlag.TOKEN_INITIALIZED in actual_token.flags
    assert pkcs11.TokenFlag.LOGIN_REQUIRED in actual_token.flags
