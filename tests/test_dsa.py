"""
PKCS#11 DSA Tests
"""

import base64

import pytest

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.util.dsa import decode_dsa_domain_parameters, encode_dsa_domain_parameters

DHPARAMS = base64.b64decode("""
MIIBHwKBgQD8jXSat2sk+j0plaMn51AVYBWEyWee3ui3llRUckVceDILsjVdBs1tXCDhU7WC+VZZ
u6ujBHZONiXcQTZ6P/jhnYlSyjEoBTf7GntlbjeASm63XYzTt4E5i7u1RI6TmEIRj6VTrM5m5DFP
fDQ+fflAJzm0phT38gYE5xfe3mmCDQIVAMIMNr/4lufeH46EGKQXVnvtJBAZAoGBANxCIKAfh1/v
MvI/2s7S1ESGuwvmvbFWpxW3gNXvyO2mWjfHC3sQrwm3qED0R71n9bIL6VqRK+tBEy6VkR+lKifA
8rPnZvADPNBhRLhgDc4JuwYinRJSUPd1iZxJCbumfscr3Fp1XuUnCcMRkWqWr7rGEUP+ht+AeXpo
ouQbj2Vq
""")


@pytest.mark.requires(Mechanism.DSA_PARAMETER_GEN)
@pytest.mark.xfail_nfast
def test_generate_params(session: pkcs11.Session) -> None:
    parameters = session.generate_domain_parameters(KeyType.DSA, 1024)
    assert isinstance(parameters, pkcs11.DomainParameters)
    assert parameters[Attribute.PRIME_BITS] == 1024

    encode_dsa_domain_parameters(parameters)


@pytest.mark.requires(Mechanism.DSA_KEY_PAIR_GEN)
@pytest.mark.requires(Mechanism.DSA_SHA1)
def test_generate_keypair_and_sign(session: pkcs11.Session) -> None:
    dhparams = session.create_domain_parameters(
        KeyType.DSA, decode_dsa_domain_parameters(DHPARAMS), local=True
    )

    public, private = dhparams.generate_keypair()
    assert isinstance(public, pkcs11.PublicKey)
    assert isinstance(private, pkcs11.PrivateKey)
    assert len(public[Attribute.VALUE]) == 1024 // 8

    data = "Message to sign"
    signature = private.sign(data, mechanism=Mechanism.DSA_SHA1)
    assert public.verify(data, signature, mechanism=Mechanism.DSA_SHA1) is True


@pytest.mark.xfail_nfast
@pytest.mark.requires(Mechanism.DSA_PARAMETER_GEN)
@pytest.mark.requires(Mechanism.DSA_KEY_PAIR_GEN)
def test_generate_keypair_directly(session: pkcs11.Session) -> None:
    public, private = session.generate_keypair(KeyType.DSA, 1024)
    assert len(public[Attribute.VALUE]) == 1024 // 8
