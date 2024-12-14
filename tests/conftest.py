import os
import secrets
import shutil
import string
import subprocess
from pathlib import Path
from typing import Iterator
from unittest import mock
from warnings import warn

import pytest
from _pytest.fixtures import SubRequest

import pkcs11

ALLOWED_RANDOM_CHARS = string.ascii_letters + string.digits
LIB_PATH = os.environ.get("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")

# trick: str.endswith() can accept tuples,
# see https://stackoverflow.com/questions/18351951/check-if-string-ends-with-one-of-the-strings-from-a-list
IS_SOFTHSM = LIB_PATH.lower().endswith(
    ("libsofthsm2.so", "libsofthsm2.dylib", "softhsm2.dll", "softhsm2-x64.dll")
)
IS_NFAST = LIB_PATH.lower().endswith(("libcknfast.so", "cknfast.dll"))
IS_OPENCRYPTOKI = LIB_PATH.endswith("libopencryptoki.so")

OPENSSL = shutil.which("openssl", path=os.environ.get("OPENSSL_PATH"))
if OPENSSL is None:
    warn("Path to OpenSSL not found. Please adjust `PATH' or define `OPENSSL_PATH'", stacklevel=2)


def pytest_collection_modifyitems(items) -> None:
    for item in items:
        markers = [marker.name for marker in item.iter_markers()]
        if "xfail_nfast" in markers and IS_NFAST:
            item.add_marker(
                pytest.mark.xfail(IS_NFAST, reason="Expected failure with nFast.", strict=True)
            )
        if "xfail_softhsm" in markers and IS_SOFTHSM:
            item.add_marker(
                pytest.mark.xfail(
                    IS_SOFTHSM, reason="Expected failure with SoftHSMvs.", strict=True
                )
            )
        if "xfail_opencryptoki" in markers:
            item.add_marker(
                pytest.mark.xfail(
                    IS_OPENCRYPTOKI, reason="Expected failure with OpenCryptoki.", strict=True
                )
            )


def get_random_string(length):
    return "".join(secrets.choice(ALLOWED_RANDOM_CHARS) for i in range(length))


@pytest.fixture(scope="session")
def lib():
    return pkcs11.lib(LIB_PATH)


@pytest.fixture
def softhsm_setup(tmp_path: Path) -> Iterator[Path]:  # pragma: hsm
    """Fixture to set up a unique SoftHSM2 configuration."""
    softhsm_dir = tmp_path / "softhsm"
    token_dir = softhsm_dir / "tokens"
    token_dir.mkdir(exist_ok=True, parents=True)

    softhsm2_conf = tmp_path / "softhsm2.conf"
    print("# SoftHSMv2 conf:", softhsm2_conf)

    with open(softhsm2_conf, "w", encoding="utf-8") as stream:
        stream.write(f"""# SoftHSM v2 configuration file

directories.tokendir = {token_dir}
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false""")

    with mock.patch.dict(os.environ, {"SOFTHSM2_CONF": str(softhsm2_conf)}):
        yield softhsm_dir


@pytest.fixture
def so_pin() -> str:
    return get_random_string(12)


@pytest.fixture
def pin() -> str:
    return get_random_string(12)


@pytest.fixture
def softhsm_token(request: "SubRequest", lib, so_pin: str, pin: str) -> pkcs11.Token:
    """Get a unique token for the current test."""
    request.getfixturevalue("softhsm_setup")
    token = get_random_string(8)

    args = (
        "softhsm2-util",
        "--init-token",
        "--free",
        "--label",
        token,
        "--so-pin",
        so_pin,
        "--pin",
        pin,
    )
    print("+", " ".join(args))
    subprocess.run(args, check=True)

    # Reinitialize library if already loaded (tokens are only seen after (re-)initialization).
    lib.reinitialize()

    return lib.get_token(token_label=token)


@pytest.fixture
def softhsm_session(softhsm_token: pkcs11.Token, pin: str) -> Iterator[pkcs11.Session]:
    session = softhsm_token.open(user_pin=pin)
    yield session
    session.close()


@pytest.fixture
def token(softhsm_token: pkcs11.Token) -> pkcs11.Token:
    return softhsm_token


@pytest.fixture
def session(
    request: "SubRequest", softhsm_session: pkcs11.Session, softhsm_token: pkcs11.Token
) -> pkcs11.Session:
    # Skip test if session does not support required mechanisms
    requirements = [mark.args[0] for mark in request.node.iter_markers(name="requires")]
    if requirements:
        unavailable = set(requirements) - softhsm_token.slot.get_mechanisms()

        if unavailable:
            pytest.skip("Requires %s" % ", ".join(map(str, unavailable)))

    return softhsm_session
