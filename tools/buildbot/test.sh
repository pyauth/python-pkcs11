#!/bin/sh
#
# Test pkcs11
#

set -xe

# Enable our virtualenv
. python_env/bin/activate

# Test parameters come from ShellCommand
# export PKCS11_MODULE=
# export PKCS11_TOKEN_LABEL=
# export PKCS11_TOKEN_PIN=

python -m unittest
