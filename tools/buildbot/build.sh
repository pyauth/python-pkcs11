#!/bin/sh
#
# Build pkcs11
#

set -xe

# Enable our virtualenv
. python_env/bin/activate

python setup.py build_ext -i
