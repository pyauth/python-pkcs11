#!/bin/sh
#
# Build pkcs11
#

set -xe

# Enable Python 3.5 from SCL
. /opt/rh/rh-python35/enable

# Enable our virtualenv
. python_env/bin/activate

python setup.py build_ext -i
