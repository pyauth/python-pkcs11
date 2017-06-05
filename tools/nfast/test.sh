#!/bin/sh
#
# Test pkcs11
#

set -xe

# Enable Python 3.5 from SCL
. /opt/rh/rh-python35/enable

# Enable our virtualenv
. python_env/bin/activate

# Test parameters
export CKNFAST_FAKE_ACCELERATOR_LOGIN=true
export CKNFAST_LOADSHARING=1
export CKNFAST_DEBUG=6
export PKCS11_MODULE=/opt/nfast/toolkits/pkcs11/libcknfast.so
export PKCS11_TOKEN_LABEL='loadshared accelerator'
export PKCS11_TOKEN_PIN='0000'

python -m unittest
