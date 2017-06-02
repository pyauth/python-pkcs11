#!/bin/sh
#
# Install dependencies for nFast tests on RHEL7
#

set -xe

# Enable Python 3.5 from SCL
. /opt/rh/rh-python35/enable

# Create virtualenv if needed
[ -d python_env ] || virtualenv -p python3 python_env

# Enable our virtualenv
. python_env/bin/activate

pip install -U pip six
pip install -U setuptools cython
pip install -r requirements.txt -r dev-requirements.txt
