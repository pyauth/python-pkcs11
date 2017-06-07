#!/bin/sh
#
# Install dependencies
#

set -xe

# Create virtualenv if needed
[ -d python_env ] || python3 -m venv python_env

# Enable our virtualenv
. python_env/bin/activate

pip install -U pip six
pip install -U setuptools cython
pip install -r requirements.txt -r dev-requirements.txt
