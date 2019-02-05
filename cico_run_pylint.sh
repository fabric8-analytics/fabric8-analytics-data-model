#!/bin/bash

set -ex

prep() {
    yum -y update
    yum -y install epel-release
    yum -y install python34 python34-virtualenv which
}

# this script is copied by CI, we don't need it
rm -f env-toolkit

prep
./run-linter.sh
