#!/bin/bash

set -ex

. cico_setup.sh

docker_login

build_image

./qa/runtests.sh

push_image
