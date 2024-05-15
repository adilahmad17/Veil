#!/bin/bash -e

make host-clean
pushd ../
    scp -r -P 8000 driver veil@localhost:~/
popd