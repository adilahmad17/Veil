#!/bin/bash -e
pushd ../
    scp -r -P 8000 examples veil@localhost:~/
popd