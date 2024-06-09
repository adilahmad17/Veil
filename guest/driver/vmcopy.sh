#!/bin/bash -e

make host-clean
pushd ../
    scp -r -P 8000 driver veil@localhost:~/
popd

# install within the guest
ssh -p 8000 veil@localhost "cd driver; make clean; make; make install"
echo "DONE"