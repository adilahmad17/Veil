#!/bin/bash -e

# Unload KVM if exists
./unload-kvm.sh || true

# Make KVM out-of-tree source
pushd kvm
    # Build the source
    make -C ../../kernel M=${PWD} clean
    make -C ../../kernel M=${PWD} modules -j`nproc`

    # Load the modules
    sudo insmod kvm.ko
    sudo modprobe ccp 
    sudo insmod kvm-amd.ko dump_invalid_vmcb=1
popd