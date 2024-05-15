#!/bin/bash -e

pushd ../ && source .env && popd
GUEST_LINUX_VER="5.17.0-rc6-snp-guest-libos"
./mount-vmdisk.sh

# install the kernel modules to the vm image
pushd linux
  sudo env PATH=$PATH make INSTALL_MOD_PATH=$VMDISKMOUNT modules_install
popd

./unmount-vmdisk.sh