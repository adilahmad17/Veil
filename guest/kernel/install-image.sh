#!/bin/bash -e

pushd ../ && source .env && popd
GUEST_LINUX_VER="5.17.0-rc6-snp-guest-libos"
./mount-vmdisk.sh

# install the kernel to the vm image
pushd linux
  sudo env PATH=$PATH make INSTALL_PATH=$VMDISKMOUNT/boot install
popd

# install the initramfs
sudo chroot $VMDISKMOUNT sudo update-initramfs -c -k $GUEST_LINUX_VER
sudo chroot $VMDISKMOUNT sudo update-grub

./unmount-vmdisk.sh