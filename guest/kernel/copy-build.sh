#!/bin/bash -e

pushd ../ && source .env && popd
./mount-vmdisk.sh
GUEST_LINUX_VER="5.17.0-rc6-snp-guest-libos"

# unlink the build directory (if exists)
sudo unlink $VMDISKMOUNT/lib/modules/$GUEST_LINUX_VER/build || true

# copy the updated build source
sudo mkdir -p $VMDISKMOUNT/lib/modules/$GUEST_LINUX_VER/build
sudo rsync -rav --exclude '.git/' --info=progress2 linux/* $VMDISKMOUNT/lib/modules/$GUEST_LINUX_VER/build/

./unmount-vmdisk.sh
