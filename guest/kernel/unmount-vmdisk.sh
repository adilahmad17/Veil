#!/bin/bash -e

pushd ../ && source .env && popd 

# check if folder is empty
if [ -z "$(ls -A $VMDISK)" ]; 
then
  echo "Empty /mnt/vmdisk, exiting."
  exit
fi

# unmount the disk
sudo umount $VMDISKMOUNT/boot/efi || true
sudo umount $VMDISKMOUNT/dev/pts || true
sudo umount $VMDISKMOUNT/dev || true
sudo umount $VMDISKMOUNT/sys || true
sudo umount $VMDISKMOUNT/proc || true
sudo umount $VMDISKMOUNT/run || true
sudo umount $VMDISKMOUNT || true

# sync everything
sync

# unmount the nbd
sudo qemu-nbd -d /dev/nbd0
