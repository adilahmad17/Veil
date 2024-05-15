#!/bin/bash -e

source .env

if [ "$1" == "no-snp" ]; then
    # Start the VM with normal SEV (no SNP)
    sudo ./launch-qemu.sh -hda $VMDISK
elif [ "$1" == "no-monitor" ]; then
    # Start the VM with SNP enabled
    sudo ./launch-qemu.sh -hda $VMDISK -sev-snp
else
    # Start the VM with SNP and security monitor enabled
    sudo ./launch-qemu.sh -hda $VMDISK -sev-snp -svsm ../monitor/svsm.bin -allow-debug
fi