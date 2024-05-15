# Veil: A Protected Services Framework for Confidential Virtual Machines

This directory contains steps to install a Veil-compatible Linux Kernel into a base Ubuntu 22.04 virtual machine image.

## Directory Structure

- `Linux`: contains the modified Linux kernel

## Steps 

1. Build guest kernel locally: `./build-kernel.sh`

2. Install kernel modules into VM disk: `./install-modules.sh`

3. Install kernel image into VM disk: `./install-image.sh`

4. Copy the build directory into VM disk: `./copy-build.sh`

    - This is needed to install Veil's kernel module

    - This will incrementally load only changes to kernel build

## Miscellaneous
- `./mount-vmdisk.sh`: Mounts the VM's QCOW2 image at ../image/mnt 
- `./unmount-vmdisk.sh`: Unmounts the VM's QCOW2 image 