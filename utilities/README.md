## Utilities for Veil's Enclave Service

This folder contains a modified *Musl C Library* (musl) and a *system call sanitizer* (SCSAN). SCSAN is designed to catch every system call executed by an enclave program. Afterwards, it copies the system call arguments to an outside buffer and executes the system call. Please refer to our research paper for details.

### Steps

1. Install SCSAN by following the README in syscall-sanitizer
2. Install musl by following the README in musl-1.2.3
3. Start the guest virtual machine and copy the utilities folder
    - Execute `./vmcopy.sh` to automatically install requisite directories in the guest