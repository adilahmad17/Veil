# Veil: A Protected Services Framework for Confidential Virtual Machines

This repository contains the prototype source code for the [Veil research paper](https://adil-ahmad.net/papers/ahmad-veil.pdf), 
presented at ACM ASPLOS 2024. 

*IMPORTANT NOTES:* 

- This repository is currently work in progress, with code being iteratively added for different services and various bugs are being fixed. 

    - Step-by-step instructions to build the repository are also coming.

- The source code is only meant for research purposes, and likely contains many bugs. Please do not use it in production systems.

## System Hardware and Software Requirements

- AMD Server CPU that supports AMD Secure Encrypted Virtualization (SEV) with Secure Nested Paging (SNP)
- Host Operating System (OS) that supports SEV-SNP
    - Currently, the only compatible host OS is Ubuntu 22.04 with a custom-built Linux kernel. SEV-SNP support is not yet upstream in the mainline Linux kernel.
    - Please follow the excellent instructions specified in [Linux Secure VM Service Module](https://github.com/AMDESE/linux-svsm?tab=readme-ov-file#preparing-the-host-) (SVSM) to ensure your OS and kernel support SEV-SNP.

**Tested System Specifications:** This repository was tested on an AMD EPYC 7443P with Ubuntu 22.04. The Linux kernel was built
following the scripts provided in Linux SVSM. For reference, the kernel version and tag is `5.14.0-rc2-snp-host-e69def60bfa5`.

## Acknowledgements

In addition to all authors credited in the paper, this repository was made possible by the contributions of the following individuals:

- Harsh Minral (MS student @ ASU, 2023) and Vikram Ramaswamy (PhD student @ ASU, current) for integrating Veil's codebase with SVSM

- Carlos Bilboa (AMD) for their help in explaining AMD Linux SVSM components for integration of Veil and SVSM