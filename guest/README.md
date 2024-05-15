# Veil: A Protected Services Framework for Confidential Virtual Machines

**NOTE:** Please setup the host OS and kernel, before performing these setup tasks.

## Prerequisite Packages

    apt-get install cloud-utils whois git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison

## Steps (INCOMPLETE)

- Create an Ubuntu Virtual Machine cloud image: 

    ```
    cd image
    ./create-image.sh
    ./bootstrap.sh
    ```

    **Test:** Execute `./start-guest.sh no-snp` and it should boot correctly. 

- Install an Secure Nested Paging (SNP) compatible Linux kernel by following instructions in the `kernel` directory. 
