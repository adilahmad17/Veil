#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
  
#include "../../helper/common.h"
#include "enclave_loader.h"

int main(int argc, const char **argv)
{
    /* Fetch name of enclave .elf */
    if (argc != 2) {
        printf("Usage: ./main <enclave-binary>\n");
        return 1;
    }
    const char *object_file_name = argv[1];
    printf("Starting the loader.\n");

    /* Load enclave ELF */
    load_enclave(object_file_name, &enclave_entry);
	printf("[LOADER] Entrypoint retrieved from enclave binary: %px\n", (void*) enclave_entry);    

    /* Open the device */
    if (!open_device_driver()) return -1;
    fflush(stdout);

    /* Establish VMM communication */
    if (!establish_ghcb()) return -1;
    fflush(stdout);

    /* Create an enclave context */
    if (!create_enclave()) return -1;
    fflush(stdout);

    /* Start the enclave for the first time */
    start_enclave();

    printf("Success; exiting application.\n");
    return 0;
}