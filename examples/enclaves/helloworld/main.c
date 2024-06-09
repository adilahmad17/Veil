#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
  
// IMPORTANT: within the guest, this link should be maintained
#ifndef HOST
    #include "../../../driver/ioctl-defines.h"
#else
    #include "../../../guest/driver/ioctl-defines.h"
#endif
#include "../helper/common.h"

int main(void)
{
    printf("Starting the application.\n");

    /* Open the device */
    if (!open_device_driver()) return -1;
    fflush(stdout);

    /* Establish VMM communication */
    if (!establish_ghcb()) return -1;
    fflush(stdout);

    /* Creating Test Enclave (entry ==> hello_world_enclave(..)) */
    enclave_entry = (unsigned long) &hello_world_enclave;
    if (!create_enclave()) return -1;
    fflush(stdout);

    /* This will jump to hello_world_enclave(..) in VMPL2 */
    start_enclave();

    /* The execution will later on return back here and exit */
    printf("Success; exiting application.\n");

    return 0;
}