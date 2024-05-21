#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include "common.h"

// within the guest, this link should be maintained
#ifndef HOST
    #include "../../driver/ioctl-defines.h"
#else
    #include "../../guest/driver/ioctl-defines.h"
#endif

int main(void)
{
    printf("Example: log retrieval from the security monitor\n");

    // open device
    int devfd = open_device_driver();
    if (devfd == -1) return -1;

    // create log dump buffer
    char* log_dump_buffer = (char*) mmap(NULL, 4096,
        PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, 0,0);
    if (!log_dump_buffer) {
        printf("Error: could not allocate buffer for logs.\n");
        return -1;
    }

    // execute ioctl command
    struct ioctl_dump_logs ioctl_dl;
    ioctl_dl.address = (unsigned long) log_dump_buffer;
    ioctl_dl.size = 4096;
    ioctl_dl.offset = 0;
    ioctl(devfd, DUMP_LOGS, &ioctl_dl);
    printf("executed ioctl command.\n");
    
    return 0;
}