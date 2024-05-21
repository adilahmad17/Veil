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

char* devname = "/dev/veil-driver";
int   devfd = -1;

int open_device_driver(void) {
    devfd = open(devname, O_RDWR);
    if (devfd < 0) {
        printf("Error: could not open device (%s)\n", devname);
        return -1;
    }
    printf("[*] Opened device driver successfully.\n");
    return devfd;
}

void close_device_driver(void) {
    close(devfd);
}