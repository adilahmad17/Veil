#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "../helper/common.h"
#include "benchmark.h"

#define UNTRUSTED_OCALL_DEBUG 0

syscall_msg_buffer* sc_buf;
ocall_open_buffer* oc_open_buf;

void untrusted_open(void) {
    int fd;
    long arg1;
    fd = open(oc_open_buf->name, oc_open_buf->mode);
    sc_buf->ret = fd;

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: open (%s) ; ret (%d).\n", 
                oc_open_buf->name, sc_buf->ret);
    #endif
}

void untrusted_getpid(void) {
    int pid;
    pid = getpid();
    sc_buf->ret = pid;

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: getpid () ; ret (%d).\n", sc_buf->ret);
    #endif
}

void untrusted_mmap(void) {
    unsigned long size  = sc_buf->arg2;
    unsigned long prot  = sc_buf->arg3;
    unsigned long attrs = sc_buf->arg4;
    unsigned long fd    = sc_buf->arg5;
    void* tmp = mmap(NULL, size, prot, attrs, fd, 0);
    if (!tmp) {
        untrusted_printf("Error: could not mmap.\n");
    }

    sc_buf->arg1 = (unsigned long) tmp;
    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: mmap () ; ret (%lx).\n", sc_buf->arg1);
    #endif
}

void untrusted_munmap(void) {
    void* buf = (void*) sc_buf->arg1;
    unsigned long size = sc_buf->arg2;
    int ret = munmap(buf, size);

    sc_buf->arg1 = (unsigned long) ret;

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: munmap () ; ret (%lx).\n", sc_buf->arg1);
    #endif
}

void untrusted_read(void) {
    int fd       = sc_buf->arg1;
    char* buf    = (char*) sc_buf->arg2;
    size_t count = sc_buf->arg3;

    int ret = read(fd, buf, count);
    if (ret == 0) {
        untrusted_printf("Error: could not read correctly.\n");
    }

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: read () ; ret (%lx).\n", ret);
    #endif
}

void untrusted_write(void) {
    int fd       = sc_buf->arg1;
    char* buf    = (char*) sc_buf->arg2;
    size_t count = sc_buf->arg3;

    int ret = write(fd, buf, count);
    if (ret == 0) {
        untrusted_printf("Error: could not write correctly.\n");
    }

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: write () ; ret (%lx).\n", ret);
    #endif
}

void untrusted_print(void) {
    char* buf    = (char*) sc_buf->arg1;

    printf("%s", buf);

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: printf ()\n");
    #endif
}

void untrusted_socket(void) {
    int arg1 = sc_buf->arg1;
    int arg2 = sc_buf->arg2;
    int arg3 = sc_buf->arg3;
    int ret = socket(arg1, arg2, arg3);
    if (ret <0) {
        untrusted_printf("Error: socket acquire failed.\n");
    }

    sc_buf->arg1 = (unsigned long) ret;

    #if UNTRUSTED_OCALL_DEBUG==1
        untrusted_printf("OCALL: socket () ; ret (%lx).\n", sc_buf->arg1);
    #endif
}

void untrusted_bind(void) {
    // struct serveraddr* = sc_buf->arg1;
    // int arg2 = sc_buf->arg2;
    // int arg3 = sc_buf->arg3;
    // int ret = socket(arg1, arg2, arg3);

    // sc_buf->arg1 = (unsigned long) ret;

    // #if UNTRUSTED_OCALL_DEBUG==1
    //     untrusted_printf("OCALL: socket () ; ret (%lx).\n", sc_buf->arg1);
    // #endif
}

bool syscall_init(void) {
    sc_buf = malloc(sizeof(syscall_msg_buffer));
    if (!sc_buf) {
        untrusted_printf("Error: Could not allocate system call buffer.\n");
        return false;
    }
    memset(sc_buf, 0, sizeof(syscall_msg_buffer));
    sc_buf->syscall_no = -1;

    oc_open_buf = malloc(sizeof(ocall_open_buffer));
    if (!oc_open_buf) {
        untrusted_printf("Error: Could not allocate ocall_open buffer.\n");
        return false;
    }
    memset(oc_open_buf, 0, sizeof(ocall_open_buffer));

    printf("[*] Successfully allocated system call buffers. \n");
    return true;
}

void syscall_fini(void) {
    free(sc_buf);
    free(oc_open_buf);
}

void syscall_handler(void) {

    /* Send to correct function based on system call id */
    switch(sc_buf->syscall_no) {
        case SYS_open:
            untrusted_open();
            break;
        case SYS_getpid:
            untrusted_getpid();
            break;
        case SYS_read:
            untrusted_read();
            break;
        case SYS_write:
            untrusted_read();
            break;
        case SYS_mmap:
            untrusted_mmap();
            break;
        case OCALL_printf:
            untrusted_print();
            break;
        case SYS_munmap:
            untrusted_munmap();
            break;
        case SYS_socket:
            untrusted_socket();
            break;
        default:
            /* Possible that no system call was executed */
            break;
    };

    /* It will return to the main function and resume */
}