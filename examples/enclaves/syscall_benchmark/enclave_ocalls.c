#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "../helper/common.h"
#include "benchmark.h"

#define ENCLAVE_OCALL_DEBUG 0

extern syscall_msg_buffer* sc_buf;
extern ocall_open_buffer* oc_open_buf;

int ocall_open(char* name, int mode) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_open;
    sc_buf->arg1 = (long) oc_open_buf;

    /* copy open buffer params */
    memcpy(oc_open_buf->name, name, strlen(name));

    oc_open_buf->name_size = strlen(name);
    oc_open_buf->mode = (long) mode;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("open --> %d\n", sc_buf->ret);
    #endif

    return sc_buf->ret;
}

void ocall_getpid(void) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_getpid;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("getpid --> %d\n", sc_buf->ret);
    #endif
}

void* ocall_mmap(void* tmp, unsigned long size, 
    unsigned long prot, unsigned long attrs, int fd, int zero) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_mmap;
    sc_buf->arg2 = size;
    sc_buf->arg3 = prot;
    sc_buf->arg4 = attrs;
    sc_buf->arg5 = fd;

    /* exit enclave */
    exit_enclave();

    tmp = (void*) sc_buf->arg1;

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("mmap --> %lx\n", tmp);
    #endif
    
    return tmp;
}

void* ocall_munmap(void* tmp, unsigned long size) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_munmap;
    sc_buf->arg1 = (long int) tmp;
    sc_buf->arg2 = size;

    /* exit enclave */
    exit_enclave();

    tmp = (void*) sc_buf->arg1;

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("mmap --> %lx\n", tmp);
    #endif
    
    return tmp;
}

void ocall_read(int fd, void* buf, size_t count) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_read;
    sc_buf->arg1 = fd;
    sc_buf->arg2 = (unsigned long) buf;
    sc_buf->arg3 = count;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("read --> %d\n", sc_buf->ret);
    #endif
}

void ocall_write(int fd, void* buf, size_t count) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_write;
    sc_buf->arg1 = fd;
    sc_buf->arg2 = (unsigned long) buf;
    sc_buf->arg3 = count;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("write --> %d\n", sc_buf->ret);
    #endif
}

void ocall_printf(char* buf) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = OCALL_printf;
    sc_buf->arg1 = (unsigned long) buf;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("write --> %d\n", sc_buf->ret);
    #endif
}

void ocall_socket(int domain, int type, int protocol) {
    /* copy system call buffer parameters */
    sc_buf->syscall_no = SYS_socket;
    sc_buf->arg1 = domain;
    sc_buf->arg2 = type;
    sc_buf->arg3 = protocol;

    /* exit enclave */
    exit_enclave();

    #if ENCLAVE_OCALL_DEBUG==1
        /* check return value */
        enclave_printf("write --> %d\n", sc_buf->ret);
    #endif
}