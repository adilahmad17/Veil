#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

/* MMAP-related headers */
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* IOCTL-related headers */
#include <sys/ioctl.h>
#include <string.h>

#include "veil.h"
#include "common.h"

syscall_msg_buffer* sc_buf;
ocall_open_buffer* oc_open_buf;

extern unsigned long ocall_exits;

long ocall_common(long sysno, long a1, long a2, long a3, long a4, long a5, long a6) {
    /* Track system call statistics */
    ocall_exits++;

    /* copy system call buffer parameters */
    sc_buf->syscall_no = sysno;
    sc_buf->arg1 = a1;
    sc_buf->arg2 = a2;
    sc_buf->arg3 = a3;
    sc_buf->arg4 = a4;
    sc_buf->arg5 = a5;
    sc_buf->arg6 = a6;

    /* exit enclave */
    exit_enclave();

    /* Clear it out to avoid duplicates. */
    sc_buf->syscall_no = 0x1000;

    /* Return back to program. */
    return sc_buf->ret;
}