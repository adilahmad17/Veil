#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "scsan.h"
#include "veil.h"
#include "common.h"

bool syscall_init(void) {
    // sc_buf = malloc(sizeof(syscall_msg_buffer));
    sc_buf = mmap(NULL, sizeof(syscall_msg_buffer), PROT_READ|PROT_WRITE, 
        MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (!sc_buf) {
        untrusted_printf("Error: Could not allocate system call buffer.\n");
        return false;
    }
    untrusted_printf("[*] System call handler set up successfully.\n");
}

void syscall_fini(void) {
    // free(sc_buf);
    munmap(sc_buf, sizeof(syscall_msg_buffer));
}

static __inline long __untrusted_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

void syscall_handler(void) {
    /* Avoid running duplicate system calls on interrupts. */
    if (syscall_args_debug && (sc_buf->syscall_no != __NR_writev)) {
        printf("ENCLAVE: syscall(%ld) {%lx, %lx, %lx, %lx, %lx, %lx}", 
            sc_buf->syscall_no, sc_buf->arg1, sc_buf->arg2, sc_buf->arg3,
            sc_buf->arg4, sc_buf->arg5, sc_buf->arg6);
    }

    /* 0x1000 is the system call number I have set for SYSCALL_INVALID */
    if (sc_buf->syscall_no != 0x1000) {
        sc_buf->ret = __untrusted_syscall6(sc_buf->syscall_no, sc_buf->arg1, 
                                            sc_buf->arg2, sc_buf->arg3, sc_buf->arg4, 
                                            sc_buf->arg5, sc_buf->arg6);
    } else {
        /* Given how the system is set-up, this should never happen. */
        printf("[warning] invalid system call seen.\n");
    }

    /* Debugging*/
    if (syscall_args_debug && (sc_buf->syscall_no != __NR_writev))
        printf(" --> %lx.\n", sc_buf->ret);
}