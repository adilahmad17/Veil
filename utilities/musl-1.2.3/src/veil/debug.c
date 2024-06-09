#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

/* MMAP-related headers */
#include <sys/mman.h>
#include <unistd.h>

/* IOCTL-related headers */
#include "syscall.h"
#include <sys/ioctl.h>

#include "veil.h"

/* Veil function for direct system call. */
static __inline long __veil_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

#if 0
/* Get current CPU */
long get_current_cpu(void) {
    long ret = 0;
    unsigned int cpu;
    // cpu = sched_getcpu();
    ret = __veil_syscall6(SYS_getcpu, (unsigned long) &cpu, 0, 0, 0, 0, 0);
    if (!ret) 
        return cpu; 
    return ret;
}

unsigned long custom_read_rsp(void)
{
	unsigned long val;
	__asm__ __volatile__ ("mov %%rsp,%0\n\t" : "=m" (val));
	return val;
}

bool resume_with_new_vmsa(void) {
    unsigned long resume_addr = (unsigned long) &&resume_location;
    
    assert_correct_cpu();

    printf("Performing a simple resume test ...\n");
    printf("Resume location = %p\n", &&resume_location);

    /* structs for communication */
    struct vmod_ioctl_test_request test;
    test.addr = resume_addr;
    
    /* create a custom stack here for testing and find its base address */
    char* stack = malloc(4096);
    if (!stack) {
        printf("Error: malloc failed.\n");
        goto resume_location;
    }
    unsigned long stack_base = (unsigned long) stack + sizeof(stack);
    test.stackaddr = custom_read_rsp();
#if 0
    test.stackaddr = enclave_stack_base;
#endif
    
    /* hypercall to create new VMSA; take special care to
     * ensure that stack is not corrupted
     */
    ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_VEIL);
    ghcb_set_sw_exit_info_1(ghcb, ((u64) get_current_cpu() << 32)
                        | SVM_VMGEXIT_SWITCH_TO_ENCLAVE);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    fflush(stdout);
    sleep(2);

    /* ioctl to the driver to create new VMSA context */
    ioctl(devfd, TEST, &test);

    __asm__ __volatile__ ("rep; vmmcall\n\r");

resume_location:
    printf("Resumed with (hopefully) a new VMSA.\n");
    return true;
}

void dump_vmcb(void) {
    ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_VEIL_DEBUG);
    ghcb_set_sw_exit_info_1(ghcb, ((u64) get_current_cpu() << 32) 
                            | SVM_VMGEXIT_DUMP_VMCB);
    ghcb_set_sw_exit_info_2(ghcb, 0);
    VMGEXIT();
}

void assert_correct_cpu(void) {
#if 0
    /* Sanity check */
    if (get_current_cpu() != 0) {
        printf("Error: OS did not allocate correct CPU\n");
        exit(-1);
    }
#endif
}
#endif