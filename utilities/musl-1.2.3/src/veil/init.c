#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>
// #include <linux/ioctl.h>
#include <sys/ioctl.h>

// SCSAN headers
#include "scsan.h"
#include "../scsan/scsan_malloc.h"
#include "syscall.h"

// Veil headers
#include "veil.h"
#include "common.h"

// Track ocall exits
unsigned long ocall_exits = 0;
unsigned long syscall_total = 0;

/* System call debugging using files */
bool syscall_file_debug;
int syscall_debug_fd;

// Track whether the enclave has started or not
extern bool enclave_execution;

extern bool open_device_driver(void);
extern bool establish_ghcb(void);
extern bool create_enclave(void);
extern void start_enclave(void);
extern void exit_enclave(void);

#if 0
/* Global variables */
char* devname = "/dev/vmod";
int   devfd = -1;

unsigned long sev_status;

// This function should be defined in every application
unsigned long enclave_main_addr;

// Track whether the enclave has started or not
bool enclave_execution = false;

/* For testing purposes, allocate the stack here */
char enclave_stack[(1 << 22) + 1] __attribute__ ((aligned (4096)));
const uintptr_t enclave_stack_base = 
    (uintptr_t) enclave_stack + sizeof(enclave_stack) - 1 ;

struct ghcb* ghcb;

bool open_device_driver(void) {
    assert_correct_cpu();

    /* Open device */
    devfd = open(devname, O_RDWR);
    if (devfd < 0) {
        printf("Error: could not open device (%s)\n", devname);
        return false;
    }

    /* Return that everything works */
    printf("[*] Opened device driver successfully.\n");
    return true;
}

bool create_enclave(void) {
    // unsigned long enclave_addr = enclave_main_addr;
    printf("Creating an enclave context ...\n");

    assert_correct_cpu();

    printf("[.] Provided enclave addr: %p\n", enclave_main_addr);
    printf("[*] Using correct CPU (0).\n");

    /* structs for communication */
    struct vmod_ioctl_test_request test;
    test.addr = enclave_main_addr;
    test.stackaddr = enclave_stack_base;

    printf("[.] Address debug: %p\n", test.addr);
    printf("[.] Stack debug: %p -- %p\n", enclave_stack_base, enclave_stack);

    /* IOCTL to the driver */
    long ret = ioctl(devfd, TEST, &test);
    if (ret != 0) {
        printf("Error: IOCTL (TEST) failed.\n");
        return false;
    }

    printf("[*] Enclave context created successfully.\n");
    return true;
}

bool establish_ghcb(void) {
    struct vmod_ioctl_establish_ghcb_request test;
    void* ghcb_addr;
    printf("Establishing GHCB ...\n");

    assert_correct_cpu();

    /* Mmap some memory region for now */
    ghcb_addr = (void*) mmap((void*) 0x80000000,
        sizeof(struct ghcb),
        PROT_READ|PROT_WRITE,
        MAP_ANON|MAP_PRIVATE,
        -1,0);
    if (!ghcb_addr) {
        printf("Error: could not allocate space for GHCB.\n");
        return false;
    }

    printf("GHCB request location = %p\n", (void*) &test);
    printf("GHCB addr = %p , size = %ld\n", ghcb_addr, sizeof(struct ghcb));

    /* Send that virtual address to VMOD */
    test.uvaddr = (unsigned long) ghcb_addr;
    test.paddr  = 0;
    long ret = ioctl(devfd, ESTABLISHGHCB, &test);
    if (ret != 0 || test.paddr == 0) {
        printf("Error: IOCTL (ESTABLISHGHCB) failed.\n");
        printf("GHCB <==> PA = %p\n", (void*)test.paddr);
        return false;
    }

    ghcb = (struct ghcb*) ghcb_addr;
    printf("GHCB <==> PA = %p\n", (void*)test.paddr);
    printf("[*] GHCB established successfully.\n");
    return true;
}

void start_enclave(void) {
    assert_correct_cpu();

    /* Specify the vCPU and enclave context */
    ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_VEIL);
	ghcb_set_sw_exit_info_1(ghcb, ((u64) get_current_cpu() << 32) 
                            | SVM_VMGEXIT_SWITCH_TO_ENCLAVE);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    /* Initiate a hypercall */
    VMGEXIT();
}

void exit_enclave(void) {
    assert_correct_cpu();

    /* Specify the vCPU and enclave context */
    ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_VEIL);
	ghcb_set_sw_exit_info_1(ghcb, ((u64) get_current_cpu() << 32)
                            | SVM_VMGEXIT_SWITCH_TO_OS);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    /* Initiate a hypercall */
    VMGEXIT();
}
#endif


/* This function is designed for enclave teardown. */
void terminate_enclave(void) {
#if 0
    /* IOCTL to the driver */
    long ret = ioctl(devfd, ENCLAVE_TEST_TERMINATE, NULL);
    if (ret != 0) {
        printf("Error: IOCTL (TEST) failed.\n");
        return;
    }
#endif

    /* Munmap */
    munmap(ghcb, sizeof(struct ghcb));

    /* Remove system call stuffs */
    syscall_fini();

    /* Close the debug file. */
    if (syscall_file_debug) close(syscall_debug_fd);

    printf("[*] Enclave context successfully destroyed.\n");
    printf("[.] Detail: enclave ocall exits = %ld\n", ocall_exits);
}

bool init_enclave() {
    untrusted_printf("[.] Enclave setup started. \n");

    /* Open the device */
    if (!open_device_driver()) {
        printf("Error: VEIL enclave device driver not found.\n");
        terminate_enclave();
        return false;
    }

    /* Establish VMM communication */
    if (!establish_ghcb()) {
        printf("Error: Enclave GHCB could not be established.\n");
        terminate_enclave();
        return false;
    }

    /* Create an enclave context */
    if (!create_enclave()) {
        printf("Error: Enclave context (VMSA) could not be created.\n");
        terminate_enclave();
        return false;
    }

    /* Initialize system call handler */
    if (!syscall_init()) {
        printf("Error: System call handlers could not be initialized.\n");
        terminate_enclave();
        return false;
    }

    /* Initialize and open the debug file. */
    if (syscall_file_debug) {
        int pid = getpid();
        char pids[20];
        sprintf(pids, "%d", pid); 
        char filename[] = "syscall-";
        strcat(filename, pids);
        syscall_debug_fd = open(filename, O_RDWR | O_CREAT);
        if (syscall_debug_fd < 0) {
            printf("Error: could not open file.\n");
            return false;
        }
    }

    untrusted_printf("[*] Enclave setup was successful. \n");

    return true;
}

void enable_enclave_execution(void) {
    enclave_execution = true;
}

void disable_enclave_execution(void) {
    enclave_execution = false;
}

void enable_syscall_debug(void) {
    syscall_args_debug = true;
}

void enable_syscall_file_debug(void) {
    syscall_file_debug = true;
}

bool check_enclave_execution(void) {
    return enclave_execution;
}

#if 0
bool init_enclave_v2(unsigned long addr) {
    untrusted_printf("[.] Enclave setup started. (main = %p)\n", (void*) addr);
    enclave_main_addr = addr;

    /* Open the device */
    if (!open_device_driver()) {
        printf("Error: VEIL enclave device driver not found.\n");
        terminate_enclave();
        return false;
    }

    /* Establish VMM communication */
    if (!establish_ghcb()) {
        printf("Error: Enclave GHCB could not be established.\n");
        terminate_enclave();
        return false;
    }

    /* Create an enclave context */
    if (!create_enclave()) {
        printf("Error: Enclave context (VMSA) could not be created.\n");
        terminate_enclave();
        return false;
    }

    /* Initialize system call handler */
    if (!syscall_init()) {
        printf("Error: System call handlers could not be initialized.\n");
        terminate_enclave();
        return false;
    }

    /* Initialize and open the debug file. */
    if (syscall_file_debug) {
        int pid = getpid();
        char pids[20];
        sprintf(pids, "%d", pid); 
        char filename[] = "syscall-";
        strcat(filename, pids);
        syscall_debug_fd = open(filename, O_RDWR | O_CREAT);
        if (syscall_debug_fd < 0) {
            printf("Error: could not open file.\n");
            return false;
        }
    }

    untrusted_printf("[*] Enclave setup was successful. \n");

    return true;
}
#endif