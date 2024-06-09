#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef MUSL
#include <linux/ioctl.h>
#endif
#include <sys/ioctl.h>

/* within the guest, this link should be maintained 
 * (added the host for testing purposes only)
 */
#ifndef HOST
    #include "../../../driver/ioctl-defines.h"
#else
    #include "../../../guest/driver/ioctl-defines.h"
#endif
#include "common.h"

/* For testing purposes, allocate the stack here */
char enclave_stack[(1 << 14)] __attribute__ ((aligned (4096)));
const uintptr_t enclave_stack_base = (uintptr_t) enclave_stack + sizeof(enclave_stack);
bool enclave_execution = false;     /* Track whether the enclave has started or not (for testing purposes) */

/* Global variables related to the device driver and GHCB */
char* devname = "/dev/veil-driver";
int   devfd = -1;
struct ghcb* ghcb;

/* Specifying enclave entry point */
unsigned long enclave_entry = 0x0;

/* Since the system only works with 1 CPU, we make sure only CPU0 is active for
 * the test execution.
 */
#ifndef MUSL
int get_current_cpu(void) {
    unsigned int cpu = -1;
    unsigned int node = -1;

    /* Get current CPU */
    getcpu(&cpu, &node);
    printf("cpu: %d, node: %d\n", cpu, node);
    
    return cpu;
}
void assert_correct_cpu(void) {
    /* Sanity check */
    if (get_current_cpu() == -1) {
        printf("Error: OS did not allocate correct CPU\n");
        exit(-1);
    }
}
#else
int get_current_cpu(void) {}
void assert_correct_cpu(void) {}
#endif

/* This function checks that the device driver is available */
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

/* This function establishes a guest-hypervisor communication block (GHCB) in 
 * the address space of the program. Enclave <--> Application transitions are
 * ensured using this GHCB.
 */
bool establish_ghcb(void) {
    struct ioctl_establish_ghcb_request* tmp;
    void* ghcb_addr;
    printf("Establishing GHCB ...\n");

    assert_correct_cpu();

    tmp = malloc(sizeof(struct ioctl_establish_ghcb_request));
    printf ("ioctl message address = %px\n", (void*) tmp);

    /* Mmap some memory region for now */
    ghcb_addr = (void*) mmap((void*) 0x100000,
        sizeof(struct ghcb),
        PROT_READ|PROT_WRITE,
        MAP_ANON|MAP_PRIVATE,
        0,0);
    if (!ghcb_addr) {
        printf("Error: could not allocate space for GHCB.\n");
        return false;
    }

    /* Send that virtual address to VMOD */
    tmp->uvaddr = (unsigned long) ghcb_addr;
    tmp->paddr  = 0;
    long ret = ioctl(devfd, ESTABLISH_GHCB, tmp);
    if (ret != 0 || tmp->paddr == 0) {
        printf("Error: IOCTL (ESTABLISHGHCB) failed.\n");
        printf("GHCB <==> PA = %p\n", (void*) tmp->paddr);
        return false;
    }

    ghcb = (struct ghcb*) ghcb_addr;
    printf("GHCB <==> PA = %p\n", (void*)tmp->paddr);
    printf("[*] GHCB established successfully.\n");
    return true;
}

/* This function executes an ioctl call and specifies the entry/stack of the enclave 
 * to be executed.
 */
bool create_enclave(void) {
    struct ioctl_enclave_request test;
    test.addr = enclave_entry;
    test.stackaddr = enclave_stack_base;

    assert_correct_cpu();

    printf("[.] Creating an enclave context (entry ==> %px, stack ==> %px)\n",
        (void*) test.addr, (void*) test.stackaddr);

    /* ioctl to veil-driver */
    long ret = ioctl(devfd, ENCLAVE_TEST, &test);
    if (ret != 0) {
        printf("Error: IOCTL (ENCLAVE) failed.\n");
        return false;
    }

    printf("[*] Enclave context created successfully!\n");
    return true;
}

/* This function is called from within the application to jump to enclave's VMPL2. */
void start_enclave(void) {
    /* Specify the exit code and info */       
    ghcb_set_sw_exit_code(ghcb, GHCB_NAE_RUN_VMPL);
	ghcb_set_sw_exit_info_1(ghcb, 2);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    /* Initiate a hypercall */
    VMGEXIT();
}

/* This function is called from within the enclave to exit back to VMPL3. */
void exit_enclave(void) {
    /* Specify the exit code and info */       
    ghcb_set_sw_exit_code(ghcb, GHCB_NAE_RUN_VMPL);
	ghcb_set_sw_exit_info_1(ghcb, 3);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    /* Initiate a hypercall */
    VMGEXIT();
}