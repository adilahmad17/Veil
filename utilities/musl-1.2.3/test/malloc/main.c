#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <poll.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdbool.h>
#include <assert.h>

/* Defined inside the musl folders. */
extern unsigned long enclave_main_addr;
extern void syscall_handler(void);
extern bool enclave_execution;

#define TESTCOUNT 4096
#define MALLOCSZ 1024

void test_malloc() {
    void* ptrs[TESTCOUNT];
    char* cptr;
    for (int i = 0; i < TESTCOUNT; i++) {
        ptrs[i] = malloc(MALLOCSZ);
        if (!ptrs[i]) {
            printf("Error: could not allocate memory.\n");
        }

        cptr = ptrs[i];
        for (int j = 0; j < MALLOCSZ; j++) {
            *cptr = '9';
        } 
    }

    for (int i = 0; i < TESTCOUNT; i++) {
        cptr = ptrs[i];
        for (int j = 0; j < MALLOCSZ; j++) {
            assert(*cptr == '9');
        }
        free(ptrs[i]);
    }
}


void run_tests() {
#if ENCLAVE==1
    /* Start of enclave code. */
    enclave_execution=true;
#endif

#if ENCLAVE==1
    printf("Testing MALLOC.\n");
    test_malloc();
#else
    printf("Testing Musl with SCSAN.\n");
    test_malloc();
#if 0
    test_ioctl();
    test_getsockname();
#endif
    printf("Tests successfully completed (Killing process now).\n");
#endif

#if ENCLAVE==1
    /* End of enclave code. */
    enclave_execution=false;
    exit_enclave();
#endif
}

int main() {

#if ENCLAVE==1
    enclave_main_addr= (unsigned long) &run_tests;
    if (!init_enclave()) {
        printf("Error: Enclave could not be initialized.\n");
        exit(-1);
    }

    start_enclave();
    while (enclave_execution == true) {
        /* Start a system call handler. */
        syscall_handler();
        start_enclave();
    }

    /* Terminate enclave */
    terminate_enclave();
#else 
    run_tests();
#endif

    return 1;
}
