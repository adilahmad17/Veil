#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <netinet/in.h>

#include "../helper/common.h"
#include "benchmark.h"

/* Track whether the enclave has started or not */
extern bool enclave_execution;

/* For cycling through tests */
int bench_test = 0;

void open_native_benchmark(void) {
    for (int i=0; i<TRIES; i++) {
        open("hello.txt", O_RDWR);
    }
}

void getpid_native_benchmark(void) {
    for (int i=0; i<TRIES; i++) {
        getpid();
    }
}

void mmap_native_benchmark(void) {
    for (int i=0;i<TRIES;i++) {
        mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    }
}

void munmap_native_benchmark(void) {
    for (int i=0;i<TRIES;i++) {
        void* buf = mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
        munmap(NULL, 10*1024);
    }
}

void read_native_benchmark(void) {
    int fd = open("hello.txt", O_RDONLY);
    void* buf = mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    size_t count = 10*1024;
    size_t ret;

    for (int i=0;i<TRIES;i++) {
        ret = read(fd, buf, count);
        if (ret == 0) {
            untrusted_printf("Error: read failed.\n");
        }
    }
}

void write_native_benchmark(void) {
    int fd = open("hello.txt.new", O_CREAT|O_RDWR);
    if (fd<0) {
        untrusted_printf("Error: could not open file.\n");
        return;
    }
    void* buf = mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    size_t count = 10*1024;
    size_t ret;

    for (int i=0;i<TRIES;i++) {
        ret = write(fd, buf, count);
        if (ret == 0) {
            untrusted_printf("Error: write failed.\n");
        }
    }
}

void printf_native_benchmark(void) {
    for (int i=0; i<TRIES; i++){
        printf("Hello World! This is a Native Linux Program.\n");
    }
}

void socket_native_benchmark(void) {
    for (int i=0; i<TRIES; i++) {
        int ret = socket(AF_INET, SOCK_STREAM, 0);
        if (ret <0) {
            untrusted_printf("Error: socket acquire failed.\n");
        }
    }
}

void benchmark_non_enclave(void) {
    enclave_printf("Starting Native SYSCALL benchmark.\n");
    
    /* Start timer */
    clock_t t;
    t = clock();

    if (bench_test == 0)
        open_native_benchmark();
    else if (bench_test == 1)
        getpid_native_benchmark();
    else if (bench_test == 2)
        mmap_native_benchmark();
    else if (bench_test == 3)
        read_native_benchmark();
    else if (bench_test == 4)
        write_native_benchmark();
    else if (bench_test == 5)
        printf_native_benchmark();
    else if (bench_test == 6)
        munmap_native_benchmark();
    else if (bench_test == 7)
        socket_native_benchmark();
    
    /* Stop timer */
    t = clock()-t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("Native bench (%x) took %f seconds\n", bench_test, time_taken);
}

bool setup_enclave(void) {
    /* Open the device */
    if (!open_device_driver()) return false;
    fflush(stdout);

    /* Establish VMM communication */
    if (!establish_ghcb()) return false;
    fflush(stdout);

    if (!syscall_init()) return false;

    return true;
}

void benchmark_enclave(void) {
    enclave_printf("Starting Enclave SYSCALL benchmark.\n");

    /* Creating Test Enclave (entry ==> enclave_syscall_benchmark_main(..)) */
    enclave_entry = (unsigned long) &enclave_syscall_benchmark_main;
    if (!create_enclave()) return;
    fflush(stdout);

    clock_t t;
    t = clock();

    /* Start the enclave for the first time */
    start_enclave();

    /* Execute a hypercall to start the enclave; keep 
     * returning to the enclave while the execution is
     * still to be completed.
     */
    while (enclave_execution == true) {
        syscall_handler();
        start_enclave();
        fflush(stdout);
    }

    t = clock()-t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("Enclave bench (%x) took %f seconds\n", bench_test, time_taken);
}

/* Application (non-enclave) function */
int main(void) {
    untrusted_printf("Starting the application.\n");

    // Setup the enclave
    if (!setup_enclave()) {
        printf("[x] Error: enclave setup failed, exiting.\n");
        return -1;
    }

    // Run for each system call
    for (int i=0; i<8; i++) {
        bench_test=i;
        benchmark_enclave();
        benchmark_non_enclave();
    }

    untrusted_printf("Success; exiting application.\n");
}
