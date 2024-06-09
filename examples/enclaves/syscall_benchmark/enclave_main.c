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
#include <netinet/in.h>

#include "../helper/common.h"
#include "benchmark.h"

/* Track whether the enclave has started or not */
extern bool enclave_execution;
extern int bench_test;

void open_enclave_benchmark(void) {
    for (int i=0;i<TRIES;i++) ocall_open("hello.txt", O_RDWR);
}

void getpid_enclave_benchmark(void) {
    for (int i=0;i<TRIES;i++) ocall_getpid();
}

void mmap_enclave_benchmark(void) {
    for (int i=0;i<TRIES;i++) {
        ocall_mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    }
}

void munmap_enclave_benchmark(void) {
    for (int i=0;i<TRIES;i++) {
        void* buf = ocall_mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
        ocall_munmap(NULL, 10*1024);
    }
}

void read_enclave_benchmark(void) {
    int fd = ocall_open("hello.txt", O_RDWR);
    void* buf = ocall_mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    size_t count = 10*1024;

    for (int i=0;i<TRIES;i++) {
        ocall_read(fd, buf, count);
    }
}

void write_enclave_benchmark(void) {
    int fd = ocall_open("hello.txt.new", O_CREAT|O_RDWR);
    void* buf = ocall_mmap(NULL, 10*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    size_t count = 10*1024;

    for (int i=0;i<TRIES;i++) {
        ocall_write(fd, buf, count);
    }
}

void printf_enclave_benchmark(void) {
    char* msg = "Hello World! This is an emulated enclave program.\n";
    char* buf = (char*) ocall_mmap(NULL, 1*1024, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    memcpy(buf, msg, strlen(msg));
    buf[strlen(msg)+1] = '\0';
    for (int i=0; i<TRIES; i++){
        ocall_printf(buf);
    }
}

void socket_enclave_benchmark(void) {
    for (int i=0; i<TRIES; i++) {
        ocall_socket(AF_INET, SOCK_STREAM, 0);
    }
}

/* Enclave function */
void enclave_syscall_benchmark_main(void) {
    /* Needed to show that enclave is running */
    enclave_execution = true;

    printf("Hello World from the enclave!\n");

    if (bench_test == 0)
        open_enclave_benchmark();
    else if (bench_test == 1)
        getpid_enclave_benchmark();
    else if (bench_test == 2)
        mmap_enclave_benchmark();
    else if (bench_test == 3)
        read_enclave_benchmark();
    else if (bench_test == 4)
        write_enclave_benchmark();
    else if (bench_test == 5)
        printf_enclave_benchmark();
    else if (bench_test == 6)
        munmap_enclave_benchmark();
    else if (bench_test == 7)
        socket_enclave_benchmark();

    /* Terminate enclave execution */
    enclave_execution = false;
    exit_enclave();
}