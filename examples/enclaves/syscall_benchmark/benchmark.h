#ifndef __ENCLAVE_OCALLS_H__
#define __ENCLAVE_OCALLS_H__

#define TRIES   100

// fancy print statements
#define enclave_printf(args...) \
    printf("enclave: " args)

#define untrusted_printf(args...) \
    printf("app: " args)

// random number assigned to printf
#define OCALL_printf 0x1234

// generic ocall message buffer
typedef struct {
    int syscall_no;
    
    long arg1;
    long arg1_size;

    long arg2;
    long arg2_size;

    long arg3;
    long arg3_size;

    long arg4;
    long arg4_size;

    long arg5;
    long arg5_size;

    int ret;
} syscall_msg_buffer;

// open ocall message buffer
typedef struct {
    char name[128];
    int name_size;
    int mode;
} ocall_open_buffer;

// Defined: enclave_main.c
void enclave_syscall_benchmark_main(void);

// Defined: enclave_ocalls.c
void ocall_getpid(void);
int ocall_open(char* name, int mode);
void* ocall_mmap(void* tmp, unsigned long size, unsigned long prot,
    unsigned long attrs, int fd, int zero);
void* ocall_munmap(void* tmp, unsigned long size);    
void ocall_read(int fd, void* buf, size_t count);
void ocall_write(int fd, void* buf, size_t count);
void ocall_socket(int domain, int type, int protocol);
void ocall_printf(char* buf);

// Defined: main.c
void open_native_benchmark(void);
void getpid_native_benchmark(void);
void mmap_native_benchmark(void);
void munmap_native_benchmark(void);
void read_native_benchmark(void);
void write_native_benchmark(void);
void printf_native_benchmark(void);
void socket_native_benchmark(void);

// Defined: syscall_handlers.c
bool syscall_init(void);
void syscall_fini(void);
void syscall_handler(void);

#endif