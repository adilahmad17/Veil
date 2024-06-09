#ifndef __IOCTL_DEFINES_H__
#define __IOCTL_DEFINES_H__

struct ioctl_enclave_request {
    unsigned long addr;
    unsigned long stackaddr;
};

struct ioctl_establish_ghcb_request {
    unsigned long uvaddr;
    unsigned long paddr;
    unsigned long sev_status;
};

struct ioctl_rmpadjust_request {
    unsigned long addr;
    unsigned long vmpl;
    unsigned long num_pages;
};

struct ioctl_enclave_secure_copy_request{
    unsigned long srcaddr;
    unsigned long dstaddr;
    unsigned long num_pages;
};

struct ioctl_dump_logs {
    unsigned long address;     // user-space address to dump logs
    unsigned long size;     // size of logs to dump
    unsigned long offset;   // offset within the protected buffer
};

// for the logging service
#define DUMP_LOGS _IOW('a', 'a', struct ioctl_dump_logs)

// for the enclave test service
#define ENCLAVE_TEST                    _IOW('a', 'b', struct ioctl_enclave_request)
#define ESTABLISH_GHCB                  _IOW('a', 'c', struct ioctl_establish_ghcb_request)
#define ENCLAVE_TEST_TERMINATE          _IOW('a', 'd', struct ioctl_establish_ghcb_request)

#endif