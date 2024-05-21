#ifndef __IOCTL_DEFINES_H__
#define __IOCTL_DEFINES_H__

struct ioctl_dump_logs {
    unsigned long address;     // user-space address to dump logs
    unsigned long size;     // size of logs to dump
    unsigned long offset;   // offset within the protected buffer
};
#define DUMP_LOGS _IOW('a', 'a', struct ioctl_dump_logs)

#endif