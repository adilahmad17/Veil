#define _GNU_SOURCE
#include "scsan.h"
#include <syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>
#include <sys/vfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>

void test_write(context_t *ctx) {
        char *s = "hello";
        intptr_t args[] = {10, (intptr_t)s, strlen(s)};
        scsan_syscall(ctx, SYS_write, args);
        // write(10, s, strlen(s));
}

void test_sendmsg(context_t *ctx) {
        // Thank you ChatGPT.
        struct sockaddr_in serv_addr;
        struct iovec iov[1];
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));

        char buffer[100];
        int fd = 123;
        char ctrl_buf[CMSG_SPACE(sizeof(int))];
        memset(ctrl_buf, 0, sizeof(ctrl_buf));
        struct cmsghdr *cmsg;
        
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(12345);
        serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        memset(buffer, 0, sizeof(buffer));
        strcpy(buffer, "Hello, server!");
        iov[0].iov_base = buffer;
        iov[0].iov_len = strlen(buffer);
        msg.msg_name = &serv_addr;
        msg.msg_namelen = sizeof(serv_addr);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
        intptr_t args[] = {fd, (intptr_t)&msg, 0};
        scsan_syscall(ctx, SYS_sendmsg, args);
        // sendmsg(fd, &msg, 0);
}

void test_writev(context_t *ctx) {
        int fd = 33;
        char buffer1[] = "Hello, ";
        char buffer2[] = "world!\n";
        struct iovec iov[2];

        iov[0].iov_base = buffer1;
        iov[0].iov_len = strlen(buffer1);
        iov[1].iov_base = buffer2;
        iov[1].iov_len = strlen(buffer2);

        intptr_t args[] = {fd, (intptr_t)iov, 2};
        scsan_syscall(ctx, SYS_writev, args);  
        // writev(fd, iov, 2);
}

void test_clock_nanosleep(context_t *ctx) {
        struct timespec sleep_interval = {
                .tv_sec = 0,
                .tv_nsec = 100000000
        };
        intptr_t args[] = {CLOCK_MONOTONIC, 0, (intptr_t)&sleep_interval, 0};
        scsan_syscall(ctx, SYS_clock_nanosleep, args); 
        // clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_interval, NULL);
}

void test_access(context_t *ctx) {
        const char *file = "/home/user/file";
        intptr_t args[] = {(intptr_t)file, R_OK};
        scsan_syscall(ctx, SYS_access, args);  
        // access(file, R_OK);
}

void test_ioctl(context_t *ctx) {
        int block = 0x78123456;
        int fd = 100;
        intptr_t args[] = {(intptr_t)fd, FIONBIO, (intptr_t)&block};
        scsan_syscall(ctx, SYS_ioctl, args);  
        // ioctl(fd, FIONBIO, &block);
}

void test_execve(context_t *ctx) {
        char *pathname = "/path/to/file";
        char *argv[] = {
                "xyz",
                "abc",
                NULL
        };
        char **envp = NULL;
        intptr_t args[] = {(intptr_t)pathname, (intptr_t)argv, (intptr_t)envp};
        scsan_syscall(ctx, SYS_execve, args);  
        // execve(pathname, argv, envp);
}

void test_set_robust_list(context_t *ctx) {
        void *addr = (void *)0xdeadbeef;
        int len = 2;
        intptr_t args[] = {(intptr_t)addr, (intptr_t)len};
        scsan_syscall(ctx, SYS_set_robust_list, args);
        // syscall(SYS_set_robust_list, addr, len);
}

void test_mmap(context_t *ctx) {
        void *addr = (void *)0xdeadbeef;
        int len = 0x1000;
        int prot = PROT_READ|PROT_WRITE;
        int flag = MAP_FIXED | MAP_FILE;
        int fd = 12345;
        int offset = 22;
        intptr_t args[] = {(intptr_t)addr, (intptr_t)len, (intptr_t)prot, (intptr_t)flag, (intptr_t)fd, (intptr_t)offset};
        scsan_syscall(ctx, SYS_mmap, args);  
        // syscall(SYS_mmap, addr, len, prot, flag, fd, offset);
}

struct kernel_sigaction {
  unsigned long sa__;
  unsigned long flags;
  unsigned long restorer;
  unsigned long masks;
};

void test_rt_sigaction(context_t *ctx) {
        struct kernel_sigaction s;
        memset(&s, 0, sizeof(s));
        void *old = NULL;
        int len = 8;
        s.masks = SIGINT|SIGHUP;
        s.flags = 0;
        s.restorer = 0xdeadbeef;
        s.sa__ = (long)SIG_IGN;
        intptr_t args[] = {(intptr_t)SIGUSR1, (intptr_t)&s, (intptr_t)old, (intptr_t)len};
        scsan_syscall(ctx, SYS_rt_sigaction, args);  
        // syscall(SYS_rt_sigaction, SIGUSR1, &s, old, len);
}

int main() {
        spec_t spec;
        init_spec(&spec);
        context_t ctx;
        init_context(&ctx, &spec);

        test_write(&ctx);
        test_sendmsg(&ctx);
        test_writev(&ctx);
        test_access(&ctx);
        test_clock_nanosleep(&ctx);
        test_ioctl(&ctx);
        test_execve(&ctx);
        test_set_robust_list(&ctx);
        test_mmap(&ctx);
        test_rt_sigaction(&ctx);

        context_free(&ctx);
}