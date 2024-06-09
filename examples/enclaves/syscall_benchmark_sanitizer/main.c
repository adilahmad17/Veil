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

/* Defined inside the musl folders. */
extern unsigned long enclave_entry;
extern void syscall_handler(void);
extern bool enclave_execution;

void test_mmap(void) {
    void *addr = (void *)NULL;
    int len = 0x1000;
    int prot = PROT_READ | PROT_WRITE;
    int flag = MAP_PRIVATE | MAP_ANONYMOUS;
    int fd = 0;
    int offset = 0;

    void* ret = mmap(addr, len, prot, flag, fd, offset);
    if (ret == NULL) {
        printf("Test: mmap failed.\n");
        return;
    }
    printf("found %p\n", ret);

    int* ret_int = ((int*) ret);
    *ret_int = 1;
    printf("MMAP: PASSED (%p)\n", ret);
}

void test_write() {
    char *s = "hello";
    intptr_t args[] = {10, (intptr_t)s, strlen(s)};
    write(10, s, 5);
}

void test_stat() {
    struct stat sfile;
    stat("stat.c", &sfile);
    printf("st_mode = %o\n", sfile.st_mode);
}

void test_writev2() {
    char *s = "hello";
    int fd = open("test.txt", O_RDWR);
    if (fd < 0) {
        printf("Test: open failed.\n");
        exit(-1);
    }

    intptr_t args[] = {fd, (intptr_t)s, strlen(s)};
    int ret = syscall(SYS_write, args);
    if (ret < 0) {
        printf("Test: write failed.\n");
        exit(-1);
    }

    printf("OPEN+WRITE: PASSED.\n");
}

void test_writev() {
        int fd = 33;
        char buffer1[] = "Hello, ";
        char buffer2[] = "world!\n";
        struct iovec iov[2];

        iov[0].iov_base = buffer1;
        iov[0].iov_len = strlen(buffer1);
        iov[1].iov_base = buffer2;
        iov[1].iov_len = strlen(buffer2);

        intptr_t args[] = {fd, (intptr_t)iov, 2};
        // syscall(SYS_writev, args);
        writev(fd, (intptr_t)iov, 2);
}

void test_ids() {

    printf("Effective group ID: %d\n", getegid());
    printf("Effective user ID: %d\n", geteuid());
    printf("Group ID: %d\n", getgid());
    printf("Process group ID: %d\n", getpgrp());
    printf("Process ID: %d\n", getpid());
    printf("Parent process ID: %d\n", getppid());
    printf("Thread ID: %d\n", gettid());
    printf("User ID: %d\n", getuid());
    
    printf("ID: PASSED.\n");
}

void test_prints() {
    /* Simply print this 20 times to be sure. */
    for (int i = 0 ; i < 1000; i++)
        printf("Hello World!\n");
}

void test_fstat() {
    int file=0;
    if((file=open("test.txt",O_RDONLY)) < -1)
        return 1;
    printf("file open complete.\n");

    struct stat fileStat;
    if(fstat(file,&fileStat) < 0)    
        return 1;

    struct stat newFileStat;
    if (fstatat(file, "", &newFileStat, AT_EMPTY_PATH) == -1) {
        perror("fstatat failed");
        return 1;
    }
    printf("fstat complete.\n");
}

void test_access() {
    int result = access("test.txt", F_OK | R_OK);
    if (result == 0) {
        printf("File %s exists and is readable\n", "test.txt");
    } else {
        perror("access failed");
        return 1;
    }
}

void handler(int signum) {
    printf("Timer expired!\n");
}

void test_alarm() {
    signal(SIGALRM, handler);
    unsigned int seconds = 2;
    alarm(seconds);
    printf("Timer set for %d seconds\n", seconds);
    sleep(3);
    return 0;
}

#if 0
void test_socket_bind() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return 1;
    }
    printf("Socket created\n");
    close(sockfd); 
}
#endif

void test_brk() {

    void* ptr2 = sbrk(1024);
    if (ptr2 == (void*)-1) {
        perror("sbrk failed");
        return 1;
    }


}

void test_chdir() {

    int ret = chdir("/tmp");
    if (ret == -1) {
        perror("chdir failed");
        return 1;
    }

}

void test_chmod() {

    int ret = chmod("test.txt", 0644);
    if (ret == -1) {
        perror("chmod failed");
        return 1;
    }

}

void test_clock_nanosleep() {

    struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };
    struct timespec rem;

    int ret = clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
    if (ret == -1) {
        perror("clock_nanosleep failed");
        return 1;
    }

}

void test_open_read_readlink_close_dup_dup2() {

    char buf[1024];

    int fd = open("test.txt", O_RDONLY);
    if (fd == -1) {
        perror("open failed");
        return 1;
    }

    const char *file_name = "test.txt";
    int dir_fd = AT_FDCWD;
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    mode_t mode = 0666; // permissions for the new file
    int fdat = openat(dir_fd, file_name, flags, mode);
    if (fdat == -1) {
        perror("openat failed");
        return 1;
    }

    if (read(fd, buf, 512) == -1) {
        perror("read failed");
        return 1;
    }

    if (readlink("testlink.txt", buf, 512) == -1) {
        perror("readlink failed");
        return 1;
    }

    int dupV = dup(fd);
    if (dupV == -1) {
        perror("dup failed");
        return 1;
    }

    int dup2V;

    int ret1 = dup2(fd, dup2V);
    if (ret1 == -1) {
        perror("dup2 failed");
        return 1;
    }

    int ret2 = close(fd);
    if (ret2 == -1) {
        perror("fd close failed");
        return 1;
    }

    close(dupV);
    close(dup2V);
}

void test_pread64() {
    int fd = open("test.txt", O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }

    off_t offset = 5;
    size_t count = 10;
    char buffer[count];

    ssize_t bytes_read = pread64(fd, buffer, count, offset);
    if (bytes_read < 0) {
        perror("pread64 failed");
        return 1;
    }

    close(fd);
}

void test_execve() {
    char *args[] = {"pwd", NULL, NULL};
    char *envp[] = {NULL};

    int ret = execve("/bin/pwd", args, envp);
    if (ret == -1) {
        perror("execve failed");
        return 1;
    }
}


void test_files() {
    int fd = open("test.txt", O_RDONLY);

    int ret = posix_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);
    if (ret == -1) {
        perror("fadvise64 failed");
        return 1;
    }

    if (faccessat(fd, "test.txt", R_OK, 0) == -1) {
        perror("faccessat failed");
        return 1;
    }

    if (fchmod(fd, S_IRUSR) == -1) {
        perror("fchmod");
        return 1;
    }

    off_t file_size = lseek(fd, 0, SEEK_END);

    if (file_size == -1) {
        perror("lseek failed");
        return 1;
    }

    struct stat file_info;
    if (lstat("test.txt", &file_info) == -1) {
        perror("lstat");
        return 1;
    }

    close(fd);
}

void test_getrandom() {

    char buf[1024];

    ssize_t nread = syscall(SYS_getrandom, buf, 1024, 0);
    if (nread == -1) {
        perror("getrandom");
        exit(1);
    }

    for (int i = 0; i < 1024; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void test_mmap_munmap_madvise_mprotect() {

    size_t page_size = sysconf(_SC_PAGESIZE);
    void *addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    if (madvise(addr, page_size, MADV_DONTNEED) == -1) {
        perror("madvise failed");
        return 1;
    }

    if (mprotect(addr, page_size, PROT_READ) == -1) {
        perror("mprotect failed");
        return 1;
    }

    if (munmap(addr, page_size) == -1) {
        perror("munmap failed");
        return 1;
    }

}

void test_mkdir_rmdir() {
    const char *dir_name = "new_dir";
    mode_t mode = 0777;
    if (mkdir(dir_name, mode) == -1) {
        perror("mkdir failed");
        return 1;
    }

    if (rmdir("new_dir") == -1) {
        perror("rmdir failed");
        return 1;
    }
}

void test_symlink() {

    if (symlink("test.txt", "symlink") == -1) {
        perror("symlink failed");
        return 1;
    }
}

void test_pipe_pipe2_poll_ppoll() {
    int pipefd[2];
    int ret;

    ret = pipe(pipefd);
    if (ret == -1) {
        perror("pipe failed");
        return 1;
    }

    int pipefd2[2];
    ret = pipe2(pipefd2, O_NONBLOCK);
    if (ret == -1) {
        perror("pipe2 failed");
        return 1;
    }

    // Use poll to wait for data to become available on the pipe
    struct pollfd pfd[2];
    pfd[0].fd = pipefd[0];
    pfd[0].events = POLLIN;
    pfd[1].fd = pipefd2[0];
    pfd[1].events = POLLIN;
    ret = poll(pfd, 2, 1000); // Wait for 1 second
    if (ret == -1) {
        perror("poll failed");
        return 1;
    } else if (ret == 0) {
        printf("Timeout expired.\n");
    } else {
        if (pfd[0].revents & POLLIN) {
            printf("Data is available on pipefd[0].\n");
        }
        if (pfd[1].revents & POLLIN) {
            printf("Data is available on pipefd2[0].\n");
        }
    }

    // Use ppoll to wait for data to become available on the pipe with a timeout and signal mask
    struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    ret = ppoll(pfd, 2, &timeout, &mask);
    if (ret == -1) {
        perror("ppoll failed");
        return 1;
    } else if (ret == 0) {
        printf("Timeout expired.\n");
    } else {
        if (pfd[0].revents & POLLIN) {
            printf("Data is available on pipefd[0].\n");
        }
        if (pfd[1].revents & POLLIN) {
            printf("Data is available on pipefd2[0].\n");
        }
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(pipefd2[0]);
    close(pipefd2[1]);
}

void test_sysinfo() {

    struct sysinfo info;

    if (sysinfo(&info) == -1) {
        perror("sysinfo failed");
        return 1;
    }

    printf("Uptime: %ld seconds\n", info.uptime);
    printf("Total RAM: %ld bytes\n", info.totalram);
    printf("Free RAM: %ld bytes\n", info.freeram);
    printf("Number of processes: %d\n", info.procs);
}

void test_select() {
    int ret;
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    // Set up the timeout value to 5 seconds
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    ret = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);
    if (ret == -1) {
        perror("select failed");
        return 1;
    } else if (ret == 0) {
        printf("Timeout reached.\n");
    } else {
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            printf("Input is available.\n");
        }
    }
}

void test_times() {
    struct tms t;
    clock_t start, end;
    long ticks = sysconf(_SC_CLK_TCK);

    start = times(&t);
    sleep(1); 
    end = times(&t);

    printf("User time: %ld.%03ld s\n", (end - start) / ticks, (end - start) % ticks);
}

void test_unlink() {

    if (unlink("symlink") == -1) {
        perror("unlink failed");
        return 1;
    }
}

void test_kill() {

    int result = kill(getpid(), SIGINT);

    if (result == -1) {
        perror("kill");
        return 1;
    }
}

void test_uname() {
    struct utsname uts;

    if (uname(&uts) == -1) {
        perror("uname failed");
        return 1;
    }

    printf("Operating system: %s\n", uts.sysname);
    printf("Hostname: %s\n", uts.nodename);
    printf("Kernel release: %s\n", uts.release);
    printf("Operating system version: %s\n", uts.version);
    printf("Hardware identifier: %s\n", uts.machine);
}

void test_ioctl() {

    int fd = open("/dev/null", O_RDONLY);

    if (fd == -1) {
        perror("open failed");
        return 1;
    }

    int flags;

    if (ioctl(fd, F_GETFD, &flags) == -1) {
        perror("ioctl F_GETFD failed");
        close(fd);
        return 1;
    }

    close(fd);

    printf("/dev/null file descriptor flags: %d\n", flags);
}


#define NUM_THREADS 2

void *print_hello(void *thread_id) {
    long id = (long) thread_id;
    printf("Hello from thread %ld\n", id);
    pthread_exit(NULL);
}

void test_pthread() {
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;

    for (t = 0; t < NUM_THREADS; t++) {
        printf("Creating thread %ld\n", t);
        rc = pthread_create(&threads[t], NULL, print_hello, (void *) t);

        if (rc) {
            fprintf(stderr, "Error: pthread_create() returned %d\n", rc);
            return 1;
        }
    }

    for (t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }

    printf("All threads have completed.\n");
}

void test_prlimit64() {
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = 100;
    if (prlimit64(0, RLIMIT_NOFILE, &rlim, NULL) != 0) {
        perror("prlimit64 failed");
        return 1;
    }

    printf("Max number of file descriptors set to %lld\n", (long long)rlim.rlim_cur);
}

void run_tests() {
#if ENCLAVE==1
    /* Start of enclave code. */
    enclave_execution=true;
#endif

#if ENCLAVE==1
    printf("Testing Musl with SCSAN.\n");
    test_write();
    test_prints();
    test_writev();
    test_ids();
    test_mmap();
    test_stat();
    test_fstat();
    test_access();
    test_brk();
    test_chdir();
    test_chmod();
    test_open_read_readlink_close_dup_dup2();
    test_files();
    test_pread64();
    test_prlimit64();
    test_mkdir_rmdir();
    test_getrandom();
    test_mmap_munmap_madvise_mprotect();
    test_symlink();
    test_sysinfo();
    test_times();
    test_uname();
    test_unlink();
#else
    printf("Testing Musl with SCSAN.\n");
    test_write();
    test_prints();
    test_writev();
    test_ids();
    test_mmap();
    test_stat();
    test_fstat();
    test_access();
    test_brk();
    test_chdir();
    test_chmod();
    test_open_read_readlink_close_dup_dup2();
    test_files();
    test_pread64();
    test_prlimit64();
    test_mkdir_rmdir();
    test_getrandom();
    test_mmap_munmap_madvise_mprotect();
    test_symlink();
    test_sysinfo();
    test_times();
    test_uname();
    test_unlink();
#endif

    printf("Tests successfully completed; Good Bye!\n");

#if ENCLAVE==1
    /* End of enclave code. */
    enclave_execution=false;
    exit_enclave();
#else
    test_kill();
#endif
}

int main() {

#if ENCLAVE==1
    printf ("Initializing the enclave (entry ==> %p) \n", (void*) &run_tests);

    enclave_entry = (unsigned long) &run_tests;
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
