# System Call Sanitizer

System call saniziter (SCSAN) is a library that helps a process to invoke system calls without letting OS touching its own memory, which is useful for enclave programs who ususally consider OS as an adversary.
To achieve this goal, SCSAN takes the system call number and arguments. It then does the deep copy for the system call arguments and allocating memory outside (TODO: will support registering memory allocation callbacks) of the program's address space. System calls are then invoked using these new arguments. After that, results are copied back to programs.

SCSAN relies on a system call specification to inform it how to copy the system call arguments. The specification encodes information such as struct hierarchy and buffer length constraints. SCSAN generates the specification by leverageing the existing system call specification in Syzkaller, the SOTA OS fuzzer.

The supported system calls are listed [here](spec/syscall). Another [list](spec/unsupported_syscall) shows the system calls we know that are not supported and causes.

## Build

In `script` directory, run `install_go.sh` to install the go compiler.

In `syzkaller` directory, run
```sh
git apply ../spec/syzkaller.patch
```
to patch Syzkaller grammer.

Finally, in project folder, run
```sh
./build.sh
```
to build.

## Test

In `test` folder, run
```sh
./run.py
```

You should see belowing output if everything works well.
```
PASS test 0
PASS test 1
...
```

## Use

Link your code with the static library `src/scsan/libscsan.a`. Here is an example code that uses SCSAN to do system call.

```c
#include "scsan.h"
#include <syscall.h>
#include <stdint.h>

int main() {
        // Read and parse the syscall spec.
        spec_t spec;
        init_spec(&spec);

        // Create a SCSAN context per thread.
        context_t ctx;
        init_context(&ctx, &spec);
        
        // Pass the syscall number and arguments to SCSAN.
        char *s = "hello";
        intptr_t args[] = {10, (intptr_t)s, strlen(s)};
        scsan_syscall(ctx, SYS_write, args);

        // Release the SCSAN context when thread exits.
        context_free(&ctx);
        return 0;
}
```

During runtime, specify the specification path using environment variables.

```sh
SCSAN_CALL_SPEC=$PROJ_DIR/spec/call_spec.gen \
SCSAN_ARG_SPEC=$PROJ_DIR/spec/arg_spec.gen \
./your_program
```

Set `SCSAN_DEBUG=1` to see more verbose debugging output.


# Warnings

Several aspects might threat the correctness and functionality of SCSAN:
* SCSAN cannot check if a non-NULL address is valid. So if an application provides such arguments, it can cause crashes.
* SCSAN uses strlen for string-type arguments (e.g., path in `open` system call). If an application passes a string without propriate NULL terminator, it can cause crashes.
* SCSAN passes through the return value. 
* SCSAN relies on Syzkaller specification to generate most of the system call rules. However, the specification itself might not be that reliable. If you find such cases, the common solution is to patch the Syzkaller spec. Take a look at the [existing patch](spec/syzkaller.patch).
