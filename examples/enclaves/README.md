## Enclave service examples

This directory contains a set of examples to show how test enclaves can be executed within Veil. 

*NOTE: These enclave applications are only designed to show performance and functionality. 
They require additional work to be made secure.*

### Directories

- **helloworld**: simple "Hello World" application inside an enclave
- **helloworld_loader**: simple ELF loader that loads and executes a "Hello World" application inside an enclave
- **syscall_benchmark**: set of system calls implemented as "ocalls" for an enclave
    - Designed to show the performance overhead of executing system calls inside enclaves
- **syscall_benchmark_sanitizer**: benchmark for system calls through our automated toolchain that intercepts system calls from a program and transforms them into ocalls
- **helper**: set of helper functions for all enclave examples
- **gramine**: Veil ported to the Gramine Library OS (FUTURE)