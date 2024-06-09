## Musl-Libc (Modified to execute with Veil and Syscall-Sanitizer)

### Pre-requisites

Build the system call sanitizer (SCSAN) by following steps mentioned in ../syscall-sanitizer

### Step 1: Compile SCSAN-musl
```
./make-musl.sh
```

### Step 2: Run benchmark (malloc and syscall) tests

```
cd tests/syscall && ./run.sh
cd tests/malloc && ./run.sh
```