HELPER = ../helper/common.c

all: main

main: main.c enclave_main.c enclave_ocalls.c syscall_handlers.c $(HELPER)
	gcc $^ -o $@

host: main.c enclave_main.c enclave_ocalls.c syscall_handlers.c $(HELPER)
	gcc $^ -o $@ -DHOST

clean:
	rm -rf main host