HELPER = ../helper/common.c
  
all: main

main: main.c enclave_main.c $(HELPER)
	gcc $^ -o $@

# for debugging on the host
host: main.c enclave_main.c $(HELPER)
	gcc $^ -o $@ -DHOST

clean:
	rm -rf main host