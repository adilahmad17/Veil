HELPER = ../../helper/common.c
CFLAGS = -w -fPIE -static -g
LDFLAGS = 

all: loader

loader: main.c enclave_loader.c $(HELPER)
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)

# for debugging on the host
host: main.c enclave_loader.c $(HELPER)
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS) -DHOST

clean:
	rm -rf loader host