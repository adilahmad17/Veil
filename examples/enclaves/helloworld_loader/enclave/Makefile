CC = gcc
CFLAGS = -c
#LDFLAGS = -nostdlib -nostdinc
#LDFLAGS = -nostdlib
SRC = enclave_main.c
TARGET = enclave

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
