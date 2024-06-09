all: main

main: main.c ioctl.c
	gcc $^ -o $@

# for testing/debugging purposes
host: main.c ioctl.c
	gcc $^ -o main -DHOST

clean:
	rm -rf main