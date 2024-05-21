all: main

main: main.c ioctl.c
	gcc $^ -o $@

host: main.c ioctl.c
	gcc $^ -o main -DHOST

clean:
	rm -rf main