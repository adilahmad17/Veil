all: main

main: main.c
	../../obj/musl-gcc -static -L../../lib -lc -g -O0 -I../../include -nostdinc $^ -o $@

clean: 
	rm -rf main
