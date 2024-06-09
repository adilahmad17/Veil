all: native

enclave: main.c
	../../../utilities/musl-1.2.3/obj/musl-gcc -static -L../../lib -lc -I../include -nostdinc -DENCLAVE=1 $^ -o $@

native: main.c
	../../../utilities/musl-1.2.3/obj/musl-gcc -static -L../../lib -lc -g -O0 -I../../include -nostdinc $^ -o $@

clean: 
	rm -rf native enclave *.txt
