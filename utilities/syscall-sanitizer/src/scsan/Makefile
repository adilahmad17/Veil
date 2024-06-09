all: libscsan.a

scsan.o: scsan.c
	$(CC) -g -c -Werror -Wall -I ../../include -o $@ $^

libscsan.a: scsan.o
	ar rcs $@ $^

.PHONY: clean

clean:
	rm -rf *.a *.o