all: test

test: test.c ../src/scsan/libscsan.a
	$(CC) -g -Werror -Wall -I ../include -o $@ $^ ../src/scsan/libscsan.a

.PHONY: clean

clean:
	rm -rf test