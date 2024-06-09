#include <stdio.h>

void exit_enclave(void);
int global_i=1;
const int b = 0;

void enclave_entry(int ptr) {
	printf("Hello world from the enclave!\n");
    int i=1;
    exit_enclave();
}