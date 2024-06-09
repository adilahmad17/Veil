#include <stdio.h>
#include "../helper/common.h"

/* Track whether the enclave has started or not */
extern bool enclave_execution;

/* Sample function where VMPL2 (enclave-test) execution will start */
void hello_world_enclave(void) {
    enclave_execution = true;

    printf("Hello World from the Enclave!\n");

    /* Terminate enclave execution */
    enclave_execution = false;

    /* Exit for the last time */
    exit_enclave();
}