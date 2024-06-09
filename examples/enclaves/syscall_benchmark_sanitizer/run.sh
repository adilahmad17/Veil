#!/bin/bash -e

# cleanup
rm -rf test.txt testlink.txt

# check arguments to see what to run
CMD="./native"
if [ "$1" == "enclave" ];
then
    CMD="./enclave"
fi

# Environment variables required by the SCSAN context
unset SCSAN_DEBUG
export SCSAN_CALL_SPEC=`pwd`/../../../utilities/syscall-sanitizer/spec//call_spec.gen
export SCSAN_ARG_SPEC=`pwd`/../../../utilities/syscall-sanitizer/spec/arg_spec.gen

# this can enable debugging of pointers during sanitization
# export SCSAN_DEBUG=0

# Rebuild and run
make clean && make $1

$CMD