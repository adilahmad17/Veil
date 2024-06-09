#!/bin/bash -e

CMD="./main"

# Environment variables required by the SCSAN context
unset SCSAN_DEBUG
export SCSAN_CALL_SPEC=`pwd`/../../../syscall-sanitizer/spec//call_spec.gen
export SCSAN_ARG_SPEC=`pwd`/../../../syscall-sanitizer/spec/arg_spec.gen
export SCSAN_DEBUG=1

# Rebuild and run
make clean && make
$CMD