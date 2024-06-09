#!/bin/bash

set -e

PROJ_DIR=$(readlink -f $(dirname $BASH_SOURCE)) 

cd $PROJ_DIR/syzkaller && git reset --hard && git apply ../spec/syzkaller.patch  && make -j`nproc`
cd $PROJ_DIR/src/rulegen && SCSAN_SYSCALL_LIST=$PROJ_DIR/spec/syscall go test -v > log
cd $PROJ_DIR/src/scsan && make
cd $PROJ_DIR/test && make
