#!/bin/bash -e

# host building for debug purposes
if [ "$1" == "host" ];
then 
    ./configure CFLAGS="-DHOST -DMUSL" --with-malloc=oldmalloc
else
    ./configure CFLAGS="-DMUSL" --with-malloc=oldmalloc
fi

# build with all threads
make -j`nproc`