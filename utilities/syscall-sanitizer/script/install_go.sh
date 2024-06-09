#!/bin/bash

CUR_DIR=$(readlink -f $(dirname $BASH_SOURCE))
source $CUR_DIR/env.sh

echo "Installing go to $DEP..."
mkdir -p $DEP
mkdir -p $DEP/gopath
cd $DEP && \
wget https://go.dev/dl/go1.18.4.linux-amd64.tar.gz && \
tar -xzf go1.18.4.linux-amd64.tar.gz && \
rm go1.18.4.linux-amd64.tar.gz