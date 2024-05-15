#!/bin/bash -e

./vmcopy.sh
ssh veil@localhost -p 8000 \
    "cd driver; make clean; make; make install-logging; sleep 1; make remove"