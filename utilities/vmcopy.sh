#!/bin/bash -e

ssh -p 8000 veil@localhost "mkdir -p ~/utilities"
ssh -p 8000 veil@localhost "mkdir -p ~/utilities/syscall-sanitizer"
rsync -avh --prune-empty-dirs -e "ssh -p 8000" musl-1.2.3 veil@localhost:~/utilities/
rsync -avh --prune-empty-dirs -e "ssh -p 8000" syscall-sanitizer/spec/ veil@localhost:~/utilities/syscall-sanitizer/spec/