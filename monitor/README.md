# Veil: A Protected Services Framework for Confidential Virtual Machines

This directory contains the code for Veil's security monitor and services integrated into AMD's Secure VM Service Module.

## Directory Structure (TODO)

## Steps

1. Install Nightly Rust and pre-requisites
```
curl https://sh.rustup.rs -sSf | sh
make prereq
rustup component add rust-src
```

2. Install the security monitor with all debugging enabled:

```
make FEATURES=verbose
```

