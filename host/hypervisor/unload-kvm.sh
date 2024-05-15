#!/bin/bash -e

sudo modprobe -r kvm_amd
sudo modprobe -r ccp
sudo modprobe -r kvm