#!/bin/bash

make

# On most standard kernel, bpf programs must be loaded as a root user
#
sudo ./bpf_loader
