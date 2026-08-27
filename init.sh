#!/bin/bash

# install libpcap library module
sudo apt update && sudo apt install -y libpcap-dev

# build the image
docker build --network=host -f test/Dockerfile -t ubuntu:1.0.0 .
