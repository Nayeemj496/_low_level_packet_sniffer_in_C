#!/bin/bash

# Check if libpcap-dev is installed; install if missing
if ! dpkg -s libpcap-dev >/dev/null 2>&1; then
    echo "libpcap-dev not found. Installing..."
    sudo apt update && sudo apt install -y libpcap-dev
else
    echo "libpcap-dev is already installed."
fi

# Check if sniffer binary exists; run make if missing
if [ ! -f "sniffer" ]; then
    echo "sniffer binary not found. Building project..."
    make
else
    echo "sniffer binary already exists. Skipping build step."
fi

# Bring up the Docker Compose stack
docker compose -f test/docker-compose.yml up
