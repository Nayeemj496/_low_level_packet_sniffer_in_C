FROM ubuntu:latest

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    net-tools \
    iputils-ping \
    traceroute \
    iproute2 \
    dnsutils \
    iptables \
    tcpdump \
    tmux && \
    rm -rf /var/lib/apt/lists/*
