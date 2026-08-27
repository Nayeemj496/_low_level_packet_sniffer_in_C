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
    curl \
    netcat-openbsd \
    nmap \
    tmux && \
    rm -rf /var/lib/apt/lists/*