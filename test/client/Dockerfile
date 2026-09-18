FROM lscr.io/linuxserver/brave:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        inetutils-telnet \
        net-tools \
        iputils-ping \
        traceroute \
        iproute2 \
        dnsutils \
        iptables \
        tcpdump \
        tmux && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 3000