FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        inetutils-telnetd \
        openbsd-inetd \
        update-inetd \
        login \
        passwd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash telnetusr && \
    echo "telnetusr:telnet" | chpasswd

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 23

ENTRYPOINT ["/entrypoint.sh"]