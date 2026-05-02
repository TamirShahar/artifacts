FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    bind9 bind9utils dnsutils \
 && rm -rf /var/lib/apt/lists/*

COPY named.conf.options /etc/bind/named.conf.options
COPY named.conf.local /etc/bind/named.conf.local
COPY db.example.com /etc/bind/db.example.com

EXPOSE 53/tcp 53/udp

CMD ["named", "-g", "-c", "/etc/bind/named.conf"]
