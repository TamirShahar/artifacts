FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    bind9 bind9utils dnsutils iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY named.conf.options /etc/bind/named.conf.options
COPY named.conf.local /etc/bind/named.conf.local
COPY db.attacker.test /etc/bind/db.attacker.test

EXPOSE 53/tcp 53/udp

CMD ["sh", "-c", "tc qdisc replace dev eth0 root netem delay 600ms && exec named -g -c /etc/bind/named.conf"]
