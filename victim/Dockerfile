FROM ubuntu:24.04

ENV container=docker

RUN apt-get update && apt-get install -y \
    build-essential g++ gcc make cmake \
    iproute2 iputils-ping curl net-tools tcpdump procps python3 netcat-openbsd dnsutils systemd-resolved \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m victim_user && useradd -m malicious_user

WORKDIR /artifact

COPY . /artifact/

RUN if [ -f client.cpp ]; then g++ client.cpp -o client; fi
RUN if [ -f cbpf_pre_processing.cpp ]; then g++ cbpf_pre_processing.cpp -o cbpf_pre_processing; fi
RUN if [ -f main.cpp ]; then g++ main.cpp -o main; fi
RUN make -C /artifact/tcp_attack/pre_processing/cbpf
RUN install -m 0755 /artifact/tcp_attack/pre_processing/cbpf/cbpf_preprocessing /usr/local/bin/cbpf_preprocessing
RUN make -C /artifact/tcp_attack/pre_processing/ipoptions
RUN install -m 0755 /artifact/tcp_attack/pre_processing/ipoptions/ipoptions_preprocessing /usr/local/bin/ipoptions_preprocessing
RUN make -C /artifact/tcp_attack/main
RUN install -m 0755 /artifact/tcp_attack/main/main_tcp /usr/local/bin/main_tcp

# Build dns_attack tools
RUN echo "Building dns_main..." && make -C /artifact/dns_attack
RUN install -m 0755 /artifact/dns_attack/dns_main /usr/local/bin/dns_main

RUN mkdir -p /etc/systemd/resolved.conf.d

RUN cat > /etc/systemd/resolved.conf.d/victim.conf <<'EOF'
[Resolve]
DNS=192.0.2.220
Domains=~.
LLMNR=no
MulticastDNS=no
DNSStubListener=yes
EOF

STOPSIGNAL SIGRTMIN+3

CMD ["/lib/systemd/systemd"]