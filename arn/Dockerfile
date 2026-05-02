FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential g++ gcc make cmake \
    iproute2 iputils-ping curl net-tools tcpdump procps sudo \
    libpcap-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /artifact

COPY . /artifact/

RUN if [ -f attack.cpp ]; then g++ attack.cpp -o attack; fi

# Build tcp_attack tools
RUN echo "Building capture_isn..." && make -C /artifact/tcp_attack/capture_isn && \
    echo "Building inject_packets..." && make -C /artifact/tcp_attack/inject_packets

# Build dns_attack tools
RUN echo "Building dns_inject..." && make -C /artifact/dns_attack

# Install binaries to /usr/local/bin
RUN install -m 0755 /artifact/tcp_attack/capture_isn/capture /usr/local/bin/capture && \
    install -m 0755 /artifact/tcp_attack/inject_packets/attacker /usr/local/bin/attacker && \
    install -m 0755 /artifact/dns_attack/dns_inject /usr/local/bin/dns_inject

CMD ["/bin/bash"]