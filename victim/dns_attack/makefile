CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -O2
LDFLAGS = -lpthread

TARGETS = dns_main

SPF_DIR = ../source_port_detection_shared_code
SPF_SOURCES = $(SPF_DIR)/linux_procfsPortFinder.cpp 

all: $(TARGETS)


dns_main: dns_main.cpp $(SPF_SOURCES)
	$(MAKE) -C $(SPF_DIR) linux
	$(CC) $(CFLAGS) -I$(SPF_DIR) -o dns_main dns_main.cpp $(SPF_SOURCES) $(LDFLAGS)


clean:
	rm -f $(TARGETS)

.PHONY: all clean
