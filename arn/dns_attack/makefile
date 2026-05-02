CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -O2
LDFLAGS = -lpthread

all: dns_inject

dns_inject: dns_inject.cpp
	$(CC) $(CFLAGS) -o dns_inject dns_inject.cpp $(LDFLAGS)

clean:
	rm -f dns_inject

.PHONY: all clean
