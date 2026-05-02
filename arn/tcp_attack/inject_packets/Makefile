# Minimal Makefile: only build attacker from attacker.cpp

CC := g++
CFLAGS := -O2 -Wall -std=c++11
LDFLAGS := -lpcap

.PHONY: all clean

all: attacker

attacker: attacker.cpp
	$(CC) $(CFLAGS) -o attacker attacker.cpp $(LDFLAGS)

clean:
	rm -f attacker

