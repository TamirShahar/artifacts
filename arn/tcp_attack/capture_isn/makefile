#!/usr/bin/make -f

# Minimal Makefile: build capture from capture.cpp for Linux only

.PHONY: all clean

CXX ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall

all: capture

capture: capture.cpp
	@echo "Building capture (Linux)..."
	$(CXX) $(CXXFLAGS) -o capture capture.cpp -pthread -lpcap
	@echo "Built: ./capture"

clean:
	@echo "Cleaning capture artifacts..."
	-rm -f capture
