#!/usr/bin/make -f

# Linux-only: compile procfs port finder object only

CXX ?= g++
CXXFLAGS := -std=c++11 -O2 -Wall

SRCS := linux_procfsPortFinder.cpp
OBJS := $(SRCS:.cpp=.o)
HEADERS := procfsPortFinder.h portFinderBase.h

.PHONY: all linux clean

all: linux

linux: $(OBJS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build artifacts..."
	-rm -f $(OBJS)
