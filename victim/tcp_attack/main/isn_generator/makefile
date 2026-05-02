# Linux-only Makefile for `isn_generator`

CXX ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra

SRCS := isn_generator_linux.cpp
OBJS := $(SRCS:.cpp=.o)
HEADERS := isnGenerator.h

.PHONY: all clean linux

all: linux

linux: $(OBJS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@echo Cleaning...
	-rm -f $(OBJS)

