#!/usr/bin/make -f

# Linux-only Makefile for ipoptions

CXX ?= g++
CXXFLAGS := -std=gnu++11 -O2

.PHONY: all clean

all: ipoptions_preprocessing

ipoptions_preprocessing: ipoptions_preprocessing.cpp
	@echo "Building ipoptions_preprocessing (Linux)..."
	$(CXX) $(CXXFLAGS) -o ipoptions_preprocessing \
		ipoptions_preprocessing.cpp \
		-pthread
	@echo "Built: ./ipoptions_preprocessing"

clean:
	@echo "Cleaning ipoptions artifacts..."
	-rm -f ipoptions_preprocessing
