
SOURCE_PORT_DIR := ../../source_port_detection_shared_code
SUBDIRS := isn_generator $(SOURCE_PORT_DIR)

# Default C++ compiler
CXX ?= g++

.PHONY: all clean linux

all: linux

# Build Linux main executable from main_tcp.cpp
linux: 
	@echo "Building main_tcp..."
	$(MAKE) -C $(SOURCE_PORT_DIR) clean linux
	$(MAKE) -C isn_generator clean linux
	$(CXX) -std=c++11 -O2 -I$(SOURCE_PORT_DIR) -Iisn_generator -o main_tcp \
		main_tcp.cpp \
		$(SOURCE_PORT_DIR)/linux_procfsPortFinder.o \
		isn_generator/isn_generator_linux.o \
		-lpthread

clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean; \
	done
	-rm -f main_tcp
