CXX = g++

COMMON_FLAGS = -Wall -Wextra -std=c++11 -O2 -pthread

TARGET = cbpf_preprocessing
SOURCE = cbpf_preprocessing.cpp
HEADERS = cbpf_program.h

all: $(TARGET)

$(TARGET): $(SOURCE) $(HEADERS)
	$(CXX) $(COMMON_FLAGS) $(SOURCE) -o $(TARGET)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
.PHONY: all clean run




