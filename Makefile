CXX = g++
CXXFLAGS = -std=c++98 -Wall -Werror -pedantic
LDFLAGS = -lm -lcrypto

TARGET = elgamal_program
SOURCES = bignum.cpp elgamal.cpp main.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all run clean
