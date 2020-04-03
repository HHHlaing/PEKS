CC=g++
CXXFLAGS=-g -std=c++17 -Wall -I /usr/local/include/pbc/ -L /usr/local/lib
LDFLAGS=-Wl,-rpath /usr/local/lib -lpbc -lssl -lcrypto -lgmp -lm
SOURCE=*.cpp
DEPS=*.hpp
EXECUTABLE=testList

target:
	$(CC) $(SOURCE) -o $(EXECUTABLE) $(CFLAG) $(LDFLAGS)
