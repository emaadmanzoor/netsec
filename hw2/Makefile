CC=gcc
CFLAGS=-Wall -g -lpcap -std=c11
SOURCES := $(wildcard *.c)
OBJS := $(SOURCES:.c=.o)

all: mydump

mydump: $(OBJS)
			$(CC) $(CFLAGS) $^ -o $@

.c.o:
	    $(CC) $(CFLAGS) -c $<

clean:
	    rm -f mydump $(OBJS)

test-eth0: mydump
			./mydump -i eth0

test-eth0-osx: mydump
			./mydump -i en0

test-file: mydump
			./mydump -r hw1.pcap

test-file-expr: mydump
			./mydump -r hw1.pcap ip

test-file-string: mydump
			./mydump -r hw1.pcap -s HTTP ip

.PHONY: all clean
