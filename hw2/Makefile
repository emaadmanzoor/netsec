CC=gcc
CFLAGS=-Wall -g -lpcap
SOURCES := $(wildcard *.c)
OBJS := $(SOURCES:.c=.o)

all: mydump

mydump: $(OBJS)
			$(CC) $(CFLAGS) $^ -o $@

.c.o:
	    $(CC) $(CFLAGS) -c $<

clean:
	    rm -f mydump $(OBJS)

test-error: mydump
			./mydump -i eth0 -r filename -s string expression

test-default: mydump
			./mydump expression

test-eth0: mydump
			./mydump -i eth0 expression

test-eth0-osx: mydump
			./mydump -i en0 "ip"

test-file: mydump
			./mydump -r ../hw1/hw1.pcap "ip"

test-string: mydump
			./mydump -r filename -s string expression

.PHONY: all clean
