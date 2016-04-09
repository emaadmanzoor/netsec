CC=gcc
CFLAGS=-Wall -g -lssl -lcrypto -std=c11 -I/usr/local/opt/openssl/include
LDFLAGS=-L/usr/local/opt/openssl/lib
SOURCES := $(wildcard *.c)
OBJS := $(SOURCES:.c=.o)

all: pbproxy

pbproxy: $(OBJS)
			$(CC) $(CFLAGS) $^ -o $@

.c.o:
	    $(CC) $(CFLAGS) -c $<

clean:
	    rm -f pbproxy $(OBJS)

test-client: pbproxy
			./pbproxy -k mykey localhost 2222

#test-server: pbproxy
#			./pbproxy -l 2222 -k mykey localhost 22

.PHONY: all clean
