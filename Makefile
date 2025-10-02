CC=gcc
CFLAGS=-D _FILE_OFFSET_BITS=64

all: find_luks
	
find_luks: find_luks.c
	$(CC) -o find_luks $(CFLAGS) find_luks.c

clean:
	rm find_luks
