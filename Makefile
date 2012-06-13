
all: poc.exe target.exe

tar: poc.exe target.exe
	tar cf threadctx.tar Makefile poc.c poc.exe target.c target.exe

%.exe: %.c
	gcc -s -O2 -lkernel32 -Wall -std=c99 -o $@ $^
