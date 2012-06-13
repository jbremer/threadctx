
default: poc.exe

%.exe: %.c
	gcc -s -O2 -lkernel32 -Wall -std=c99 -o $@ $^
