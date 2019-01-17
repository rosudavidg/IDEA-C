all: build run clean

build:
	gcc -Wall -o exe main.c -lm

run:
	./exe

clean:
	rm -f exe