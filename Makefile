#
# Makefile for the malloc lab driver
#
CC = clang
CFLAGS = -Werror -Wall -Wextra -O3 -g

all: bin/mdriver-implicit bin/mdriver-explicit

bin/mdriver-implicit: out/mdriver-implicit.o out/mm-implicit.o out/memlib.o out/fsecs.o out/fcyc.o out/clock.o out/ftimer.o
	$(CC) $(CFLAGS) $^ -o $@

bin/mdriver-explicit: out/mdriver-explicit.o out/mm-explicit.o out/memlib.o out/fsecs.o out/fcyc.o out/clock.o out/ftimer.o
	$(CC) $(CFLAGS) $^ -o $@

out/mdriver-implicit.o: driver/mdriver.c
	$(CC) $(CFLAGS) -c -DSTAGE0 $^ -o $@

out/mdriver-explicit.o: driver/mdriver.c
	$(CC) $(CFLAGS) -c -DSTAGE1 $^ -o $@

out/%.o: src/%.c
	$(CC) $(CFLAGS) -Iinclude -c $^ -o $@

out/%.o: driver/%.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f out/* bin/*
