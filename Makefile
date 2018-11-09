CFLAGS=-Wall -Iinclude -std=c11 -O2
SRCS=$(wildcard *.c)
HDRS=$(wildcard include/*.h)
OBJS=$(SRCS:.c=.o)

all: pe32 pe32p

pe32: pe32.o
	cc -o $@ $^

pe32p: pe32p.o
	cc -o $@ $^

$(OBJS): $(HDRS)

clean:
	rm -f pe32 pe32p *.o

.PHONY: clean
