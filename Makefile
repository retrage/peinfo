CFLAGS=-Wall -Iinclude -std=c11 -O2
TARGET=pe32p
SRCS=$(TARGET).c
HDRS=$(wildcard include/*.h)
OBJS=$(SRCS:.c=.o)

$(TARGET): $(OBJS)
	cc -o $@ $^

$(OBJS): $(HDRS)

clean:
	rm -f $(TARGET) *.o

.PHONY: clean
