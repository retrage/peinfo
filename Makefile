CFLAGS=-Wall -Iinclude -std=c11 -O0 -g
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
HDRS=$(wildcard include/*.h)
TARGET=peinfo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^

$(OBJS): $(HDRS)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
