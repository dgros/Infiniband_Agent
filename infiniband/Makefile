
IB_ROOT := /usr

CC      := gcc
CFLAGS  := -Wall
LDFLAGS := 
LIBS    := -libverbs

all: ibping

ibping: ibping.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	/bin/rm ibping *.o

