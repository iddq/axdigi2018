VERSION = $(shell git rev-parse --short HEAD)
CFLAGS = -g -Wall
CPPFLAGS = -DVERSION="\"$(VERSION)\""

SRCS =  \
	axdigi2018.c
OBJS = $(SRCS:.c=.o)

all: axdigi2018

axdigi2018: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -f axdigi2018 $(OBJS)
