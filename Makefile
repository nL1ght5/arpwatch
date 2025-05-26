CC = gcc
CFLAGS = -Wall
OBJS = main.o

all: arpwatch2

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

arpwatch2: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -f arpwatch2 *.o
