CFLAGS=-Wall -Werror -g -pthread

TARGETS=server

all: $(TARGETS)

server: firewall.o server.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(TARGETS) *.o
