CFLAGS=-Wall -Werror -g -pthread

TARGETS=server client

all: $(TARGETS)

server: firewall.o server.o
	$(CC) $(CFLAGS) $^ -o target/$@

client: client.o
	$(CC) $(CFLAGS) $^ -o target/$@

%.o: %.c
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(TARGETS) *.o
