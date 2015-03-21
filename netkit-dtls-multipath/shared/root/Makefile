CC = gcc
CFLAGS=-Wall -std=gnu99 -DWOLFSSL_DTLS -g
LIBS=-lwolfssl -lpthread
SOURCES_C = client.c
SOURCES_S = server.c
OBJECTS_C = $(SOURCES_C:.c=.o)
OBJECTS_S = $(SOURCES_S:.c=.o)
DEPS = $(wildcard *.h)

all:client server $(DEPS) clean

%.o:%.c
	@echo "******************************************************"
	$(CC) -o $@ -c $^ $(CFLAGS)
	@echo "******************************************************"

client:$(OBJECTS_C)
	@echo "******************************************************"
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	@echo "******************************************************"

server:$(OBJECTS_S)
	@echo "******************************************************"
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	@echo "******************************************************"

clean:
	rm -f *.o
	rm -f *~
mproper:clean
	rm -f server client
