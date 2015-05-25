CC = gcc
CFLAGS=-Wall -std=gnu99 -DWOLFSSL_DTLS -DWOLFSSL_MPDTLS -g
LIBS=-lwolfssl -lpthread
SOURCES_D = strlib.c tun_device_common.c tun_device_linux.c configuration.c gen.c
SOURCES_C = client.c
SOURCES_S = server.c
OBJECTS_C = $(SOURCES_C:.c=.o)
OBJECTS_S = $(SOURCES_S:.c=.o)
OBJECTS_D = $(SOURCES_D:.c=.o)
DEPS = $(wildcard *.h)

all:client server $(DEPS) clean

%.o:%.c
	@echo "******************************************************"
	$(CC) -o $@ -c $^ $(CFLAGS)
	@echo "******************************************************"

client: $(OBJECTS_D) $(OBJECTS_C)
	@echo "******************************************************"
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	@echo "******************************************************"

server: $(OBJECTS_D) $(OBJECTS_S)
	@echo "******************************************************"
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	@echo "******************************************************"

clean:
	rm -f *.o
	rm -f *~
mproper:clean
	rm -f server client
