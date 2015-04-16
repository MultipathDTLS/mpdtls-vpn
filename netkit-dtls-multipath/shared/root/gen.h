#ifndef GEN_H_
#define GEN_H_


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include "configuration.h"
#include "tun_device.h"

#define PORT_NUMBER 6586
#define SOCKET_T int
#define MESSAGE_MAX_LENGTH 1400

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in6 sockaddr_in6;

struct configuration config;

void *readIncoming(void *);
void *readFromTun(void*);

typedef struct ReaderTunArgs{
    WOLFSSL *ssl;
    int tunfd;
} ReaderTunArgs;

#endif /*GEN_H_*/