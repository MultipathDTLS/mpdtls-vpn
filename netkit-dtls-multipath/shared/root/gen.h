#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT_NUMBER 6586
#define SOCKET_T int

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in6 sockaddr_in6;
