#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cyassl/ssl.h>
#include <arpa/inet.h>

#define PORT_NUMBER 6586
#define SOCKET_T int

typedef struct sockaddr_in sockaddr_in;
