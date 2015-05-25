/*
 * gen.h
 *
 * Copyright (C) 2015 Quentin Devos, Loic Fortemps
 *
 * This file is part of MPDTLS-VPN.
 *
 * MPDTLS-VPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MPDTLS-VPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MPDTLS-VPN.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
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
#include <unistd.h>

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
#include <netinet/ip.h>
#include <linux/if_tun.h>
#include "configuration.h"
#include "tun_device.h"

#define PORT_NUMBER 6586
#define SOCKET_T int
#define MESSAGE_MAX_LENGTH 1400

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in6 sockaddr_in6;

typedef struct {
    unsigned char type;           // 1 byte : message type
    uint16_t port;                // 2 bytes : port
    struct in_addr ip1;           // 4 bytes : IP address 1 (IPv4)
    struct in_addr ip2;           // 4 bytes : IP address 2 (IPv4)
}  __attribute__ ((packed)) // important
message_t;

/* DTLS header */
typedef struct {
    unsigned char contentType; // same as struct message's type (unsigned char)
    uint16_t version;
    uint16_t epoch;
    uint64_t seq_number:48;
    uint16_t length;
} __attribute__((packed)) dtlsheader_t;

/*
 * Union used to store a VPN packet
 */
typedef union {
    struct ip *ip;
    dtlsheader_t *dtlsheader;
    message_t *message;
    unsigned char *raw;
} packet_t;

struct configuration config;

void *readIncoming(void *);
void *readFromTun(void*);
void *sendLines(void*);

typedef struct ReaderArgs{
    WOLFSSL *ssl;
    int tunfd;
    int debug;
} ReaderArgs;

typedef struct WriterArgs{
    WOLFSSL *ssl;
    int debug;
} WriterArgs;

#endif /*GEN_H_*/
