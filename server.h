/*
 * server.h
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
#include "gen.h"
#define MAX_THREADS 10

/** Set up the server ctx
**/
void InitiateContext();

/**
* Wait for client to connect and initiate the connection
*/
void answerClient(WOLFSSL*, sockaddr*,unsigned short, int, int);


/**
* Method to initialize the DTLS handshake and keys exchange
* Receive from a <family> kind address
*/
int udp_read_connect(int sockfd, unsigned short family);

/**
* Create the socket with adress serv_addr
* This socket will be reusable
*/
int createSocket(sockaddr *serv_addr, unsigned short family);