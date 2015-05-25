/*
 * client.h
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
#include <sys/time.h>


/** INITIATE the connection and return the ssl object corresponding
**/
WOLFSSL* InitiateDTLS(WOLFSSL_CTX *ctx, sockaddr *serv_addr, int *sockfd, WOLFSSL_SESSION *);