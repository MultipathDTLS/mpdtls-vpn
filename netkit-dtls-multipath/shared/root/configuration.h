/*
 * Campagnol configuration
 *
 * Copyright (C) 2008-2009 Florent Bondoux
 *
 * This file is part of Campagnol.
 *
 * Campagnol is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Campagnol is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Campagnol.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * 
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include "gen.h"

struct configuration {

    struct in_addr vpnIP;                       // VPN IP address
    struct in_addr vpnNetmask;                  // VPN Netmask
    char *network;                              // VPN subnetwork as a string

    int tun_mtu;                                // MTU of the tun device

    char *tun_device;                           // The name of the TUN interface
    char *tap_id;                               // Version of the OpenVPN's TAP driver

    int txqueue;                                // TX queue length for the TUN device (0 means default)
    int tun_one_queue;                          // Single queue mode
};

extern void initConfig(void);
extern void freeConfig(void);

#endif /*CONFIGURATION_H_*/
