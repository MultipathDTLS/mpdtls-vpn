/*
 * Campagnol configuration
 *
 * Copyright (C) 2008-2011 Florent Bondoux
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

/*
 * Check the configuration
 * Create the "config" structure containing all the configuration variables
 */
#include "configuration.h"

/* set default values in config */
void initConfig() {

    memset(&config.vpnIP, 0, sizeof(config.vpnIP));
    memset(&config.vpnNetmask, 0, sizeof(config.vpnNetmask));
    config.network = "255.255.255.0";
    config.tun_mtu = 1419;
    config.tun_device = NULL;
    config.tap_id = NULL;

    config.txqueue = 0;
    config.tun_one_queue = 0;
}

// #ifdef HAVE_IFADDRS_H
// /*
//  * Search the local IP address to use. Copy it into "ip" and set "localIPset".
//  * If iface != NULL, get the IP associated with the given interface
//  * Otherwise search the IP of the first non loopback interface
//  */
// static int get_local_IP(struct in_addr * ip, int *localIPset, char *iface) {
//     struct ifaddrs *ifap = NULL, *ifap_first = NULL;
//     if (getifaddrs(&ifap) != 0) {
//         perror("getifaddrs");
//         return -1;
//     }

//     ifap_first = ifap;
//     while (ifap != NULL) {
//         if (iface == NULL && ((ifap->ifa_flags & IFF_LOOPBACK)
//                 || !(ifap->ifa_flags & IFF_RUNNING)
//                 || !(ifap->ifa_flags & IFF_UP))) {
//             ifap = ifap->ifa_next;
//             continue; // local or not running interface, skip it
//         }
//         if (iface == NULL || strcmp(ifap->ifa_name, iface) == 0) {
//             /* If the interface has no link level address (like a TUN device),
//              * then ifap->ifa_addr is NULL.
//              * Only look for AF_INET addresses
//              */
//             if (ifap->ifa_addr != NULL && ifap->ifa_addr->sa_family == AF_INET) {
//                 *ip = (((struct sockaddr_in *) ifap->ifa_addr)->sin_addr);
//                 *localIPset = 1;
//                 break;
//             }
//         }
//         ifap = ifap->ifa_next;
//     }
//     freeifaddrs(ifap_first);
//     return 0;
// }
// #else

// /*
//  * Search the local IP address to use. Copy it into "ip" and set "localIPset".
//  * If iface != NULL, get the IP associated with the given interface
//  * Otherwise search the IP of the first non loopback interface
//  *
//  * see http://groups.google.com/group/comp.os.linux.development.apps/msg/10f14dda86ee351a
//  */
// #define IFRSIZE   ((int)(size * sizeof (struct ifreq)))
// static int get_local_IP(struct in_addr * ip, int *localIPset, char *iface) {
//     struct ifconf ifc;
//     struct ifreq *ifr, ifreq_flags;
//     int sockfd, size = 1;
//     struct in_addr ip_tmp;

//     ifc.ifc_len = 0;
//     ifc.ifc_req = NULL;

//     sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

//     do {
//         ++size;
//         /* realloc buffer size until no overflow occurs  */
//         ifc.ifc_req = realloc(ifc.ifc_req, IFRSIZE);
//         ifc.ifc_len = IFRSIZE;
//         if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
//             perror("ioctl SIOCGIFCONF");
//             return -1;
//         }
//     }while (IFRSIZE <= ifc.ifc_len);

//     ifr = ifc.ifc_req;
//     for (;(char *) ifr < (char *) ifc.ifc_req + ifc.ifc_len; ++ifr) {

// //        if (ifr->ifr_addr.sa_data == (ifr+1)->ifr_addr.sa_data) {
// //            continue; // duplicate, skip it
// //        }

//         strncpy(ifreq_flags.ifr_name, ifr->ifr_name, IFNAMSIZ);
//         if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq_flags)) {
//             perror("ioctl SIOCGIFFLAGS");
//             return -1;
//         }
//         if (iface == NULL && ((ifreq_flags.ifr_flags & IFF_LOOPBACK)
//                 || !(ifreq_flags.ifr_flags & IFF_RUNNING)
//                 || !(ifreq_flags.ifr_flags & IFF_UP))) {
//             continue; // local or not running interface, skip it
//         }

//         if (iface == NULL || strcmp (ifr->ifr_name, iface) == 0) {
//             ip_tmp = (((struct sockaddr_in *) &(ifr->ifr_addr))->sin_addr);
//             if (ip_tmp.s_addr != INADDR_ANY && ip_tmp.s_addr != INADDR_NONE) {
//                 *ip = ip_tmp;
//                 *localIPset = 1;
//                 break;
//             }
//         }
//     }
//     close(sockfd);
//     free(ifc.ifc_req);
//     return 0;
// }
// #endif

/*
 * Get the broadcast IP for the VPN subnetwork
 * vpnip: IPv4 address of the client
 * len: number of bits in the netmask
 * broadcast (out): broadcast address
 * netmask (out): netmask
 *
 * vpnIP and broadcast are in network byte order
 *
static int get_ipv4_broadcast(uint32_t vpnip, int len, uint32_t *broadcast,
        uint32_t *netmask) {
    if (len < 0 || len > 32) {// validity of len
        return -1;
    }
    // compute the netmask
    if (len == 32) {
        *netmask = 0xffffffff;
    }
    else {
        *netmask = ~(0xffffffff >> len);
    }
    // network byte order
    *netmask = htonl(*netmask);
    *broadcast = (vpnip & *netmask) | ~*netmask;
    return 0;
}*/

void freeConfig() {
    if (config.network) free(config.network);
    if (config.tun_device) free(config.tun_device);
    if (config.tap_id) free(config.tap_id);
}

