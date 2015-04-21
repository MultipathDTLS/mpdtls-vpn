#include "gen.h"


void *readFromTun(void* _args) {
    ReaderTunArgs *args = (ReaderTunArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int tunfd = args->tunfd;
    packet_t u;
    u.raw = malloc(MESSAGE_MAX_LENGTH);
    int n;
    while((n = read(tunfd, u.raw, MESSAGE_MAX_LENGTH)) > 0){
        printf(
        ">> Sending a VPN message: size %d from SRC = %02x.%02x.%02x.%02x to DST = %02x.%02x.%02x.%02x\n",
        n, (ntohl(u.ip->ip_src.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 0) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 0) & 0xFF);
        if(wolfSSL_write(ssl, u.raw, n) != n){
            perror("wolfSSL_write failed");
        }
    }
    printf("STOP readFromTun\n");
    return NULL;
}

void *readIncoming(void* _args){
    ReaderTunArgs *args = (ReaderTunArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int tunfd = args->tunfd;
    packet_t u;
    u.raw = malloc(MESSAGE_MAX_LENGTH);
    int n, i;
    while(1){
        n = wolfSSL_read(ssl, u.raw, MESSAGE_MAX_LENGTH);
        if(n <= 0){
            if(n < 0) {
                printf("ERROR RECEIVED : keep going");
                continue;
            }else{
                break;
            }
        }
        printf("-------------------------------------------------------\n");
        printf(
        ">> Receiving a VPN message: size %d from SRC = %02x.%02x.%02x.%02x to DST = %02x.%02x.%02x.%02x\n",
        n, (ntohl(u.ip->ip_src.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 0) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 0) & 0xFF);
        for(i=0;i<n;i++)
            printf("%02x ", u.raw[i]);
        printf("\n-------------------------------------------------------\n");
        write_tun(tunfd, u.raw, n);
    }
    printf("STOP readIncoming\n");
    return NULL;
}
