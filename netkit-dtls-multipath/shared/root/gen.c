#include "gen.h"


void *readFromTun(void* _args) {
    ReaderTunArgs *args = (ReaderTunArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int tunfd = args->tunfd;
    char u[MESSAGE_MAX_LENGTH];
    int n;
    while((n = read(tunfd, u, MESSAGE_MAX_LENGTH)) > 0){
        printf("Packet received from tun (%d), transmitting it through DTLS ...\n",n);
        if(wolfSSL_write(ssl, u, n) != n){
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
    char mesg[MESSAGE_MAX_LENGTH];
    int n, i;
    while((n = wolfSSL_read(ssl, mesg, MESSAGE_MAX_LENGTH-1)) > 0){
        printf("-------------------------------------------------------\n");
        mesg[n] = 0;
        printf("Received the following:\n");
        for(i=0;i<n;i++)
            printf("%02x ", mesg[i]);
        printf("\n-------------------------------------------------------\n");
        write_tun(tunfd, mesg, n);
    }
    printf("STOP readIncoming\n");
    return NULL;
}
