#include "gen.h"



void *readFromTun(void* _args) {
    ReaderArgs *args = (ReaderArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int tunfd = args->tunfd;
    packet_t u;
    u.raw = malloc(MESSAGE_MAX_LENGTH);
    int n;
    while((n = read(tunfd, u.raw, MESSAGE_MAX_LENGTH)) > 0){
        /*printf(
        ">> Sending a VPN message: size %d from SRC = %02x.%02x.%02x.%02x to DST = %02x.%02x.%02x.%02x\n",
        n, (ntohl(u.ip->ip_src.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_src.s_addr) >> 0) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 24) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 16) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 8) & 0xFF,
        (ntohl(u.ip->ip_dst.s_addr) >> 0) & 0xFF);*/
        if(wolfSSL_write(ssl, u.raw, n) != n){
            perror("wolfSSL_write failed");
        }
    }
    printf("STOP readFromTun\n");
    return NULL;
}

void *readIncoming(void* _args){
    ReaderArgs *args = (ReaderArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int tunfd = args->tunfd;
    packet_t u;
    u.raw = malloc(MESSAGE_MAX_LENGTH);
    int n;
    while((n = wolfSSL_read(ssl, u.raw, MESSAGE_MAX_LENGTH)) > 0){
        /*printf("-------------------------------------------------------\n");
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
        printf("\n-------------------------------------------------------\n");*/
        write_tun(tunfd, u.raw, n);
    }
    printf("STOP readIncoming\n");
    return NULL;
}

/**
* Send text input through the ssl object
*/
void *sendLines(void* _args){
    WriterArgs *args = (WriterArgs *)_args;
    WOLFSSL *ssl = args->ssl;
    int debug = args->debug;
    char sendline[1000];
    while (fgets(sendline, 1000,stdin) != NULL)
    {
        if(strcmp(sendline, "add interface\n") == 0) {
            printf("Adding new interface, please enter the new address: \n");
            if (fgets(sendline, 1000,stdin) != NULL) {
                if (wolfSSL_mpdtls_new_addr(ssl, sendline) !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                }
            }
            continue;
        }
        if(strcmp(sendline,"connect\n")==0){
            char *buf = NULL;
            wolfSSL_mpdtls_ask_connect(ssl, &buf, NULL);

            printf("%s\n", buf);
            free(buf);

            int remote, host, res = 0; 
            
            do {
                printf("Choose 1 address in each list and give the 2 indices as \"host[space]remote\"\n");
                if (fgets(sendline, 1000,stdin) != NULL){
                    res = sscanf(sendline, "%d %d", &host, &remote);
                }
            } while (res != 2);

            if (wolfSSL_mpdtls_connect_addr(ssl, host, remote) != SSL_SUCCESS) {
                fprintf(stderr, "wolfSSL_mpdtls_connect_addr error\n" );
            }
            continue;
        }
        if(strcmp(sendline,"change scheduling\n")==0) {

            printf("1) Round Robin : every flow has the same importance\n");
            printf("2) Optimize Latency : give more priority to flows with lower delays\n");
            int res=0,r;
            uint res2;
            do {
                printf("Choose one option among the one proposed and include the number of tokens (i[space]n) \n");
                if (fgets(sendline, 1000,stdin) != NULL){
                    r = sscanf(sendline, "%d %d", &res, &res2);
                }
            } while (r!=2 || res < 1 || res > 2);
            switch(res) {
                case 1:
                    wolfSSL_mpdtls_modify_scheduler_policy(ssl, ROUND_ROBIN, res2);
                break;
                case 2:
                    wolfSSL_mpdtls_modify_scheduler_policy(ssl, OPTIMIZE_LATENCY, res2);
                break;
            }

        }

        if(strcmp(sendline,"stats\n")==0){
            wolfSSL_Debugging_ON();
            wolfSSL_mpdtls_stats(ssl);
            if(!debug)
                wolfSSL_Debugging_OFF();
        }
    if(strcmp(sendline,"debug on\n")==0){
        wolfSSL_Debugging_ON();
    }
    if(strcmp(sendline,"debug off\n")==0){
        wolfSSL_Debugging_OFF();
    }
        if(strcmp(sendline,"exit\n")==0){
            printf("Shutting down... \n");
            break;
        }
    }

    return NULL;
}
