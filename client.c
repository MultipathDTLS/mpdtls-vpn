/*
 * client.c
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

#include "client.h"

int main(int argc, char *argv[]){
    int error;
    struct addrinfo *res;
    struct addrinfo hints;
    sockaddr *addr;

    //default values
    char *ip_serv = "127.0.0.1";
    char *vpn_ip = "10.0.0.1";
    char *vpn_sub = "10.0.0.0/24";

    pthread_t reader, writer, tun;

    int c;
    int debug = 0;
    while((c = getopt(argc, argv, "hds:v:n:")) != -1) {
        switch(c)
        {
            case 's' :
                ip_serv = optarg;
                break;
            case 'v':
                vpn_ip = optarg;
                break;
            case 'n' :
                vpn_sub = optarg;
                break;
            case 'd' :
                debug = 1;
                break;
            case 'h' :
                printf("Usage : ./client [-s serverIP/domain] [-v vpn_ip] [-n vpn_network] [options]\n");
                printf("Ex : ./client example.org -v 10.0.0.2 -n 10.0.0.0/24 \n\n");
                printf("Available options : \n");
                printf("\t -d \t\t Debug mode : will display the debug messages\n");
                printf("\t -h \t\t Display this help message \n");
                return EXIT_SUCCESS;
        }
    }
    
    /* getaddrinfo() case.  It can handle multiple addresses. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    error = getaddrinfo(ip_serv, NULL, &hints, &res);
    if (error) {
        printf("%s\n", gai_strerror(error));
        return EXIT_FAILURE;
    } else {
        if(res) { //we take only the first one
             addr = (struct sockaddr *) res->ai_addr;
             printf("Family detected : %d \n",addr->sa_family);
        }else{
            printf("No address found \n");
            freeaddrinfo(res);
            return EXIT_FAILURE;
        }
    }

    /** Pointers to be freed later **/

    /* initialiaze config */
    initConfig();
    inet_aton(vpn_ip, &config.vpnIP);
    config.network = vpn_sub;
    int tunfd = init_tun();

    if(tunfd < 0) {
        printf("Impossible to open the TUN interface, you must have the right permissions \n");
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }


    wolfSSL_Init();// Initialize wolfSSL
    if(debug)
        wolfSSL_Debugging_ON(); //enable debug inside wolfssl
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx = NULL;
    int sockfd;

    ssl = InitiateDTLS(ctx,addr,&sockfd, NULL);

    //we don't need the server addr anymore
    freeaddrinfo(res);

    ReaderArgs r_args;
    r_args.tunfd = tunfd;
    r_args.ssl = ssl;

    WriterArgs w_args;
    w_args.ssl = ssl;
    w_args.debug = debug;

    int ret;
    if((ret = pthread_create(&reader, NULL, readIncoming, (void *) &r_args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }

    if((ret = pthread_create(&writer, NULL, sendLines, (void *) &w_args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }


    if((ret = pthread_create(&tun, NULL, readFromTun, (void *) &r_args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }
    

    pthread_join(writer, NULL);
    pthread_cancel(reader);
    pthread_cancel(tun);

    close(sockfd);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf("DONE\n");
    return EXIT_SUCCESS;
}

/** INITIATE the connection and return the ssl object corresponding
**/
WOLFSSL* InitiateDTLS(WOLFSSL_CTX *ctx, sockaddr *serv_addr, int *sockfd, WOLFSSL_SESSION *sess){

    WOLFSSL* ssl;

    WOLFSSL_METHOD* method = wolfDTLSv1_2_client_method();
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "wolfSSL_CTX_new error.\n");

        exit(EXIT_FAILURE);
    }

    /* Example of how to add a new interface in the context
    if (wolfSSL_mpdtls_new_addr_CTX(ctx, "11.0.1.1") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
    }
    */

    if (wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-SHA:AES256-SHA") != SSL_SUCCESS)
        perror("client can't set cipher list 1");

    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        perror("can't load client cert file");

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        perror("can't load client key file, ");

    if (wolfSSL_CTX_load_verify_locations(ctx,"certs/ca-cert.pem",NULL) != SSL_SUCCESS) {

       perror("Error loading certs/ca.crt, please check the file.\n");
       printf("%d", wolfSSL_CTX_load_verify_locations(ctx,"./certs/ca.crt",0));
       exit(EXIT_FAILURE);

    }
      
       // create the socket
    if((*sockfd=socket(serv_addr->sa_family,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }


    if( (ssl = wolfSSL_new(ctx)) == NULL) {

       fprintf(stderr, "wolfSSL_new error.\n");

       exit(EXIT_FAILURE);

    }

    //we put the right port

    unsigned int sz = 0;
    if(serv_addr->sa_family == AF_INET){
        sz = sizeof(struct sockaddr_in);
        ((sockaddr_in*) serv_addr)->sin_port = htons(PORT_NUMBER);
    }else if(serv_addr->sa_family == AF_INET6){
        sz = sizeof(struct sockaddr_in6);
        ((sockaddr_in6*) serv_addr)->sin6_port = htons(PORT_NUMBER);
    }
    
    wolfSSL_UseMultiPathDTLS(ssl, 1);
    wolfSSL_set_fd(ssl, *sockfd);



    if(wolfSSL_dtls_set_peer(ssl, serv_addr, sz)!=SSL_SUCCESS){
            perror("Error while trying to define the peer for the connection");
        }

    if(sess != NULL) {
        if(wolfSSL_set_session(ssl,sess)!=SSL_SUCCESS) {
            perror("SSL_set_session failed");
        }
    }

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        int  err = wolfSSL_get_error(ssl, 0);
        char buffer[1000];
        printf("err = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        perror("SSL_connect failed");
    }

    printf("Check for MPDTLS compatibility : %d \n",wolfSSL_mpdtls(ssl));


    return ssl;
}
