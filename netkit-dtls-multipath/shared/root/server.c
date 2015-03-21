/* server.c
* Launch a DTLS V1.2 server waiting for client to send data
* The certificates used for this application are self-signed
*
* Date : 14/10/2014
*
*/
//#define DEBUG

#include "server.h"

int main(int argc, char *argv[]){

    unsigned short family = AF_INET;
    if(argc > 1){
        family = AF_INET6;
    }

    /** Pointers to be freed later **/

    wolfSSL_Init();// Initialize wolfSSL
    wolfSSL_Debugging_ON(); //enable debug
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;
    sockaddr *serv_addr = NULL;

    ctx = InitiateDTLS(ctx);
    answerClients(ctx,ssl,serv_addr, family);

    printf("Shutdown server and clean...");
    free(serv_addr);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf(" DONE\n");
    return 0;
}

void answerClients(WOLFSSL_CTX *ctx, WOLFSSL *ssl, sockaddr *serv_addr, unsigned short family){
    int shutdown = 0;
    int clientfd;
    int childpid;
    int sockfd;

    while (!shutdown) {
        ssl = 0;

        sockfd = createSocket(serv_addr, family);
        printf("Current socket : %d \n",sockfd);

        clientfd = udp_read_connect(sockfd, family);
        if (clientfd == -1){
            perror("udp accept failed");
            break;
        }else{
#ifndef DEBUG
            if((childpid = fork())<0){
                perror("Error on fork");
                exit(EXIT_FAILURE);
            }else if(childpid == 0){
#endif
                //Dont know why but if you close the server socket, nothing works
                //printf("Close socket %d (child) \n",sockfd);
                //close(sockfd);
                printf("Child created with socket %d \n",clientfd);               
                if( (ssl = wolfSSL_new(ctx)) == NULL) {

                   fprintf(stderr, "wolfSSL_new error SSL \n" );

                   exit(EXIT_FAILURE);

               }

                wolfSSL_set_fd(ssl, clientfd);

                //handshake
                if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
                    char errorString[80];
                    int err = wolfSSL_get_error(ssl, 0);
                    wolfSSL_ERR_error_string(err, errorString);
                    printf("SSL_accept failed : %s \n",errorString);
                    wolfSSL_free(ssl);
                    close(clientfd);
                    break;
                }

                /*
                if (wolfSSL_mpdtls_new_addr(ssl, "::1") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                }
                */

                //*
                if (wolfSSL_mpdtls_new_addr(ssl, "127.0.0.2") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                }
                //*/
                
                wolfSSL_write(ssl, "ok", strlen("ok"));


                printf("Check for mpdtls extension : %d \n", wolfSSL_mpdtls(ssl));
                printf("Server child waiting for incoming msg \n");
                readIncoming(ssl,clientfd);
                printf("Server child exiting \n");
                close(clientfd);
                break;
#ifndef DEBUG
            } else {
                close(clientfd);
            }
#endif
        }
        printf("Close socket %d (parent) \n",sockfd);
        close(sockfd);
    }

}
/**
* Create the socket with adress serv_addr and family family (AF_INET or AF_INET6)
* This socket will be reusable
*/
int createSocket(sockaddr *serv_addr, unsigned short family){

    int sockfd;
    socklen_t sz = (family==AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    if (family == AF_INET) {
        sockaddr_in *addr = malloc(sizeof(sockaddr_in));
        bzero(addr, sizeof(sockaddr_in));

        addr->sin_family = AF_INET;
        addr->sin_port = htons(PORT_NUMBER);
        addr->sin_addr.s_addr = INADDR_ANY;

        serv_addr = (sockaddr*) addr;

    }else if(family == AF_INET6) {

        sockaddr_in6 *addr = malloc(sizeof(sockaddr_in6));
        bzero(addr, sizeof(sockaddr_in6));

        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(PORT_NUMBER);
        addr->sin6_addr = in6addr_any;

        serv_addr = (sockaddr*) addr;

    }

            // create the socket
    if((sockfd=socket(family,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }

        // set SO_REUSEADDR on a socket to true (1):
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


        //bind server socket to INADDR_ANY
    if (bind(sockfd, serv_addr,sz) < 0)
            perror("ERROR on binding");

    return sockfd;
}

int readIncoming(WOLFSSL *ssl, int sd){
    char mesg[1000];
    int n;
    while((n = wolfSSL_read(ssl, mesg, sizeof(mesg)-1)) > 0){
        printf("-------------------------------------------------------\n");
        mesg[n] = 0;
        printf("Received the following:\n");
        printf("%s",mesg);
        printf("-------------------------------------------------------\n");
        if(strcmp(mesg,"exit\n")==0)
            break;
    }
    return (strcmp(mesg,"exit\n")==0);
}

/** INITIATE the connection and return the CTX object corresponding
**/
WOLFSSL_CTX* InitiateDTLS(WOLFSSL_CTX *ctx){

   WOLFSSL_METHOD* method = wolfDTLSv1_2_server_method();
   if ( (ctx = wolfSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "wolfSSL_CTX_new error \n");
        exit(EXIT_FAILURE);
   }

    //Certs

    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
            perror("can't load server cert file");

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
            perror("can't load server key file, ");

    if (wolfSSL_CTX_load_verify_locations(ctx, "certs/client-cert.pem", 0) != SSL_SUCCESS)
            perror("can't load ca file, Please run from wolfSSL home dir");

    //Cipher suite
    if(wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA")!=SSL_SUCCESS){
        fprintf(stderr, "WOLFSSl Cipher List error \n");
        exit(EXIT_FAILURE);
    }

   return ctx;
}

/**
* Method to initialize the connection between client and server (learn client address)
*/
int udp_read_connect(int sockfd, unsigned short family)
{
    sockaddr *cliaddr;
    char          b[1500];
    int           n;
    socklen_t     len = 0;

    //build answer structure according to what we want to receive
    if(family == AF_INET){
        sockaddr_in addr;
        len = sizeof(sockaddr_in);
        bzero(&addr, len);
        cliaddr = (sockaddr*) &addr;
    }else{
        sockaddr_in6 addr;
        len = sizeof(sockaddr_in6);
        bzero(&addr, len);
        cliaddr = (sockaddr*) &addr;
    }

    n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK, cliaddr, &len);
    if (n > 0) {
        if (connect(sockfd, cliaddr, len) != 0)
            perror("udp connect failed");
    }
    else{
        fprintf(stderr,"recvfrom failed (sockfd : %d,n : %d) \n",sockfd,n);
        sockfd = -1;
    }

    return sockfd;
}