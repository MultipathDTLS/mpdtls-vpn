/* server.c
* Launch a DTLS V1.2 server waiting for client to send data
* The certificates used for this application are self-signed
*
* Date : 8/10/2014
*
*/
#include "server.h"

int main(int argc, char *argv[]){

    /** Pointers to be freed later **/

    CyaSSL_Init();// Initialize CyaSSL
    CYASSL* ssl = NULL;
    CYASSL_CTX* ctx = NULL;
    sockaddr_in *serv_addr = NULL;
    int sockfd;

    ctx = InitiateDTLS(ctx,serv_addr,&sockfd);
    answerClients(ctx,ssl,&sockfd);

    printf("Shutdown server and clean...");
    close(sockfd);
    free(serv_addr);
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl); 
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
    printf(" DONE\n");
    return 0;
}

void answerClients(CYASSL_CTX *ctx, CYASSL *ssl, int *sockfd){
    int shutdown = 0;
    int clientfd;

    while (!shutdown) {
        ssl = 0;

        clientfd = udp_read_connect(*sockfd);
        if (clientfd == -1) perror("udp accept failed");

        if( (ssl = CyaSSL_new(ctx)) == NULL) {

           fprintf(stderr, "CyaSSL_new error SSL \n" );

           exit(EXIT_FAILURE);

       }

        CyaSSL_set_fd(ssl, *sockfd);

        if (CyaSSL_accept(ssl) != SSL_SUCCESS) {
            printf("SSL_accept failed\n");
            CyaSSL_free(ssl);
            close(clientfd);
            break;
        }

        shutdown = readIncoming(ssl);
    }

}

int readIncoming(CYASSL *ssl){
    char mesg[1000];
    int n;
    while((n = CyaSSL_read(ssl, mesg, sizeof(mesg)-1)) > 0){
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
CYASSL_CTX* InitiateDTLS(CYASSL_CTX *ctx, sockaddr_in *serv_addr, int *sockfd){

   CYASSL_METHOD* method = CyaDTLSv1_2_server_method();
   if ( (ctx = CyaSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "CyaSSL_CTX_new error \n");
        exit(EXIT_FAILURE);
   }
        // create the socket
    if((*sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }

    //Certs

    if (CyaSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
            perror("can't load server cert file");

    if (CyaSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
            perror("can't load server key file, ");

    if (CyaSSL_CTX_load_verify_locations(ctx, "certs/client-cert.pem", 0) != SSL_SUCCESS)
            perror("can't load ca file, Please run from CyaSSL home dir");

    //Cipher suite
    if(CyaSSL_CTX_set_cipher_list(ctx, "AES256-SHA")!=SSL_SUCCESS){
        fprintf(stderr, "CYASSl Cipher List error \n");
        exit(EXIT_FAILURE);
    }

    serv_addr = malloc(sizeof(sockaddr_in));
    bzero(serv_addr, sizeof(sockaddr_in));

    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT_NUMBER);
    serv_addr->sin_addr.s_addr = INADDR_ANY;

    if (bind(*sockfd, (struct sockaddr *) serv_addr,sizeof(sockaddr_in)) < 0)
            perror("ERROR on binding");

   return ctx;
}

/**
* Method to initialize the DTLS handshake and keys exchange
*/
int udp_read_connect(int sockfd)
{
    sockaddr_in cliaddr;
    char          b[1500];
    int           n;
    socklen_t     len = sizeof(cliaddr);

    n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK,
                      (struct sockaddr*)&cliaddr, &len);
    if (n > 0) {
        if (connect(sockfd, (const struct sockaddr*)&cliaddr,
                    sizeof(cliaddr)) != 0)
            perror("udp connect failed");
    }
    else{
        perror("recvfrom failed");
        sockfd = -1;
    }

    return sockfd;
}