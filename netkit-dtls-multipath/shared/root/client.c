#include "client.h"


int main(int argc, char *argv[]){
    char *ip_serv = "127.0.0.1"; //default server address
    
    if(argc > 1){
        ip_serv = argv[1];
    }

    /** Pointers to be freed later **/

    CyaSSL_Init();// Initialize CyaSSL
    CYASSL* ssl;
    CYASSL_CTX* ctx = NULL;
    sockaddr_in *serv_addr = NULL;
    int sockfd;

    ssl = InitiateDTLS(ip_serv,ctx,serv_addr,&sockfd);
    sendLines(ssl);

    close(sockfd);
    free(serv_addr);
    CyaSSL_free(ssl); 
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
    return 0;
}

/**
* Send text input through the ssl object
*/
void sendLines(CYASSL* ssl){
    char sendline[1000];
    while (fgets(sendline, 1000,stdin) != NULL)
    {
        if(CyaSSL_write(ssl, sendline, strlen(sendline)) != strlen(sendline)){
            perror("CyaSSL_write failed");
        }
        printf("Sended\n");
        if(strcmp(sendline,"exit\n")==0){
            printf("Shutting down client \n");
            break;
        }
    }
}

/** INITIATE the connection and return the ssl object corresponding
**/
CYASSL* InitiateDTLS(char *ip_serv, CYASSL_CTX *ctx, sockaddr_in *serv_addr, int *sockfd){

    CYASSL* ssl;

   CYASSL_METHOD* method = CyaDTLSv1_2_client_method();
   if ( (ctx = CyaSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "CyaSSL_CTX_new error.\n");

        exit(EXIT_FAILURE);
   }

   if (CyaSSL_CTX_set_cipher_list(ctx, "AES256-SHA") != SSL_SUCCESS)
        perror("client can't set cipher list 1");

    if (CyaSSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        perror("can't load client cert file");

    if (CyaSSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        perror("can't load client key file, ");

    if (CyaSSL_CTX_load_verify_locations(ctx,"certs/ca-cert.pem",NULL) != SSL_SUCCESS) {

       perror("Error loading certs/ca.crt, please check the file.\n");
       printf("%d", CyaSSL_CTX_load_verify_locations(ctx,"./certs/ca.crt",0));
       exit(EXIT_FAILURE);

   }
      
       // create the socket
    if((*sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }


   if( (ssl = CyaSSL_new(ctx)) == NULL) {

       fprintf(stderr, "CyaSSL_new error.\n");

       exit(EXIT_FAILURE);

   }

    CyaSSL_set_fd(ssl, *sockfd);

    serv_addr = malloc(sizeof(sockaddr_in));
    bzero(serv_addr, sizeof(sockaddr_in));

    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT_NUMBER);
    serv_addr->sin_addr.s_addr = inet_addr(ip_serv);

    if(CyaSSL_dtls_set_peer(ssl, (struct sockaddr *)serv_addr, sizeof(sockaddr_in))!=SSL_SUCCESS){
            perror("Error while trying to define the peer for the connection");
        }

    if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
        int  err = CyaSSL_get_error(ssl, 0);
        char buffer[1000];
        printf("err = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));
        perror("SSL_connect failed");
    }

    printf("Check for MPDTLS compatibility : %d \n",CyaSSL_mpdtls(ssl));


    return ssl;
}