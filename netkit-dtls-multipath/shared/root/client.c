#include "client.h"


int main(int argc, char *argv[]){
    int error;
    struct addrinfo *res;
    struct addrinfo hints;
    sockaddr *addr;
    char *ip_serv = "127.0.0.1"; //default server address
    
    if(argc > 1){
        ip_serv = argv[1];
    }

    /* getaddrinfo() case.  It can handle multiple addresses. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    error = getaddrinfo(ip_serv, NULL, &hints, &res);
    if (error) {
        printf(gai_strerror(error));
        return EXIT_FAILURE;
    } else {
        if(res) { //we take only the first one
             addr = (struct sockaddr *) res->ai_addr;
             printf("Family detected : %d \n",addr->sa_family);
        }else{
            printf("No address found \n");
            return EXIT_FAILURE;
        }
    }

    /** Pointers to be freed later **/

    wolfSSL_Init();// Initialize wolfSSL
    wolfSSL_Debugging_ON(); //enable debug
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx = NULL;
    int sockfd;

    ssl = InitiateDTLS(ctx,addr,&sockfd);
    char mesg[1000];
    wolfSSL_read(ssl, mesg, sizeof(mesg)-1);

    //Add new addresses if needed
    //*
    if (wolfSSL_mpdtls_new_addr(ssl, "127.0.0.3") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                
    }
    //*/
    
    sendLines(ssl);

    close(sockfd);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}

/**
* Send text input through the ssl object
*/
void sendLines(WOLFSSL* ssl){
    char sendline[1000];
    while (fgets(sendline, 1000,stdin) != NULL)
    {
        if(strcmp(sendline, "add interface\n") == 0) {
            printf("Adding new interface, please enter the new address: \n");
            if (fgets(sendline, 1000,stdin) != NULL) {
                if (wolfSSL_mpdtls_new_addr(ssl, sendline) !=SSL_SUCCESS) {
                                fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                                exit(EXIT_FAILURE);
                }
            }
            continue;
        }
        if(strcmp(sendline, "read pipe\n") == 0) {
            printf("Reading from the pipes...\n");
            wolfSSL_read(ssl, sendline, sizeof(sendline)-1);
            printf("Read %s from the pipes\n", sendline);
            continue;
        }
        if(wolfSSL_write(ssl, sendline, strlen(sendline)) != strlen(sendline)){
            perror("wolfSSL_write failed");
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
WOLFSSL* InitiateDTLS(WOLFSSL_CTX *ctx, sockaddr *serv_addr, int *sockfd){

    WOLFSSL* ssl;

   WOLFSSL_METHOD* method = wolfDTLSv1_2_client_method();
   if ( (ctx = wolfSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "wolfSSL_CTX_new error.\n");

        exit(EXIT_FAILURE);
   }

   if (wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA") != SSL_SUCCESS)
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
    

    wolfSSL_set_fd(ssl, *sockfd);


    if(wolfSSL_dtls_set_peer(ssl, serv_addr, sz)!=SSL_SUCCESS){
            perror("Error while trying to define the peer for the connection");
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