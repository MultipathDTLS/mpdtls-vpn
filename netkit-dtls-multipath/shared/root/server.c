/* server.c
* Launch a DTLS V1.2 server waiting for client to send data
* The certificates used for this application are self-signed
*
* Date : 14/10/2014
*
*/
#include "server.h"

int main(int argc, char *argv[]){

    /** Pointers to be freed later **/

    CyaSSL_Init();// Initialize CyaSSL
    //CyaSSL_Debugging_ON(); //enable debug
    CYASSL* ssl = NULL;
    CYASSL_CTX* ctx = NULL;
    sockaddr_in *serv_addr = NULL;

    ctx = InitiateDTLS(ctx,serv_addr);
    answerClients(ctx,ssl,serv_addr);

    printf("Shutdown server and clean...");
    free(serv_addr);
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl); 
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
    printf(" DONE\n");
    return 0;
}

void answerClients(CYASSL_CTX *ctx, CYASSL *ssl, sockaddr_in *serv_addr){
    int shutdown = 0;
    int clientfd;
    int childpid;
    int sockfd;

    while (!shutdown) {
        ssl = 0;

        sockfd = createSocket(serv_addr);
        printf("Current socket : %d \n",sockfd);
        //handshake
        clientfd = udp_read_connect(sockfd);
        if (clientfd == -1){
            perror("udp accept failed");
            break;
        }else{
            if((childpid = fork())<0){
                perror("Error on fork");
                exit(EXIT_FAILURE);
            }else if(childpid == 0){
                //Dont know why but if you close the server socket, nothing works
                //printf("Close socket %d (child) \n",sockfd);
                //close(sockfd);
                printf("Child created with socket %d \n",clientfd);               
                if( (ssl = CyaSSL_new(ctx)) == NULL) {

                   fprintf(stderr, "CyaSSL_new error SSL \n" );

                   exit(EXIT_FAILURE);

               }
                /* We add 2 addresses manually */
                if (CyaSSL_mpdtls_new_addr(ssl, "127.0.0.1") !=SSL_SUCCESS) {
                    fprintf(stderr, "CyaSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                }

                if (CyaSSL_mpdtls_new_addr(ssl, "127.0.0.2") !=SSL_SUCCESS) {
                    fprintf(stderr, "CyaSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                }

                CyaSSL_set_fd(ssl, clientfd);

                if (CyaSSL_accept(ssl) != SSL_SUCCESS) {
                    char errorString[80];
                    int err = CyaSSL_get_error(ssl, 0);
                    CyaSSL_ERR_error_string(err, errorString);
                    printf("SSL_accept failed : %s \n",errorString);
                    CyaSSL_free(ssl);
                    close(clientfd);
                    break;
                }
                printf("Check for mpdtls extension : %d \n", CyaSSL_mpdtls(ssl));
                printf("Server child waiting for incoming msg \n");
                readIncoming(ssl);
                printf("Server child exiting \n");
                close(clientfd);
                break;
            }else{
                close(clientfd);
            }
        }
        printf("Close socket %d (parent) \n",sockfd);
        close(sockfd);
    }

}
/**
* Create the socket with adress serv_addr
* This socket will be reusable
*/
int createSocket(sockaddr_in *serv_addr){

    int sockfd;

    serv_addr = malloc(sizeof(sockaddr_in));
    bzero(serv_addr, sizeof(sockaddr_in));

    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT_NUMBER);
    serv_addr->sin_addr.s_addr = INADDR_ANY;

            // create the socket
    if((sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }

        // set SO_REUSEADDR on a socket to true (1):
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


        //bind server socket to INADDR_ANY
    if (bind(sockfd, (struct sockaddr *) serv_addr,sizeof(sockaddr_in)) < 0)
            perror("ERROR on binding");

    return sockfd;
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
CYASSL_CTX* InitiateDTLS(CYASSL_CTX *ctx, sockaddr_in *serv_addr){

   CYASSL_METHOD* method = CyaDTLSv1_2_server_method();
   if ( (ctx = CyaSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "CyaSSL_CTX_new error \n");
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

   return ctx;
}

/**
* Method to initialize the connection between client and server (learn client address)
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
        fprintf(stderr,"recvfrom failed (sockfd : %d,n : %d) \n",sockfd,n);
        sockfd = -1;
    }

    return sockfd;
}