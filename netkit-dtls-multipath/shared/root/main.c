#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <errno.h>
#include <unistd.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cyassl/ssl.h>

#define SERVER_MODE 0
#define CLIENT_MODE 1

typedef struct sockaddr_in sockaddr_in;

int main(int argc, char *argv[]){
 /* Create and initialize SSL_CTX structure */
    int mode = SERVER_MODE; //0 = server, 1 = client
    int option = 0;
    while ((option = getopt(argc, argv,"c")) != -1) {
        switch (option) {
             case 'c' : mode = CLIENT_MODE;
                 break;
             case 'h' :
                printf("USAGE : <exec> [-c] by default run as a server, if c is supplied then server");
                break;
        }
    }

    CyaSSL_Init();// Initialize CyaSSL
    CYASSL_CTX* ctx;

   CYASSL_METHOD* method = CyaDTLSv1_2_client_method();
   if ( (ctx = CyaSSL_CTX_new(method)) == NULL){

        fprintf(stderr, "CyaSSL_CTX_new error.\n");

        exit(EXIT_FAILURE);

   }
   /* Load CA certificates into CYASSL_CTX */


   if (CyaSSL_CTX_load_verify_locations(ctx,"ca.crt",NULL) != SSL_SUCCESS) {

       perror("Error loading certs/ca.crt, please check the file.\n");
       printf("%d", CyaSSL_CTX_load_verify_locations(ctx,"./certs/ca.crt",0));
       exit(EXIT_FAILURE);

   }

    int sockfd, newsockfd, portno, clilen, n;
    // create the socket
    if((sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        fprintf(stderr,"Error opening socket");
        exit(EXIT_FAILURE);
    }


    /* Create CYASSL object */

   CYASSL* ssl;


   if( (ssl = CyaSSL_new(ctx)) == NULL) {

       fprintf(stderr, "CyaSSL_new error.\n");

       exit(EXIT_FAILURE);

   }


   CyaSSL_set_fd(ssl, sockfd);
    
    struct sockaddr_in *serv_addr, cliaddr;
    char buffer[256];
    socklen_t len;
    char mesg[1000];

    serv_addr = malloc(sizeof(sockaddr_in));
    bzero(serv_addr, sizeof(sockaddr_in));

    portno = 6585;
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(portno);
    serv_addr->sin_addr.s_addr = INADDR_ANY;

    if(mode == SERVER_MODE){
        if (bind(sockfd, (struct sockaddr *) serv_addr,sizeof(sockaddr_in)) < 0)
            perror("ERROR on binding");
        //connect(sockfd, (const struct sockaddr *) serv_addr,sizeof(sockaddr_in));
        //FIX ME , ADD SOMETHING FOR DTLS TO WORK
       for (;;)
       {
          if ((n = CyaSSL_read(ssl, mesg, 1000)) <= 0){
               perror("CyaSSL_read error");
               exit(EXIT_FAILURE);
          }
          //sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
          printf("-------------------------------------------------------\n");
          mesg[n] = 0;
          printf("Received the following:\n");
          printf("%s",mesg);
          printf("-------------------------------------------------------\n");
       }
    }else{
        serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        char sendline[1000];
        char recvline[1000];
        if(CyaSSL_dtls_set_peer(ssl, (struct sockaddr *)serv_addr, sizeof(sockaddr_in))!=SSL_SUCCESS)
            perror("Error while trying to crypt the connection");
       while (fgets(sendline, 1000,stdin) != NULL)
       {
            if(CyaSSL_write(ssl, sendline, strlen(sendline)) != strlen(sendline)){
                perror("CyaSSL_write failed");
            }
          //sendto(sockfd,sendline,strlen(sendline),0,(struct sockaddr *)serv_addr,sizeof(sockaddr_in));
          //n=recvfrom(sockfd,recvline,10000,0,NULL,NULL);
          //recvline[n]=0;
          printf("Sended\n");
       }
    }
    //we clean everything
    close(sockfd);
    free(serv_addr);
    CyaSSL_free(ssl); 
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
   return 0;
}
