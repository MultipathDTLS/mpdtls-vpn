/* server.c
* Launch a DTLS V1.2 server waiting for client to send data
* The certificates used for this application are self-signed
*
* Date : 14/10/2014
*
*/
//#define DEBUG

#include "server.h"

WOLFSSL_CTX *ctx; //general context

int main(int argc, char *argv[]){

    unsigned short family = AF_INET;
    char *vpn_ip = "10.0.0.2";
    char *vpn_sub = "10.0.0.0/24";

    if(argc > 3){
        family = AF_INET6;
    } 
    if (argc > 2) {
        vpn_ip = argv[1];
        vpn_sub = argv[2];
    }

    /** Pointers to be freed later **/
    /* initialiaze config */
    initConfig();
    inet_aton(vpn_ip, &config.vpnIP);
    inet_aton(vpn_sub, &config.vpnNetmask);

    wolfSSL_Init();// Initialize wolfSSL
    wolfSSL_Debugging_ON(); //enable debug
    WOLFSSL* ssl = NULL;

    sockaddr *serv_addr = NULL;

    InitiateContext();
    answerClients(ssl,serv_addr, family);

    printf("Shutdown server and clean...");
    free(serv_addr);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    freeConfig();
    printf(" DONE\n");
    return 0;
}

void answerClients(WOLFSSL *ssl, sockaddr *serv_addr, unsigned short family){
    int i;
    int clientfd;
    int sockfd;
    pthread_t *server_thread[MAX_THREADS];
    int n_thread = 0;
    int ret;

    while (1) {
        ssl = 0;

        sockfd = createSocket(serv_addr, family);
        printf("Current socket : %d \n",sockfd);

        clientfd = udp_read_connect(sockfd, family);
        if (clientfd == -1){
            perror("udp accept failed");
            break;
        }else if(n_thread < MAX_THREADS){
            //we create a new thread to handle the communication
            server_thread[n_thread] = (pthread_t *) malloc(sizeof(pthread_t));
            if((ret = pthread_create(server_thread[n_thread], NULL, answerClient, (void *) &clientfd))!=0) {
                fprintf (stderr, "%s", strerror (ret));
            }
            n_thread++;
        }
        /*
        printf("Close socket %d (parent) \n",sockfd);
        close(sockfd);
        */
    }
    //clean all threads
    printf("WAITING FOR THREADS TO JOIN\n");
    for(i=0; i< n_thread; i++) {
        pthread_join(*server_thread[i],NULL);
    }

}

void *answerClient(void* _fd) {
    WOLFSSL *ssl;
    int clientfd = *((int*) _fd);
    int tunfd = init_tun();
    printf("Child created with socket %d \n",clientfd);               
    if( (ssl = wolfSSL_new(ctx)) == NULL) {

       fprintf(stderr, "wolfSSL_new error SSL \n" );

       exit(EXIT_FAILURE);

    }

    wolfSSL_UseMultiPathDTLS(ssl, 0x01);
    wolfSSL_set_fd(ssl, clientfd);


    //handshake
    if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
        char errorString[80];
        int err = wolfSSL_get_error(ssl, 0);
        wolfSSL_ERR_error_string(err, errorString);
        printf("SSL_accept failed : %s \n",errorString);
        wolfSSL_free(ssl);
        close(clientfd);
        return NULL;
    }

    /*
    if (wolfSSL_mpdtls_new_addr(ssl, "::1") !=SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
        exit(EXIT_FAILURE);
    }
    */

    /*
    if (wolfSSL_mpdtls_new_addr(ssl, "192.168.3.101") !=SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
        exit(EXIT_FAILURE);
    }
    //*/

    printf("Check for mpdtls extension : %d \n", wolfSSL_mpdtls(ssl));
    printf("Server child waiting for incoming msg \n");

    ReaderTunArgs args;
    args.tunfd = tunfd;
    args.ssl = ssl;
    pthread_t reader;

    int ret;
    if((ret = pthread_create(&reader, NULL, readIncoming, (void *) &args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }

    readFromTun(&args);
    
    printf("Server thread exiting \n");
    close_tun(tunfd);
    close(clientfd);
    return NULL;
}
/**
* Create the socket with adress serv_addr and family family (AF_INET or AF_INET6)
* This socket will be reusable
*/
int createSocket(sockaddr *serv_addr, unsigned short family){

    int sockfd;

    socklen_t sz = (family==AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if(serv_addr == NULL) {
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

/** Initialise the ssl context that will be used for all incoming connections
**/
void InitiateContext(){

   WOLFSSL_METHOD* method = wolfDTLSv1_2_server_method();
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL){
        fprintf(stderr, "wolfSSL_CTX_new error \n");
        exit(EXIT_FAILURE);
    }

    /*
    if (wolfSSL_mpdtls_new_addr_CTX(ctx, "127.0.0.3") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                
    }
    //*/

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
