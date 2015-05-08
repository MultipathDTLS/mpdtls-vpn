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


    int c;
    int debug = 0;
    int multipath = 1;
    while((c = getopt(argc, argv, "hdfsv:n:")) != -1) {
        switch(c)
        {
            case 'v':
                vpn_ip = optarg;
                break;
            case 'n' :
                vpn_sub = optarg;
                break;
            case 'l' :
                family = AF_INET6;
                break;
            case 'd' :
                debug = 1;
                break;
            case 's' :
                multipath = 0;
                break;
            case 'h' :
                printf("Usage : ./server [-v vpn_ip] [-n vpn_network] [options]\n");
                printf("Ex : ./server -v 10.0.0.2 -n 10.0.0.0/24 \n\n");
                printf("Available options : \n");
                printf("\t -s \t\t use Simple DTLS (without Multipath)\n");
                printf("\t -f \t\t Run the server on IPv6 family socket\n");
                printf("\t -d \t\t Debug mode : will display the debug messages\n");
                printf("\t -h \t\t Display this help message \n");
                return EXIT_SUCCESS;
        }
    }

    /** Pointers to be freed later **/
    /* initialiaze config */
    initConfig();
    inet_aton(vpn_ip, &config.vpnIP);
    config.network = vpn_sub;

    wolfSSL_Init();// Initialize wolfSSL
    if(debug)
        wolfSSL_Debugging_ON(); //enable debug
    WOLFSSL* ssl = NULL;

    sockaddr *serv_addr = NULL;

    InitiateContext();
    answerClient(ssl,serv_addr, family, debug, multipath);

    printf("Shutdown server and clean...");
    free(serv_addr);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    freeConfig();
    printf(" DONE\n");
    return EXIT_SUCCESS;
}

void answerClient(WOLFSSL *ssl, sockaddr *serv_addr, unsigned short family, int debug, int mp) {
    int clientfd;
    int sockfd;

    sockfd = createSocket(serv_addr, family);
    printf("Server ready and waiting for connection ... \n");
    clientfd = udp_read_connect(sockfd, family);
    int tunfd = init_tun();

    if( (ssl = wolfSSL_new(ctx)) == NULL) {

       fprintf(stderr, "wolfSSL_new error SSL \n" );

       exit(EXIT_FAILURE);

    }
    if(mp)
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
    */
    printf("Check for mpdtls extension : %d \n", wolfSSL_mpdtls(ssl));
    printf("Server waiting for incoming msg \n");

    ReaderArgs r_args;
    r_args.tunfd = tunfd;
    r_args.ssl = ssl;

    WriterArgs w_args;
    w_args.ssl = ssl;
    w_args.debug = debug;

    pthread_t reader, writer, tun;

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
    
    close_tun(tunfd);
    close(clientfd);
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
    if(wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-SHA:AES256-SHA")!=SSL_SUCCESS){
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
