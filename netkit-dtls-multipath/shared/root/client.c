#include "client.h"

int main(int argc, char *argv[]){
    int error;
    struct addrinfo *res;
    struct addrinfo hints;
    sockaddr *addr;
    char *ip_serv = "127.0.0.1"; //default server address
    char *vpn_ip = "10.0.0.2";
    char *vpn_sub = "10.0.0.0/24";

    pthread_t reader, writer, tun;
    
    if(argc > 3){
        ip_serv = argv[3];
    }
    if (argc > 2) {
        vpn_ip = argv[1];
        vpn_sub = argv[2];
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
            return EXIT_FAILURE;
        }
    }

    /** Pointers to be freed later **/

    /* initialiaze config */
    initConfig();
    inet_aton(vpn_ip, &config.vpnIP);
    config.network = vpn_sub;

    /*for debug purposes */
    int tunfd = init_tun();

    wolfSSL_Init();// Initialize wolfSSL
    //wolfSSL_Debugging_ON(); //enable debug
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx = NULL;
    //WOLFSSL_SESSION *sess;
    int sockfd;

    ssl = InitiateDTLS(ctx,addr,&sockfd, NULL);

    //sess = wolfSSL_get_session(ssl);

    /*//simulate deco/reco

    printf("SIMULATE LOSS OF CONNECTION\n");
    sleep(10);

    ssl = InitiateDTLS(ctx,addr,&sockfd, sess); 
    //*/
    //Add new addresses if needed
    /*
    if (wolfSSL_mpdtls_new_addr(ssl, "127.0.0.3") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
                
    }
    //*/

    ReaderTunArgs args;
    args.tunfd = tunfd;
    args.ssl = ssl;

    int ret;
    if((ret = pthread_create(&reader, NULL, readIncoming, (void *) &args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }

    if((ret = pthread_create(&writer, NULL, sendLines, (void *) ssl))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }


    if((ret = pthread_create(&tun, NULL, readFromTun, (void *) &args))!=0) {
        fprintf (stderr, "%s", strerror (ret));
    }
    

    pthread_join(writer, NULL);
    pthread_cancel(reader);
    pthread_cancel(tun);

    close(sockfd);
    wolfSSL_free(ssl); 
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    freeConfig();
    return 0;
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

    //*
    if (wolfSSL_mpdtls_new_addr_CTX(ctx, "11.0.1.1") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
    }
    if (wolfSSL_mpdtls_new_addr_CTX(ctx, "11.0.2.1") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
    }
    if (wolfSSL_mpdtls_new_addr_CTX(ctx, "11.0.3.1") !=SSL_SUCCESS) {
                    fprintf(stderr, "wolfSSL_mpdtls_new_addr error \n" );
                    exit(EXIT_FAILURE);
    }

    //*/

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
