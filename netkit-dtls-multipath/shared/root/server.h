#include "gen.h"

/** Set up the server and return the ctx object corresponding
**/
CYASSL_CTX* InitiateDTLS(CYASSL_CTX *ctx, sockaddr_in *serv_addr, int *sockfd);

/*
* Read all the data sent by a particular client on this ssl socket
* return if 'exit' is sended
*/
int readIncoming(CYASSL *ssl);

/**
* Wait for clients to connect and initiate the connection
*/
void answerClients(CYASSL_CTX *ctx, CYASSL *ssl, int *sockfd);

/**
* Method to initialize the DTLS handshake and keys exchange
*/
int udp_read_connect(int sockfd);