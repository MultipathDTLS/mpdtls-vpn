#include "gen.h"
#define MAX_THREADS 10

/** Set up the server ctx
**/
void InitiateContext();

/**
* Wait for clients to connect and initiate the connection
*/
void answerClients(WOLFSSL *ssl, sockaddr *serv_addr, unsigned short family);

/**
* Interact with one particular client
*/
void* answerClient(void*);

/**
* Method to initialize the DTLS handshake and keys exchange
* Receive from a <family> kind address
*/
int udp_read_connect(int sockfd, unsigned short family);

/**
* Create the socket with adress serv_addr
* This socket will be reusable
*/
int createSocket(sockaddr *serv_addr, unsigned short family);