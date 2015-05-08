#include "gen.h"
#define MAX_THREADS 10

/** Set up the server ctx
**/
void InitiateContext();

/**
* Wait for client to connect and initiate the connection
*/
void answerClient(WOLFSSL*, sockaddr*,unsigned short, int, int);


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