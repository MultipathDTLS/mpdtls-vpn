#include "gen.h"
#include <sys/time.h>


/** INITIATE the connection and return the ssl object corresponding
**/
WOLFSSL* InitiateDTLS(WOLFSSL_CTX *ctx, sockaddr *serv_addr, int *sockfd);

void *sendLines(void* ssl);
void *readIncoming(void *ssl);