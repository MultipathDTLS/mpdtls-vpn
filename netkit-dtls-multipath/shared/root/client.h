#include "gen.h"
#include <sys/time.h>


/** INITIATE the connection and return the ssl object corresponding
**/
CYASSL* InitiateDTLS(CYASSL_CTX *ctx, sockaddr *serv_addr, int *sockfd);

void sendLines(CYASSL* ssl);