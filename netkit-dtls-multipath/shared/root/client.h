#include "gen.h"
#include <sys/time.h>


/** INITIATE the connection and return the ssl object corresponding
**/
CYASSL* InitiateDTLS(char *ip_serv, CYASSL_CTX *ctx, sockaddr_in *serv_addr, int *sockfd);

void sendLines(CYASSL* ssl);