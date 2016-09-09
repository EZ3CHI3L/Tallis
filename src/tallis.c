#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "tallis.h"
#include "net.h"
#include "error.h"

int main(int argc, char *argv[])
{
    tallis_t *tallis = malloc(sizeof(tallis_t));
    tallis->host = "irc.freenode.net";
    tallis->port = "6697";
    tallis->bio = NULL;
    tallis->ssl_connection = NULL;
    ssl_init(tallis->ssl_connection);
    tallis->ssl_context = SSL_CTX_new(TLSv1_2_client_method());
    tallis->ssl_connection = SSL_new(tallis->ssl_context);
    tallis->param = SSL_get0_param(tallis->ssl_connection);

    int rv;

    rv = tallis_connect(tallis);

    if (rv)
        DIE("%s\n", "connection failed");

    rv = tallis_verify(tallis);

    if (rv)
        DIE("%s\n", "certificate verificiation failed");

    rv = tallis_loop(tallis);

    if (rv)
        DIE("%s\n", "socket connection terminated");

    rv = ssl_shutdown(tallis);

    if (rv)
        DIE("%s\n", "ssl shutdown failed");
}

_Noreturn void tallis_shutdown(tallis_t* tallis)
{
    exit(ssl_shutdown(tallis));
}
