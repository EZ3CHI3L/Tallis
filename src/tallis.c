#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
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
    tallis_ssl_init();
    tallis->ssl_context = SSL_CTX_new(TLS_method());
    tallis->ssl_connection = SSL_new(tallis->ssl_context);
    tallis->param = SSL_get0_param(tallis->ssl_connection);

    int rv;

    rv = tallis_init_ssl_verify(tallis);

    if (rv)
        DIE("%s\n", "error initializing ssl verification data");

    rv = tallis_connect(tallis);

    if (rv)
        DIE("%s\n", "connection failed");

    ERR_clear_error();
    X509 *cert = NULL;
    cert = SSL_get_peer_certificate(tallis->ssl_connection);

    if (!cert)
        DIE("%s\n", ERR_error_string(ERR_get_error(), NULL));

    X509_free(cert);

    rv = tallis_ssl_verify(tallis, cert);

    if (rv)
        DIE("%s\n", "certificate verificiation failed");
    else
        printf("%s\n", "certificate verification succeeded");

    /*
    rv = tallis_verify_cert_chain(tallis, cert);

    if (rv)
        DIE("%s\n", "failed to verify certificate chain");
    */

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
