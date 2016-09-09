#ifndef TALLIS_H
#define TALLIS_H
#define SASL_AUTH_STRING "dGFsbGlzAHRhbGxpcwBwYXNzd29yZA=="
#include <openssl/ssl.h>
#include <openssl/bio.h>
typedef struct tallis_bot_struct
{
    int sfd;
    BIO *bio;
    SSL *ssl_connection;
    SSL_CTX *ssl_context;
    X509_VERIFY_PARAM *param;
    char *host, *port;
} tallis_t;
void tallis_shutdown(tallis_t*);
#endif /* TALLIS_H */
