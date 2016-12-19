#ifndef TALLIS_H
#define TALLIS_H
#define SASL_AUTH_STRING "NULL"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <libconfig.h>
typedef struct tallis_bot_struct
{
    int sfd, has_config, has_sasl;
    size_t challenge_len;
    BIO *bio;
    SSL *ssl_connection;
    SSL_CTX *ssl_context;
    X509_VERIFY_PARAM *param;
    char *host, *port, *nick, *nethost, *domain, *sasl_challenge;
    const char *sasl_password;
    config_t config;
} tallis_t;
void tallis_shutdown(tallis_t*);
#endif /* TALLIS_H */
