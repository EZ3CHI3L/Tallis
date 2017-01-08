#ifndef TALLIS_H
#define TALLIS_H
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <libconfig.h>
typedef struct tallis_config_settings_struct
{
    config_t config;
    int has_config, has_nick, has_sasl, has_sasl_password;
} settings_t;

typedef struct tallis_bot_struct
{
    int sfd;
    BIO *bio;
    SSL *ssl_connection;
    SSL_CTX *ssl_context;
    X509_VERIFY_PARAM *param;
    char *remote_host, *remote_port, *nick,
         *nethost, *domain, *sasl_challenge;
    const char *sasl_password;
    size_t sasl_challenge_len;
    settings_t settings;
} tallis_t;
void tallis_shutdown(tallis_t*);
#endif /* TALLIS_H */
