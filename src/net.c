#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libconfig.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "tallis.h"
#include "net.h"
#include "conf.h"
#include "irc.h"
#include "lexer.h"
#include "error.h"

void tallis_ssl_init()
{
    SSL_library_init();
}

int ssl_shutdown(tallis_t *tallis)
{
    int rv, err;
    ERR_clear_error();
    rv = SSL_shutdown(tallis->ssl_connection);

    if (rv == 0)
        SSL_shutdown(tallis->ssl_connection);

    if (rv < 0)
    {
        err = SSL_get_error(tallis->ssl_connection, rv);

        if (err == SSL_ERROR_SSL)
            fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));

        fprintf(stderr, "%s\n", SSL_state_string(tallis->ssl_connection));

        return 1;
    }

    ERR_free_strings();
    SSL_free(tallis->ssl_connection);
    SSL_CTX_free(tallis->ssl_context);
    return 0;
}

int tallis_init_ssl_verify(tallis_t *tallis)
{
    int rv;

    ERR_clear_error();
    rv = SSL_CTX_load_verify_locations(
            tallis->ssl_context,
            "/etc/ssl/certs/AddTrust_External_Root.pem",
            "/etc/ssl/certs");

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    X509_VERIFY_PARAM_set_hostflags(
            tallis->param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    ERR_clear_error();
    rv = X509_VERIFY_PARAM_set_flags(
            tallis->param,
            X509_V_FLAG_CRL_CHECK || X509_V_FLAG_CRL_CHECK_ALL);

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    rv = X509_VERIFY_PARAM_set1_host(tallis->param, tallis->host, 0);

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    SSL_CTX_set_verify(tallis->ssl_context, SSL_VERIFY_PEER, NULL);
    SSL_set_verify(tallis->ssl_connection, SSL_VERIFY_PEER, NULL);

    return 0;
}

int tallis_ssl_verify(tallis_t *tallis, X509 *cert)
{
    int rv;

    ERR_clear_error();
    rv = SSL_get_verify_result(tallis->ssl_connection);

    if (rv != X509_V_OK)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    return 0;
}

int tallis_verify_cert_chain(tallis_t *tallis, X509 *cert)
{
    int rv;

    ERR_clear_error();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (!ctx)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    ERR_clear_error();
    X509_STORE *store = X509_STORE_new();

    if (!store)
    {
        X509_STORE_free(store);
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    ERR_clear_error();
    rv = X509_STORE_CTX_init(ctx, store, cert, NULL);

    if (!rv)
    {
        X509_STORE_free(store);
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CB_ISSUER_CHECK);
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

    X509_STORE_load_locations(
            store,
            "/etc/ssl/certs/AddTrust_External_Root.pem",
            NULL);

    X509_STORE_set_default_paths(store);

    X509_LOOKUP_load_file(
            lookup,
            "/etc/ssl/certs/AddTrust_External_Root.pem",
            X509_FILETYPE_PEM);

    X509_STORE_add_cert(store, cert);

    ERR_clear_error();
    rv = X509_verify_cert(ctx);

    if (rv != 1)
    {
        fprintf(stderr, "%d\n", rv);
        X509_STORE_free(store);
        fprintf(
                stderr,
                "%s\n%s\n",
                ERR_error_string(ERR_get_error(), NULL),
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

        return 1;
    }

    return 0;
}

int tallis_base64_encode(char *src, int len, char **dest)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, src, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *dest=(*bufferPtr).data;

    return 0;
}

int tallis_sasl_authenticate(tallis_t* tallis)
{
    int rv, sasl_flag = 0;

    rv = config_lookup_bool(&tallis->config, "sasl", &sasl_flag);

    if (!rv)
        return 1;

    if (sasl_flag == 0)
        return 1;

    rv = config_lookup_string(&tallis->config, "sasl_password",
            &tallis->sasl_password);

    if (!rv)
        return 1;

    return 0;
}

int tallis_connect(tallis_t *tallis)
{
   int rv;

    ERR_clear_error();
    tallis->bio = BIO_new_ssl_connect(tallis->ssl_context);

    if (!tallis->bio)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    BIO_get_ssl(tallis->bio, &(tallis->ssl_connection));
    SSL_set_mode(tallis->ssl_connection, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(tallis->bio, tallis->host);
    BIO_set_conn_port(tallis->bio, tallis->port);

    ERR_clear_error();
    rv = BIO_do_connect(tallis->bio);

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    ERR_clear_error();
    rv = BIO_do_handshake(tallis->bio);

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    return 0;
}

int tallis_send(tallis_t *tallis, int n, ...)
{
    ssize_t len;
    va_list vargs;
    va_start(vargs, n);

    for (int i = 0; i < n; ++i)
    {
        const char *msg = va_arg(vargs, const char*);
        ERR_clear_error();
        len = BIO_write(tallis->bio, msg, strlen(msg));

        if (!len)
        {
            if (!BIO_should_retry(tallis->bio))
            {
                fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
                return 1;
            }
            puts("retry write?");
        }

        /*
        printf("-->");
        tallis_print((char*) msg, strlen(msg));
        */
    }

    va_end(vargs);
    return 0;
}

inline void tallis_print(char *buf, ssize_t len)
{
    for (int i = 0; i < len; ++i)
        printf("%c", buf[i]);
}

void tallis_parse(tallis_t *tallis, char buf[], int len)
{
    char pong[512] = "PONG :";

    if (strncmp(buf, "PING :", 6) == 0)
        tallis_send(tallis, 1, strncat(pong, buf + 6, len - 6));

    if (strstr(buf, "CAP * ACK :multi-prefix sasl"))
        tallis_send(tallis, 1, "AUTHENTICATE PLAIN\r\n");

    if (strstr(buf, "CAP * NAK :multi-prefix sasl") != NULL)
        tallis_send(tallis, 1, "CAP END\r\n");

    if (strstr(buf, "AUTHENTICATE +") != NULL)
        tallis_send(
                tallis,
                3,
                "AUTHENTICATE ",
                tallis->sasl_challenge,
                "\r\n");

    if (strstr(buf, "SASL authentication successful") != NULL)
        tallis_send(tallis, 1, "CAP END\r\n");

    if (strstr(buf, "~tallis quit") != NULL)
        tallis_shutdown(tallis);

    /* lexer_analyze(buf); */
}

int tallis_loop(tallis_t *tallis)
{
    ssize_t len;
    char buf[512] = {0}, initial_message[512];
    snprintf(initial_message, 512, "%s %s\r\n%s %s %s %s :%s\r\n", "NICK",
            tallis->nick, "USER", tallis->nick, tallis->nethost,
            tallis->domain, tallis->nick);

    /*
     * WRITE A FUCKING PARSER
    tallis_server_capabilities_t capabilities = {false};
    tallis_check_capability(tallis, &capabilities, buf);
    tallis_sasl_authenticate(tallis, buf);
    */

    if (!tallis_sasl_authenticate(tallis))
    {
        char *temp = malloc(strlen(tallis->nick) * 2 +
                strlen(tallis->sasl_password) + 3);

        memcpy(temp, tallis->nick, strlen(tallis->nick));
        temp[strlen(tallis->nick) + 2] = '\0';
        memcpy(temp + strlen(tallis->nick) + 1,
                tallis->nick, strlen(tallis->nick) + 1);
        temp[strlen(tallis->nick) * 2 + 2] = '\0';
        memcpy(temp + strlen(tallis->nick) * 2 + 2, tallis->sasl_password,
                strlen(tallis->sasl_password));

        tallis_base64_encode(temp,
                strlen(temp) * 2 + strlen(tallis->sasl_password) + 2,
                &tallis->sasl_challenge);

        tallis_send(tallis, 1, "CAP REQ :multi-prefix sasl\r\n");
    }
    else
        puts("running with SASL disabled");

    if (tallis_send(tallis, 1, initial_message))
        return 1;

    while (1)
    {
        memset(buf, '\0', 512);
        len = BIO_read(tallis->bio, buf, 512);

        if (!len)
        {
            if (!BIO_should_retry(tallis->bio))
            {
                fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
                return 1;
            }
            puts("retry read?");
        }

        buf[len] = '\0';
        tallis_print(buf, len);
        tallis_parse(tallis, buf, len);
    }
    return 0;
}
