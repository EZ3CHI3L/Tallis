#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "tallis.h"
#include "net.h"
#include "irc.h"
#include "lexer.h"
#include "error.h"

void ssl_init()
{
    SSL_load_error_strings();
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

int tallis_verify(tallis_t *tallis)
{
    long rv;
    ERR_clear_error();
    rv = SSL_get_verify_result(tallis->ssl_connection);

    if (rv != X509_V_OK)
        return 1;

    return 0;
}

int tallis_connect(tallis_t *tallis)
{
    int rv;

    ERR_clear_error();
    rv = SSL_CTX_load_verify_locations(
            tallis->ssl_context,
            NULL,
            "../certs");

    SSL_CTX_set_default_verify_paths(tallis->ssl_context);

    if (!rv)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    X509_VERIFY_PARAM_set_hostflags(
            tallis->param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    X509_VERIFY_PARAM_set1_host(tallis->param, tallis->host, 0);
    SSL_CTX_set_verify(tallis->ssl_context, SSL_VERIFY_PEER, NULL);
    SSL_set_verify(tallis->ssl_connection, SSL_VERIFY_PEER, NULL);

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

        printf("-->");
        tallis_print((char*) msg, strlen(msg));
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
                1,
                "AUTHENTICATE AGJvb2dpZXBvcABkaWVtZWlzdGVyc2luZ2Vy\r\n");

    if (strstr(buf, "SASL authentication successful") != NULL)
        tallis_send(tallis, 1, "CAP END\r\n");

    if (strstr(buf, "MODE tallis :") != NULL)
        tallis_send(tallis, 1, "JOIN #lainchan\r\n");

    /*
    if (strstr(buf, "~tallis quit") != NULL)
        tallis_shutdown(tallis);

    if (strstr(buf, "~tallis about") != NULL)
        tallis_send(
                tallis,
                1,
                "PRIVMSG #lainchan :\
                I am tallis, I was written in C and I use TLS\r\n");
    */

    lexer_analyze(buf);
}

int tallis_loop(tallis_t *tallis)
{
    ssize_t len;
    char buf[512] = {0};
    const char *nick = "NICK tallis\r\n";
    const char *user = "USER tallis eleison vatican.va :tallis\r\n";

    if (tallis_check_capability(tallis))
        return 1;

    if (tallis_send(tallis, 2, nick, user))
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
