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
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, src, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *dest=(*bufferPtr).data;

    return 0;
}

int tallis_get_sasl_password(tallis_t* tallis)
{
    int rv, sasl_flag = 0;

    rv = config_lookup_bool(&tallis->config, "sasl", &sasl_flag);

    if (!rv || sasl_flag == 0)
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

int tallis_send(tallis_t *tallis, const char *msg, size_t len)
{
    ssize_t bytes_written;
    int retry_limit = 2;

    ERR_clear_error();
    bytes_written = BIO_write(tallis->bio, msg, len);

    while (BIO_should_retry(tallis->bio) && bytes_written < len)
        bytes_written = BIO_write(tallis->bio, msg, len);

    if (!bytes_written)
    {
        fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

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
    size_t msg_len;

    if (strncmp(buf, "PING :", 6) == 0)
    {
        const char *pong_msg = strncat(pong, buf + 6, len - 6);
        msg_len = strlen(pong_msg);
        tallis_send(tallis, pong_msg, msg_len);
    }

    if (strstr(buf, "CAP * ACK :multi-prefix sasl"))
    {
        const char *sasl_mechanism_msg = "AUTHENTICATE PLAIN\r\n";
        msg_len = strlen(sasl_mechanism_msg);
        tallis_send(tallis, sasl_mechanism_msg, msg_len);
    }

    if (strstr(buf, "CAP * NAK :multi-prefix sasl") != NULL)
    {
        const char *cap_end_msg = "CAP END\r\n";
        msg_len = strlen(cap_end_msg);
        tallis_send(tallis, cap_end_msg, msg_len);
    }

    if (strstr(buf, "AUTHENTICATE +") != NULL)
    {
        const char *sasl_auth_msg = "AUTHENTICATE";
        msg_len = strlen(sasl_auth_msg);
        tallis_send(tallis, sasl_auth_msg, msg_len);

        const char *space = " ";
        msg_len = strlen(space);
        tallis_send(tallis, space, msg_len);

        if (tallis->sasl_challenge)
            msg_len = strlen(tallis->sasl_challenge);
        tallis_send(tallis, tallis->sasl_challenge, msg_len);

        const char *delimiter = "\r\n";
        msg_len = strlen(delimiter);
        tallis_send(tallis, delimiter, msg_len);
    }

    if (strstr(buf, "SASL authentication successful") != NULL)
    {
        const char *cap_end_msg = "CAP END\r\n";
        msg_len = strlen(cap_end_msg);
        tallis_send(tallis, cap_end_msg, msg_len);
    }

    if (strstr(buf, "~tallis quit") != NULL)
        tallis_shutdown(tallis);

    /* lexer_analyze(buf); */
}

int tallis_loop(tallis_t *tallis)
{
    ssize_t bytes_read;
    size_t msg_len;
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

    /* ignore the following */
    if (!tallis_get_sasl_password(tallis))
        tallis->has_sasl = 1;
    else
        tallis->has_sasl = 0;

    if (!tallis->has_config || !tallis->has_sasl)
        puts("running with SASL disabled");
    else if (tallis->has_config && tallis->has_sasl)
    {
        size_t nicklen = strlen(tallis->nick),
               passlen = strlen(tallis->sasl_password);

        tallis->challenge_len = nicklen + 1 + nicklen + 1 + passlen;

        char *temp = malloc(tallis->challenge_len);

        memcpy(temp, tallis->nick, nicklen);
        memcpy(temp + nicklen + 1, tallis->nick, nicklen + 1);
        memcpy(temp + nicklen * 2 + 2, tallis->sasl_password, passlen);

        tallis_base64_encode(temp, tallis->challenge_len,
                &tallis->sasl_challenge);

        const char *cap_req_msg = "CAP REQ :multi-prefix sasl\r\n";
        msg_len = strlen(cap_req_msg);
        tallis_send(tallis, cap_req_msg, msg_len);
    }

    msg_len = strlen(initial_message);
    if (tallis_send(tallis, initial_message, msg_len))
        return 1;

    while (1)
    {
        memset(buf, '\0', 512);
        bytes_read = BIO_read(tallis->bio, buf, 512);

        if (!bytes_read)
        {
            if (!BIO_should_retry(tallis->bio))
            {
                fprintf(stderr, ERR_error_string(ERR_get_error(), NULL));
                return 1;
            }
            puts("retry read?");
        }

        buf[bytes_read] = '\0';
        tallis_print(buf, bytes_read);
        tallis_parse(tallis, buf, bytes_read);
    }
    return 0;
}
