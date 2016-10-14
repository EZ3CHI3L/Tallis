#ifndef NET_H
#define NET_H
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include "tallis.h"
void tallis_ssl_init();
int ssl_shutdown(tallis_t*);
int tallis_connect(tallis_t*);
int tallis_init_ssl_verify(tallis_t*);
int tallis_ssl_verify(tallis_t*, X509*);
int tallis_verify_cert_chain(tallis_t*, X509*);
int tallis_send(tallis_t*, int, ...);
int tallis_loop(tallis_t*);
void tallis_print(char*, ssize_t);
#endif /* NET_H */
