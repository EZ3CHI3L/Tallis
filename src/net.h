#ifndef NET_H
#define NET_H
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "tallis.h"
void ssl_init();
int ssl_shutdown(tallis_t*);
int tallis_connect(tallis_t*);
int tallis_ssl_verify(tallis_t*);
int tallis_send(tallis_t*, int, ...);
int tallis_loop(tallis_t*);
void tallis_print(char*, ssize_t);
#endif /* NET_H */
