#ifndef IRC_H
#define IRC_H
#include <stdbool.h>
#include "tallis.h"
typedef struct tallis_server_capabilities_struct
{
    bool cap_sasl, cap_multi_prefix;
} tallis_server_capabilities_t;
void tallis_check_capability(tallis_t*,
        tallis_server_capabilities_t*, char*);
#endif /* IRC_H */
