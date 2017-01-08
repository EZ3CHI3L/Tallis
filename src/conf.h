#ifndef CONF_H
#define CONF_H
#include <libconfig.h>
#include "tallis.h"
int tallis_check_sasl(tallis_t*);
int tallis_get_sasl_password(tallis_t*);
void tallis_config_fail(tallis_t*);
char *tallis_set_conf_path(void);
int tallis_parse_config(config_t*, const char*);
#endif /* CONF_H */
