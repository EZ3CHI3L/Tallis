#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "irc.h"
#include "tallis.h"
#include "net.h"

/* Use CAP to determine capabilities of IRC server (SASL support etc) */
void tallis_check_capability(tallis_t *tallis,
        tallis_server_capabilities_t* capabilities, char *buf)
{
    char *command = "CAP REQ :multi-prefix sasl\r\n";
    int msg_len = strlen(command);
    tallis_send(tallis, command, msg_len);

    if (strstr(buf, "CAP * ACK :multi-prefix sasl"))
        capabilities->cap_multi_prefix = capabilities->cap_sasl = true;
}
