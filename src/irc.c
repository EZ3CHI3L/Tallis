#include <stdio.h>
#include "tallis.h"
#include "net.h"

/* Use CAP to determine capabilities of IRC server (SASL support etc) */
int tallis_check_capability(tallis_t *tallis)
{
    char *command = "CAP REQ :multi-prefix sasl\r\n";
    tallis_send(tallis, 1, command);
    return 0;
}
