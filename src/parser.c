#include <stdio.h>

static void subcommand()
{
    keyword();
    expect(test_arg_sym);
}

static void precursor()
{
    expect(tilde_sym);
    expect(progname);
}

static void command()
{
    next_symbol();
    precursor();
    subcommand();
}

int tallis_parse_response(tallis_t *tallis, char *buf)
{
}
