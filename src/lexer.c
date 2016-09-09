#include <stdio.h>
#include "lexer.h"

int lexer_analyze(char *input)
{
    symbol_table sym = lexer_tokenize(input);
    for(int i = 0; i < 6; ++i)
        printf("%d\n", sym);
    return 0;
}

symbol_table lexer_tokenize(char *input)
{
    symbol_table sym = PRECURSOR;

    return sym;
}
