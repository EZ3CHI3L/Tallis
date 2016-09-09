#ifndef LEXER_H
#define LEXER_H
typedef enum
{
    PRECURSOR,
    VALUE_INT,
    OPERATOR_PLUS,
    OPERATOR_MINUS,
    OPERATOR_MULTIPLY,
    KEYWORD_EVAL
} symbol_table;
int lexer_analyze(char*);
symbol_table lexer_tokenize(char*);
#endif /* LEXER_H */
