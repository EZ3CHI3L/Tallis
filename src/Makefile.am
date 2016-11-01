bin_PROGRAMS = tallis
LDADD = $(LIBSSL_LIBS) $(OPENSSL_LIBS)
tallis_SOURCES = tallis.c net.c irc.c lexer.c error.c
AM_CFLAGS = -std=c11 -g -march=native -fPIC -Wall -Werror -Wfatal-errors -Wno-unused-variable -pedantic
