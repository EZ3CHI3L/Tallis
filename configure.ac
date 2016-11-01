AC_INIT([tallis], [0.2], [ezechiel@protonmail.ch])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_CONFIG_MACRO_DIR([m4])
PKG_CHECK_MODULES([LIBSSL], [libssl >= 1.1])
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1])
AC_OUTPUT
