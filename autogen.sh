#!/bin/sh -e

echo 'Domine, Quo Vadis?'
(
    libtoolize --copy
    aclocal -I m4
    autoconf
    autoheader
    automake --add-missing --copy --no-force
)
