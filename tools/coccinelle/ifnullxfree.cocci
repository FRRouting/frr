/// NULL check before some freeing functions is not needed.
///
// Copyright: (C) 2014 Fabian Frederick.  GPLv2.
// Copyright: (C) 2019 Quentin Young.  GPLv2.
// Comments: -
// Options: --no-includes --include-headers

virtual patch

@r2 depends on patch@
expression E;
expression Y;
@@
- if (E != NULL)
XFREE(Y, E);
