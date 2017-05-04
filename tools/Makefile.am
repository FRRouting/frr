AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
AM_CFLAGS = $(WERROR)
EXTRA_DIST =

bin_PROGRAMS = permutations
sbin_PROGRAMS = ssd

permutations_SOURCES = permutations.c
permutations_LDADD = ../lib/libfrr.la

sbin_SCRIPTS = frr-reload.py frr

EXTRA_DIST += frr.service frr-reload.py frr

EXTRA_DIST += xml2cli.pl

ssd_SOURCES = start-stop-daemon.c
