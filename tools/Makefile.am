AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
AM_CFLAGS = $(WERROR)

bin_PROGRAMS = permutations
permutations_SOURCES = permutations.c
permutations_LDADD = ../lib/libzebra.la

sbin_SCRIPTS = quagga-reload.py quagga

EXTRA_DIST = quagga.service quagga-reload.py quagga

