## Process this file with Automake to create Makefile.in

INCLUDES = @GUILE_CFLAGS@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -I. -I$(srcdir)

bin_PROGRAMS = zebra-guile
zebra_guile_SOURCES = zebra-guile.c zebra-support.c guile-bgp.c
noinst_HEADERS = zebra-guile.h
zebra_guile_LDADD = @GUILE_LDFLAGS@ ../bgpd/libbgp.a ../lib/libzebra.la
