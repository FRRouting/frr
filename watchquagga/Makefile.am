## Process this file with Automake to create Makefile.in

INCLUDES = @INCLUDES@ -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSTATEDIR=\"$(localstatedir)/\"

sbin_PROGRAMS = watchquagga

watchquagga_SOURCES = watchquagga.c
watchquagga_LDADD = ../lib/libzebra.la @LIBCAP@
