## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = librip.a
module_LTLIBRARIES =
sbin_PROGRAMS = ripd

librip_a_SOURCES = \
	rip_memory.c \
	ripd.c rip_zebra.c rip_interface.c rip_debug.c \
	rip_routemap.c rip_peer.c rip_offset.c

noinst_HEADERS = \
	rip_memory.h \
	ripd.h rip_debug.h rip_interface.h

ripd_SOURCES = \
	rip_main.c $(librip_a_SOURCES)

ripd_LDADD = ../lib/libfrr.la @LIBCAP@

if ALL_STATIC
ripd_LDFLAGS = -all-static
endif

if SNMP
module_LTLIBRARIES += ripd_snmp.la
endif
ripd_snmp_la_SOURCES = rip_snmp.c
ripd_snmp_la_CFLAGS = $(WERROR) $(SNMP_CFLAGS)
ripd_snmp_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
ripd_snmp_la_LIBADD = ../lib/libfrrsnmp.la

examplesdir = $(exampledir)
dist_examples_DATA = ripd.conf.sample

EXTRA_DIST = RIPv2-MIB.txt

