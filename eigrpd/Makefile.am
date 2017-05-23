## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libeigrp.a
sbin_PROGRAMS = eigrpd

libeigrp_a_SOURCES = \
	eigrpd.c eigrp_zebra.c \
	eigrp_interface.c eigrp_neighbor.c \
	eigrp_dump.c eigrp_vty.c \
	eigrp_network.c eigrp_packet.c \
	eigrp_topology.c eigrp_fsm.c \
	eigrp_hello.c eigrp_update.c \
	eigrp_query.c eigrp_reply.c \
	eigrp_snmp.c eigrp_siaquery.c \
	eigrp_siareply.c eigrp_filter.c \
	eigrp_memory.c


eigrpdheaderdir = $(pkgincludedir)/eigrpd

eigrpdheader_HEADERS = \
	eigrp_topology.h eigrp_dump.h eigrpd.h

noinst_HEADERS = \
	eigrp_const.h eigrp_structs.h \
	eigrp_macros.h eigrp_interface.h \
	eigrp_neighbor.h eigrp_network.h \
	eigrp_packet.h eigrp_memory.h \
	eigrp_zebra.h eigrp_vty.h \
	eigrp_snmp.h eigrp_filter.h \
	eigrp_fsm.h

eigrpd_SOURCES = eigrp_main.c $(libeigrp_a_SOURCES)

eigrpd_LDADD = ../lib/libfrr.la @LIBCAP@

if ALL_STATIC
eigrpd_LDFLAGS = -all-static
endif

EXTRA_DIST = EIGRP-MIB.txt

examplesdir = $(exampledir)
dist_examples_DATA = eigrpd.conf.sample
