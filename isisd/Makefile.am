## Process this file with automake to produce Makefile.in.

# INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -Itopology
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib 
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600
LIBS = @LIBS@ 
noinst_LIBRARIES = libisis.a
sbin_PROGRAMS = isisd 

libisis_a_SOURCES = \
	isis_adjacency.c isis_lsp.c dict.c isis_circuit.c isis_pdu.c \
	isis_tlv.c isisd.c isis_misc.c isis_network.c isis_zebra.c isis_dr.c \
	isis_flags.c isis_dynhn.c iso_checksum.c isis_csm.c isis_events.c \
	isis_spf.c isis_route.c isis_routemap.c


noinst_HEADERS = \
	isisd.h isis_pdu.h isis_tlv.h isis_adjacency.h isis_constants.h \
	isis_lsp.h dict.h isis_circuit.h isis_misc.h isis_network.h \
	isis_zebra.h isis_dr.h isis_flags.h isis_dynhn.h isis_common.h \
	iso_checksum.h isis_csm.h isis_events.h isis_spf.h isis_route.h \
	include-netbsd/clnp.h include-netbsd/esis.h include-netbsd/iso.h

isisd_SOURCES = \
	isis_main.c $(libisis_a_SOURCES)

isisd_LDADD = ../lib/libzebra.la @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = isisd.conf.sample
