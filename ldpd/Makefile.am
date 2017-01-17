## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600
EXTRA_DIST=

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libldp.a
sbin_PROGRAMS = ldpd

BUILT_SOURCES = ldp_vty_cmds.c
EXTRA_DIST += ldp_vty.xml

libldp_a_SOURCES = \
	accept.c address.c adjacency.c control.c hello.c init.c interface.c \
	keepalive.c l2vpn.c labelmapping.c lde.c lde_lib.c ldpd.c \
	ldpe.c log.c neighbor.c notification.c packet.c pfkey.c \
	socket.c util.c ldp_vty_cmds.c ldp_vty_conf.c ldp_vty_exec.c \
	ldp_debug.c ldp_zebra.c

noinst_HEADERS = \
	control.h lde.h ldpd.h ldpe.h ldp.h log.h ldp_debug.h ldp_vty.h

ldp_vty_cmds.c: $(srcdir)/ldp_vty.xml $(srcdir)/../tools/xml2cli.pl
	@PERL@ $(srcdir)/../tools/xml2cli.pl $(srcdir)/ldp_vty.xml > $@

ldpd_SOURCES = ldpd.c
ldpd_LDADD = libldp.a ../lib/libzebra.la @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = ldpd.conf.sample
