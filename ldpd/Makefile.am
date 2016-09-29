## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib \
              -DVTY_DEPRECATE_INDEX
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libldp.a
sbin_PROGRAMS = ldpd

libldp_a_SOURCES = \
	accept.c address.c adjacency.c control.c hello.c init.c interface.c \
	keepalive.c l2vpn.c labelmapping.c lde.c lde_lib.c ldpd.c \
	ldpe.c log.c neighbor.c notification.c packet.c pfkey.c \
	socket.c util.c ldp_vty_cmds.c ldp_vty_conf.c ldp_vty_exec.c \
	ldp_debug.c ldp_zebra.c

noinst_HEADERS = \
	control.h lde.h ldpd.h ldpe.h ldp.h log.h ldp_debug.h ldp_vty.h

ldpd_SOURCES = ldpd.c
ldpd_LDADD = libldp.a ../lib/libzebra.la @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = ldpd.conf.sample
