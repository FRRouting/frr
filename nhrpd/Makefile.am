## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib -DQUAGGA_NO_DEPRECATED_INTERFACES
DEFS = @DEFS@ @CARES_CFLAGS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(PICFLAGS) #$(WERROR)
AM_LDFLAGS = $(PICLDFLAGS)

sbin_PROGRAMS = nhrpd

nhrpd_SOURCES = \
	zbuf.c \
	znl.c \
	resolver.c \
	linux.c \
	netlink_arp.c \
	netlink_gre.c \
	vici.c \
	reqid.c \
	nhrp_event.c \
	nhrp_packet.c \
	nhrp_interface.c \
	nhrp_vc.c \
	nhrp_peer.c \
	nhrp_cache.c \
	nhrp_nhs.c \
	nhrp_route.c \
	nhrp_shortcut.c \
	nhrp_vty.c \
	nhrp_main.c

nhrpd_LDADD = ../lib/libzebra.la @LIBCAP@ @CARES_LIBS@

#dist_examples_DATA = nhrpd.conf.sample
