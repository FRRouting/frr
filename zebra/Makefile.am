## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

LIBCAP = @LIBCAP@

ipforward = @IPFORWARD@
if_method = @IF_METHOD@
rt_method = @RT_METHOD@
rtread_method = @RTREAD_METHOD@
kernel_method = @KERNEL_METHOD@
ioctl_method = @IOCTL_METHOD@

otherobj = $(ioctl_method) $(ipforward) $(if_method) \
	$(rt_method) $(rtread_method) $(kernel_method)

if HAVE_NETLINK
othersrc = zebra_fpm_netlink.c
endif

AM_CFLAGS = $(WERROR)

sbin_PROGRAMS = zebra

noinst_PROGRAMS = testzebra

zebra_SOURCES = \
	zebra_memory.c \
	zserv.c main.c interface.c connected.c zebra_rib.c zebra_routemap.c \
	redistribute.c debug.c rtadv.c zebra_snmp.c zebra_vty.c \
	irdp_main.c irdp_interface.c irdp_packet.c router-id.c zebra_fpm.c \
	$(othersrc) zebra_ptm.c zebra_rnh.c zebra_ptm_redistribute.c \
	zebra_ns.c zebra_vrf.c zebra_static.c zebra_mpls.c

testzebra_SOURCES = test_main.c zebra_rib.c interface.c connected.c debug.c \
	zebra_vty.c zebra_ptm.c zebra_routemap.c zebra_ns.c zebra_vrf.c \
	kernel_null.c  redistribute_null.c ioctl_null.c misc_null.c zebra_rnh_null.c \
	zebra_ptm_null.c rtadv_null.c if_null.c zserv_null.c zebra_static.c \
	zebra_memory.c zebra_mpls_null.c

noinst_HEADERS = \
	zebra_memory.h \
	connected.h ioctl.h rib.h rt.h zserv.h redistribute.h debug.h rtadv.h \
	interface.h ipforward.h irdp.h router-id.h kernel_socket.h \
	rt_netlink.h zebra_fpm.h zebra_fpm_private.h zebra_rnh.h \
	zebra_ptm_redistribute.h zebra_ptm.h zebra_routemap.h \
	zebra_ns.h zebra_vrf.h ioctl_solaris.h zebra_static.h zebra_mpls.h

zebra_LDADD = $(otherobj) ../lib/libzebra.la $(LIBCAP)

testzebra_LDADD = ../lib/libzebra.la $(LIBCAP)

zebra_DEPENDENCIES = $(otherobj)

EXTRA_DIST = if_ioctl.c if_ioctl_solaris.c if_netlink.c \
        if_sysctl.c ipforward_proc.c \
	ipforward_solaris.c ipforward_sysctl.c rt_netlink.c \
	rt_socket.c rtread_netlink.c rtread_sysctl.c \
	rtread_getmsg.c kernel_socket.c kernel_netlink.c \
	ioctl.c ioctl_solaris.c \
	GNOME-SMI GNOME-PRODUCT-ZEBRA-MIB

client : client_main.o ../lib/libzebra.la
	$(CC) -g -o client client_main.o ../liblzebra.la $(LIBS) $(LIB_IPV6)

quaggaconfdir = $(sysconfdir)

examplesdir = $(exampledir)
dist_examples_DATA = zebra.conf.sample
