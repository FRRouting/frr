## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects 1.12
include common.am

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

EXTRA_DIST =
BUILT_SOURCES =

bin_PROGRAMS =
sbin_PROGRAMS =
noinst_PROGRAMS =
noinst_HEADERS =
noinst_LIBRARIES =
lib_LTLIBRARIES =
pkginclude_HEADERS =

include lib/subdir.am

SUBDIRS = . qpb fpm @ZEBRA@ @LIBRFP@ @RFPTEST@ \
	 @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ @LDPD@ \
         @ISISD@ @PIMD@ @NHRPD@ @EIGRPD@ @BABELD@ \
	 @WATCHFRR@ @VTYSH@ @OSPFCLIENT@ @DOC@ m4 @pkgsrcdir@ \
         redhat @SOLARIS@ tests tools snapcraft

DIST_SUBDIRS = . qpb fpm zebra bgpd ripd ripngd ospfd ospf6d ldpd \
	  isisd watchfrr vtysh ospfclient doc m4 pkgsrc redhat tests \
	  solaris pimd nhrpd eigrpd bgpd/rfp-example/librfp \
	  bgpd/rfp-example/rfptest tools snapcraft babeld python \
	  # end

EXTRA_DIST += aclocal.m4 SERVICES REPORTING-BUGS \
	update-autotools \
	vtysh/Makefile.in vtysh/Makefile.am \
	tools/rrcheck.pl tools/rrlookup.pl tools/zc.pl \
	tools/zebra.el tools/multiple-bgpd.sh

ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS += defaults.h
