## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects 1.12
include common.am

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir) -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
LIBCAP = @LIBCAP@

EXTRA_DIST =
BUILT_SOURCES =
CLEANFILES =

examplesdir = $(exampledir)

bin_PROGRAMS =
sbin_PROGRAMS =
noinst_PROGRAMS =
noinst_HEADERS =
noinst_LIBRARIES =
lib_LTLIBRARIES =
module_LTLIBRARIES =
pkginclude_HEADERS =
dist_examples_DATA =

include lib/subdir.am
include zebra/subdir.am
include qpb/subdir.am
include fpm/subdir.am

SUBDIRS = . @LIBRFP@ @RFPTEST@ \
	 @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ @LDPD@ \
         @ISISD@ @PIMD@ @NHRPD@ @EIGRPD@ @BABELD@ \
	 @WATCHFRR@ @VTYSH@ @OSPFCLIENT@ @DOC@ m4 @pkgsrcdir@ \
         redhat @SOLARIS@ tests tools snapcraft

DIST_SUBDIRS = . bgpd ripd ripngd ospfd ospf6d ldpd \
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
