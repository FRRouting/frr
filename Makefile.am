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
	 @WATCHFRR@ @VTYSH@ @OSPFCLIENT@ @DOC@ \
         @SOLARIS@ tests tools

DIST_SUBDIRS = . bgpd ripd ripngd ospfd ospf6d ldpd \
	  isisd watchfrr vtysh ospfclient doc tests \
	  solaris pimd nhrpd eigrpd bgpd/rfp-example/librfp \
	  bgpd/rfp-example/rfptest tools babeld \
	  # end

if PKGSRC
rcdir=@pkgsrcrcdir@
rc_SCRIPTS = \
	pkgsrc/bgpd.sh \
	pkgsrc/ospf6d.sh \
	pkgsrc/ospfd.sh \
	pkgsrc/ripd.sh \
	pkgsrc/ripngd.sh \
	pkgsrc/zebra.sh \
	# end
endif

EXTRA_DIST += \
	REPORTING-BUGS \
	SERVICES \
	aclocal.m4 \
	update-autotools \
	m4/README.txt \
	\
	python/clidef.py \
	python/clippy/__init__.py \
	\
	redhat/frr.init \
	redhat/frr.service \
	redhat/daemons \
	redhat/frr.logrotate \
	redhat/frr.pam \
	redhat/frr.spec \
	redhat/README.rpm_build.md \
	\
	snapcraft/snapcraft.yaml \
	snapcraft/README.snap_build.md \
	snapcraft/README.usage.md \
	snapcraft/extra_version_info.txt \
	snapcraft/scripts \
	snapcraft/defaults \
	snapcraft/helpers \
	snapcraft/snap \
	\
	tools/multiple-bgpd.sh \
	tools/rrcheck.pl \
	tools/rrlookup.pl \
	tools/zc.pl \
	tools/zebra.el \
	\
	vtysh/Makefile.am \
	vtysh/Makefile.in \
	# end

ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS += defaults.h
