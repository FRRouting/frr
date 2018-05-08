## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects 1.12
include common.am

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/lib \
	      -I$(top_builddir) -I$(top_builddir)/include -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)
VERSION_TYPE := $(shell if echo $(VERSION) | grep -q '^[0-9\.]*$$'; then echo RELEASE ; else echo DEV ; fi)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" -DCONFDATE=$(CONFDATE) -DVERSION_TYPE_$(VERSION_TYPE)
LIBCAP = @LIBCAP@

EXTRA_DIST =
BUILT_SOURCES =
CLEANFILES =

examplesdir = $(exampledir)

bin_PROGRAMS =
sbin_PROGRAMS =
sbin_SCRIPTS =
noinst_PROGRAMS =
noinst_HEADERS =
noinst_LIBRARIES =
lib_LTLIBRARIES =
module_LTLIBRARIES =
pkginclude_HEADERS =
nodist_pkginclude_HEADERS =
dist_examples_DATA =

## libtool, the self-made GNU scourge
## ... this should fix relinking
## ... and AUTOMAKE_DUMMY is needed to prevent automake from treating this
##     as overriding the normal targets...
$(AUTOMAKE_DUMMY)install-moduleLTLIBRARIES: install-libLTLIBRARIES
$(AUTOMAKE_DUMMY)install-binPROGRAMS: install-libLTLIBRARIES
$(AUTOMAKE_DUMMY)install-sbinPROGRAMS: install-libLTLIBRARIES

include include/subdir.am
include lib/subdir.am
include zebra/subdir.am
include watchfrr/subdir.am
include qpb/subdir.am
include fpm/subdir.am
include tools/subdir.am

include ripd/subdir.am
include ripngd/subdir.am
include ospfd/subdir.am
include ospf6d/subdir.am
include ospfclient/subdir.am
include isisd/subdir.am
include nhrpd/subdir.am
include ldpd/subdir.am
include babeld/subdir.am
include eigrpd/subdir.am
include sharpd/subdir.am
include pimd/subdir.am
include pbrd/subdir.am

SUBDIRS = . @LIBRFP@ @RFPTEST@ \
	 @BGPD@ \
	 @VTYSH@ @DOC@ \
         @SOLARIS@ tests

DIST_SUBDIRS = . \
	  bgpd \
	  bgpd/rfp-example/librfp \
	  bgpd/rfp-example/rfptest \
	  vtysh \
	  doc \
	  tests \
	  packaging/solaris \
	  packaging/debianpkg \
	  # end

if PKGSRC
rcdir=@pkgsrcrcdir@
rc_SCRIPTS = \
	packaging/pkgsrc/bgpd.sh \
	packaging/pkgsrc/ospf6d.sh \
	packaging/pkgsrc/ospfd.sh \
	packaging/pkgsrc/ripd.sh \
	packaging/pkgsrc/ripngd.sh \
	packaging/pkgsrc/zebra.sh \
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
	packaging/redhat/frr.init \
	packaging/redhat/frr.service \
	packaging/redhat/daemons \
	packaging/redhat/frr.logrotate \
	packaging/redhat/frr.pam \
	packaging/redhat/frr.spec \
	packaging/redhat/README.rpm_build.md \
	\
	packaging/snapcraft/snapcraft.yaml \
	packaging/snapcraft/README.snap_build.md \
	packaging/snapcraft/README.usage.md \
	packaging/snapcraft/extra_version_info.txt \
	packaging/snapcraft/scripts \
	packaging/snapcraft/defaults \
	packaging/snapcraft/helpers \
	packaging/snapcraft/snap \
	\
	vtysh/Makefile.am \
	vtysh/Makefile.in \
	# end

ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS += defaults.h

indent:
	tools/indent.py `find sharpd bgpd eigrpd include isisd lib nhrpd ospf6d ospfd pimd qpb ripd vtysh zebra -name '*.[ch]' | grep -v include/linux`
