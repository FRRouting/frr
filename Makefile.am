## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects 1.12
include common.am

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/lib \
	      -I$(top_builddir) -I$(top_builddir)/include -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)
VERSION_TYPE := $(shell if echo $(VERSION) | grep -q '^[0-9\.]*$$'; then echo RELEASE ; else echo DEV ; fi)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" -DCONFDATE=$(CONFDATE) -DVERSION_TYPE_$(VERSION_TYPE)
LIBCAP = @LIBCAP@

# overwriting these vars breaks cross-compilation.  let's be helpful and warn.
#
# note: "#AUTODERP# " will be removed from Makefile by configure.  These are
# GNU make directives & automake will f*ck them up by trying to process them
# as automake directives.
#
#AUTODERP# null=
#AUTODERP# SPACE=$(null) $(null)
#AUTODERP# mkcheck_CC =       $(findstring $(SPACE)CC=,      $(SPACE)$(MAKEOVERRIDES))
#AUTODERP# mkcheck_CFLAGS =   $(findstring $(SPACE)CFLAGS=,  $(SPACE)$(MAKEOVERRIDES))
#AUTODERP# mkcheck_CPPFLAGS = $(findstring $(SPACE)CPPFLAGS=,$(SPACE)$(MAKEOVERRIDES))
#AUTODERP# mkcheck_CCLD =     $(findstring $(SPACE)CCLD=,    $(SPACE)$(MAKEOVERRIDES))
#AUTODERP# mkcheck_LD =       $(findstring $(SPACE)LD=,      $(SPACE)$(MAKEOVERRIDES))
#AUTODERP# mkcheck_LDFLAGS =  $(findstring $(SPACE)LDFLAGS=, $(SPACE)$(MAKEOVERRIDES))
#AUTODERP# #
#AUTODERP# ifneq ($(mkcheck_CC),)
#AUTODERP#   $(warning WARNING: you have overwritten the "CC" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# ifneq ($(mkcheck_CFLAGS),)
#AUTODERP#   $(warning WARNING: you have overwritten the "CFLAGS" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# ifneq ($(mkcheck_CPPFLAGS),)
#AUTODERP#   $(warning WARNING: you have overwritten the "CPPFLAGS" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# ifneq ($(mkcheck_CCLD),)
#AUTODERP#   $(warning WARNING: you have overwritten the "CCLD" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# ifneq ($(mkcheck_LD),)
#AUTODERP#   $(warning WARNING: you have overwritten the "LD" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# ifneq ($(mkcheck_LDFLAGS),)
#AUTODERP#   $(warning WARNING: you have overwritten the "LDFLAGS" variable on the make command line.)
#AUTODERP# endif
#AUTODERP# #
#AUTODERP# ifneq ($(mkcheck_CC)$(mkcheck_CFLAGS)$(mkcheck_CPPFLAGS)$(mkcheck_CCLD)$(mkcheck_LD)$(mkcheck_LDFLAGS),)
#AUTODERP#   $(warning ------)
#AUTODERP#   $(warning While overwriting these variables works most of the time, it is not recommended and can cause confusing build errors.)
#AUTODERP#   $(warning This is especially problematic when cross-compiling, since tools that run on the build system during the build process will not be compiled correctly.)
#AUTODERP#   $(warning All of these variables should be supplied to 'configure', and they will be remembered and correctly applied during 'make'.)
#AUTODERP#   $(warning ------)
#AUTODERP# endif

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
include debianpkg/subdir.am

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

SUBDIRS = . @LIBRFP@ @RFPTEST@ \
	 @BGPD@ \
	 @VTYSH@ @DOC@ \
         @SOLARIS@ tests

DIST_SUBDIRS = . bgpd \
	  vtysh doc tests \
	  solaris bgpd/rfp-example/librfp \
	  bgpd/rfp-example/rfptest \
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
	vtysh/Makefile.am \
	vtysh/Makefile.in \
	# end

ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS += defaults.h

indent:
	tools/indent.py `find sharpd bgpd eigrpd include isisd lib nhrpd ospf6d ospfd pimd qpb ripd vtysh zebra -name '*.[ch]' | grep -v include/linux`
