## Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = subdir-objects 1.12
include common.am

AM_CPPFLAGS += -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/lib \
	      -I$(top_builddir) -I$(top_builddir)/include -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" -DCONFDATE=$(CONFDATE)
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
nodist_noinst_DATA =
lib_LTLIBRARIES =
module_LTLIBRARIES =
pkginclude_HEADERS =
nodist_pkginclude_HEADERS =
dist_examples_DATA =
man_MANS =

## libtool, the self-made GNU scourge
## ... this should fix relinking
## ... and AUTOMAKE_DUMMY is needed to prevent automake from treating this
##     as overriding the normal targets...
$(AUTOMAKE_DUMMY)install-moduleLTLIBRARIES: install-libLTLIBRARIES
$(AUTOMAKE_DUMMY)install-binPROGRAMS: install-libLTLIBRARIES
$(AUTOMAKE_DUMMY)install-sbinPROGRAMS: install-libLTLIBRARIES

include doc/subdir.am
include doc/user/subdir.am
include doc/manpages/subdir.am
include doc/developer/subdir.am
include include/subdir.am
include lib/subdir.am
include zebra/subdir.am
include watchfrr/subdir.am
include qpb/subdir.am
include fpm/subdir.am
include tools/subdir.am
include debianpkg/subdir.am
include solaris/subdir.am

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
include staticd/subdir.am
include bfdd/subdir.am

SUBDIRS = . @LIBRFP@ @RFPTEST@ \
	 @BGPD@ \
	 @VTYSH@ \
         tests

DIST_SUBDIRS = . bgpd \
	  vtysh tests \
	  bgpd/rfp-example/librfp \
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
	aclocal.m4 \
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
	\
	doc/Makefile \
	doc/developer/Makefile \
	doc/manpages/Makefile \
	doc/user/Makefile \
	# end

ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS += defaults.h

indent:
	tools/indent.py `find sharpd bgpd eigrpd include isisd lib nhrpd ospf6d ospfd pimd qpb ripd vtysh zebra -name '*.[ch]' | grep -v include/linux`

if HAVE_GCOV

coverage: check
	@ find . -name '*.o' -exec gcov {} \;

yorn:
	@ echo "OK to upload coverage to https://coverage.io [y/N]:"
	@ read yn; test "$$yn" = "y"

upload-check-coverage:
	@ if [ "x${COMMIT}" = "x" ]; then echo "COMMIT required"; exit 1; fi
	@ if [ "x${TOKEN}" = "x" ]; then echo "TOKEN required"; exit 1; fi
	curl -s https://codecov.io/bash | bash -s - -C ${COMMIT} -t ${TOKEN}

force-check-coverage: coverage upload-check-coverage

check-coverage: coverage yorn upload-check-coverage

endif
