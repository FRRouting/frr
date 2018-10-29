# Solaris packages automake file

# XXX This file uses GNU make extensions.

.PHONY: packages all all-files

all: all-files

prefix = @prefix@
exec_prefix = @exec_prefix@
bindir = @bindir@
sbindir = @sbindir@
libexecdir = @libexecdir@
datarootdir = @datarootdir@
datadir = @datadir@
sysconfdir = @sysconfdir@
sharedstatedir = @sharedstatedir@
localstatedir = @localstatedir@
libdir = @libdir@
includedir = @includedir@
infodir = @infodir@
mandir = @mandir@
frr_statedir = @frr_statedir@

builddir = @builddir@
srcdir = @srcdir@
top_builddir = @top_builddir@
top_srcdir = @top_srcdir@
abs_builddir = @abs_builddir@
abs_srcdir = @abs_srcdir@
abs_top_builddir = @abs_top_builddir@
abs_top_srcdir = @abs_top_srcdir@

enable_user = @enable_user@
enable_group = @enable_group@
enable_vty_group = @enable_vty_group@

PACKAGE_NAME = @PACKAGE_NAME@
PACKAGE_TARNAME = @PACKAGE_TARNAME@
PACKAGE_VERSION = @PACKAGE_VERSION@
PACKAGE_BUGREPORT = @PACKAGE_BUGREPORT@
CONFDATE = @CONFDATE@

host_cpu = @host_cpu@
host_os = @host_os@

SED = @SED@
MAKE = @MAKE@

# the names of the various subpackages, and some convenient 
# derived variables.
pkg_names = daemons dev doc libs smf
pkg_frr_daemons = zebra bgpd ospfd ospf6d ripd ripngd
pkg_name_rev = $(PACKAGE_VERSION)-$(CONFDATE)-$(host_os)-$(host_cpu)
pkg_depends = $(pkg_names:%=depend.%)
pkg_packages = $(pkg_names:%=@PACKAGE_TARNAME@-%-$(pkg_name_rev).pkg)
pkg_pkginfos = $(pkg_names:%=pkginfo.%.full)
pkg_prototypes = $(pkg_names:%=prototype.%)
pkg_manifests = frr.xml

# pkgmk variable substitutions wont grok ${variable} in prototype
# file, so we cant let autoconf generate the file sadly
# wish automake would just provide a template for this
edit = $(SED) \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix,$(exec_prefix),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@sbindir\@,$(sbindir),g' \
	-e 's,@libexecdir\@,$(libexecdir),g' \
	-e 's,@datadir\@,$(datadir),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@sharedstatedir\@,$(sharedstatedir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	-e 's,@infodir\@,$(infodir),g' \
	-e 's,@mandir\@,$(mandir),g' \
	-e 's,@enable_user\@,$(enable_user),g' \
	-e 's,@enable_group\@,$(enable_group),g' \
	-e 's,@enable_vty_group\@,$(enable_vty_group),g' \
	-e 's,@frr_statedir\@,$(frr_statedir),g' \
	-e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	-e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	-e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	-e 's,[@]CONFDATE[@],$(CONFDATE),g' \
	-e 's,[@]host_cpu[@],$(host_cpu),g' \
	-e 's,[@]host_os[@],$(host_os),g'

# common options for pkgmk
pkg_make_vars = exec_prefix=$(exec_prefix) prefix=$(prefix) \
	builddir=$(builddir) srcdir=$(srcdir) \
	top_builddir=$(top_builddir) top_srcdir=$(top_srcdir) \
	abs_builddir=$(abs_builddir) abs_srcdir=$(abs_srcdir) \
	abs_top_builddir=$(abs_top_builddir) abs_top_srcdir=$(abs_top_srcdir)

# pkgmk: write the package to spool in build dir, to avoid root dependencies
pkg_make = pkgmk -o -d $(abs_builddir) \
	-f $< DESTDIR="$(DESTDIR)/" $(pkg_make_vars)

# pkgtrans: write a pkg file stream, shame we cant pipe directly to it from
# pkgmk..
pkg_trans = pkgtrans -s $(abs_builddir) "$(abs_builddir)/$@"

# pkgmk can only cope with a single pkginfo, cant 'stack' various 
# pkginfo template files and a package specific pkginfo file in the prototype
# Create the package specific template here, and create the full pkginfo
# by cating this and the common pkginfo.tmpl together.
pkginfo.tmpl: $(srcdir)/pkginfo.tmpl.in Makefile
	rm -f $@
	$(edit) $< > $@

pkginfo.%.tmpl: $(srcdir)/pkginfo.%.tmpl.in Makefile
	rm -f $@
	$(edit) $< > $@

pkginfo.%.full: pkginfo.%.tmpl pkginfo.tmpl Makefile
	cat pkginfo.tmpl pkginfo.$*.tmpl > $@

# use 'edit' above to transform prototype.in to pkgmk acceptable prototype
prototype.%: $(srcdir)/prototype.%.in Makefile
	rm -f $@
	$(edit) $< > $@

# use edit to construct the SMF manifest files
%.xml: $(srcdir)/%.xml.in Makefile
	rm -f $@
	$(edit) $< > $@
# use edit to construct the depend files
depend.%: $(srcdir)/depend.%.in Makefile
	rm -f $@
	$(edit) $< > $@

# method file (bit like init script)
frr.init: $(srcdir)/frr.init.in Makefile
	rm -f $@
	$(edit) $< > $@

# construct the pkg
$(PACKAGE_TARNAME)-%-$(pkg_name_rev).pkg: prototype.% \
		depend.% frr.init pkginfo.%.full
	($(pkg_make) && \
	$(pkg_trans) "FRR$*")

%.pkg.gz : %.pkg
	(gzip -c $< > $@)

pkg-root-install:
	(cd $(top_builddir) && \
	 $(MAKE) DESTDIR=$(abs_builddir)/frr-root install)

packages: $(pkg_packages)

all-files: $(pkg_pkginfos) pkginfo.tmpl $(pkg_prototypes) \
	$(pkg_manifests) $(pkg_depends) frr.init
