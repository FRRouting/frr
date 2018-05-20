# This is necessary to support VPATH builds.
srcdir = @srcdir@
VPATH = @srcdir@

# This variable is used as the documentation source location in frr-sphinx.mk
SOURCESDIR = @srcdir@

include @srcdir@/../frr-sphinx.mk

# -----------------------------------------------------------------------------
# Automake requires that 3rd-party Makefiles recognize these targets.
# -----------------------------------------------------------------------------
# install
# install-data
# install-exec
# uninstall
# install-dvi
# install-html
# install-info
# install-ps
# install-pdf
# installdirs
# check
# installcheck
# mostlyclean
# clean
# distclean
# maintainer-clean
# dvi
# pdf
# ps
# info
# html
# tags
# ctags

# When building 'all', the logic is that we want to make docs that are easily
# readable by the person that just built them. Technically the reST source is
# readable in its own right, but we'll also build info and html because those
# offer sequentially better reading experiences. PDF is not built by default
# because it takes quite a while.
all: info

# info and html already have built-in sphinx rules; pdf goes to latexpdf
pdf: latexpdf

# install user manual as info file
install-info: info
	install -d ${DESTDIR}${infodir}
	gzip < _build/texinfo/frr.info > ${DESTDIR}${infodir}/frr.info.gz
	install-info _build/texinfo/frr.info ${DESTDIR}${infodir}/dir

install-data: install-info

install: install-data
