## Process this file with automake to produce Makefile.in.

include ../common.am

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
AM_YFLAGS = -d -Dapi.prefix=@BISON_OPENBRACE@cmd_yy@BISON_CLOSEBRACE@ @BISON_VERBOSE@

command_lex.h: command_lex.c
	@if test ! -f $@; then rm -f command_lex.c; else :; fi
	@if test ! -f $@; then $(MAKE) $(AM_MAKEFLAGS) command_lex.c; else :; fi
command_parse.lo: command_lex.h

lib_LTLIBRARIES = libfrr.la
libfrr_la_LDFLAGS = -version-info 0:0:0 

libfrr_la_SOURCES = \
	network.c pid_output.c getopt.c getopt1.c \
	checksum.c vector.c linklist.c vty.c \
	graph.c command_parse.y command_lex.l command_match.c \
	command_graph.c \
	command.c \
	sockunion.c prefix.c thread.c if.c buffer.c table.c hash.c \
	filter.c routemap.c distribute.c stream.c log.c plist.c \
	zclient.c sockopt.c md5.c if_rmap.c keychain.c privs.c \
	sigevent.c pqueue.c jhash.c workqueue.c nexthop.c json.c \
	ptm_lib.c csv.c bfd.c vrf.c systemd.c ns.c memory.c memory_vty.c \
	imsg-buffer.c imsg.c skiplist.c \
	qobj.c wheel.c \
	event_counter.c \
	grammar_sandbox.c \
	srcdest_table.c \
	spf_backoff.c \
	libfrr.c \
	strlcpy.c \
	strlcat.c \
	sha256.c \
	module.c \
	hook.c \
	frr_pthread.c \
	# end

BUILT_SOURCES = route_types.h gitversion.h command_parse.h command_lex.h

libfrr_la_LIBADD = @LIBCAP@

if SNMP
lib_LTLIBRARIES +=  libfrrsnmp.la
endif

libfrrsnmp_la_CFLAGS = $(WERROR) $(SNMP_CFLAGS)
libfrrsnmp_la_LDFLAGS = -version-info 0:0:0
libfrrsnmp_la_LIBADD = libfrr.la $(SNMP_LIBS)
libfrrsnmp_la_SOURCES = \
	agentx.c \
	smux.c \
	snmp.c \
	#end

pkginclude_HEADERS = \
	frratomic.h \
	buffer.h checksum.h filter.h getopt.h hash.h \
	if.h linklist.h log.h \
	graph.h command_match.h \
	command_graph.h \
	command.h \
	memory.h network.h prefix.h routemap.h distribute.h sockunion.h \
	stream.h table.h thread.h vector.h version.h vty.h zebra.h \
	plist.h zclient.h sockopt.h smux.h md5.h if_rmap.h keychain.h \
	privs.h sigevent.h pqueue.h jhash.h zassert.h \
	workqueue.h route_types.h libospf.h nexthop.h json.h \
	ptm_lib.h csv.h bfd.h vrf.h ns.h systemd.h bitfield.h \
	fifo.h memory_vty.h mpls.h imsg.h openbsd-queue.h openbsd-tree.h \
	skiplist.h qobj.h wheel.h \
	event_counter.h \
	monotime.h \
	spf_backoff.h \
	srcdest_table.h \
	module.h \
	hook.h \
	libfrr.h \
	sha256.h \
	frr_pthread.h \
	vrf_int.h \
	# end

noinst_HEADERS = \
	plist_int.h \
	log_int.h \
	clippy.h

noinst_PROGRAMS = grammar_sandbox clippy

grammar_sandbox_SOURCES = grammar_sandbox_main.c
grammar_sandbox_LDADD = libfrr.la

clippy_SOURCES = \
	defun_lex.l \
	command_parse.y \
	command_lex.l \
	command_graph.c \
	command_py.c \
	memory.c \
	graph.c \
	vector.c \
	clippy.c \
	#end
clippy_CPPFLAGS = -D_GNU_SOURCE
clippy_CFLAGS   = $(PYTHON_CFLAGS)
clippy_LDADD    = $(PYTHON_LIBS)

plist.lo: plist_clippy.c

EXTRA_DIST = \
	queue.h \
	command_lex.h \
	route_types.pl route_types.txt \
	gitversion.pl

route_types.h: $(srcdir)/route_types.txt $(srcdir)/route_types.pl
	@PERL@ $(srcdir)/route_types.pl < $(srcdir)/route_types.txt > $@

if GIT_VERSION

# bit of a trick here to always have up-to-date git stamps without triggering
# unneccessary rebuilds.  .PHONY causes the .tmp file to be rebuilt always,
# but if we use that on gitversion.h it'll ripple through the .c file deps.
# (even if gitversion.h's file timestamp doesn't change, make will think it
# did, because of .PHONY...)

.PHONY: gitversion.h.tmp
.SILENT: gitversion.h gitversion.h.tmp
GITH=gitversion.h
gitversion.h.tmp: $(srcdir)/../.git
	@PERL@ $(srcdir)/gitversion.pl $(srcdir) > ${GITH}.tmp
gitversion.h: gitversion.h.tmp
	{ test -f ${GITH} && diff -s -q ${GITH}.tmp ${GITH}; } || cp -v ${GITH}.tmp ${GITH}

else
.PHONY: gitversion.h
gitversion.h:
	true
endif
