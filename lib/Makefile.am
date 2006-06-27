## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib @SNMP_INCLUDES@
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libzebra.la
libzebra_la_LDFLAGS = -version-info 0:0:0 

libzebra_la_SOURCES = \
	network.c pid_output.c getopt.c getopt1.c daemon.c \
	checksum.c vector.c linklist.c vty.c command.c \
	sockunion.c prefix.c thread.c if.c memory.c buffer.c table.c hash.c \
	filter.c routemap.c distribute.c stream.c str.c log.c plist.c \
	zclient.c sockopt.c smux.c md5.c if_rmap.c keychain.c privs.c \
	sigevent.c pqueue.c jhash.c memtypes.c workqueue.c

BUILT_SOURCES = memtypes.h route_types.h

libzebra_la_DEPENDENCIES = @LIB_REGEX@

libzebra_la_LIBADD = @LIB_REGEX@

pkginclude_HEADERS = \
	buffer.h checksum.h command.h filter.h getopt.h hash.h \
	if.h linklist.h log.h \
	memory.h network.h prefix.h routemap.h distribute.h sockunion.h \
	str.h stream.h table.h thread.h vector.h version.h vty.h zebra.h \
	plist.h zclient.h sockopt.h smux.h md5.h if_rmap.h keychain.h \
	privs.h sigevent.h pqueue.h jhash.h zassert.h memtypes.h \
	workqueue.h route_types.h

EXTRA_DIST = regex.c regex-gnu.h memtypes.awk route_types.awk route_types.txt

memtypes.h: $(srcdir)/memtypes.c $(srcdir)/memtypes.awk
	($(GAWK) -f $(srcdir)/memtypes.awk $(srcdir)/memtypes.c > $@)

route_types.h: $(srcdir)/route_types.txt $(srcdir)/route_types.awk
	($(GAWK) -f $(srcdir)/route_types.awk $(srcdir)/route_types.txt > $@)
