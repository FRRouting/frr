## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libzebra.la
libzebra_la_LDFLAGS = -version 0:0:0

libzebra_la_SOURCES = \
	network.c pid_output.c getopt.c getopt1.c daemon.c \
	checksum.c vector.c linklist.c vty.c command.c \
	sockunion.c prefix.c thread.c if.c memory.c buffer.c table.c hash.c \
	filter.c routemap.c distribute.c stream.c str.c log.c plist.c \
	zclient.c sockopt.c smux.c md5.c if_rmap.c keychain.c privs.c \
	sigevent.c pqueue.c jhash.c

libzebra_la_DEPENDENCIES = @LIB_REGEX@

libzebra_la_LIBADD = @LIB_REGEX@

pkginclude_HEADERS = \
	buffer.h command.h filter.h getopt.h hash.h if.h linklist.h log.h \
	memory.h network.h prefix.h routemap.h distribute.h sockunion.h \
	str.h stream.h table.h thread.h vector.h version.h vty.h zebra.h \
	plist.h zclient.h sockopt.h smux.h md5-gnu.h if_rmap.h keychain.h \
	privs.h sigevent.h pqueue.h jhash.h zassert.h

EXTRA_DIST = regex.c regex-gnu.h

