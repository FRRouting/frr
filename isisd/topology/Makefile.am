## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

noinst_LIBRARIES = libtopology.a

libtopology_a_SOURCES = \
	spgrid.c

libtopology_a_DEPENDENCIES = @LIB_REGEX@

libtopology_a_LIBADD = @LIB_REGEX@ ../../lib/libzebra.la

noinst_HEADERS = \
	spgrid.h

EXTRA_DIST = regex.c regex-gnu.h

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

## File dependency.
