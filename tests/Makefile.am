INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

noinst_PROGRAMS = testsig
testsig_SOURCES = test-sig.c

testsig_LDADD = ../lib/libzebra.la @LIBCAP@


