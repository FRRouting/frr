INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

noinst_PROGRAMS = testsig testbuffer testmemory
testsig_SOURCES = test-sig.c
testbuffer_SOURCES = test-buffer.c
testmemory_SOURCES = test-memory.c

testsig_LDADD = ../lib/libzebra.la @LIBCAP@
testbuffer_LDADD = ../lib/libzebra.la @LIBCAP@
testmemory_LDADD = ../lib/libzebra.la @LIBCAP@

