INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

noinst_PROGRAMS = testsig testbuffer testmemory heavy heavywq heavythread
testsig_SOURCES = test-sig.c
testbuffer_SOURCES = test-buffer.c
testmemory_SOURCES = test-memory.c
heavy_SOURCES = heavy.c main.c
heavywq_SOURCES = heavy-wq.c main.c
heavythread_SOURCES = heavy-thread.c main.c

testsig_LDADD = ../lib/libzebra.la @LIBCAP@
testbuffer_LDADD = ../lib/libzebra.la @LIBCAP@
testmemory_LDADD = ../lib/libzebra.la @LIBCAP@
heavy_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
heavywq_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
heavythread_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
