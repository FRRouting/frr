INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)

noinst_PROGRAMS = testsig testbuffer testmemory heavy heavywq heavythread \
		aspathtest testprivs teststream testbgpcap ecommtest \
		testbgpmpattr testchecksum

testsig_SOURCES = test-sig.c
testbuffer_SOURCES = test-buffer.c
testmemory_SOURCES = test-memory.c
testprivs_SOURCES = test-privs.c
teststream_SOURCES = test-stream.c
heavy_SOURCES = heavy.c main.c
heavywq_SOURCES = heavy-wq.c main.c
heavythread_SOURCES = heavy-thread.c main.c
aspathtest_SOURCES = aspath_test.c
testbgpcap_SOURCES = bgp_capability_test.c
ecommtest_SOURCES = ecommunity_test.c
testbgpmpattr_SOURCES =  bgp_mp_attr_test.c
testchecksum_SOURCES = test-checksum.c

testsig_LDADD = ../lib/libzebra.la @LIBCAP@
testbuffer_LDADD = ../lib/libzebra.la @LIBCAP@
testmemory_LDADD = ../lib/libzebra.la @LIBCAP@
testprivs_LDADD = ../lib/libzebra.la @LIBCAP@
teststream_LDADD = ../lib/libzebra.la @LIBCAP@
heavy_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
heavywq_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
heavythread_LDADD = ../lib/libzebra.la @LIBCAP@ -lm
aspathtest_LDADD = ../lib/libzebra.la @LIBCAP@ -lm ../bgpd/libbgp.a
testbgpcap_LDADD = ../lib/libzebra.la @LIBCAP@ -lm ../bgpd/libbgp.a
ecommtest_LDADD = ../lib/libzebra.la @LIBCAP@ -lm ../bgpd/libbgp.a
testbgpmpattr_LDADD = ../lib/libzebra.la @LIBCAP@ -lm ../bgpd/libbgp.a
testchecksum_LDADD = ../lib/libzebra.la @LIBCAP@ 
