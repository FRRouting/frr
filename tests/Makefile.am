AUTOMAKE_OPTIONS    = dejagnu
DEJATOOL = libfrr

SUBDIRS = \
	bgpd.tests \
	libfrr.tests

EXTRA_DIST = \
	config/unix.exp \
	lib/bgpd.exp \
	lib/libfrr.exp \
	global-conf.exp \
	testcommands.in \
	testcommands.refout \
	testcli.in \
	testcli.refout

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

if BGPD
TESTS_BGPD = aspathtest testbgpcap ecommtest testbgpmpattr testbgpmpath
DEJATOOL += bgpd
else
TESTS_BGPD =
endif

if ENABLE_BGP_VNC
BGP_VNC_RFP_LIB=@top_builddir@/$(LIBRFP)/librfp.a 
else
BGP_VNC_RFP_LIB =
endif

check_PROGRAMS = testsig testsegv testbuffer testmemory heavy heavywq heavythread \
		testprivs teststream testchecksum tabletest testnexthopiter \
		testcommands test-timer-correctness test-timer-performance \
		testcli \
		test-srcdest-table \
		$(TESTS_BGPD)

../vtysh/vtysh_cmd.c:
	$(MAKE) -C ../vtysh vtysh_cmd.c

test-commands-defun.c: ../vtysh/vtysh_cmd.c
	sed \
		-e 's/"vtysh\.h"/"tests.h"/' \
		-e 's/vtysh_init_cmd/test_init_cmd/' \
		-e 's/VTYSH_[A-Z][A-Z_0-9]*/0/g' \
		< ../vtysh/vtysh_cmd.c \
		> test-commands-defun.c

BUILT_SOURCES = test-commands-defun.c
noinst_HEADERS = prng.h tests.h common-cli.h

testcli_SOURCES = test-cli.c common-cli.c
testsig_SOURCES = test-sig.c
testsegv_SOURCES = test-segv.c
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
testbgpmpath_SOURCES = bgp_mpath_test.c
tabletest_SOURCES = table_test.c
testnexthopiter_SOURCES = test-nexthop-iter.c prng.c
testcommands_SOURCES = test-commands-defun.c test-commands.c prng.c
test_timer_correctness_SOURCES = test-timer-correctness.c prng.c
test_timer_performance_SOURCES = test-timer-performance.c prng.c
test_srcdest_table_SOURCES = test-srcdest-table.c prng.c

testcli_LDADD = ../lib/libfrr.la @LIBCAP@
testsig_LDADD = ../lib/libfrr.la @LIBCAP@
testsegv_LDADD = ../lib/libfrr.la @LIBCAP@
testbuffer_LDADD = ../lib/libfrr.la @LIBCAP@
testmemory_LDADD = ../lib/libfrr.la @LIBCAP@
testprivs_LDADD = ../lib/libfrr.la @LIBCAP@
teststream_LDADD = ../lib/libfrr.la @LIBCAP@
heavy_LDADD = ../lib/libfrr.la @LIBCAP@ -lm
heavywq_LDADD = ../lib/libfrr.la @LIBCAP@ -lm
heavythread_LDADD = ../lib/libfrr.la @LIBCAP@ -lm
aspathtest_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ -lm
testbgpcap_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ -lm
ecommtest_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ -lm
testbgpmpattr_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ -lm
testchecksum_LDADD = ../lib/libfrr.la @LIBCAP@ 
testbgpmpath_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ -lm
tabletest_LDADD = ../lib/libfrr.la @LIBCAP@ -lm
testnexthopiter_LDADD = ../lib/libfrr.la @LIBCAP@
testcommands_LDADD = ../lib/libfrr.la @LIBCAP@
test_timer_correctness_LDADD = ../lib/libfrr.la @LIBCAP@
test_timer_performance_LDADD = ../lib/libfrr.la @LIBCAP@
test_srcdest_table_LDADD = ../lib/libfrr.la @LIBCAP@
