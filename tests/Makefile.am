include ../common.am

PYTHON ?= python

AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS += \
	-I.. \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/tests/helpers/c \
	-I$(top_builddir)/tests/helpers/c \
	-O
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

if BGPD
TESTS_BGPD = \
	bgpd/test_aspath \
	bgpd/test_capability \
	bgpd/test_packet \
	bgpd/test_peer_attr \
	bgpd/test_ecommunity \
	bgpd/test_mp_attr \
	bgpd/test_mpath
else
TESTS_BGPD =
endif

if ISISD
if SOLARIS
TESTS_ISISD =
else
TESTS_ISISD = \
	isisd/test_fuzz_isis_tlv \
	isisd/test_isis_vertex_queue \
	# end
endif
else
TESTS_ISISD =
endif

if OSPF6D
TESTS_OSPF6D = \
	ospf6d/test_lsdb \
	# end
else
TESTS_OSPF6D =
endif

if ENABLE_BGP_VNC
BGP_VNC_RFP_LIB=@top_builddir@/$(LIBRFP)/librfp.a
else
BGP_VNC_RFP_LIB =
endif

lib/cli/test_cli.o: lib/cli/test_cli_clippy.c
ospf6d/test_lsdb.o: ospf6d/test_lsdb_clippy.c

check_PROGRAMS = \
	lib/test_buffer \
	lib/test_checksum \
	lib/test_heavy_thread \
	lib/test_heavy_wq \
	lib/test_heavy \
	lib/test_memory \
	lib/test_nexthop_iter \
	lib/test_privs \
	lib/test_ringbuf \
	lib/test_srcdest_table \
	lib/test_segv \
	lib/test_sig \
	lib/test_stream \
	lib/test_table \
	lib/test_timer_correctness \
	lib/test_timer_performance \
	lib/test_ttable \
	lib/test_zlog \
	lib/test_graph \
	lib/cli/test_cli \
	lib/cli/test_commands \
	$(TESTS_BGPD) \
	$(TESTS_ISISD) \
	$(TESTS_OSPF6D) \
	# end

if ZEROMQ
check_PROGRAMS += \
	lib/test_zmq \
	# end
endif

../vtysh/vtysh_cmd.c:
	$(MAKE) -C ../vtysh vtysh_cmd.c

lib/cli/test_commands_defun.c: ../vtysh/vtysh_cmd.c
	sed \
		-e 's/"vtysh\.h"/"tests.h"/' \
		-e 's/vtysh_init_cmd/test_init_cmd/' \
		-e 's/VTYSH_[A-Z][A-Z_0-9]*/0/g' \
		< ../vtysh/vtysh_cmd.c \
		> "$@"

isisd/test_fuzz_isis_tlv_tests.h: $(top_srcdir)/tests/isisd/test_fuzz_isis_tlv_tests.h.gz
	gzip -d < $(top_srcdir)/tests/isisd/test_fuzz_isis_tlv_tests.h.gz > "$@"

noinst_HEADERS = \
	./helpers/c/prng.h \
	./helpers/c/tests.h \
	./lib/cli/common_cli.h

lib_test_buffer_SOURCES = lib/test_buffer.c
lib_test_checksum_SOURCES = lib/test_checksum.c
lib_test_heavy_thread_SOURCES = lib/test_heavy_thread.c helpers/c/main.c
lib_test_heavy_wq_SOURCES = lib/test_heavy_wq.c helpers/c/main.c
lib_test_heavy_SOURCES = lib/test_heavy.c helpers/c/main.c
lib_test_memory_SOURCES = lib/test_memory.c
lib_test_nexthop_iter_SOURCES = lib/test_nexthop_iter.c helpers/c/prng.c
lib_test_privs_SOURCES = lib/test_privs.c
lib_test_ringbuf_SOURCES = lib/test_ringbuf.c
lib_test_srcdest_table_SOURCES = lib/test_srcdest_table.c \
                                 helpers/c/prng.c
lib_test_segv_SOURCES = lib/test_segv.c
lib_test_sig_SOURCES = lib/test_sig.c
lib_test_stream_SOURCES = lib/test_stream.c
lib_test_table_SOURCES = lib/test_table.c
lib_test_timer_correctness_SOURCES = lib/test_timer_correctness.c \
                                     helpers/c/prng.c
lib_test_timer_performance_SOURCES = lib/test_timer_performance.c \
                                     helpers/c/prng.c
lib_test_ttable_SOURCES = lib/test_ttable.c
lib_test_zlog_SOURCES = lib/test_zlog.c
lib_test_graph_SOURCES = lib/test_graph.c
lib_test_zmq_SOURCES = lib/test_zmq.c
lib_test_zmq_CFLAGS = $(AM_CFLAGS) $(ZEROMQ_CFLAGS)
lib_cli_test_cli_SOURCES = lib/cli/test_cli.c lib/cli/common_cli.c
lib_cli_test_commands_SOURCES = lib/cli/test_commands_defun.c \
                                lib/cli/test_commands.c \
                                helpers/c/prng.c
bgpd_test_aspath_SOURCES = bgpd/test_aspath.c
bgpd_test_capability_SOURCES = bgpd/test_capability.c
bgpd_test_packet_SOURCES = bgpd/test_packet.c
bgpd_test_peer_attr_SOURCES = bgpd/test_peer_attr.c
bgpd_test_ecommunity_SOURCES = bgpd/test_ecommunity.c
bgpd_test_mp_attr_SOURCES = bgpd/test_mp_attr.c
bgpd_test_mpath_SOURCES = bgpd/test_mpath.c
isisd_test_fuzz_isis_tlv_SOURCES = isisd/test_fuzz_isis_tlv.c
nodist_isisd_test_fuzz_isis_tlv_SOURCES = isisd/test_fuzz_isis_tlv_tests.h
BUILT_SOURCES=isisd/test_fuzz_isis_tlv_tests.h
CLEANFILES=isisd/test_fuzz_isis_tlv_tests.h
isisd_test_fuzz_isis_tlv_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_builddir)/tests/isisd
isisd_test_isis_vertex_queue_SOURCES = isisd/test_isis_vertex_queue.c

ospf6d_test_lsdb_SOURCES = ospf6d/test_lsdb.c lib/cli/common_cli.c

ALL_TESTS_LDADD = ../lib/libfrr.la @LIBCAP@
BGP_TEST_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) $(ALL_TESTS_LDADD) -lm
ISISD_TEST_LDADD = ../isisd/libisis.a $(ALL_TESTS_LDADD)
OSPF6_TEST_LDADD = ../ospf6d/libospf6.a $(ALL_TESTS_LDADD)

lib_test_buffer_LDADD = $(ALL_TESTS_LDADD)
lib_test_checksum_LDADD = $(ALL_TESTS_LDADD)
lib_test_heavy_thread_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_heavy_wq_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_heavy_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_memory_LDADD = $(ALL_TESTS_LDADD)
lib_test_nexthop_iter_LDADD = $(ALL_TESTS_LDADD)
lib_test_privs_LDADD = $(ALL_TESTS_LDADD)
lib_test_ringbuf_LDADD = $(ALL_TESTS_LDADD)
lib_test_srcdest_table_LDADD = $(ALL_TESTS_LDADD)
lib_test_segv_LDADD = $(ALL_TESTS_LDADD)
lib_test_sig_LDADD = $(ALL_TESTS_LDADD)
lib_test_stream_LDADD = $(ALL_TESTS_LDADD)
lib_test_table_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_timer_correctness_LDADD = $(ALL_TESTS_LDADD)
lib_test_timer_performance_LDADD = $(ALL_TESTS_LDADD)
lib_test_ttable_LDADD = $(ALL_TESTS_LDADD)
lib_test_zlog_LDADD = $(ALL_TESTS_LDADD)
lib_test_graph_LDADD = $(ALL_TESTS_LDADD)
lib_test_zmq_LDADD = ../lib/libfrrzmq.la $(ALL_TESTS_LDADD) $(ZEROMQ_LIBS)
lib_cli_test_cli_LDADD = $(ALL_TESTS_LDADD)
lib_cli_test_commands_LDADD = $(ALL_TESTS_LDADD)
bgpd_test_aspath_LDADD = $(BGP_TEST_LDADD)
bgpd_test_capability_LDADD = $(BGP_TEST_LDADD)
bgpd_test_packet_LDADD = $(BGP_TEST_LDADD)
bgpd_test_peer_attr_LDADD = $(BGP_TEST_LDADD)
bgpd_test_ecommunity_LDADD = $(BGP_TEST_LDADD)
bgpd_test_mp_attr_LDADD = $(BGP_TEST_LDADD)
bgpd_test_mpath_LDADD = $(BGP_TEST_LDADD)
isisd_test_fuzz_isis_tlv_LDADD = $(ISISD_TEST_LDADD)
isisd_test_isis_vertex_queue_LDADD = $(ISISD_TEST_LDADD)
ospf6d_test_lsdb_LDADD = $(OSPF6_TEST_LDADD)

EXTRA_DIST = \
    runtests.py \
    bgpd/test_aspath.py \
    bgpd/test_capability.py \
    bgpd/test_ecommunity.py \
    bgpd/test_mp_attr.py \
    bgpd/test_mpath.py \
	bgpd/test_peer_attr.py \
    helpers/python/frrsix.py \
    helpers/python/frrtest.py \
    isisd/test_fuzz_isis_tlv.py \
    isisd/test_fuzz_isis_tlv_tests.h.gz \
    isisd/test_isis_vertex_queue.py \
    lib/cli/test_commands.in \
    lib/cli/test_commands.py \
    lib/cli/test_commands.refout \
    lib/cli/test_cli.in \
    lib/cli/test_cli.py \
    lib/cli/test_cli.refout \
    lib/test_nexthop_iter.py \
    lib/test_ringbuf.py \
    lib/test_srcdest_table.py \
    lib/test_stream.py \
    lib/test_stream.refout \
    lib/test_table.py \
    lib/test_timer_correctness.py \
    lib/test_ttable.py \
    lib/test_ttable.refout \
    lib/test_zlog.py \
    lib/test_graph.py \
    lib/test_graph.refout \
    ospf6d/test_lsdb.py \
    ospf6d/test_lsdb.in \
    ospf6d/test_lsdb.refout \
    # end

.PHONY: tests.xml
tests.xml: $(check_PROGRAMS)
	$(PYTHON) $(srcdir)/runtests.py --junitxml=$@ -v $(srcdir)
check: tests.xml
