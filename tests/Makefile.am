AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS = \
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
	bgpd/test_ecommunity \
	bgpd/test_mp_attr \
	bgpd/test_mpath
else
TESTS_BGPD =
endif

if ENABLE_BGP_VNC
BGP_VNC_RFP_LIB=@top_builddir@/$(LIBRFP)/librfp.a
else
BGP_VNC_RFP_LIB =
endif

check_PROGRAMS = \
	lib/test_buffer \
	lib/test_checksum \
	lib/test_heavy_thread \
	lib/test_heavy_wq \
	lib/test_heavy \
	lib/test_memory \
	lib/test_nexthop_iter \
	lib/test_privs \
	lib/test_segv \
	lib/test_sig \
	lib/test_stream \
	lib/test_table \
	lib/test_timer_correctness \
	lib/test_timer_performance \
	lib/cli/test_cli \
	lib/cli/test_commands \
	$(TESTS_BGPD)

../vtysh/vtysh_cmd.c:
	$(MAKE) -C ../vtysh vtysh_cmd.c

lib/cli/test_commands_defun.c: ../vtysh/vtysh_cmd.c
	sed \
		-e 's/"vtysh\.h"/"tests.h"/' \
		-e 's/vtysh_init_cmd/test_init_cmd/' \
		-e 's/VTYSH_[A-Z][A-Z_0-9]*/0/g' \
		< ../vtysh/vtysh_cmd.c \
		> "$@"

BUILT_SOURCES = lib/cli/test_commands_defun.c

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
lib_test_segv_SOURCES = lib/test_segv.c
lib_test_sig_SOURCES = lib/test_sig.c
lib_test_stream_SOURCES = lib/test_stream.c
lib_test_table_SOURCES = lib/test_table.c
lib_test_timer_correctness_SOURCES = lib/test_timer_correctness.c \
                                     helpers/c/prng.c
lib_test_timer_performance_SOURCES = lib/test_timer_performance.c \
                                     helpers/c/prng.c
lib_cli_test_cli_SOURCES = lib/cli/test_cli.c lib/cli/common_cli.c
lib_cli_test_commands_SOURCES = lib/cli/test_commands_defun.c \
                                lib/cli/test_commands.c \
                                helpers/c/prng.c
bgpd_test_aspath_SOURCES = bgpd/test_aspath.c
bgpd_test_capability_SOURCES = bgpd/test_capability.c
bgpd_test_ecommunity_SOURCES = bgpd/test_ecommunity.c
bgpd_test_mp_attr_SOURCES = bgpd/test_mp_attr.c
bgpd_test_mpath_SOURCES = bgpd/test_mpath.c

ALL_TESTS_LDADD = ../lib/libfrr.la @LIBCAP@
BGP_TEST_LDADD = ../bgpd/libbgp.a $(BGP_VNC_RFP_LIB) $(ALL_TESTS_LDADD) -lm

lib_test_buffer_LDADD = $(ALL_TESTS_LDADD)
lib_test_checksum_LDADD = $(ALL_TESTS_LDADD)
lib_test_heavy_thread_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_heavy_wq_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_heavy_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_memory_LDADD = $(ALL_TESTS_LDADD)
lib_test_nexthop_iter_LDADD = $(ALL_TESTS_LDADD)
lib_test_privs_LDADD = $(ALL_TESTS_LDADD)
lib_test_segv_LDADD = $(ALL_TESTS_LDADD)
lib_test_sig_LDADD = $(ALL_TESTS_LDADD)
lib_test_stream_LDADD = $(ALL_TESTS_LDADD)
lib_test_table_LDADD = $(ALL_TESTS_LDADD) -lm
lib_test_timer_correctness_LDADD = $(ALL_TESTS_LDADD)
lib_test_timer_performance_LDADD = $(ALL_TESTS_LDADD)
lib_cli_test_cli_LDADD = $(ALL_TESTS_LDADD)
lib_cli_test_commands_LDADD = $(ALL_TESTS_LDADD)
bgpd_test_aspath_LDADD = $(BGP_TEST_LDADD)
bgpd_test_capability_LDADD = $(BGP_TEST_LDADD)
bgpd_test_ecommunity_LDADD = $(BGP_TEST_LDADD)
bgpd_test_mp_attr_LDADD = $(BGP_TEST_LDADD)
bgpd_test_mpath_LDADD = $(BGP_TEST_LDADD)
