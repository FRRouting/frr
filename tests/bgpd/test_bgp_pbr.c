// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Flowspec PBR: debug dump of a policy-route filter.
 *
 * bgp_pbr_dump_entry() runs with "debug bgp zebra" for every Flowspec
 * policy route installed or removed. It builds the match description in a
 * fixed buffer from peer-supplied values (ports, packet length, TCP flags,
 * DSCP, flow label); the description must never overrun that buffer and
 * must show every field.
 *
 * bgp_pbr.c is included so the static function can be called directly, and
 * zlog_debug() is redirected to capture the message. Each case runs in a
 * child process so that a crash fails only that case.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "prefix.h"
#include "zclient.h"
#include "jhash.h"
#include "pbr.h"
#include "lib/printfrr.h"
#include "lib/lib_errors.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_errors.h"

static char captured[512];

static void test_zlog_debug(const char *fmt, ...) PRINTFRR(1, 2);
static void test_zlog_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintfrr(captured, sizeof(captured), fmt, ap);
	va_end(ap);
}

#undef zlog_debug
#define zlog_debug test_zlog_debug
#include "bgpd/bgp_pbr.c"
#undef zlog_debug

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11
#define EXIT_BAD_ROW  12

struct range {
	bool set;
	uint16_t min, max;
};

struct valmask {
	bool set;
	uint16_t val, mask;
};

struct tcase {
	const char *description;
	enum kind kind;
	bool null_filter;
	bool add;
	const char *src;
	uint8_t protocol;
	struct range src_port, dst_port, pkt_len;
	struct valmask tcp_flags, dscp, flow_label, pkt_len_val;
	/* expected protocol text and match text; the match text is the part
	 * built in the 64-byte buffer, and match_len is its length
	 */
	const char *proto;
	const char *match;
	size_t match_len;
};

/* 52 characters: TCP source, destination and packet length ranges */
#define RANGES_52 "from [65535:65535]to [65535:65535] len [65535:65535]"
/* 51 characters: the same with a 4-digit packet length minimum */
#define RANGES_51 "from [65535:65535]to [65535:65535] len [6553:65535]"

static const struct tcase tcases[] = {
	{ .description = "TCP source and destination port ranges",
	  .kind = POSITIVE,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 80, 80 },
	  .dst_port = { true, 1024, 2048 },
	  .proto = "proto 6",
	  .match = "from [80:80]to [1024:2048]",
	  .match_len = 26 },
	{ .description = "ICMP type and code",
	  .kind = POSITIVE,
	  .add = true,
	  .protocol = IPPROTO_ICMP,
	  .src_port = { true, 8, 0 },
	  .dst_port = { true, 0, 0 },
	  .proto = "proto 1",
	  .match = "type 8, code 0",
	  .match_len = 14 },
	{ .description = "UDP packet length range",
	  .kind = POSITIVE,
	  .add = true,
	  .protocol = IPPROTO_UDP,
	  .pkt_len = { true, 64, 1500 },
	  .proto = "proto 17",
	  .match = " len [64:1500]",
	  .match_len = 14 },
	{ .description = "DSCP and flow label are both shown",
	  .kind = POSITIVE,
	  .add = true,
	  .dscp = { true, 10, 0 },
	  .flow_label = { true, 5, 1 },
	  .proto = "",
	  .match = " dscp 10! flow_label 5",
	  .match_len = 22 },
	{ .description = "negated packet length value",
	  .kind = NEGATIVE,
	  .add = true,
	  .protocol = IPPROTO_UDP,
	  .pkt_len_val = { true, 1500, 1 },
	  .proto = "proto 17",
	  .match = " ! len 1500",
	  .match_len = 11 },
	{ .description = "ports are not shown for a protocol other than TCP, UDP or ICMP",
	  .kind = NEGATIVE,
	  .add = true,
	  .protocol = IPPROTO_GRE,
	  .src_port = { true, 80, 80 },
	  .proto = "proto 47",
	  .match = "",
	  .match_len = 0 },
	{ .description = "NULL filter logs nothing", .kind = NEGATIVE, .null_filter = true },
	{ .description = "63-character match text fits",
	  .kind = BOUNDARY,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 65535, 65535 },
	  .dst_port = { true, 65535, 65535 },
	  .pkt_len = { true, 6553, 65535 },
	  .tcp_flags = { true, 1, 1 },
	  .proto = "proto 6",
	  .match = RANGES_51 "tcpflags 1/1",
	  .match_len = 63 },
	{ .description = "64-character match text is not truncated",
	  .kind = BOUNDARY,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 65535, 65535 },
	  .dst_port = { true, 65535, 65535 },
	  .pkt_len = { true, 65535, 65535 },
	  .tcp_flags = { true, 1, 1 },
	  .proto = "proto 6",
	  .match = RANGES_52 "tcpflags 1/1",
	  .match_len = 64 },
	{ .description = "64-character match text followed by DSCP",
	  .kind = BOUNDARY,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 65535, 65535 },
	  .dst_port = { true, 65535, 65535 },
	  .pkt_len = { true, 65535, 65535 },
	  .tcp_flags = { true, 1, 1 },
	  .dscp = { true, 46, 0 },
	  .proto = "proto 6",
	  .match = RANGES_52 "tcpflags 1/1 dscp 46",
	  .match_len = 72 },
	{ .description = "65-character match text followed by DSCP",
	  .kind = BOUNDARY,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 65535, 65535 },
	  .dst_port = { true, 65535, 65535 },
	  .pkt_len = { true, 65535, 65535 },
	  .tcp_flags = { true, 16, 1 },
	  .dscp = { true, 46, 0 },
	  .proto = "proto 6",
	  .match = RANGES_52 "tcpflags 10/1 dscp 46",
	  .match_len = 73 },
	{ .description = "every field at its maximum gives the longest match text",
	  .kind = BOUNDARY,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 65535, 65535 },
	  .dst_port = { true, 65535, 65535 },
	  .pkt_len = { true, 65535, 65535 },
	  .tcp_flags = { true, 0xffff, 0xffff },
	  .dscp = { true, 65535, 1 },
	  .flow_label = { true, 65535, 1 },
	  .proto = "proto 6",
	  .match = RANGES_52 "tcpflags ffff/ffff! dscp 65535! flow_label 65535",
	  .match_len = 100 },
	{ .description = "default route source prefix /0",
	  .kind = BOUNDARY,
	  .add = true,
	  .src = "0.0.0.0/0",
	  .proto = "",
	  .match = "",
	  .match_len = 0 },
	{ .description = "host source prefix /32",
	  .kind = BOUNDARY,
	  .add = true,
	  .src = "192.0.2.1/32",
	  .proto = "",
	  .match = "",
	  .match_len = 0 },
	{ .description = "TCP flags set the protocol to TCP",
	  .kind = CORNER,
	  .add = true,
	  .tcp_flags = { true, 2, 2 },
	  .proto = "proto 6",
	  .match = "tcpflags 2/2",
	  .match_len = 12 },
	{ .description = "port range with max 0 shows min twice",
	  .kind = CORNER,
	  .add = true,
	  .protocol = IPPROTO_TCP,
	  .src_port = { true, 22, 0 },
	  .proto = "proto 6",
	  .match = "from [22:22]",
	  .match_len = 12 },
	{ .description = "removal with a source prefix and no match fields",
	  .kind = CORNER,
	  .add = false,
	  .src = "10.0.0.0/8",
	  .proto = "",
	  .match = "",
	  .match_len = 0 },
	{ .description = "IPv6 source prefix",
	  .kind = CORNER,
	  .add = true,
	  .src = "2001:db8::/32",
	  .proto = "",
	  .match = "",
	  .match_len = 0 },
};

static struct bgp_pbr_range_port *set_range(const struct range *r, struct bgp_pbr_range_port *out)
{
	if (!r->set)
		return NULL;
	out->min_port = r->min;
	out->max_port = r->max;
	return out;
}

static struct bgp_pbr_val_mask *set_valmask(const struct valmask *v, struct bgp_pbr_val_mask *out)
{
	if (!v->set)
		return NULL;
	out->val = v->val;
	out->mask = v->mask;
	return out;
}

/* the whole log line the case should produce ("" when nothing is logged) */
static void expected_line(const struct tcase *tc, char *buf, size_t size)
{
	if (tc->null_filter) {
		buf[0] = '\0';
		return;
	}
	snprintfrr(buf, size, "BGP: %s FS PBR from %s to <all>, %s %s",
		   tc->add ? "adding" : "removing", tc->src ? tc->src : "<all>", tc->proto,
		   tc->match);
}

static int run_case(const struct tcase *tc)
{
	struct bgp_pbr_filter bpf = {};
	struct bgp_pbr_range_port src_port, dst_port, pkt_len;
	struct bgp_pbr_val_mask tcp_flags, dscp, flow_label, pkt_len_val;
	struct prefix src;
	char expected[512];

	bpf.protocol = tc->protocol;
	if (tc->src) {
		if (!str2prefix(tc->src, &src))
			return EXIT_BAD_ROW;
		bpf.src = &src;
	}
	bpf.src_port = set_range(&tc->src_port, &src_port);
	bpf.dst_port = set_range(&tc->dst_port, &dst_port);
	bpf.pkt_len = set_range(&tc->pkt_len, &pkt_len);
	bpf.tcp_flags = set_valmask(&tc->tcp_flags, &tcp_flags);
	bpf.dscp = set_valmask(&tc->dscp, &dscp);
	bpf.flow_label = set_valmask(&tc->flow_label, &flow_label);
	bpf.pkt_len_val = set_valmask(&tc->pkt_len_val, &pkt_len_val);

	captured[0] = '\0';
	bgp_pbr_dump_entry(tc->null_filter ? NULL : &bpf, tc->add);

	expected_line(tc, expected, sizeof(expected));
	printf("    got: \"%s\"\n", captured);
	return strcmp(captured, expected) ? EXIT_MISMATCH : EXIT_MATCH;
}

/* waitpid(), retried if a signal interrupts it */
static int wait_child(pid_t pid, int *status)
{
	int rc;

	do {
		rc = waitpid(pid, status, 0);
	} while (rc < 0 && errno == EINTR);
	return rc;
}

int main(int argc, char **argv)
{
	int failures = 0;

	printf("BGP Flowspec PBR dump tests\n\n");

	for (size_t i = 0; i < array_size(tcases); i++) {
		const struct tcase *tc = &tcases[i];
		char expected[512], why[600] = "";
		int status;
		pid_t pid;

		/* the table states each match text length; check it is right */
		if (tc->match && strlen(tc->match) != tc->match_len) {
			printf("[%-8s] %s ... failed (table: match length %zu, not %zu)\n",
			       kind2str[tc->kind], tc->description, strlen(tc->match),
			       tc->match_len);
			failures++;
			continue;
		}

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		if (pid < 0)
			snprintfrr(why, sizeof(why), " (fork failed: %m)");
		else if (wait_child(pid, &status) < 0)
			snprintfrr(why, sizeof(why), " (waitpid failed: %m)");
		else if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH) {
			expected_line(tc, expected, sizeof(expected));
			snprintfrr(why, sizeof(why), " (expected \"%s\")", expected);
		} else if (WEXITSTATUS(status) == EXIT_BAD_ROW)
			snprintfrr(why, sizeof(why), " (table: bad source prefix \"%s\")", tc->src);
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}

	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
