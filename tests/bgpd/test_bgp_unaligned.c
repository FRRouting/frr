// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IPv4 addresses read from unaligned BGP wire data.
 *
 * Copyright (C) 2026 Dave Seddon
 *
 * Extended communities and the CLUSTER_LIST attribute carry IPv4 addresses
 * at arbitrary byte offsets. Casting such a pointer to struct in_addr * and
 * loading through it is undefined behaviour, and faults on CPUs that need
 * aligned loads. These rows check the decoded values and, under
 * -fsanitize=alignment (as in FRR's --enable-undefined-sanitizer builds),
 * fail on any misaligned load.
 *
 *  - ECOM_STR:   display string of an extended community
 *  - ECOM_MATCH: ecommunity_node_target_match() against a local ID
 *  - CLUSTER:    bgp_attr_parse() of an iBGP UPDATE with CLUSTER_LIST at a
 *                chosen stream offset; the parsed list must match. Long
 *                lists (.ids) are generated and use the extended length
 *                flag above 255 octets.
 *
 * Each case runs in a child process so that a sanitizer abort or a crash
 * fails only that case.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "filter.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"

/*
 * UBSan recovers from errors unless built with -fno-sanitize-recover, and
 * a child that recovers would still exit with EXIT_MATCH. Make the first
 * error fatal so a misaligned load fails its case. UBSAN_OPTIONS can still
 * override this.
 */
const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

enum op { ECOM_STR, ECOM_MATCH, CLUSTER };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define MAX_VALUE 16
#define MAX_IDS	  128

struct tcase {
	const char *description;
	enum kind kind;
	enum op op;
	/* ECOM_*: extended community values; CLUSTER: CLUSTER_LIST value */
	uint8_t value[MAX_VALUE];
	size_t len;
	size_t ids;	      /* CLUSTER: generate this many cluster IDs instead */
	const char *local_id; /* ECOM_MATCH */
	size_t offset;	      /* CLUSTER: stream offset of the attributes */
	/* expected */
	const char *str;	       /* ECOM_STR */
	bool match;		       /* ECOM_MATCH */
	enum bgp_attr_parse_ret parse; /* CLUSTER */
};

/*
 * Extended community values: type 0x01, then sub-type 0x09 (Node Target,
 * IPv4 address, 2 reserved octets) or 0x02 (IPv4 Route Target, IPv4
 * address, 2-octet local administrator).
 */

/*
 * ORIGIN igp, AS_PATH 65000, NEXT_HOP, LOCAL_PREF: 27 octets, then the
 * CLUSTER_LIST header (3 octets), so its value starts at offset + 30.
 */
static const uint8_t ibgp_attrs[] = {
	0x40, 0x01, 0x01, 0x00,				      /* ORIGIN igp */
	0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, /* AS_PATH 65000 */
	0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02,	      /* NEXT_HOP */
	0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64,	      /* LOCAL_PREF */
};

static const struct tcase tcases[] = {
	{ .description = "route target is displayed",
	  .kind = POSITIVE,
	  .op = ECOM_STR,
	  .value = { 0x01, 0x02, 10, 0, 0, 1, 0x00, 5 },
	  .len = 8,
	  .str = "RT:10.0.0.1:5" },
	{ .description = "node target is displayed",
	  .kind = POSITIVE,
	  .op = ECOM_STR,
	  .value = { 0x01, 0x09, 10, 0, 0, 1, 0x00, 0x00 },
	  .len = 8,
	  .str = "NT:10.0.0.1" },
	{ .description = "node target matches the local ID",
	  .kind = POSITIVE,
	  .op = ECOM_MATCH,
	  .value = { 0x01, 0x09, 10, 0, 0, 1, 0x00, 0x00 },
	  .len = 8,
	  .local_id = "10.0.0.1",
	  .match = true },
	{ .description = "node target does not match another ID",
	  .kind = NEGATIVE,
	  .op = ECOM_MATCH,
	  .value = { 0x01, 0x09, 10, 0, 0, 1, 0x00, 0x00 },
	  .len = 8,
	  .local_id = "10.0.0.2",
	  .match = false },
	{ .description = "route target is not a node target match",
	  .kind = NEGATIVE,
	  .op = ECOM_MATCH,
	  .value = { 0x01, 0x02, 10, 0, 0, 1, 0x00, 0x00 },
	  .len = 8,
	  .local_id = "10.0.0.1",
	  .match = false },
	{ .description = "node target 255.255.255.255 is displayed",
	  .kind = BOUNDARY,
	  .op = ECOM_STR,
	  .value = { 0x01, 0x09, 255, 255, 255, 255, 0x00, 0x00 },
	  .len = 8,
	  .str = "NT:255.255.255.255" },
	{ .description = "second node target matches the local ID",
	  .kind = CORNER,
	  .op = ECOM_MATCH,
	  .value = { 0x01, 0x09, 10, 0, 0, 1, 0x00, 0x00, 0x01, 0x09, 10, 0, 0, 2, 0x00, 0x00 },
	  .len = 16,
	  .local_id = "10.0.0.2",
	  .match = true },
	{ .description = "cluster list value 4-octet aligned",
	  .kind = POSITIVE,
	  .op = CLUSTER,
	  .value = { 192, 0, 2, 1 },
	  .len = 4,
	  .offset = 2,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "cluster list of 3 octets is malformed",
	  .kind = NEGATIVE,
	  .op = CLUSTER,
	  .value = { 192, 0, 2 },
	  .len = 3,
	  .offset = 2,
	  .parse = BGP_ATTR_PARSE_WITHDRAW },
	{ .description = "cluster list value at offset 2 mod 4",
	  .kind = BOUNDARY,
	  .op = CLUSTER,
	  .value = { 192, 0, 2, 1 },
	  .len = 4,
	  .offset = 0,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "cluster list value at an odd offset",
	  .kind = CORNER,
	  .op = CLUSTER,
	  .value = { 192, 0, 2, 1 },
	  .len = 4,
	  .offset = 3,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "two cluster IDs at an odd offset",
	  .kind = CORNER,
	  .op = CLUSTER,
	  .value = { 192, 0, 2, 1, 198, 51, 100, 7 },
	  .len = 8,
	  .offset = 1,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "63 cluster IDs, the most without extended length",
	  .kind = BOUNDARY,
	  .op = CLUSTER,
	  .ids = 63,
	  .offset = 1,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "64 cluster IDs with extended length",
	  .kind = BOUNDARY,
	  .op = CLUSTER,
	  .ids = 64,
	  .offset = 3,
	  .parse = BGP_ATTR_PARSE_PROCEED },
	{ .description = "65 cluster IDs with extended length",
	  .kind = CORNER,
	  .op = CLUSTER,
	  .ids = 65,
	  .offset = 2,
	  .parse = BGP_ATTR_PARSE_PROCEED },
};

static struct peer *peer;

static int run_ecom(const struct tcase *tc)
{
	uint8_t *val = XMALLOC(MTYPE_TMP, tc->len);
	struct ecommunity *ecom;
	int rc = EXIT_MATCH;

	memcpy(val, tc->value, tc->len);
	ecom = ecommunity_parse(val, tc->len, false);
	assert(ecom);

	if (tc->op == ECOM_STR) {
		char *str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);

		printf("    \"%s\"\n", str);
		if (!strmatch(str, tc->str))
			rc = EXIT_MISMATCH;
		XFREE(MTYPE_ECOMMUNITY_STR, str);
	} else {
		struct in_addr id;
		bool match;

		inet_pton(AF_INET, tc->local_id, &id);
		match = ecommunity_node_target_match(ecom, &id);
		printf("    match %d\n", match);
		if (match != tc->match)
			rc = EXIT_MISMATCH;
	}

	XFREE(MTYPE_TMP, val);
	return rc;
}

static int run_cluster(const struct tcase *tc)
{
	struct stream *s = peer->connection->curr;
	struct attr attr = {};
	struct bgp_nlri mp_update = {};
	struct bgp_nlri mp_withdraw = {};
	struct cluster_list *cluster;
	enum bgp_attr_parse_ret ret;
	uint8_t ids[MAX_IDS * 4];
	const uint8_t *value = tc->value;
	size_t len = tc->len;
	bool extlen;
	size_t total;
	int rc = EXIT_MATCH;

	assert(tc->ids <= MAX_IDS);
	if (tc->ids) {
		/* 10.0.0.1, 10.0.0.2, ... */
		for (size_t i = 0; i < tc->ids; i++) {
			ids[4 * i] = 10;
			ids[4 * i + 1] = 0;
			ids[4 * i + 2] = (i + 1) >> 8;
			ids[4 * i + 3] = (i + 1) & 0xff;
		}
		value = ids;
		len = 4 * tc->ids;
	}
	extlen = len > 255;
	total = sizeof(ibgp_attrs) + (extlen ? 4 : 3) + len;

	stream_reset(s);
	for (size_t i = 0; i < tc->offset; i++)
		stream_putc(s, 0);
	stream_write(s, ibgp_attrs, sizeof(ibgp_attrs));
	stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | (extlen ? BGP_ATTR_FLAG_EXTLEN : 0));
	stream_putc(s, BGP_ATTR_CLUSTER_LIST);
	if (extlen)
		stream_putw(s, len);
	else
		stream_putc(s, len);
	printf("    CLUSTER_LIST value at stream offset %zu\n", stream_get_endp(s));
	stream_write(s, value, len);
	stream_set_getp(s, tc->offset);

	ret = bgp_attr_parse(peer->connection, &attr, total, &mp_update, &mp_withdraw, true);
	cluster = bgp_attr_exists(&attr, BGP_ATTR_CLUSTER_LIST) ? bgp_attr_get_cluster(&attr)
								: NULL;

	printf("    parse %d, cluster list %d octets\n", ret, cluster ? cluster->length : -1);
	if (ret != tc->parse)
		rc = EXIT_MISMATCH;
	if (ret == BGP_ATTR_PARSE_PROCEED &&
	    (!cluster || (size_t)cluster->length != len || memcmp(cluster->list, value, len)))
		rc = EXIT_MISMATCH;

	bgp_attr_unintern_sub(&attr);
	return rc;
}

static int run_table(const struct tcase *table, size_t n)
{
	int failures = 0;

	for (size_t i = 0; i < n; i++) {
		const struct tcase *tc = &table[i];
		char why[96] = "";
		int status;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = tc->op == CLUSTER ? run_cluster(tc) : run_ecom(tc);

			fflush(stdout);
			_exit(rc);
		}

		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH)
			snprintfrr(why, sizeof(why), " (expected %s)",
				   tc->op == ECOM_STR	  ? tc->str
				   : tc->op == ECOM_MATCH ? (tc->match ? "match" : "no match")
				   : tc->parse == BGP_ATTR_PARSE_PROCEED ? "parsed, same list"
									 : "treat-as-withdraw");
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}
	return failures;
}

int main(void)
{
	static struct bgp *bgp;
	static as_t asn = 65000;
	int failures;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("test unaligned");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_labels_init();
	bgp_community_alias_init();

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return -1;

	peer = peer_create_accept(bgp, NULL);
	peer->host = (char *)"foo";
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(BGP_MAX_PACKET_SIZE);
	peer->sort = BGP_PEER_IBGP;
	peer->as = 65000;
	peer->local_as = 65000;
	peer->as_type = AS_SPECIFIED;
	SET_FLAG(peer->cap, PEER_CAP_AS4_RCV);
	SET_FLAG(peer->cap, PEER_CAP_AS4_ADV);
	for (int afi = AFI_IP; afi < AFI_MAX; afi++)
		for (int safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			peer->afc[afi][safi] = 1;
			peer->afc_adv[afi][safi] = 1;
		}

	printf("BGP unaligned IPv4 address tests\n\n");
	failures = run_table(tcases, array_size(tcases));
	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
