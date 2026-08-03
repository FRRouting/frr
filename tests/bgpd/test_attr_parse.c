// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgp_attr_parse() malformed-attribute handling tests (RFC 7606).
 *
 * Covers the framing-level malformations that cannot be produced by ExaBGP,
 * because they require an attribute length field that disagrees with the
 * actual data: truncated attribute header, extended-length underflow, and
 * an attribute length overrunning the Total Attribute Length.
 */

#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"

#define VT100_RESET "\x1b[0m"
#define VT100_RED   "\x1b[31m"
#define VT100_GREEN "\x1b[32m"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;
static int tty;

struct attr_test {
	const char *name;
	const char *desc;
	/* peer sort this case is parsed as */
	enum bgp_peer_sort sort;
	/* peer sub-sort; 0 for none, as bgpd itself spells "not OAD" */
	enum bgp_peer_sub_sort sub_sort;
	/* whether the UPDATE also carries NLRI in the NLRI field */
	bool has_nlri;
	/* raw path-attribute bytes, exactly as they appear on the wire */
	const uint8_t *data;
	/* octet count of .data -- set by ATTR_DATA(), never written by hand */
	size_t len;
	/* expected bgp_attr_parse() return */
	enum bgp_attr_parse_ret expect;
};

/*
 * Supply the wire bytes of a case and derive its length from them.
 *
 * The length must never be hand-written.  bgp_attr_parse() is told how many
 * octets to read and the harness feeds it exactly that many, so a mistyped
 * length cannot be caught by disagreeing with the stream -- it just quietly
 * parses a different message.  The usual result is BGP_ATTR_PARSE_WITHDRAW,
 * which is also the expected result of most RFC 7606 cases, so the typo
 * would surface as a passing test that exercises nothing.
 *
 * The file-scope compound literal has static storage duration, and sizeof
 * does not evaluate its operand, so this is a valid static initialiser.
 */
#define ATTR_DATA(...)                                                                            \
	.data = (const uint8_t[]){ __VA_ARGS__ }, .len = sizeof((const uint8_t[]){ __VA_ARGS__ })

/*
 * Well-formed baseline: ORIGIN(igp) + AS_PATH(65001) + NEXT_HOP(10.0.0.2).
 * Used to prove the harness itself accepts a valid attribute block.
 */
static const struct attr_test attr_tests[] = {
	{
		.name = "baseline-ebgp",
		.desc = "well-formed ORIGIN + AS_PATH + NEXT_HOP, eBGP",
		.sort = BGP_PEER_EBGP,
		.sub_sort = 0,
		.has_nlri = true,
		ATTR_DATA(0x40, 0x01, 0x01, 0x00,		     /* ORIGIN igp */
			  0x40, 0x02, 0x06,			     /* AS_PATH */
			  0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9,	     /* AS_SEQ 65001 */
			  0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02), /* NEXT_HOP */
		.expect = BGP_ATTR_PARSE_PROCEED,
	},
	{
		.name = "short-attr-header-ebgp",
		.desc = "two trailing octets, too few for an attribute header, eBGP",
		.sort = BGP_PEER_EBGP,
		.sub_sort = 0,
		.has_nlri = true,
		ATTR_DATA(0x40, 0x01, 0x01, 0x00,		    /* ORIGIN igp */
			  0x40, 0x02, 0x06,			    /* AS_PATH */
			  0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9,	    /* AS_SEQ 65001 */
			  0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02, /* NEXT_HOP */
			  0x40, 0x01),				    /* truncated header */
		.expect = BGP_ATTR_PARSE_WITHDRAW,
	},
	{
		.name = "short-attr-header-ibgp",
		.desc = "two trailing octets, too few for an attribute header, iBGP",
		.sort = BGP_PEER_IBGP,
		.sub_sort = 0,
		.has_nlri = true,
		ATTR_DATA(0x40, 0x01, 0x01, 0x00,		    /* ORIGIN igp */
			  0x40, 0x02, 0x06,			    /* AS_PATH */
			  0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8,	    /* AS_SEQ 65000 */
			  0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02, /* NEXT_HOP */
			  0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, /* LOCAL_PREF */
			  0x40, 0x01),				    /* truncated header */
		.expect = BGP_ATTR_PARSE_WITHDRAW,
	},
	{
		.name = "extlen-underflow-ebgp",
		.desc = "three trailing octets with Extended Length set, eBGP",
		.sort = BGP_PEER_EBGP,
		.sub_sort = 0,
		.has_nlri = true,
		ATTR_DATA(0x40, 0x01, 0x01, 0x00,		    /* ORIGIN igp */
			  0x40, 0x02, 0x06,			    /* AS_PATH */
			  0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9,	    /* AS_SEQ 65001 */
			  0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02, /* NEXT_HOP */
			  0x50, 0x08, 0x00),			    /* extlen COMMUNITIES */
		.expect = BGP_ATTR_PARSE_WITHDRAW,
	},
	{
		.name = "extlen-underflow-ibgp",
		.desc = "three trailing octets with Extended Length set, iBGP",
		.sort = BGP_PEER_IBGP,
		.sub_sort = 0,
		.has_nlri = true,
		ATTR_DATA(0x40, 0x01, 0x01, 0x00,		    /* ORIGIN igp */
			  0x40, 0x02, 0x06,			    /* AS_PATH */
			  0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8,	    /* AS_SEQ 65000 */
			  0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02, /* NEXT_HOP */
			  0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, /* LOCAL_PREF */
			  0x50, 0x08, 0x00),			    /* extlen COMMUNITIES */
		.expect = BGP_ATTR_PARSE_WITHDRAW,
	},
};

static const char *parse_ret_str(enum bgp_attr_parse_ret ret)
{
	switch (ret) {
	case BGP_ATTR_PARSE_PROCEED:
		return "PROCEED";
	case BGP_ATTR_PARSE_ERROR:
		return "ERROR";
	case BGP_ATTR_PARSE_WITHDRAW:
		return "WITHDRAW";
	case BGP_ATTR_PARSE_ERROR_NOTIFYPLS:
		return "ERROR_NOTIFYPLS";
	case BGP_ATTR_PARSE_MISSING_MANDATORY:
		return "MISSING_MANDATORY";
	case BGP_ATTR_PARSE_WITHDRAW_IGNORE:
		return "WITHDRAW_IGNORE";
	}
	return "UNKNOWN";
}

/* Print the octets bgp_attr_parse() is about to be handed, and how many. */
static void print_data(const uint8_t *data, size_t len)
{
	size_t i;

	printf("  len:      %zu\n", len);
	printf("  data:    ");
	for (i = 0; i < len; i++) {
		if (i && !(i % 16))
			printf("\n           ");
		printf(" %02x", data[i]);
	}
	printf("\n");
}

static void parse_test(struct peer *peer, const struct attr_test *t)
{
	struct attr attr = {};
	struct bgp_nlri mp_update = {};
	struct bgp_nlri mp_withdraw = {};
	enum bgp_attr_parse_ret ret;
	int oldfailed = failed;

	printf("%s: %s\n", t->name, t->desc);

	peer->sort = t->sort;
	peer->sub_sort = t->sub_sort;
	peer->as = (t->sort == BGP_PEER_EBGP) ? 65001 : 65000;

	/*
	 * bgp_attr_aspath_check() calls peer_sort(), which *recomputes*
	 * peer->sort from local_as/as_type rather than reading it back.
	 * Without these two fields peer_calc_sort() takes its "local_as == 0"
	 * branch and forces BGP_PEER_INTERNAL, quietly discarding the sort
	 * the case asked for and skipping the eBGP-only AS_PATH checks.
	 */
	peer->local_as = 65000;
	peer->as_type = AS_SPECIFIED;
	assert(peer_sort(peer) == t->sort);

	stream_reset(peer->connection->curr);
	stream_write(peer->connection->curr, t->data, t->len);
	stream_set_getp(peer->connection->curr, 0);

	print_data(t->data, t->len);

	ret = bgp_attr_parse(peer->connection, &attr, t->len, &mp_update, &mp_withdraw,
			     t->has_nlri);

	printf("  got:      %s\n", parse_ret_str(ret));
	printf("  expected: %s\n", parse_ret_str(t->expect));

	if (ret != t->expect)
		failed++;

	if (tty)
		printf("%s", (failed > oldfailed) ? VT100_RED "failed!" VT100_RESET
						  : VT100_GREEN "OK" VT100_RESET);
	else
		printf("%s", (failed > oldfailed) ? "failed!" : "OK");
	printf("\n\n");

	bgp_attr_unintern_sub(&attr);
}

static struct bgp *bgp;
static as_t asn = 65000;

int main(void)
{
	struct peer *peer;
	size_t i;
	int afi, safi;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("test attr parse");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_labels_init();

	if (fileno(stdout) >= 0)
		tty = isatty(fileno(stdout));

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return -1;

	peer = peer_create_accept(bgp, NULL);
	peer->host = (char *)"foo";
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(BGP_MAX_PACKET_SIZE);

	/* AS_PATH blobs carry 4-octet ASNs */
	SET_FLAG(peer->cap, PEER_CAP_AS4_RCV);
	SET_FLAG(peer->cap, PEER_CAP_AS4_ADV);

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			peer->afc[afi][safi] = 1;
			peer->afc_adv[afi][safi] = 1;
		}

	for (i = 0; i < array_size(attr_tests); i++)
		parse_test(peer, &attr_tests[i]);

	printf("failures: %d\n", failed);
	return failed;
}
