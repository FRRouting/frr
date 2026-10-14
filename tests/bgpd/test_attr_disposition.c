// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Qipeng Ding */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>
#include "command.h"
#include "qobj.h"
#include "stream.h"
#include "privs.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_packet.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static void large_community(struct stream *s)
{
	stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
	stream_putc(s, 12);
	stream_putl(s, 65020);
	stream_putl(s, 1);
	stream_putl(s, 100);
}

/* All attributes are valid. Configured community withdrawal exercises deferred
 * handling without constructing erroneous peer input or opening sockets.
 */
static void valid_policy_control(struct peer *peer, bool withdraw, bool community_first)
{
	struct attr attr = {};
	struct bgp_nlri update = {};
	struct bgp_nlri withdrawn = {};
	struct stream *s = peer->connection->curr;
	struct in_addr next_hop;
	struct in6_addr next_hop6;
	struct in6_addr prefix6;
	enum bgp_attr_parse_ret ret;

	stream_reset(s);
	assert(inet_pton(AF_INET, "192.0.2.13", &next_hop) == 1);
	assert(inet_pton(AF_INET6, "2001:db8:1::13", &next_hop6) == 1);
	assert(inet_pton(AF_INET6, "2001:db8:75::", &prefix6) == 1);
	stream_putc(s, BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_ORIGIN);
	stream_putc(s, 1);
	stream_putc(s, BGP_ORIGIN_IGP);
	stream_putc(s, BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_AS_PATH);
	stream_putc(s, 6);
	stream_putc(s, 2);
	stream_putc(s, 1);
	stream_putl(s, 65020);
	stream_putc(s, BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_NEXT_HOP);
	stream_putc(s, 4);
	stream_put(s, &next_hop, sizeof(next_hop));
	if (community_first)
		large_community(s);
	stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
	stream_putc(s, BGP_ATTR_MP_REACH_NLRI);
	stream_putc(s, 30);
	stream_putw(s, 2);
	stream_putc(s, 1);
	stream_putc(s, 16);
	stream_put(s, &next_hop6, sizeof(next_hop6));
	stream_putc(s, 0);
	stream_putc(s, 64);
	stream_put(s, &prefix6, 8);
	if (!community_first)
		large_community(s);
	peer->withdraw_attrs[BGP_ATTR_LARGE_COMMUNITIES] = withdraw;
	ret = bgp_attr_parse(peer->connection, &attr, stream_get_endp(s), &update,
			     &withdrawn, true);
	assert(ret == (withdraw ? BGP_ATTR_PARSE_WITHDRAW_IGNORE : BGP_ATTR_PARSE_PROCEED));
	assert(update.afi == AFI_IP6 && update.safi == SAFI_UNICAST && update.length == 9);
	assert(bgp_attr_exists(&attr, BGP_ATTR_MP_REACH_NLRI));
	assert(stream_get_getp(s) == stream_get_endp(s));
	bgp_attr_unintern_sub(&attr);
}

int main(void)
{
	struct bgp *bgp;
	as_t asn = 65000;
	struct peer *peer;
	enum bgp_attr_parse_ret pending = BGP_ATTR_PARSE_PROCEED;
	char host[] = "local-valid-policy";

	assert(bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_WITHDRAW_IGNORE));
	assert(!bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_PROCEED));
	assert(pending == BGP_ATTR_PARSE_WITHDRAW_IGNORE);
	assert(bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_WITHDRAW));
	assert(pending == BGP_ATTR_PARSE_WITHDRAW);
	assert(bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_WITHDRAW_IGNORE));
	assert(pending == BGP_ATTR_PARSE_WITHDRAW);
	assert(!bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_ERROR));
	assert(!bgp_attr_defer_withdraw(&pending, BGP_ATTR_PARSE_ERROR_NOTIFYPLS));

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("valid policy controls");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_community_alias_init();
	bgp_labels_init();
	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) >= 0);
	peer = peer_create_accept(bgp, NULL);
	peer->host = host;
	peer->as = 65020;
	peer->local_as = 65000;
	peer->as_type = AS_SPECIFIED;
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(256);
	SET_FLAG(peer->cap, PEER_CAP_AS4_RCV | PEER_CAP_AS4_ADV);
	assert(peer_sort(peer) == BGP_PEER_EBGP);
	valid_policy_control(peer, true, true);
	valid_policy_control(peer, true, false);
	valid_policy_control(peer, false, true);
	valid_policy_control(peer, false, false);
	puts("Deferred withdrawal, fatal dispositions and valid MP policy controls: OK");
	return 0;
}
