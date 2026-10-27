// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Regression test for the prefix-list ORF a peer sends us: each peer must
 * get its own ORF prefix-list, also when peers in different BGP instances
 * have the same address, so one peer's ORF changes and teardown leave the
 * other peer's filter alone.
 */

#include <zebra.h>

#include "frr_pthread.h"
#include "memory.h"
#include "plist.h"
#include "privs.h"
#include "sockunion.h"
#include "stream.h"
#include "vrf.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static as_t asn = 100;

#define ORF_ENTRY_LEN 11 /* common, seq (4), ge, le, prefixlen, 3 prefix bytes */

static void orf_entry(struct stream *s, uint8_t common, uint32_t seq, const char *pfx)
{
	struct in_addr a;

	inet_pton(AF_INET, pfx, &a);
	stream_putc(s, common);
	stream_putl(s, seq);
	stream_putc(s, 0);  /* ge */
	stream_putc(s, 0);  /* le */
	stream_putc(s, 24); /* prefixlen */
	stream_put(s, &a, 3);
}

/* ROUTE-REFRESH for IPv4 unicast carrying one prefix ORF of orf_len bytes. */
static struct stream *refresh_begin(uint8_t when, size_t orf_len)
{
	struct stream *s = stream_new(BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE);

	bgp_packet_set_marker(s, BGP_MSG_ROUTE_REFRESH);
	stream_putw(s, IANA_AFI_IPV4);
	stream_putc(s, 0);
	stream_putc(s, IANA_SAFI_UNICAST);
	stream_putc(s, when);
	stream_putc(s, ORF_TYPE_PREFIX);
	stream_putw(s, orf_len);
	return s;
}

static void refresh_send(struct peer *peer, struct stream *s)
{
	struct event t = { .master = master, .yield = EVENT_YIELD_TIME_SLOT };

	monotime(&t.real);
	bgp_packet_set_size(s);
	frr_with_mutex (&peer->connection->io_mtx) {
		stream_fifo_push(peer->connection->ibuf, s);
	}
	frr_with_mutex (&bm->peer_connection_mtx) {
		peer_connection_fifo_add_tail(&bm->connection_fifo, peer->connection);
	}
	bgp_process_packet(&t);

	/* The event loop never runs: drop any re-queued connection. */
	frr_with_mutex (&bm->peer_connection_mtx) {
		while (peer_connection_fifo_pop(&bm->connection_fifo))
			;
	}
}

static struct peer *peer_setup(struct bgp *bgp, const char *addr)
{
	union sockunion su;
	struct peer *peer;
	struct peer_af *paf;

	str2sockunion(addr, &su);
	peer = peer_create(&su, NULL, bgp, asn, asn, AS_SPECIFIED, NULL, true, NULL,
			   CONNECTION_OUTGOING);
	assert(peer);
	peer_activate(peer, AFI_IP, SAFI_UNICAST);

	SET_FLAG(peer->cap, PEER_CAP_REFRESH_ADV);
	SET_FLAG(peer->af_cap[AFI_IP][SAFI_UNICAST],
		 PEER_CAP_ORF_PREFIX_RM_ADV | PEER_CAP_ORF_PREFIX_SM_RCV);
	peer->afc_nego[AFI_IP][SAFI_UNICAST] = 1;
	peer->connection->status = Established;

	paf = peer_af_find(peer, AFI_IP, SAFI_UNICAST);
	assert(paf);
	update_group_adjust_peer(paf);
	assert(paf->subgroup);
	return peer;
}

/* Immediate refresh adding one permit entry for pfx/24. */
static void orf_add(struct peer *peer, uint32_t seq, const char *pfx)
{
	struct stream *s = refresh_begin(REFRESH_IMMEDIATE, ORF_ENTRY_LEN);

	orf_entry(s, ORF_COMMON_PART_ADD, seq, pfx);
	refresh_send(peer, s);
}

static enum prefix_list_type orf_apply(struct peer *peer, const char *pfx)
{
	struct prefix p;

	str2prefix(pfx, &p);
	return prefix_list_apply(peer->orf_plist[AFI_IP][SAFI_UNICAST], &p);
}

/*
 * Each check builds on the previous one, and once two peers share a list
 * the later checks would read a list the other peer may have deleted, so
 * the test stops at the first failure.
 */
static bool check(const char *name, bool ok)
{
	printf("%s: %s\n", name, ok ? "OK" : "failed!");
	return ok;
}

int main(int argc, char **argv)
{
	struct bgp *bgp_a = NULL, *bgp_b = NULL;
	struct peer *a, *b;
	struct stream *s;

	setvbuf(stdout, NULL, _IONBF, 0);
	qobj_init();
	cmd_init(1);
	zlog_aux_init("NONE: ", LOG_ERR);
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();

	if (bgp_get(&bgp_a, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0 ||
	    bgp_get(&bgp_b, &asn, "view-b", BGP_INSTANCE_TYPE_VIEW, NULL, ASNOTATION_PLAIN) < 0)
		return 1;

	/* The same neighbor address in two instances, each sending ORF. */
	a = peer_setup(bgp_a, "192.0.2.2");
	b = peer_setup(bgp_b, "192.0.2.2");
	orf_add(a, 5, "10.1.1.0");
	orf_add(b, 5, "10.2.2.0");
	assert(a->orf_plist[AFI_IP][SAFI_UNICAST] && b->orf_plist[AFI_IP][SAFI_UNICAST]);

	if (!check("each peer has its own ORF prefix-list",
		   a->orf_plist[AFI_IP][SAFI_UNICAST] != b->orf_plist[AFI_IP][SAFI_UNICAST]))
		return 1;

	if (!check("peer A filters with its own entries only",
		   orf_apply(a, "10.1.1.0/24") == PREFIX_PERMIT &&
			   orf_apply(a, "10.2.2.0/24") == PREFIX_DENY))
		return 1;

	/* Peer B withdraws its whole ORF: peer A's filter stays. */
	s = refresh_begin(REFRESH_IMMEDIATE, 1);
	stream_putc(s, ORF_COMMON_PART_REMOVE_ALL);
	refresh_send(b, s);
	if (!check("Remove-All from peer B leaves peer A's ORF prefix-list",
		   !b->orf_plist[AFI_IP][SAFI_UNICAST] && a->orf_plist[AFI_IP][SAFI_UNICAST] &&
			   orf_apply(a, "10.1.1.0/24") == PREFIX_PERMIT))
		return 1;

	/* Peer B sends ORF again and goes down: peer A's filter stays. */
	orf_add(b, 6, "10.3.3.0");
	bgp_stop(b->connection);
	if (!check("peer B going down leaves peer A's ORF prefix-list",
		   !b->orf_plist[AFI_IP][SAFI_UNICAST] && a->orf_plist[AFI_IP][SAFI_UNICAST] &&
			   orf_apply(a, "10.1.1.0/24") == PREFIX_PERMIT))
		return 1;

	bgp_delete(bgp_b);
	bgp_delete(bgp_a);
	bgp_pthreads_finish();
	return 0;
}
