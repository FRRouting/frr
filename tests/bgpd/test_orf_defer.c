// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Regression test for prefix-list ORF with "defer" refresh: the update
 * group's conf peer, whose orf_plist subgroup_announce_check() filters
 * with, must follow the ORF peer's orf_plist on every path, including the
 * ones that delete the ORF prefix-list (a malformed entry, removing the
 * last entry) before a REFRESH_DEFER return.
 *
 * Each case first installs an ORF prefix-list with an Immediate refresh,
 * then sends a Deferred refresh that ends with the list deleted, and
 * checks that the conf peer's copy matches the peer's (both NULL).
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
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static struct bgp *bgp;
static as_t asn = 100;
static int failed;

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

static struct peer *peer_setup(const char *addr)
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

static void check(const char *name, struct peer *peer)
{
	struct peer_af *paf = peer_af_find(peer, AFI_IP, SAFI_UNICAST);
	struct prefix_list *conf = UPDGRP_PEER(PAF_UPDGRP(paf))->orf_plist[AFI_IP][SAFI_UNICAST];
	struct prefix_list *own = peer->orf_plist[AFI_IP][SAFI_UNICAST];

	if (own == NULL && conf == NULL) {
		printf("%s: OK\n", name);
		return;
	}
	printf("%s: failed! peer orf_plist %p, conf peer orf_plist %p\n", name, own, conf);
	failed = 1;
}

/* Immediate refresh adding one entry: both pointers set to the new list. */
static void install(struct peer *peer)
{
	struct stream *s = refresh_begin(REFRESH_IMMEDIATE, ORF_ENTRY_LEN);
	struct peer_af *paf = peer_af_find(peer, AFI_IP, SAFI_UNICAST);

	orf_entry(s, ORF_COMMON_PART_ADD, 5, "10.1.1.0");
	refresh_send(peer, s);

	assert(peer->orf_plist[AFI_IP][SAFI_UNICAST]);
	assert(UPDGRP_PEER(PAF_UPDGRP(paf))->orf_plist[AFI_IP][SAFI_UNICAST] ==
	       peer->orf_plist[AFI_IP][SAFI_UNICAST]);
}

int main(int argc, char **argv)
{
	struct peer *peer;
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

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return 1;

	/* A malformed entry (prefix truncated) removes the whole list. */
	peer = peer_setup("192.0.2.2");
	install(peer);
	s = refresh_begin(REFRESH_DEFER, ORF_ENTRY_LEN - 3);
	stream_putc(s, ORF_COMMON_PART_ADD);
	stream_putl(s, 10);
	stream_putc(s, 0);
	stream_putc(s, 0);
	stream_putc(s, 24);
	refresh_send(peer, s);
	check("defer, malformed entry", peer);

	/*
	 * Removing the last entries deletes the now empty list. The first
	 * entry is an Add: a leading Remove is taken as Remove-All.
	 */
	peer = peer_setup("192.0.2.3");
	install(peer);
	s = refresh_begin(REFRESH_DEFER, 3 * ORF_ENTRY_LEN);
	orf_entry(s, ORF_COMMON_PART_ADD, 10, "10.2.2.0");
	orf_entry(s, ORF_COMMON_PART_REMOVE, 5, "10.1.1.0");
	orf_entry(s, ORF_COMMON_PART_REMOVE, 10, "10.2.2.0");
	refresh_send(peer, s);
	check("defer, remove the last entries", peer);

	/* Remove-All. */
	peer = peer_setup("192.0.2.4");
	install(peer);
	s = refresh_begin(REFRESH_DEFER, 1);
	stream_putc(s, ORF_COMMON_PART_REMOVE_ALL);
	refresh_send(peer, s);
	check("defer, remove-all", peer);

	bgp_delete(bgp);
	bgp_pthreads_finish();

	return failed;
}
