// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Qipeng Ding */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>
#include "hash.h"
#include "qobj.h"
#include "stream.h"
#include "privs.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_network.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

/* Exercise the real outbound queues, not a network peer or an input parser. */
static void run_case(bool advertised, unsigned int limit)
{
	struct bgp bgp = {};
	struct peer peer = {};
	struct update_group group = {};
	struct update_subgroup subgroup = {};
	struct bgp_synchronize sync = {};
	struct bgp_path_info path = {};
	struct bgp_path_info control_path = {};
	struct attr small = {};
	struct attr large = {};
	struct attr *small_owner;
	struct attr *large_owner;
	struct prefix prefix;
	struct prefix control_prefix;
	struct bgp_dest *dest;
	struct bgp_dest *control_dest;
	struct bgp_adj_out *adj;
	struct bgp_table *table;
	struct bpacket *packet;
	char text[7000] = {};
	char host[] = "local-outbound-unit";

	bgp.as = 65010;
	bgp.default_subgroup_pkt_queue_max = 100;
	peer.bgp = &bgp;
	peer.as = 65020;
	peer.local_as = 65010;
	peer.sort = BGP_PEER_EBGP;
	peer.host = host;
	peer.max_packet_size = limit;
	SET_FLAG(peer.cap, PEER_CAP_AS4_ADV | PEER_CAP_AS4_RCV);
	group.bgp = &bgp;
	group.conf = &peer;
	group.afi = AFI_IP;
	group.safi = SAFI_UNICAST;
	subgroup.update_group = &group;
	subgroup.sync = &sync;
	subgroup.work = stream_new(limit + BGP_MAX_PACKET_SIZE_OVERFLOW);
	subgroup.scratch = stream_new(limit);
	subgroup.hash = hash_create(bgp_advertise_attr_hash_key,
				    bgp_advertise_attr_hash_cmp, "outbound unit");
	TAILQ_INIT(&subgroup.adjq);
	bgp_adv_fifo_init(&sync.update);
	bgp_adv_fifo_init(&sync.withdraw);
	bpacket_queue_init(&subgroup.pkt_queue);
	bpacket_queue_add(&subgroup.pkt_queue, NULL, NULL);
	path.lock = 1;
	path.peer = &peer;
	assert(str2prefix("198.51.100.60/32", &prefix) == 1);
	table = bgp_table_init(&bgp, AFI_IP, SAFI_UNICAST);
	dest = bgp_node_get(table, &prefix);
	path.net = dest;
	small.origin = BGP_ORIGIN_IGP;
	assert(inet_pton(AF_INET, "192.0.2.13", &small.nexthop) == 1);
	small.aspath = aspath_str2aspath("65020", ASNOTATION_PLAIN);
	bgp_attr_set(&small, BGP_ATTR_ORIGIN);
	bgp_attr_set(&small, BGP_ATTR_AS_PATH);
	bgp_attr_set(&small, BGP_ATTR_NEXT_HOP);
	small_owner = bgp_attr_intern(&small);
	if (advertised) {
		assert(bgp_adj_out_set_subgroup(dest, &subgroup, small_owner, &path));
		packet = subgroup_update_packet(&subgroup);
		assert(packet && packet->buffer && subgroup.scount == 1);
	}
	for (unsigned int i = 0; i < 1100; i++)
		strlcat(text, "65020 ", sizeof(text));
	large = small;
	large.aspath = aspath_str2aspath(text, ASNOTATION_PLAIN);
	assert(large.aspath && aspath_size(large.aspath) > 4096);
	large_owner = bgp_attr_intern(&large);
	assert(bgp_adj_out_set_subgroup(dest, &subgroup, large_owner, &path));
	assert(str2prefix("198.51.100.61/32", &control_prefix) == 1);
	control_dest = bgp_node_get(table, &control_prefix);
	control_path.lock = 1;
	control_path.net = control_dest;
	control_path.peer = &peer;
	assert(bgp_adj_out_set_subgroup(control_dest, &subgroup, small_owner, &control_path));
	packet = subgroup_update_packet(&subgroup);
	if (limit == 4096 && advertised) {
		assert(packet && packet->buffer);
		assert(stream_get_endp(packet->buffer) == 28);
		assert(stream_getw_from(packet->buffer, 19) == 5);
		assert(stream_getc_from(packet->buffer, 21) == 32);
		assert(memcmp(STREAM_DATA(packet->buffer) + 22, &prefix.u.prefix4, 4) == 0);
		assert(subgroup.scount == 0 && subgroup.pscount == 1);
	} else if (limit == 4096) {
		assert(!packet && subgroup.scount == 0 && subgroup.pscount == 1);
	} else {
		assert(packet && packet->buffer);
		assert(stream_get_endp(packet->buffer) > 4096);
		assert(stream_getw_from(packet->buffer, 19) == 0);
		assert(subgroup.scount == 1 && subgroup.pscount == 2);
	}
	assert(bgp_adv_fifo_count(&sync.update) == 1 && !bgp_adv_fifo_count(&sync.withdraw));
	adj = TAILQ_FIRST(&subgroup.adjq);
	if (limit == 4096)
		assert(adj && adj->dest == control_dest && adj->adv && !adj->attr);
	else
		assert(adj && adj->attr && !adj->adv);
	/* An unrelated, encodable attribute group must not be flushed. */
	packet = subgroup_update_packet(&subgroup);
	assert(packet && packet->buffer && stream_getw_from(packet->buffer, 19) == 0);
	assert(!bgp_adv_fifo_count(&sync.update));
	bgp_adj_out_unset_subgroup(control_dest, &subgroup, 0);
	assert(subgroup_withdraw_packet(&subgroup));
	assert(control_path.lock == 1);

	/* A later encodable path must still be advertised after the drop. */
	assert(bgp_adj_out_set_subgroup(dest, &subgroup, small_owner, &path));
	packet = subgroup_update_packet(&subgroup);
	assert(packet && packet->buffer && subgroup.scount == 1);
	assert(stream_getw_from(packet->buffer, 19) == 0);
	bgp_adj_out_unset_subgroup(dest, &subgroup, 0);
	assert(subgroup_withdraw_packet(&subgroup));
	assert(!TAILQ_FIRST(&subgroup.adjq) && subgroup.scount == 0);
	assert(path.lock == 1);
	bgp_attr_unintern(&small_owner);
	bgp_attr_unintern(&large_owner);
	bpacket_queue_cleanup(&subgroup.pkt_queue);
	assert(subgroup.hash->count == 0);
	hash_clean_and_free(&subgroup.hash, NULL);
	stream_free(subgroup.work);
	stream_free(subgroup.scratch);
	bgp_dest_unlock_node(dest);
	bgp_dest_unlock_node(control_dest);
	bgp_table_finish(&table);
}

int main(void)
{
	qobj_init();
	bgp_attr_init();
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	run_case(true, 4096);
	run_case(false, 4096);
	run_case(true, 65535);
	run_case(false, 65535);
	puts("Unencodable replacement, new path, extended limit and recovery: OK");
	return 0;
}
