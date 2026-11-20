// SPDX-License-Identifier: GPL-2.0-or-later
/* Regression tests for replacing locally originated BGP-LS link identities. */

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>

#include "frr_pthread.h"
#include "privs.h"
#include "qobj.h"
#include "stream.h"
#include "vrf.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_ted.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static as_t asn = 65001;
static unsigned int failures;

enum local_v6 { ABSENT, ORIGINAL, REPLACEMENT };

struct path_state {
	struct bgp_path_info *path;
	uint32_t id;
	uint32_t metric;
};

static struct in_addr address4(unsigned int direction)
{
	struct in_addr address;

	assert(inet_pton(AF_INET, direction ? "10.254.0.9" : "10.254.0.8", &address) == 1);
	return address;
}

static struct in6_addr address6(unsigned int direction, enum local_v6 state)
{
	struct in6_addr address = {};
	const char *text;

	if (state == ABSENT)
		return address;
	if (state == ORIGINAL)
		text = direction ? "2001:db8:6501:5::1" : "2001:db8:6501:5::";
	else
		text = direction ? "2001:db8:6501:5::3" : "2001:db8:6501:5::2";
	assert(inet_pton(AF_INET6, text, &address) == 1);
	return address;
}

static struct ls_node_id node_id(unsigned int direction)
{
	struct ls_node_id id = { .origin = ISIS_L2 };

	id.id.iso.sys_id[5] = direction + 3;
	id.id.iso.level = 2;
	return id;
}

static struct ls_attributes *edge_attributes(unsigned int direction, enum local_v6 state,
					     uint32_t metric)
{
	struct ls_attributes *attr = ls_attributes_new(node_id(direction), address4(direction),
						       address6(direction, state), 0);

	assert(attr);
	attr->standard.remote = address4(!direction);
	attr->standard.remote6 = address6(!direction, ORIGINAL);
	attr->metric = metric;
	SET_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR | LS_ATTR_NEIGH_ADDR6 | LS_ATTR_METRIC);
	return attr;
}

static int send_edge(struct bgp *bgp, unsigned int direction, enum local_v6 state, uint32_t metric,
		     uint8_t event)
{
	struct ls_message msg = {
		.type = LS_MSG_TYPE_ATTRIBUTES,
		.event = event,
		.data.attr = edge_attributes(direction, state, metric),
	};
	int ret = bgp_ls_process_message(bgp, &msg);

	// ADD/UPDATE/SYNC transfer attributes; DELETE borrows only the key.
	if (event == LS_MSG_EVENT_DELETE || ret < 0)
		ls_attributes_del(msg.data.attr);
	return ret;
}

static struct bgp *fixture_new(void)
{
	struct bgp *bgp = NULL;

	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) >= 0);
	assert(bgp && bgp->peer_self && bgp->ls_info && bgp->ls_info->ted);
	assert(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS]);
	for (unsigned int direction = 0; direction < 2; direction++) {
		struct ls_node *node = ls_node_new(node_id(direction), (struct in_addr){ 0 },
						   (struct in6_addr){ 0 });
		struct ls_message msg = {
			.type = LS_MSG_TYPE_NODE,
			.event = LS_MSG_EVENT_ADD,
			.data.node = node,
		};

		assert(node);
		// Captured nodes have only six-byte IGP Router-IDs.
		assert(bgp_ls_process_message(bgp, &msg) == 0);
	}
	return bgp;
}

static void seed_edges(struct bgp *bgp, enum local_v6 state)
{
	assert(send_edge(bgp, 0, state, 10, LS_MSG_EVENT_ADD) == 0);
	assert(send_edge(bgp, 1, state, 10, LS_MSG_EVENT_ADD) == 0);
}

static struct bgp_ls_nlri expected_link(unsigned int direction, enum local_v6 state)
{
	struct bgp_ls_nlri nlri = { .nlri_type = BGP_LS_NLRI_TYPE_LINK };
	struct bgp_ls_link_nlri *link = &nlri.nlri_data.link;
	struct bgp_ls_node_descriptor *nodes[] = { &link->local_node, &link->remote_node };

	// Expected keys are independent of the TED converter.
	link->protocol_id = BGP_LS_PROTO_ISIS_L2;
	for (unsigned int i = 0; i < 2; i++) {
		nodes[i]->igp_router_id_len = 6;
		nodes[i]->igp_router_id.raw[5] = (i ? !direction : direction) + 3;
		nodes[i]->present_tlvs = BGP_LS_NODE_DESC_IGP_ROUTER_BIT;
	}
	link->link_desc.ipv4_intf_addr = address4(direction);
	link->link_desc.ipv4_neigh_addr = address4(!direction);
	link->link_desc.ipv6_neigh_addr = address6(!direction, ORIGINAL);
	link->link_desc.present_tlvs = BGP_LS_LINK_DESC_IPV4_INTF_BIT |
				       BGP_LS_LINK_DESC_IPV4_NEIGH_BIT |
				       BGP_LS_LINK_DESC_IPV6_NEIGH_BIT;
	if (state != ABSENT) {
		link->link_desc.ipv6_intf_addr = address6(direction, state);
		SET_FLAG(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT);
	}
	return nlri;
}

static bool active(struct bgp *bgp, struct bgp_path_info *path)
{
	return path->peer == bgp->peer_self && CHECK_FLAG(path->flags, BGP_PATH_VALID) &&
	       !CHECK_FLAG(path->flags, BGP_PATH_REMOVED);
}

static struct path_state find_path(struct bgp *bgp, struct bgp_ls_nlri *key)
{
	struct path_state result = {};
	struct bgp_ls_nlri *nlri = bgp_ls_nlri_lookup(&bgp->ls_info->nlri_hash, key);
	struct prefix prefix = { .family = AF_UNSPEC, .prefixlen = 32 };
	struct bgp_dest *dest;
	struct bgp_path_info *path;

	if (!nlri)
		return result;
	prefix.u.val32[0] = nlri->id;
	dest = bgp_node_lookup(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS], &prefix);
	if (!dest)
		return result;
	for (path = bgp_dest_get_bgp_path_info(dest); path; path = path->next) {
		if (active(bgp, path)) {
			struct bgp_ls_attr *attr = bgp_attr_get_ls_attr(path->attr);

			result.path = path;
			result.id = nlri->id;
			result.metric = attr ? attr->igp_metric : UINT32_MAX;
			break;
		}
	}
	bgp_dest_unlock_node(dest);
	return result;
}

static unsigned int active_links(struct bgp *bgp)
{
	struct bgp_dest *dest;
	unsigned int count = 0;

	// Count active RIB paths; hash and TED entries can outlive withdrawals.
	for (dest = bgp_table_top(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS]); dest;
	     dest = bgp_route_next(dest)) {
		struct bgp_path_info *path;

		if (!dest->ls_nlri || dest->ls_nlri->nlri_type != BGP_LS_NLRI_TYPE_LINK)
			continue;
		for (path = bgp_dest_get_bgp_path_info(dest); path; path = path->next)
			count += active(bgp, path);
	}
	return count;
}

static bool exact_pair(struct bgp *bgp, enum local_v6 a, enum local_v6 b)
{
	struct bgp_ls_nlri keys[] = { expected_link(0, a), expected_link(1, b) };

	return active_links(bgp) == 2 && find_path(bgp, &keys[0]).path &&
	       find_path(bgp, &keys[1]).path;
}

static void check(const char *name, bool ok)
{
	printf("BGPLS_CASE %s: %s\n", name, ok ? "OK" : "failed!");
	failures += !ok;
}

static void test_captured_wire(void)
{
	// Literal bytes from the independent 2026-10-30 capture.
	static const uint8_t wire[2][2][97] = {
		{
			{
				0x00, 0x02, 0x00, 0x49, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x02, 0x03, 0x00, 0x06, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x0a, 0x02, 0x03,
				0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00,
				0x04, 0x0a, 0xfe, 0x00, 0x08, 0x01, 0x04, 0x00, 0x04, 0x0a, 0xfe,
				0x00, 0x09, 0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65,
				0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			{
				0x00, 0x02, 0x00, 0x49, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x02, 0x03, 0x00, 0x06, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x0a, 0x02, 0x03,
				0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00,
				0x04, 0x0a, 0xfe, 0x00, 0x09, 0x01, 0x04, 0x00, 0x04, 0x0a, 0xfe,
				0x00, 0x08, 0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65,
				0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			{
				0x00, 0x02, 0x00, 0x5d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x02, 0x03, 0x00, 0x06, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x0a, 0x02, 0x03,
				0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00,
				0x04, 0x0a, 0xfe, 0x00, 0x08, 0x01, 0x04, 0x00, 0x04, 0x0a, 0xfe,
				0x00, 0x09, 0x01, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65,
				0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65, 0x01, 0x00,
				0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			{
				0x00, 0x02, 0x00, 0x5d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x02, 0x03, 0x00, 0x06, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x0a, 0x02, 0x03,
				0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00,
				0x04, 0x0a, 0xfe, 0x00, 0x09, 0x01, 0x04, 0x00, 0x04, 0x0a, 0xfe,
				0x00, 0x08, 0x01, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65,
				0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x65, 0x01, 0x00,
				0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	};
	bool ok = true;

	for (unsigned int full = 0; full < 2; full++) {
		struct bgp *bgp = fixture_new();
		enum local_v6 state = full ? ORIGINAL : ABSENT;

		seed_edges(bgp, state);
		for (unsigned int direction = 0; direction < 2; direction++) {
			struct bgp_ls_nlri key = expected_link(direction, state);
			struct bgp_ls_nlri *nlri = bgp_ls_nlri_lookup(&bgp->ls_info->nlri_hash,
								      &key);
			struct stream *s = stream_new(128);
			int len = nlri ? bgp_ls_encode_nlri(s, nlri) : -1;

			// Value lengths exclude the four-byte NLRI header.
			ok &= len == (full ? 97 : 77) && stream_get_endp(s) == (size_t)len &&
			      memcmp(STREAM_DATA(s), wire[full][direction], (size_t)len) == 0 &&
			      find_path(bgp, &key).path != NULL;
			stream_free(s);
		}
		bgp_delete(bgp);
	}
	check("captured_partial_full_wire", ok);
}

static void test_transition(const char *name, enum local_v6 from, enum local_v6 to, uint8_t event)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri old[] = { expected_link(0, from), expected_link(1, from) };
	bool ok;

	seed_edges(bgp, from);
	ok = exact_pair(bgp, from, from);
	assert(send_edge(bgp, 0, to, 10, event) == 0);
	ok &= !find_path(bgp, &old[0]).path && exact_pair(bgp, to, from);
	assert(send_edge(bgp, 1, to, 10, event) == 0);
	ok &= !find_path(bgp, &old[1]).path && exact_pair(bgp, to, to);
	check(name, ok);
	bgp_delete(bgp);
}

static void test_repeated_and_delete(void)
{
	struct bgp *bgp = fixture_new();
	bool ok;

	seed_edges(bgp, ORIGINAL);
	ok = exact_pair(bgp, ORIGINAL, ORIGINAL);
	for (unsigned int i = 0; i < 8; i++) {
		enum local_v6 state = i % 2 ? ORIGINAL : REPLACEMENT;

		for (unsigned int direction = 0; direction < 2; direction++)
			assert(send_edge(bgp, direction, state, 10, LS_MSG_EVENT_UPDATE) == 0);
		ok &= exact_pair(bgp, state, state);
	}
	check("repeated_replacement", ok);
	assert(send_edge(bgp, 0, ORIGINAL, 10, LS_MSG_EVENT_DELETE) == 0);
	ok = active_links(bgp) == 1;
	assert(send_edge(bgp, 1, ORIGINAL, 10, LS_MSG_EVENT_DELETE) == 0);
	check("delete_after_replacement", ok && active_links(bgp) == 0);
	bgp_delete(bgp);
}

static void test_attribute_updates(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri key = expected_link(0, ORIGINAL);
	struct path_state before, after;
	uint64_t queued;

	seed_edges(bgp, ORIGINAL);
	before = find_path(bgp, &key);
	assert(before.path);
	queued = bgp->node_already_on_queue;
	assert(send_edge(bgp, 0, ORIGINAL, 23, LS_MSG_EVENT_UPDATE) == 0);
	after = find_path(bgp, &key);
	// A pending queue counts one attribute call, two for withdraw+add.
	check("metric_only_no_withdraw", exact_pair(bgp, ORIGINAL, ORIGINAL) &&
						 after.path == before.path &&
						 after.id == before.id && after.metric == 23 &&
						 bgp->node_already_on_queue == queued + 1);
	queued = bgp->node_already_on_queue;
	assert(send_edge(bgp, 0, ORIGINAL, 23, LS_MSG_EVENT_UPDATE) == 0);
	after = find_path(bgp, &key);
	check("identical_refresh_no_withdraw", exact_pair(bgp, ORIGINAL, ORIGINAL) &&
						       after.path == before.path &&
						       bgp->node_already_on_queue == queued);
	bgp_delete(bgp);
}

static void test_descriptor_changes(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri old = expected_link(0, ORIGINAL);
	struct bgp_ls_nlri current = old;
	struct bgp_ls_nlri reverse = expected_link(1, ORIGINAL);
	struct ls_message msg = { .type = LS_MSG_TYPE_ATTRIBUTES, .event = LS_MSG_EVENT_UPDATE };
	bool ok = true;

	seed_edges(bgp, ORIGINAL);
	// MT-ID and neighbor IPv6 changes also rekey the same TED edge.
	for (unsigned int step = 0; step < 2; step++) {
		msg.data.attr = edge_attributes(0, ORIGINAL, 10);
		msg.data.attr->mt_id = 2;
		SET_FLAG(msg.data.attr->flags, LS_ATTR_MT_ID);
		current.nlri_data.link.link_desc.mt_id = 2;
		SET_FLAG(current.nlri_data.link.link_desc.present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT);
		if (step) {
			msg.data.attr->standard.remote6 = address6(1, REPLACEMENT);
			current.nlri_data.link.link_desc.ipv6_neigh_addr = address6(1, REPLACEMENT);
		}
		assert(bgp_ls_process_message(bgp, &msg) == 0);
		ok &= !find_path(bgp, &old).path && find_path(bgp, &current).path &&
		      find_path(bgp, &reverse).path && active_links(bgp) == 2;
		old = current;
	}
	assert(send_edge(bgp, 0, ORIGINAL, 10, LS_MSG_EVENT_UPDATE) == 0);
	check("mtid_and_remote_ipv6_identity",
	      ok && !find_path(bgp, &old).path && exact_pair(bgp, ORIGINAL, ORIGINAL));
	bgp_delete(bgp);
}

static void test_reverse_arrival(void)
{
	bool ok = true;

	for (unsigned int first = 0; first < 2; first++) {
		struct bgp *bgp = fixture_new();

		assert(send_edge(bgp, first, ORIGINAL, 10, LS_MSG_EVENT_UPDATE) == 0);
		ok &= active_links(bgp) == 0;
		assert(send_edge(bgp, !first, ORIGINAL, 10, LS_MSG_EVENT_ADD) == 0);
		ok &= exact_pair(bgp, ORIGINAL, ORIGINAL);
		bgp_delete(bgp);
	}
	check("missing_old_and_reverse_arrival", ok);
}

static void test_primary_key_migration(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri old = expected_link(0, ORIGINAL);
	struct bgp_ls_nlri moved = old;
	struct bgp_ls_nlri reverse = expected_link(1, ORIGINAL);
	struct ls_message msg = {
		.type = LS_MSG_TYPE_ATTRIBUTES,
		.event = LS_MSG_EVENT_ADD,
		.data.attr = edge_attributes(0, ORIGINAL, 10),
	};
	bool ok;

	seed_edges(bgp, ORIGINAL);
	assert(inet_pton(AF_INET, "10.254.0.10", &msg.data.attr->standard.local) == 1);
	moved.nlri_data.link.link_desc.ipv4_intf_addr = msg.data.attr->standard.local;
	assert(bgp_ls_process_message(bgp, &msg) == 0);
	ok = find_path(bgp, &old).path && find_path(bgp, &moved).path && active_links(bgp) == 3;
	// Primary-key migration uses ADD(new), then DELETE(old).
	assert(send_edge(bgp, 0, ORIGINAL, 10, LS_MSG_EVENT_DELETE) == 0);
	check("primary_key_add_delete",
	      ok && !find_path(bgp, &old).path && find_path(bgp, &moved).path &&
		      find_path(bgp, &reverse).path && active_links(bgp) == 2);
	bgp_delete(bgp);
}

static void test_rejected_update(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri key = expected_link(0, ORIGINAL);
	struct ls_message msg = { .type = LS_MSG_TYPE_ATTRIBUTES, .event = LS_MSG_EVENT_UPDATE };
	struct path_state before;
	uint64_t queued;
	bool ok;

	seed_edges(bgp, ORIGINAL);
	before = find_path(bgp, &key);
	queued = bgp->node_already_on_queue;
	ok = bgp_ls_process_message(bgp, NULL) < 0;
	ok &= bgp_ls_process_message(bgp, &msg) < 0;
	msg.event = LS_MSG_EVENT_UNDEF;
	msg.data.attr = edge_attributes(0, ABSENT, 10);
	ok &= bgp_ls_process_message(bgp, &msg) < 0;
	ls_attributes_del(msg.data.attr);
	check("rejected_update_preserves_route", ok && exact_pair(bgp, ORIGINAL, ORIGINAL) &&
							 find_path(bgp, &key).path == before.path &&
							 bgp->node_already_on_queue == queued);
	bgp_delete(bgp);
}

static void test_unadvertisable_update(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri old = expected_link(0, ORIGINAL);
	struct bgp_ls_nlri reverse = expected_link(1, ORIGINAL);
	struct ls_message msg = {
		.type = LS_MSG_TYPE_ATTRIBUTES,
		.event = LS_MSG_EVENT_UPDATE,
		.data.attr = edge_attributes(0, ABSENT, 10),
	};
	bool ok;

	seed_edges(bgp, ORIGINAL);
	// An accepted edge without an address pair must be withdrawn.
	UNSET_FLAG(msg.data.attr->flags, LS_ATTR_NEIGH_ADDR);
	msg.data.attr->standard.remote.s_addr = 0;
	ok = bgp_ls_process_message(bgp, &msg) == 0;
	check("unadvertisable_update_withdraws_old", ok && !find_path(bgp, &old).path &&
							     find_path(bgp, &reverse).path &&
							     active_links(bgp) == 1);
	bgp_delete(bgp);
}

static void test_connected_unadvertisable_update(void)
{
	struct bgp *bgp = fixture_new();
	struct bgp_ls_nlri forward = expected_link(0, ORIGINAL);
	struct bgp_ls_nlri reverse = expected_link(1, ORIGINAL);
	struct ls_attributes query = { .flags = LS_ATTR_LOCAL_ADDR, .standard.local = address4(0) };
	struct ls_message msg = { .type = LS_MSG_TYPE_ATTRIBUTES, .event = LS_MSG_EVENT_ADD };
	struct ls_edge *edge;
	bool ok;

	// Different key families keep the endpoints connected.
	for (unsigned int direction = 0; direction < 2; direction++) {
		msg.data.attr = edge_attributes(direction, ORIGINAL, 10);
		if (direction) {
			UNSET_FLAG(msg.data.attr->flags, LS_ATTR_LOCAL_ADDR);
			msg.data.attr->standard.local.s_addr = 0;
		} else {
			UNSET_FLAG(msg.data.attr->flags, LS_ATTR_NEIGH_ADDR);
			msg.data.attr->standard.remote.s_addr = 0;
		}
		assert(bgp_ls_process_message(bgp, &msg) == 0);
	}
	UNSET_FLAG(forward.nlri_data.link.link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT);
	forward.nlri_data.link.link_desc.ipv4_neigh_addr.s_addr = 0;
	UNSET_FLAG(reverse.nlri_data.link.link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT);
	reverse.nlri_data.link.link_desc.ipv4_intf_addr.s_addr = 0;
	edge = ls_find_edge_by_source(bgp->ls_info->ted, &query);
	ok = edge && edge->source && edge->destination && find_path(bgp, &forward).path &&
	     find_path(bgp, &reverse).path && active_links(bgp) == 2;

	msg.event = LS_MSG_EVENT_UPDATE;
	msg.data.attr = edge_attributes(0, ABSENT, 10);
	UNSET_FLAG(msg.data.attr->flags, LS_ATTR_NEIGH_ADDR);
	msg.data.attr->standard.remote.s_addr = 0;
	assert(bgp_ls_process_message(bgp, &msg) == 0);
	edge = ls_find_edge_by_source(bgp->ls_info->ted, &query);
	// Prove the edge is connected but has no complete address pair.
	check("connected_unadvertisable_withdraws_old",
	      ok && edge && edge->source && edge->destination &&
		      !CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR6) &&
		      !find_path(bgp, &forward).path && find_path(bgp, &reverse).path &&
		      active_links(bgp) == 1);
	bgp_delete(bgp);
}

int main(void)
{
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

	// Worker threads run; the main loop stays undrained. No peer exists.
	test_captured_wire();
	test_transition("partial_to_full", ABSENT, ORIGINAL, LS_MSG_EVENT_UPDATE);
	test_transition("full_to_partial", ORIGINAL, ABSENT, LS_MSG_EVENT_UPDATE);
	test_transition("ipv6_address_replacement", ORIGINAL, REPLACEMENT, LS_MSG_EVENT_UPDATE);
	test_transition("add_replaces_existing", ABSENT, ORIGINAL, LS_MSG_EVENT_ADD);
	test_transition("sync_replaces_existing", ABSENT, ORIGINAL, LS_MSG_EVENT_SYNC);
	test_repeated_and_delete();
	test_attribute_updates();
	test_descriptor_changes();
	test_reverse_arrival();
	test_primary_key_migration();
	test_rejected_update();
	test_unadvertisable_update();
	test_connected_unadvertisable_update();
	bgp_pthreads_finish();
	printf("BGPLS_SUMMARY failures=%u\n", failures);
	return failures ? 1 : 0;
}
