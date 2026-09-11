// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Link State database tests.
 *
 * Copyright (C) 2026 Carmine Scarpitta
 */

#include <zebra.h>

#include "link_state.h"

static struct in_addr ipv4(const char *address)
{
	struct in_addr result;

	assert(inet_pton(AF_INET, address, &result) == 1);
	return result;
}

static struct ls_node_id node_id(uint8_t id)
{
	struct ls_node_id result = {
		.origin = ISIS_L1,
		.id.iso.level = 1,
	};

	result.id.iso.sys_id[ISO_SYS_ID_LEN - 1] = id;
	return result;
}

static struct ls_attributes *edge_attributes(uint8_t advertiser, const char *local,
					     const char *remote)
{
	struct ls_attributes *attributes;

	attributes = ls_attributes_new(node_id(advertiser), ipv4(local), in6addr_any, 0);
	assert(attributes);

	attributes->standard.remote = ipv4(remote);
	SET_FLAG(attributes->flags, LS_ATTR_NEIGH_ADDR);
	return attributes;
}

/*
 * Verify that edge updates and reverse-edge insertion keep the TED
 * consistent through teardown.
 */
static void test_edge_remote_endpoint_update(void)
{
	struct ls_ted *ted;
	struct ls_edge *a_to_b;
	struct ls_edge *b_to_a;
	struct ls_edge *c_to_b;
	struct ls_vertex *a;
	struct ls_vertex *b;
	struct ls_vertex *c;

	ted = ls_ted_new(1, "link-state-test", 0);
	assert(ted);

	a_to_b = ls_edge_add(ted, edge_attributes(3, "10.0.0.3", "10.0.0.1"));
	b_to_a = ls_edge_add(ted, edge_attributes(1, "10.0.0.1", "10.0.0.3"));
	assert(a_to_b && b_to_a);
	assert(a_to_b->destination == b_to_a->source);
	assert(b_to_a->destination == a_to_b->source);

	a = a_to_b->source;
	b = b_to_a->source;
	assert(a->key > b->key);

	assert(ls_edge_update(ted, edge_attributes(1, "10.0.0.1", "10.0.0.2")) == b_to_a);
	assert(b_to_a->destination == NULL);
	assert(listnode_lookup(a->incoming_edges, b_to_a) == NULL);

	c_to_b = ls_edge_add(ted, edge_attributes(2, "10.0.0.2", "10.0.0.1"));
	assert(c_to_b);
	c = c_to_b->source;
	assert(c->key > b->key && c->key < a->key);
	assert(b_to_a->destination == c);
	assert(c_to_b->destination == b);

	ls_ted_del_all(&ted);
	assert(ted == NULL);
}

int main(void)
{
	test_edge_remote_endpoint_update();
	printf("Link State database tests passed.\n");
}
