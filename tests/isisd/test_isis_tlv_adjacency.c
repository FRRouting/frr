// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#include "test_common.h"

#include "isisd/isis_adjacency.h"
#include "isisd/isis_tlvs.h"

static unsigned int enabled_count, disabled_count;
static bool nexthop_enabled;
static struct in_addr nexthop;

static int ipv4_enabled(struct isis_adjacency *adj, int family, bool global)
{
	assert(family == AF_INET && !global);
	assert(!nexthop_enabled);
	assert(adj->ipv4_address_count);
	nexthop = adj->ipv4_addresses[0];
	nexthop_enabled = true;
	enabled_count++;
	return 0;
}

static int ipv4_disabled(struct isis_adjacency *adj, int family, bool global)
{
	assert(family == AF_INET && !global);
	assert(nexthop_enabled);
	/* Consumers must see the old address before it is replaced. */
	assert(adj->ipv4_address_count);
	assert(IPV4_ADDR_SAME(&nexthop, &adj->ipv4_addresses[0]));
	nexthop_enabled = false;
	disabled_count++;
	return 0;
}

static void update_addresses(struct isis_adjacency *adj, const char *first, const char *second,
			     bool want_changed, unsigned int want_enabled,
			     unsigned int want_disabled)
{
	struct isis_tlvs *tlvs = isis_alloc_tlvs();
	struct in_addr addr;
	bool changed;

	if (first) {
		assert(inet_pton(AF_INET, first, &addr) == 1);
		isis_tlvs_add_ipv4_address(tlvs, &addr);
	}
	if (second) {
		assert(inet_pton(AF_INET, second, &addr) == 1);
		isis_tlvs_add_ipv4_address(tlvs, &addr);
	}

	isis_tlvs_to_adj(tlvs, adj, &changed);
	assert(changed == want_changed);
	assert(enabled_count == want_enabled);
	assert(disabled_count == want_disabled);
	assert(nexthop_enabled == (first != NULL));
	if (first) {
		assert(inet_pton(AF_INET, first, &addr) == 1);
		assert(IPV4_ADDR_SAME(&nexthop, &addr));
	}
	isis_free_tlvs(tlvs);
}

int main(int argc, char **argv)
{
	struct isis_adjacency adj = {};

	hook_register(isis_adj_ip_enabled_hook, ipv4_enabled);
	hook_register(isis_adj_ip_disabled_hook, ipv4_disabled);

	update_addresses(&adj, NULL, NULL, false, 0, 0);
	update_addresses(&adj, "10.0.2.4", NULL, true, 1, 0);
	update_addresses(&adj, "10.0.2.4", NULL, false, 1, 0);

	/* Removing the link address borrows the neighbor's loopback instead. */
	update_addresses(&adj, "4.4.4.4", NULL, true, 2, 1);
	update_addresses(&adj, "4.4.4.4", NULL, false, 2, 1);

	/* Secondary address changes must not churn the primary Adj-SID. */
	update_addresses(&adj, "4.4.4.4", "10.10.10.10", true, 2, 1);
	update_addresses(&adj, "4.4.4.4", "10.10.10.11", true, 2, 1);
	update_addresses(&adj, "4.4.4.4", NULL, true, 2, 1);

	/* Also cover a replacement that changes the number of addresses. */
	update_addresses(&adj, "10.0.2.4", "10.0.2.5", true, 3, 2);
	update_addresses(&adj, "10.0.2.5", "10.0.2.4", true, 4, 3);
	update_addresses(&adj, NULL, NULL, true, 4, 4);
	update_addresses(&adj, NULL, NULL, false, 4, 4);

	hook_unregister(isis_adj_ip_enabled_hook, ipv4_enabled);
	hook_unregister(isis_adj_ip_disabled_hook, ipv4_disabled);
	XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj.ipv4_addresses);
	printf("OK\n");
	return 0;
}
