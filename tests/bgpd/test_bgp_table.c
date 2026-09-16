// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Routing table range lookup test
 * Copyright (C) 2012 OSR.
 * Copyright (C) 2018 Marcel Röthke (marcel.roethke@haw-hamburg.de), for HAW
 * Hamburg
 *
 * This file is part of FRRouting
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "bgpd/bgp_table.h"
#include "linklist.h"

/* Satisfy link requirements from including bgpd.h */
struct zebra_privs_t bgpd_privs = {0};
/*
 * test_node_t
 *
 * Information that is kept for each node in the radix tree.
 */
struct test_node_t {
	/*
	 * Human readable representation of the string.
	 */
	const char *prefix_str;
};

/*
 * add_node
 *
 * Add the given prefix (passed in as a string) to the given table.
 */
static void add_node(struct bgp_table *table, const char *prefix_str, struct test_node_t *tn)
{
	struct prefix_ipv4 p;
	struct bgp_dest *dest;

	assert(prefix_str);

	if (str2prefix_ipv4(prefix_str, &p) <= 0)
		assert(0);

	dest = bgp_node_get(table, (struct prefix *)&p);
	if (dest->info) {
		assert(0);
		return;
	}

	tn->prefix_str = prefix_str;
	dest->info = tn;
}

static bool prefix_in_array(const struct prefix *p, struct prefix *prefix_array,
			    size_t prefix_array_size)
{
	for (size_t i = 0; i < prefix_array_size; ++i) {
		if (prefix_same(p, &prefix_array[i]))
			return true;
	}
	return false;
}

static void check_lookup_result(struct bgp_dest *match, va_list arglist)
{
	char *prefix_str;
	struct prefix *prefixes = NULL;
	size_t prefix_count = 0;

	while ((prefix_str = va_arg(arglist, char *))) {
		++prefix_count;
		prefixes = realloc(prefixes, sizeof(*prefixes) * prefix_count);

		if (str2prefix(prefix_str, &prefixes[prefix_count - 1]) <= 0)
			assert(0);
	}

	/* check if the result is empty and if it is allowd to be empty */
	assert((prefix_count == 0 && !match) || prefix_count > 0);
	if (!match) {
		free(prefixes);
		return;
	}

	struct bgp_dest *dest = match;

	while ((dest = bgp_route_next_until(dest, match))) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (bgp_dest_has_bgp_path_info_data(dest)
		    && !prefix_in_array(dest_p, prefixes, prefix_count)) {
			printf("prefix %pFX was not expected!\n", dest_p);
			assert(0);
		}
	}

	free(prefixes);
}

static void do_test(struct bgp_table *table, const char *prefix, ...)
{
	va_list arglist;
	struct prefix p;


	va_start(arglist, prefix);
	printf("\nDoing lookup for %s\n", prefix);
	if (str2prefix(prefix, &p) <= 0)
		assert(0);
	struct bgp_dest *dest = bgp_table_subtree_lookup(table, &p);

	check_lookup_result(dest, arglist);

	va_end(arglist);

	printf("Checks successfull\n");
}

/*
 * test_range_lookup
 */
static void test_range_lookup(void)
{
	struct bgp_table *table = bgp_table_init(NULL, AFI_IP, SAFI_UNICAST);

	printf("Testing bgp_table_range_lookup\n");

	printf("Setup bgp_table");
	static const char *const prefixes[] = { "1.16.0.0/16",	"1.16.128.0/18", "1.16.192.0/18",
						"1.16.64.0/19", "1.16.160.0/19", "1.16.32.0/20",
						"1.16.32.0/21", "16.0.0.0/16" };

	int num_prefixes = array_size(prefixes);
	struct test_node_t tns[num_prefixes];

	for (int i = 0; i < num_prefixes; i++)
		add_node(table, prefixes[i], &tns[i]);

	do_test(table, "1.16.0.0/17", "1.16.64.0/19", "1.16.32.0/20",
		"1.16.32.0/20", "1.16.32.0/21", NULL);
	do_test(table, "1.16.128.0/17", "1.16.128.0/18", "1.16.192.0/18",
		"1.16.160.0/19", NULL);

	do_test(table, "1.16.0.0/16", "1.16.0.0/16", "1.16.128.0/18",
		"1.16.192.0/18", "1.16.64.0/19", "1.16.160.0/19",
		"1.16.32.0/20", "1.16.32.0/21", NULL);

	do_test(table, "1.17.0.0/16", NULL);

	do_test(table, "128.0.0.0/8", NULL);

	do_test(table, "16.0.0.0/8", "16.0.0.0/16", NULL);

	do_test(table, "0.0.0.0/2", "1.16.0.0/16", "1.16.128.0/18",
		"1.16.192.0/18", "1.16.64.0/19", "1.16.160.0/19",
		"1.16.32.0/20", "1.16.32.0/21", "16.0.0.0/16", NULL);

	bgp_table_finish(&table);
}

/*
 * Reference-count checks for BGP_DEST_AUTOUNLOCK.
 *
 * add_node() leaves exactly one permanent reference on each dest it adds, so
 * any balanced operation must leave the count back at one.
 */

/*
 * stable_lock_count
 *
 * Reference count of the dest for the given prefix, discounting the reference
 * taken by the lookup this helper does itself.
 */
static unsigned int stable_lock_count(struct bgp_table *table, const char *prefix_str)
{
	struct prefix p;
	struct bgp_dest *dest;
	unsigned int locks;

	if (str2prefix(prefix_str, &p) <= 0)
		assert(0);

	dest = bgp_node_lookup(table, &p);
	assert(dest);
	locks = route_node_get_lock_count(bgp_dest_to_rnode(dest));
	bgp_dest_unlock_node(dest);

	return locks - 1;
}

/*
 * One acquire, more than one exit.  Neither path releases the dest by hand.
 */
static void autounlock_single(struct bgp_table *table, const char *prefix_str, bool early)
{
	struct prefix p;

	if (str2prefix(prefix_str, &p) <= 0)
		assert(0);

	struct bgp_dest *dest BGP_DEST_AUTOUNLOCK = bgp_node_lookup(table, &p);

	assert(dest);
	if (early)
		return;

	assert(bgp_dest_get_prefix(dest));
}

/*
 * A walk left early.  route_next() only releases the current dest when it
 * advances, so leaving the loop early is what used to leak.  A NULL stop
 * prefix runs the walk to completion instead.
 */
static bool autounlock_walk(struct bgp_table *table, const struct prefix *stop)
{
	struct bgp_dest *dest BGP_DEST_AUTOUNLOCK = NULL;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		if (stop && prefix_same(bgp_dest_get_prefix(dest), stop))
			return true;

	return false;
}

/*
 * The same walk without the attribute, which must leak, so that the checks
 * above are known to be able to detect a regression.  The caller releases
 * the returned dest.
 */
static struct bgp_dest *leaky_walk(struct bgp_table *table, const struct prefix *stop)
{
	struct bgp_dest *dest;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		if (prefix_same(bgp_dest_get_prefix(dest), stop))
			return dest;

	return NULL;
}

/*
 * test_autounlock
 */
static void test_autounlock(void)
{
	struct bgp_table *table = bgp_table_init(NULL, AFI_IP, SAFI_UNICAST);
	static const char *const prefixes[] = { "10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24",
						"10.2.0.0/16" };
	int num_prefixes = array_size(prefixes);
	struct test_node_t tns[num_prefixes];
	struct bgp_dest *leaked;
	unsigned long count;
	struct prefix stop;

	printf("\nTesting BGP_DEST_AUTOUNLOCK reference counts\n");

	for (int i = 0; i < num_prefixes; i++)
		add_node(table, prefixes[i], &tns[i]);
	count = bgp_table_count(table);

	for (int i = 0; i < num_prefixes; i++)
		assert(stable_lock_count(table, prefixes[i]) == 1);
	printf("Checks successfull\n");

	/* one acquire, early exit and full path */
	autounlock_single(table, "10.1.0.0/16", true);
	assert(stable_lock_count(table, "10.1.0.0/16") == 1);
	autounlock_single(table, "10.1.0.0/16", false);
	assert(stable_lock_count(table, "10.1.0.0/16") == 1);
	printf("Checks successfull\n");

	/* walk left early, stopping at each position in turn */
	for (int i = 0; i < num_prefixes; i++) {
		if (str2prefix(prefixes[i], &stop) <= 0)
			assert(0);

		assert(autounlock_walk(table, &stop));

		for (int j = 0; j < num_prefixes; j++)
			assert(stable_lock_count(table, prefixes[j]) == 1);
	}
	printf("Checks successfull\n");

	/* walk run to completion, where the cleanup must be a no-op */
	assert(!autounlock_walk(table, NULL));
	for (int i = 0; i < num_prefixes; i++)
		assert(stable_lock_count(table, prefixes[i]) == 1);
	printf("Checks successfull\n");

	/* control: the same walk without the attribute leaks one reference */
	if (str2prefix(prefixes[1], &stop) <= 0)
		assert(0);
	leaked = leaky_walk(table, &stop);
	assert(leaked);
	assert(stable_lock_count(table, prefixes[1]) == 2);
	bgp_dest_unlock_node(leaked);
	assert(stable_lock_count(table, prefixes[1]) == 1);
	printf("Checks successfull\n");

	/* nothing was created or destroyed along the way */
	assert(bgp_table_count(table) == count);

	bgp_table_finish(&table);
}

int main(void)
{
	test_range_lookup();
	test_autounlock();
}
