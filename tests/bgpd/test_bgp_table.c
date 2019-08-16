/*
 * BGP Routing table range lookup test
 * Copyright (C) 2012 OSR.
 * Copyright (C) 2018 Marcel Röthke (marcel.roethke@haw-hamburg.de), for HAW
 * Hamburg
 *
 * This file is part of FRRouting
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
	 * Human readable representation of the string. Allocated using
	 * malloc()/dup().
	 */
	char *prefix_str;
};

/*
 * add_node
 *
 * Add the given prefix (passed in as a string) to the given table.
 */
static void add_node(struct bgp_table *table, const char *prefix_str)
{
	struct prefix_ipv4 p;
	struct test_node_t *node;
	struct bgp_node *rn;

	assert(prefix_str);

	if (str2prefix_ipv4(prefix_str, &p) <= 0)
		assert(0);

	rn = bgp_node_get(table, (struct prefix *)&p);
	if (rn->info) {
		assert(0);
		return;
	}

	node = malloc(sizeof(struct test_node_t));
	assert(node);
	node->prefix_str = strdup(prefix_str);
	assert(node->prefix_str);
	rn->info = node;
}

static void print_range_result(struct list *list)
{

	struct listnode *listnode;
	struct bgp_node *bnode;

	for (ALL_LIST_ELEMENTS_RO(list, listnode, bnode)) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(&bnode->p, buf, PREFIX2STR_BUFFER);
		printf("%s\n", buf);
	}
}

static void check_lookup_result(struct list *list, va_list arglist)
{
	char *prefix_str;
	unsigned int prefix_count = 0;

	printf("Searching results\n");
	while ((prefix_str = va_arg(arglist, char *))) {
		struct listnode *listnode;
		struct bgp_node *bnode;
		struct prefix p;
		bool found = false;

		prefix_count++;
		printf("Searching for %s\n", prefix_str);

		if (str2prefix(prefix_str, &p) <= 0)
			assert(0);

		for (ALL_LIST_ELEMENTS_RO(list, listnode, bnode)) {
			if (prefix_same(&bnode->p, &p))
				found = true;
		}

		assert(found);
	}

	printf("Checking for unexpected result items\n");
	printf("Expecting %d found %d\n", prefix_count, listcount(list));
	assert(prefix_count == listcount(list));
}

static void do_test(struct bgp_table *table, const char *prefix,
		    uint32_t maxlen, ...)
{
	va_list arglist;
	struct list *list = list_new();
	struct prefix p;

	list->del = (void (*)(void *))bgp_unlock_node;

	va_start(arglist, maxlen);
	printf("\nDoing lookup for %s-%d\n", prefix, maxlen);
	if (str2prefix(prefix, &p) <= 0)
		assert(0);
	bgp_table_range_lookup(table, &p, maxlen, list);
	print_range_result(list);

	check_lookup_result(list, arglist);

	list_delete(&list);

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
	const char *prefixes[] = {"1.16.0.0/16",   "1.16.128.0/18",
				  "1.16.192.0/18", "1.16.64.0/19",
				  "1.16.160.0/19", "1.16.32.0/20",
				  "1.16.32.0/21",  "16.0.0.0/16"};

	int num_prefixes = array_size(prefixes);

	for (int i = 0; i < num_prefixes; i++)
		add_node(table, prefixes[i]);

	do_test(table, "1.16.0.0/17", 20, "1.16.64.0/19", "1.16.32.0/20", NULL);
	do_test(table, "1.16.128.0/17", 20, "1.16.128.0/18", "1.16.192.0/18",
		"1.16.160.0/19", NULL);

	do_test(table, "1.16.128.0/17", 20, "1.16.128.0/18", "1.16.192.0/18",
		"1.16.160.0/19", NULL);

	do_test(table, "1.16.0.0/16", 18, "1.16.0.0/16", "1.16.128.0/18",
		"1.16.192.0/18", NULL);

	do_test(table, "1.16.0.0/16", 21, "1.16.0.0/16", "1.16.128.0/18",
		"1.16.192.0/18", "1.16.64.0/19", "1.16.160.0/19",
		"1.16.32.0/20", "1.16.32.0/21", NULL);

	do_test(table, "1.17.0.0/16", 20, NULL);

	do_test(table, "128.0.0.0/8", 16, NULL);

	do_test(table, "16.0.0.0/8", 16, "16.0.0.0/16", NULL);

	do_test(table, "0.0.0.0/2", 21, "1.16.0.0/16", "1.16.128.0/18",
		"1.16.192.0/18", "1.16.64.0/19", "1.16.160.0/19",
		"1.16.32.0/20", "1.16.32.0/21", "16.0.0.0/16", NULL);
}

int main(void)
{
	test_range_lookup();
}
