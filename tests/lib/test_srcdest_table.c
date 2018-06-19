/*
 * Test srcdest table for correctness.
 *
 * Copyright (C) 2017 by David Lamparter & Christian Franke,
 *                       Open Source Routing / NetDEF Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "hash.h"
#include "memory.h"
#include "prefix.h"
#include "prng.h"
#include "srcdest_table.h"
#include "table.h"

/* Copied from ripngd/ripng_nexthop.h - maybe the whole s6_addr32 thing
 * should be added by autoconf if not present?
 */
#ifndef s6_addr32
#if defined(SUNOS_5)
/* Some SunOS define s6_addr32 only to kernel */
#define s6_addr32 _S6_un._S6_u32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif /* SUNOS_5 */
#endif /*s6_addr32*/

struct thread_master *master;

/* This structure is copied from lib/srcdest_table.c to which it is
 * private as far as other parts of Quagga are concerned.
 */
struct srcdest_rnode {
	/* must be first in structure for casting to/from route_node */
	ROUTE_NODE_FIELDS;

	struct route_table *src_table;
};

struct test_state {
	struct route_table *table;
	struct hash *log;
};

static char *format_srcdest(const struct prefix_ipv6 *dst_p,
			    const struct prefix_ipv6 *src_p)
{
	char dst_str[BUFSIZ];
	char src_str[BUFSIZ];
	char *rv;
	int ec;

	prefix2str((const struct prefix *)dst_p, dst_str, sizeof(dst_str));
	if (src_p && src_p->prefixlen)
		prefix2str((const struct prefix *)src_p, src_str,
			   sizeof(src_str));
	else
		src_str[0] = '\0';

	ec = asprintf(&rv, "%s%s%s", dst_str,
		      (src_str[0] != '\0') ? " from " : "", src_str);

	assert(ec > 0);
	return rv;
}

static unsigned int log_key(void *data)
{
	struct prefix *hash_entry = data;
	struct prefix_ipv6 *dst_p = (struct prefix_ipv6 *)&hash_entry[0];
	struct prefix_ipv6 *src_p = (struct prefix_ipv6 *)&hash_entry[1];
	unsigned int hash = 0;
	unsigned int i;

	hash = (hash * 33) ^ (unsigned int)dst_p->prefixlen;
	for (i = 0; i < 4; i++)
		hash = (hash * 33) ^ (unsigned int)dst_p->prefix.s6_addr32[i];

	hash = (hash * 33) ^ (unsigned int)src_p->prefixlen;
	if (src_p->prefixlen)
		for (i = 0; i < 4; i++)
			hash = (hash * 33)
			       ^ (unsigned int)src_p->prefix.s6_addr32[i];

	return hash;
}

static int log_cmp(const void *a, const void *b)
{
	if (a == NULL || b == NULL)
		return 0;

	return !memcmp(a, b, 2 * sizeof(struct prefix));
}

static void log_free(void *data)
{
	XFREE(MTYPE_TMP, data);
}

static void *log_alloc(void *data)
{
	void *rv = XMALLOC(MTYPE_TMP, 2 * sizeof(struct prefix));
	memcpy(rv, data, 2 * sizeof(struct prefix));
	return rv;
}

static struct test_state *test_state_new(void)
{
	struct test_state *rv;

	rv = XCALLOC(MTYPE_TMP, sizeof(*rv));
	assert(rv);

	rv->table = srcdest_table_init();
	assert(rv->table);

	rv->log = hash_create(log_key, log_cmp, NULL);
	return rv;
}

static void test_state_free(struct test_state *test)
{
	route_table_finish(test->table);
	hash_clean(test->log, log_free);
	hash_free(test->log);
	XFREE(MTYPE_TMP, test);
}

static void test_state_add_route(struct test_state *test,
				 struct prefix_ipv6 *dst_p,
				 struct prefix_ipv6 *src_p)
{
	struct route_node *rn =
		srcdest_rnode_get(test->table, (struct prefix *)dst_p, src_p);
	struct prefix hash_entry[2];

	memset(hash_entry, 0, sizeof(hash_entry));
	memcpy(&hash_entry[0], dst_p, sizeof(*dst_p));
	memcpy(&hash_entry[1], src_p, sizeof(*src_p));

	if (rn->info) {
		route_unlock_node(rn);
		assert(hash_lookup(test->log, hash_entry) != NULL);
		return;
	} else {
		assert(hash_lookup(test->log, hash_entry) == NULL);
	}

	rn->info = (void *)0xdeadbeef;
	hash_get(test->log, hash_entry, log_alloc);
};

static void test_state_del_route(struct test_state *test,
				 struct prefix_ipv6 *dst_p,
				 struct prefix_ipv6 *src_p)
{
	struct route_node *rn = srcdest_rnode_lookup(
		test->table, (struct prefix *)dst_p, src_p);
	struct prefix hash_entry[2];

	memset(hash_entry, 0, sizeof(hash_entry));
	memcpy(&hash_entry[0], dst_p, sizeof(*dst_p));
	memcpy(&hash_entry[1], src_p, sizeof(*src_p));

	if (!rn) {
		assert(!hash_lookup(test->log, hash_entry));
		return;
	}

	assert(rn->info == (void *)0xdeadbeef);
	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);

	struct prefix *hash_entry_intern = hash_release(test->log, hash_entry);
	assert(hash_entry_intern != NULL);
	XFREE(MTYPE_TMP, hash_entry_intern);
}

static void verify_log(struct hash_backet *backet, void *arg)
{
	struct test_state *test = arg;
	struct prefix *hash_entry = backet->data;
	struct prefix *dst_p = &hash_entry[0];
	struct prefix_ipv6 *src_p = (struct prefix_ipv6 *)&hash_entry[1];
	struct route_node *rn = srcdest_rnode_lookup(test->table, dst_p, src_p);

	assert(rn);
	assert(rn->info == (void *)0xdeadbeef);

	route_unlock_node(rn);
}

static void dump_log(struct hash_backet *backet, void *arg)
{
	struct prefix *hash_entry = backet->data;
	struct prefix_ipv6 *dst_p = (struct prefix_ipv6 *)&hash_entry[0];
	struct prefix_ipv6 *src_p = (struct prefix_ipv6 *)&hash_entry[1];
	char *route_id = format_srcdest(dst_p, src_p);

	fprintf(stderr, "  %s\n", route_id);
	free(route_id);
}

static void test_dump(struct test_state *test)
{
	fprintf(stderr, "Contents of hash table:\n");
	hash_iterate(test->log, dump_log, test);
	fprintf(stderr, "\n");
}

static void test_failed(struct test_state *test, const char *message,
			struct prefix_ipv6 *dst_p, struct prefix_ipv6 *src_p)
{
	char *route_id = format_srcdest(dst_p, src_p);

	fprintf(stderr, "Test failed. Error: %s\n", message);
	fprintf(stderr, "Route in question: %s\n", route_id);
	free(route_id);

	test_dump(test);
	assert(3 == 4);
}

static void test_state_verify(struct test_state *test)
{
	struct route_node *rn;
	struct prefix hash_entry[2];

	memset(hash_entry, 0, sizeof(hash_entry));

	/* Verify that there are no elements in the table which have never
	 * been added */
	for (rn = route_top(test->table); rn; rn = srcdest_route_next(rn)) {
		struct prefix_ipv6 *dst_p, *src_p;

		/* While we are iterating, we hold a lock on the current
		 * route_node,
		 * so all the lock counts we check for take that into account;
		 * in idle
		 * state all the numbers will be exactly one less.
		 *
		 * Also this makes quite some assumptions based on the current
		 * implementation details of route_table and srcdest_table -
		 * another
		 * valid implementation might trigger assertions here.
		 */

		if (rnode_is_dstnode(rn)) {
			struct srcdest_rnode *srn = (struct srcdest_rnode *)rn;
			unsigned int expected_lock = 1; /* We are in the loop */

			if (rn->info
			    != NULL) /* The route node is not internal */
				expected_lock++;
			if (srn->src_table != NULL) /* There's a source table
						       associated with rn */
				expected_lock++;

			if (rn->lock != expected_lock)
				test_failed(
					test,
					"Dest rnode lock count doesn't match expected count!",
					(struct prefix_ipv6 *)&rn->p, NULL);
		} else {
			unsigned int expected_lock = 1; /* We are in the loop */

			if (rn->info
			    != NULL) /* The route node is not internal */
				expected_lock++;

			if (rn->lock != expected_lock) {
				struct prefix_ipv6 *dst_p, *src_p;
				srcdest_rnode_prefixes(
					rn, (struct prefix **)&dst_p,
					(struct prefix **)&src_p);

				test_failed(
					test,
					"Src rnode lock count doesn't match expected count!",
					dst_p, src_p);
			}
		}

		if (!rn->info)
			continue;

		assert(rn->info == (void *)0xdeadbeef);

		srcdest_rnode_prefixes(rn, (struct prefix **)&dst_p,
				       (struct prefix **)&src_p);
		memcpy(&hash_entry[0], dst_p, sizeof(*dst_p));
		if (src_p)
			memcpy(&hash_entry[1], src_p, sizeof(*src_p));
		else
			memset(&hash_entry[1], 0, sizeof(hash_entry[1]));

		if (hash_lookup(test->log, hash_entry) == NULL)
			test_failed(test, "Route is missing in hash", dst_p,
				    src_p);
	}

	/* Verify that all added elements are still in the table */
	hash_iterate(test->log, verify_log, test);
}

static void get_rand_prefix(struct prng *prng, struct prefix_ipv6 *p)
{
	int i;

	memset(p, 0, sizeof(*p));

	for (i = 0; i < 4; i++)
		p->prefix.s6_addr32[i] = prng_rand(prng);
	p->prefixlen = prng_rand(prng) % 129;
	p->family = AF_INET6;

	apply_mask((struct prefix *)p);
}

static void get_rand_prefix_pair(struct prng *prng, struct prefix_ipv6 *dst_p,
				 struct prefix_ipv6 *src_p)
{
	get_rand_prefix(prng, dst_p);
	if ((prng_rand(prng) % 4) == 0) {
		get_rand_prefix(prng, src_p);
		if (src_p->prefixlen)
			return;
	}

	memset(src_p, 0, sizeof(*src_p));
}

static void test_state_add_rand_route(struct test_state *test,
				      struct prng *prng)
{
	struct prefix_ipv6 dst_p, src_p;

	get_rand_prefix_pair(prng, &dst_p, &src_p);
	test_state_add_route(test, &dst_p, &src_p);
}

static void test_state_del_rand_route(struct test_state *test,
				      struct prng *prng)
{
	struct prefix_ipv6 dst_p, src_p;

	get_rand_prefix_pair(prng, &dst_p, &src_p);
	test_state_del_route(test, &dst_p, &src_p);
}

static void test_state_del_one_route(struct test_state *test, struct prng *prng)
{
	unsigned int which_route;

	if (test->log->count == 0)
		return;

	which_route = prng_rand(prng) % test->log->count;

	struct route_node *rn;
	struct prefix *dst_p, *src_p;
	struct prefix_ipv6 dst6_p, src6_p;

	for (rn = route_top(test->table); rn; rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		if (!which_route) {
			route_unlock_node(rn);
			break;
		}
		which_route--;
	}

	assert(rn);
	srcdest_rnode_prefixes(rn, &dst_p, &src_p);
	memcpy(&dst6_p, dst_p, sizeof(dst6_p));
	if (src_p)
		memcpy(&src6_p, src_p, sizeof(src6_p));
	else
		memset(&src6_p, 0, sizeof(src6_p));

	test_state_del_route(test, &dst6_p, &src6_p);
}

static void run_prng_test(void)
{
	struct test_state *test = test_state_new();
	struct prng *prng = prng_new(0);
	size_t i;

	for (i = 0; i < 1000; i++) {
		switch (prng_rand(prng) % 10) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
			test_state_add_rand_route(test, prng);
			break;
		case 5:
		case 6:
		case 7:
			test_state_del_one_route(test, prng);
			break;
		case 8:
		case 9:
			test_state_del_rand_route(test, prng);
			break;
		}
		test_state_verify(test);
	}

	prng_free(prng);
	test_state_free(test);
}

int main(int argc, char *argv[])
{
	run_prng_test();
	printf("PRNG Test successful.\n");
	return 0;
}
