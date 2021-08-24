/*
 * Nexthop module test.
 *
 * Copyright (C) 2021 by Volta Networks, Inc.
 *
 * This file is part of FRR.
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
#include <nexthop.h>

static bool verbose;

static void test_run_first(void)
{
	int ret, i;
	struct nexthop *nh1, *nh2;
	struct in_addr addr;
	struct in6_addr addr6;
	mpls_label_t labels[MPLS_MAX_LABELS];

	/* Test comparison apis */

	/* ifindex comparisons */
	nh1 = nexthop_from_ifindex(11, 0);
	nh2 = nexthop_from_ifindex(12, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret < 0);

	nexthop_free(nh1);
	nh1 = nexthop_from_ifindex(12, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh1);
	nexthop_free(nh2);

	/* ipv4, vrf */
	addr.s_addr = 0x04030201;
	nh1 = nexthop_from_ipv4(&addr, NULL, 0);
	nh2 = nexthop_from_ipv4(&addr, NULL, 111);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh2);

	addr.s_addr = 0x04030202;
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh2);

	addr.s_addr = 0x04030201;
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	/* Weight */
	nh2->weight = 20;

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh1);
	nexthop_free(nh2);

	/* ipv6 */
	memset(addr6.s6_addr, 0, sizeof(addr6.s6_addr));
	nh1 = nexthop_from_ipv6(&addr6, 0);
	nh2 = nexthop_from_ipv6(&addr6, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh2);

	nh2 = nexthop_from_ipv6(&addr6, 1);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh2);

	addr6.s6_addr[14] = 1;
	addr6.s6_addr[15] = 1;
	nh2 = nexthop_from_ipv6(&addr6, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh1);
	nexthop_free(nh2);

	/* Blackhole */
	nh1 = nexthop_from_blackhole(BLACKHOLE_REJECT, 0);
	nh2 = nexthop_from_blackhole(BLACKHOLE_REJECT, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh2);

	nh2 = nexthop_from_blackhole(BLACKHOLE_NULL, 0);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	/* Labels */
	addr.s_addr = 0x04030201;
	nh1 = nexthop_from_ipv4(&addr, NULL, 0);
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);

	memset(labels, 0, sizeof(labels));
	labels[0] = 111;
	labels[1] = 222;

	nexthop_add_labels(nh1, ZEBRA_LSP_STATIC, 2, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_add_labels(nh2, ZEBRA_LSP_STATIC, 2, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh2);

	/* LSP type isn't included */
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);
	nexthop_add_labels(nh2, ZEBRA_LSP_LDP, 2, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh2);

	labels[2] = 333;
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);
	nexthop_add_labels(nh2, ZEBRA_LSP_LDP, 3, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	nexthop_free(nh1);
	nexthop_free(nh2);

	nh1 = nexthop_from_ipv4(&addr, NULL, 0);
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);

	for (i = 0; i < MPLS_MAX_LABELS; i++)
		labels[i] = 111 * (i + 1);

	nexthop_add_labels(nh1, ZEBRA_LSP_LDP, MPLS_MAX_LABELS, labels);
	nexthop_add_labels(nh2, ZEBRA_LSP_LDP, MPLS_MAX_LABELS, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret == 0);

	nexthop_free(nh2);

	/* Test very last label in stack */
	labels[15] = 999;
	nh2 = nexthop_from_ipv4(&addr, NULL, 0);
	nexthop_add_labels(nh2, ZEBRA_LSP_LDP, MPLS_MAX_LABELS, labels);

	ret = nexthop_cmp_basic(nh1, nh2);
	assert(ret != 0);

	/* End */
	nexthop_free(nh1);
	nexthop_free(nh2);
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp("-v", argv[1]))
		verbose = true;
	test_run_first();
	printf("Simple test passed.\n");
}
