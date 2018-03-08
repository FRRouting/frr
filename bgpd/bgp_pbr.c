/*
 * BGP pbr
 * Copyright (C) 6WIND
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

#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_pbr.h"

uint32_t bgp_pbr_match_hash_key(void *arg)
{
	struct bgp_pbr_match *pbm = (struct bgp_pbr_match *)arg;
	uint32_t key;

	key = jhash_1word(pbm->vrf_id, 0x4312abde);
	key = jhash_1word(pbm->flags, key);
	return jhash_1word(pbm->type, key);
}

int bgp_pbr_match_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match *r1, *r2;

	r1 = (const struct bgp_pbr_match *)arg1;
	r2 = (const struct bgp_pbr_match *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (r1->type != r2->type)
		return 0;

	if (r1->flags != r2->flags)
		return 0;

	if (r1->action != r2->action)
		return 0;

	return 1;
}

uint32_t bgp_pbr_match_entry_hash_key(void *arg)
{
	struct bgp_pbr_match_entry *pbme;
	uint32_t key;

	pbme = (struct bgp_pbr_match_entry *)arg;
	key = prefix_hash_key(&pbme->src);
	key = jhash_1word(prefix_hash_key(&pbme->dst), key);

	return key;
}

int bgp_pbr_match_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match_entry *r1, *r2;

	r1 = (const struct bgp_pbr_match_entry *)arg1;
	r2 = (const struct bgp_pbr_match_entry *)arg2;

	/* on updates, comparing
	 * backpointer is not necessary
	 */

	/* unique value is self calculated
	 */

	/* rate is ignored for now
	 */

	if (!prefix_same(&r1->src, &r2->src))
		return 0;

	if (!prefix_same(&r1->dst, &r2->dst))
		return 0;

	return 1;
}

uint32_t bgp_pbr_action_hash_key(void *arg)
{
	struct bgp_pbr_action *pbra;
	uint32_t key;

	pbra = (struct bgp_pbr_action *)arg;
	key = jhash_1word(pbra->table_id, 0x4312abde);
	key = jhash_1word(pbra->fwmark, key);
	return key;
}

int bgp_pbr_action_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_action *r1, *r2;

	r1 = (const struct bgp_pbr_action *)arg1;
	r2 = (const struct bgp_pbr_action *)arg2;

	/* unique value is self calculated
	 * table and fwmark is self calculated
	 */
	if (r1->rate != r2->rate)
		return 0;

	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (memcmp(&r1->nh, &r2->nh, sizeof(struct nexthop)))
		return 0;
	return 1;
}

struct bgp_pbr_action *bgp_pbr_action_rule_lookup(uint32_t unique)
{
	return NULL;
}

struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
						 uint32_t unique)
{
	return NULL;
}

struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(vrf_id_t vrf_id,
						       char *ipset_name,
						       uint32_t unique)
{
	return NULL;
}

void bgp_pbr_init(struct bgp *bgp)
{
	bgp->pbr_match_hash =
		hash_create_size(8, bgp_pbr_match_hash_key,
				 bgp_pbr_match_hash_equal,
				 "Match Hash");
	bgp->pbr_action_hash =
		hash_create_size(8, bgp_pbr_action_hash_key,
				 bgp_pbr_action_hash_equal,
				 "Match Hash Entry");
}
