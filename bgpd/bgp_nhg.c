// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#include <zebra.h>
#include "memory.h"
#include "jhash.h"

#include <bgpd/bgpd.h>
#include <bgpd/bgp_debug.h>
#include <bgpd/bgp_nhg.h>
#include <bgpd/bgp_zebra.h>

extern struct zclient *zclient;

/* BGP NHG hash table. */
struct bgp_nhg_cache_head nhg_cache_table;

/****************************************************************************
 * L3 NHGs are used for fast failover of nexthops in the dplane. These are
 * the APIs for allocating L3 NHG ids. Management of the L3 NHG itself is
 * left to the application using it.
 * PS: Currently EVPN host routes is the only app using L3 NHG for fast
 * failover of remote ES links.
 ***************************************************************************/
static bitfield_t bgp_nh_id_bitmap;
static uint32_t bgp_nhg_start;

/* XXX - currently we do nothing on the callbacks */
static void bgp_nhg_add_cb(const char *name)
{
}

static void bgp_nhg_modify_cb(const struct nexthop_group_cmd *nhgc)
{
}

static void bgp_nhg_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_cb(const char *name)
{
}

static void bgp_nhg_zebra_init(void)
{
	static bool bgp_nhg_zebra_inited;

	if (bgp_nhg_zebra_inited)
		return;

	bgp_nhg_zebra_inited = true;
	bgp_nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);
	nexthop_group_init(bgp_nhg_add_cb, bgp_nhg_modify_cb,
			   bgp_nhg_add_nexthop_cb, bgp_nhg_del_nexthop_cb,
			   bgp_nhg_del_cb);
}

void bgp_nhg_init(void)
{
	uint32_t id_max;

	id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1, 16 * 1024);
	bf_init(bgp_nh_id_bitmap, id_max);
	bf_assign_zero_index(bgp_nh_id_bitmap);

	if (BGP_DEBUG(nht, NHT) || BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("bgp nhg range %u - %u", bgp_nhg_start + 1,
			   bgp_nhg_start + id_max);
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("bgp nexthop group init");

	bgp_nhg_cache_init(&nhg_cache_table);
}

void bgp_nhg_finish(void)
{
	bf_free(bgp_nh_id_bitmap);
}

uint32_t bgp_nhg_id_alloc(void)
{
	uint32_t nhg_id = 0;

	bgp_nhg_zebra_init();
	bf_assign_index(bgp_nh_id_bitmap, nhg_id);
	if (nhg_id)
		nhg_id += bgp_nhg_start;

	return nhg_id;
}

void bgp_nhg_id_free(uint32_t nhg_id)
{
	if (!nhg_id || (nhg_id <= bgp_nhg_start))
		return;

	nhg_id -= bgp_nhg_start;

	bf_release_index(bgp_nh_id_bitmap, nhg_id);
}

/* display in a debug trace BGP NHG information, with a custom 'prefix' string */
static void bgp_nhg_debug(struct bgp_nhg_cache *nhg, const char *prefix)
{
	char nexthop_buf[BGP_NEXTHOP_BUFFER_SIZE];

	if (!nhg->nexthop_num)
		return;

	if (nhg->nexthop_num > 1) {
		zlog_debug("NHG %u: %s", nhg->id, prefix);
		bgp_debug_zebra_nh(nhg->nexthops, nhg->nexthop_num);
		return;
	}
	bgp_debug_zebra_nh_buffer(&nhg->nexthops[0], nexthop_buf, sizeof(nexthop_buf));
	zlog_debug("NHG %u: %s (%s)", nhg->id, prefix, nexthop_buf);
}

static struct bgp_nhg_cache *bgp_nhg_find_per_id(uint32_t id)
{
	struct bgp_nhg_cache *nhg;

	frr_each_safe (bgp_nhg_cache, &nhg_cache_table, nhg)
		if (nhg->id == id)
			return nhg;

	return NULL;
}

uint32_t bgp_nhg_cache_hash(const struct bgp_nhg_cache *nhg)
{
	return jhash_1word((uint32_t)nhg->nexthop_num, 0x55aa5a5a);
}

uint32_t bgp_nhg_cache_compare(const struct bgp_nhg_cache *a, const struct bgp_nhg_cache *b)
{
	int i, ret;

	if (a->flags != b->flags)
		return a->flags - b->flags;

	for (i = 0; i < a->nexthop_num; i++) {
		ret = zapi_nexthop_cmp(&a->nexthops[i], &b->nexthops[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static void bgp_nhg_add_or_update_nhg(struct bgp_nhg_cache *bgp_nhg)
{
	struct zapi_nhg api_nhg = {};
	int i;

	if (bgp_nhg->nexthop_num == 0) {
		/* assumption that dependent nhg are removed before when id is installed */
		if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
			zlog_debug("%s: nhg %u not sent: no valid nexthops", __func__, bgp_nhg->id);
		return;
	}

	api_nhg.id = bgp_nhg->id;
	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION))
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_ALLOW_RECURSION);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE))
		SET_FLAG(api_nhg.message, ZAPI_MESSAGE_SRTE);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_IBGP))
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_IBGP);

	for (i = 0; i < bgp_nhg->nexthop_num; i++) {
		if (api_nhg.nexthop_num >= MULTIPATH_NUM) {
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_warn("%s: number of nexthops greater than maximum number of multipathes, discard some nexthops.",
					  __func__);
			break;
		}
		memcpy(&api_nhg.nexthops[api_nhg.nexthop_num], &bgp_nhg->nexthops[i],
		       sizeof(struct zapi_nexthop));
		api_nhg.nexthop_num++;
	}
	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

struct bgp_nhg_cache *bgp_nhg_new(uint32_t flags, uint16_t nexthop_num, struct zapi_nexthop api_nh[])
{
	struct bgp_nhg_cache *nhg;
	int i;

	nhg = XCALLOC(MTYPE_BGP_NHG_CACHE, sizeof(struct bgp_nhg_cache));
	for (i = 0; i < nexthop_num; i++)
		memcpy(&nhg->nexthops[i], &api_nh[i], sizeof(struct zapi_nexthop));

	nhg->nexthop_num = nexthop_num;
	nhg->flags = flags;

	nhg->id = bgp_nhg_id_alloc();

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		bgp_nhg_debug(nhg, "creation");

	LIST_INIT(&(nhg->paths));
	bgp_nhg_cache_add(&nhg_cache_table, nhg);

	/* prepare the nexthop */
	bgp_nhg_add_or_update_nhg(nhg);

	return nhg;
}

/* called when ZEBRA notified the BGP NHG id is installed */
void bgp_nhg_id_set_installed(uint32_t id)
{
	static struct bgp_nhg_cache *nhg;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	SET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u: ID is installed", nhg->id);
}

/* called when ZEBRA notified the BGP NHG id is removed */
void bgp_nhg_id_set_removed(uint32_t id)
{
	static struct bgp_nhg_cache *nhg;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u: ID is uninstalled", nhg->id);
	UNSET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	SET_FLAG(nhg->state, BGP_NHG_STATE_REMOVED);
}
