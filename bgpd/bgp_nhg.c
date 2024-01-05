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
#include <bgpd/bgp_nhg_private.h>
#include <bgpd/bgp_nhg.h>
#include <bgpd/bgp_nexthop.h>
#include <bgpd/bgp_zebra.h>
#include <bgpd/bgp_vty.h>

#include "bgpd/bgp_nhg_clippy.c"

extern struct zclient *zclient;

DEFINE_MTYPE_STATIC(BGPD, BGP_NHG_CONNECTED, "BGP NHG Connected");

/* BGP NHG hash table. */
struct bgp_nhg_cache_head nhg_cache_table;
/* BGP NHG parent hash table ordered by ids. */
struct bgp_nhg_parent_cache_head nhg_parent_cache_table;

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

/* BGP NHGs are either child or parent nhgs. To reflect dependency between a parent
 * and its childs (and reversely reflect that a child is used by a list of parents),
 * a tree of 'bgp_nhg_connected' structures are used. The below API is used to
 * handle those structures.
 */
static void bgp_nhg_connected_free(struct bgp_nhg_connected *dep)
{
	XFREE(MTYPE_BGP_NHG_CONNECTED, dep);
}

static struct bgp_nhg_connected *bgp_nhg_connected_new(struct bgp_nhg_cache *nhg)
{
	struct bgp_nhg_connected *new = NULL;

	new = XCALLOC(MTYPE_BGP_NHG_CONNECTED, sizeof(struct bgp_nhg_connected));
	new->nhg = nhg;

	return new;
}

static __attribute__((__unused__)) bool
bgp_nhg_connected_tree_is_empty(const struct bgp_nhg_connected_tree_head *head)
{
	return bgp_nhg_connected_tree_count(head) ? false : true;
}

struct bgp_nhg_cache *bgp_nhg_connected_tree_del_nhg(struct bgp_nhg_connected_tree_head *head,
						     struct bgp_nhg_cache *depend)
{
	struct bgp_nhg_connected lookup = {};
	struct bgp_nhg_connected *remove = NULL;
	struct bgp_nhg_cache *removed_nhg;

	lookup.nhg = depend;

	/* Lookup to find the element, then remove it */
	remove = bgp_nhg_connected_tree_find(head, &lookup);
	if (remove)
		/* Re-returning here just in case this API changes..
		 * the _del list api's are a bit undefined at the moment.
		 *
		 * So hopefully returning here will make it fail if the api
		 * changes to something different than currently expected.
		 */
		remove = bgp_nhg_connected_tree_del(head, remove);

	/* If the entry was sucessfully removed, free the 'connected` struct */
	if (remove) {
		removed_nhg = remove->nhg;
		bgp_nhg_connected_free(remove);
		return removed_nhg;
	}

	return NULL;
}

/* Assuming UNIQUE RB tree. If this changes, assumptions here about
 * insertion need to change.
 */
struct bgp_nhg_cache *bgp_nhg_connected_tree_add_nhg(struct bgp_nhg_connected_tree_head *head,
						     struct bgp_nhg_cache *depend)
{
	struct bgp_nhg_connected *new = NULL;

	new = bgp_nhg_connected_new(depend);

	/* On success, NULL will be returned from the
	 * RB code.
	 */
	if (new && (bgp_nhg_connected_tree_add(head, new) == NULL))
		return NULL;

	/* If it wasn't successful, it must be a duplicate. We enforce the
	 * unique property for the `nhg_connected` tree.
	 */
	bgp_nhg_connected_free(new);

	return depend;
}

static __attribute__((__unused__)) unsigned int bgp_nhg_childs_count(const struct bgp_nhg_cache *nhg)
{
	return bgp_nhg_connected_tree_count(&nhg->nhg_childs);
}

static __attribute__((__unused__)) bool bgp_nhg_childs_is_empty(const struct bgp_nhg_cache *nhg)
{
	return bgp_nhg_connected_tree_is_empty(&nhg->nhg_childs);
}

static __attribute__((__unused__)) void bgp_nhg_childs_del(struct bgp_nhg_cache *from,
							   struct bgp_nhg_cache *depend)
{
	bgp_nhg_connected_tree_del_nhg(&from->nhg_childs, depend);
}

static void bgp_nhg_childs_init(struct bgp_nhg_cache *nhg)
{
	bgp_nhg_connected_tree_init(&nhg->nhg_childs);
}

static __attribute__((__unused__)) unsigned int bgp_nhg_parents_count(const struct bgp_nhg_cache *nhg)
{
	return bgp_nhg_connected_tree_count(&nhg->nhg_parents);
}

static __attribute__((__unused__)) void bgp_nhg_parents_del(struct bgp_nhg_cache *from,
							    struct bgp_nhg_cache *dependent)
{
	bgp_nhg_connected_tree_del_nhg(&from->nhg_parents, dependent);
}

static void bgp_nhg_parents_init(struct bgp_nhg_cache *nhg)
{
	bgp_nhg_connected_tree_init(&nhg->nhg_parents);
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
	bgp_nhg_parent_cache_init(&nhg_parent_cache_table);
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

void bgp_nhg_debug_parent(uint32_t child_ids[], int count, char *group_buf, size_t len)
{
	int i;
	char *ptr = group_buf;
	size_t written_len = 0;

	group_buf[0] = '\0';
	for (i = 0; i < count; i++) {
		written_len += snprintf(ptr, len - written_len, "%u", child_ids[i]);
		ptr = group_buf + written_len;
		if (i + 1 < count) {
			written_len += snprintf(ptr, len - written_len, ", ");
			ptr = group_buf + written_len;
		}
	}
}

/* display in a debug trace BGP NHG information, with a custom 'prefix' string */
static void bgp_nhg_debug(struct bgp_nhg_cache *nhg, const char *prefix)
{
	char nexthop_buf[BGP_NEXTHOP_BUFFER_SIZE];

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		bgp_nhg_debug_parent(nhg->childs.childs, nhg->childs.child_num, nexthop_buf,
				     sizeof(nexthop_buf));
		zlog_debug("NHG %u: child %s (%s)", nhg->id, prefix, nexthop_buf);
		return;
	}
	if (!nhg->nexthops.nexthop_num)
		return;

	if (nhg->nexthops.nexthop_num > 1) {
		zlog_debug("NHG %u: %s", nhg->id, prefix);
		bgp_debug_zebra_nh(nhg->nexthops.nexthops, nhg->nexthops.nexthop_num);
		return;
	}
	bgp_debug_zebra_nh_buffer(&nhg->nexthops.nexthops[0], nexthop_buf, sizeof(nexthop_buf));
	zlog_debug("NHG %u: %s (%s)", nhg->id, prefix, nexthop_buf);
}

static struct bgp_nhg_cache *bgp_nhg_find_per_id(uint32_t id)
{
	struct bgp_nhg_cache *nhg;
	struct bgp_nhg_cache nhg_tmp = { 0 };

	/* parse list of childs */
	frr_each_safe (bgp_nhg_cache, &nhg_cache_table, nhg) {
		if (nhg->id == id)
			return nhg;
	}

	/* parse list of parents */
	nhg_tmp.id = id;
	return bgp_nhg_parent_cache_find(&nhg_parent_cache_table, &nhg_tmp);
}

/* compare parent child list and return true if same */
static bool bgp_nhg_parent_cache_compare_childs(const struct bgp_nhg_cache *a,
						const struct bgp_nhg_cache *b)
{
	int i;

	if (a->childs.child_num != b->childs.child_num)
		return false;

	for (i = 0; i < a->childs.child_num; i++) {
		if (a->childs.childs[i] != b->childs.childs[i])
			return false;
	}
	return true;
}

struct bgp_nhg_cache *bgp_nhg_parent_find_per_child(struct bgp_path_info *p_mpinfo[],
						    uint32_t *valid_nh_count,
						    struct bgp_nhg_cache *lookup)
{
	struct bgp_nhg_cache *nhg;
	unsigned int i;

	/* look in current pi->bgp_nhg in priority */
	for (i = 0; i < *valid_nh_count; i++) {
		if (p_mpinfo[i] && p_mpinfo[i]->bgp_nhg &&
		    bgp_nhg_parent_cache_compare_childs(lookup, p_mpinfo[i]->bgp_nhg))
			return p_mpinfo[i]->bgp_nhg;
	}
	/* get first matching nhg */
	frr_each_safe (bgp_nhg_parent_cache, &nhg_parent_cache_table, nhg) {
		if (bgp_nhg_parent_cache_compare_childs(lookup, nhg))
			return nhg;
	}
	return NULL;
}

int bgp_nhg_parent_cache_compare(const struct bgp_nhg_cache *a, const struct bgp_nhg_cache *b)
{
	if (a->id != b->id)
		return a->id - b->id;
	return 0;
}

uint32_t bgp_nhg_cache_hash(const struct bgp_nhg_cache *nhg)
{
	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT))
		return jhash_1word((uint32_t)nhg->childs.child_num, 0x55aa5a5a);
	return jhash_1word((uint32_t)nhg->nexthops.nexthop_num, 0x55aa5a5a);
}

uint32_t bgp_nhg_cache_compare(const struct bgp_nhg_cache *a, const struct bgp_nhg_cache *b)
{
	int i, ret;

	if (a->flags != b->flags)
		return a->flags - b->flags;

	if (CHECK_FLAG(a->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		for (i = 0; i < a->childs.child_num; i++) {
			if (a->childs.childs[i] != b->childs.childs[i])
				return a->childs.childs[i] - b->childs.childs[i];
		}
		return 0;
	}

	for (i = 0; i < a->nexthops.nexthop_num; i++) {
		ret = zapi_nexthop_cmp(&a->nexthops.nexthops[i], &b->nexthops.nexthops[i]);
		if (ret)
			return ret;
	}
	return 0;
}

/* return the first nexthop-vrf available, VRF_DEFAULT otherwise */
static vrf_id_t bgp_nhg_get_vrfid(struct bgp_nhg_cache *nhg)
{
	vrf_id_t vrf_id = VRF_DEFAULT;
	int i = 0;
	struct bgp_nhg_cache *child_nhg;

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		for (i = 0; i < nhg->childs.child_num; i++) {
			child_nhg = bgp_nhg_find_per_id(nhg->childs.childs[i]);
			if (child_nhg)
				return bgp_nhg_get_vrfid(child_nhg);
		}
	}

	for (i = 0; i < nhg->nexthops.nexthop_num; i++)
		return nhg->nexthops.nexthops[i].vrf_id;

	return vrf_id;
}

static bool bgp_nhg_add_or_update_nhg_group(struct bgp_nhg_cache *bgp_nhg,
					    struct zapi_nhg_group *api_nhg_group)
{
	bool ret = true;
	int i;
	struct bgp_nhg_cache *child_nhg;

	api_nhg_group->id = bgp_nhg->id;
	api_nhg_group->child_group_num = 0;
	for (i = 0; i < bgp_nhg->childs.child_num; i++) {
		if (api_nhg_group->child_group_num >= MULTIPATH_NUM) {
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_warn("%s: number of nexthops greater than max multipath size, truncating",
					  __func__);
			break;
		}
		child_nhg = bgp_nhg_find_per_id(bgp_nhg->childs.childs[i]);
		if (!child_nhg || !CHECK_FLAG(child_nhg->state, BGP_NHG_STATE_INSTALLED)) {
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_warn("%s: nhg %u not sent, child NHG ID %u not present or not installed.",
					  __func__, bgp_nhg->id, bgp_nhg->childs.childs[i]);
			continue;
		}
		api_nhg_group->child_group_id[i] = bgp_nhg->childs.childs[i];
		api_nhg_group->child_group_num++;
	}
	if (api_nhg_group->child_group_num == 0) {
		if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
			zlog_debug("%s: nhg %u not sent: no valid groups", __func__,
				   api_nhg_group->id);
		ret = false;
	}
	return ret;
}

static bool bgp_nhg_add_or_update_nhg_nexthop(struct bgp_nhg_cache *bgp_nhg,
					      struct zapi_nhg *api_nhg)
{
	int i;

	if (bgp_nhg->nexthops.nexthop_num == 0) {
		/* assumption that dependent nhg are removed before when id is installed */
		if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
			zlog_debug("%s: nhg %u not sent: no valid nexthops", __func__, bgp_nhg->id);
		return false;
	}

	api_nhg->id = bgp_nhg->id;

	for (i = 0; i < bgp_nhg->nexthops.nexthop_num; i++) {
		if (api_nhg->nexthop_num >= MULTIPATH_NUM) {
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_warn("%s: number of nexthops greater than maximum number of multipathes, discard some nexthops.",
					  __func__);
			break;
		}
		memcpy(&api_nhg->nexthops[api_nhg->nexthop_num], &bgp_nhg->nexthops.nexthops[i],
		       sizeof(struct zapi_nexthop));
		api_nhg->nexthop_num++;
	}
	return true;
}

static void bgp_nhg_add_or_update_nhg(struct bgp_nhg_cache *bgp_nhg)
{
	struct zapi_nhg api_nhg = {};
	struct zapi_nhg_group api_nhg_group = {};
	uint32_t message = 0;
	uint8_t flags = 0;

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION))
		SET_FLAG(flags, NEXTHOP_GROUP_ALLOW_RECURSION);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE))
		SET_FLAG(message, ZAPI_MESSAGE_SRTE);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_IBGP))
		SET_FLAG(flags, NEXTHOP_GROUP_IBGP);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		if (bgp_nhg_add_or_update_nhg_group(bgp_nhg, &api_nhg_group)) {
			api_nhg_group.flags = flags;
			api_nhg_group.message = message;
			zclient_nhg_child_send(zclient, ZEBRA_NHG_CHILD_ADD, &api_nhg_group);
		}
		return;
	}

	api_nhg.flags = flags;
	api_nhg.message = message;

	if (bgp_nhg_add_or_update_nhg_nexthop(bgp_nhg, &api_nhg))
		zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

struct bgp_nhg_cache *bgp_nhg_new(uint32_t flags, uint16_t num, struct zapi_nexthop api_nh[],
				  uint32_t api_group[])
{
	struct bgp_nhg_cache *nhg;
	int i;

	nhg = XCALLOC(MTYPE_BGP_NHG_CACHE, sizeof(struct bgp_nhg_cache));
	if (CHECK_FLAG(flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		for (i = 0; i < num; i++)
			nhg->childs.childs[i] = api_group[i];
		nhg->childs.child_num = num;
	} else {
		for (i = 0; i < num; i++)
			memcpy(&nhg->nexthops.nexthops[i], &api_nh[i], sizeof(struct zapi_nexthop));
		nhg->nexthops.nexthop_num = num;
	}
	nhg->flags = flags;

	nhg->id = bgp_nhg_id_alloc();

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		bgp_nhg_debug(nhg, "creation");

	LIST_INIT(&(nhg->paths));
	bgp_nhg_parents_init(nhg);
	bgp_nhg_childs_init(nhg);
	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT))
		bgp_nhg_parent_cache_add(&nhg_parent_cache_table, nhg);
	else
		bgp_nhg_cache_add(&nhg_cache_table, nhg);

	/* prepare the nexthop */
	bgp_nhg_add_or_update_nhg(nhg);

	return nhg;
}

/* Called when a child nexthop-group must be detached from parent:
 * The child is detached from the parent. The parent is marked as updated
 * if the number of childs is not 0.
 */
static void bgp_nhg_detach_child_from_parent(struct bgp_nhg_cache *nhg,
					     struct bgp_nhg_cache *nhg_child)
{
	int i, j;
	struct bgp_path_info *path, *safe;
	char nexthop_buf[BGP_NEXTHOP_BUFFER_SIZE];

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP)) {
		bgp_debug_zebra_nh_buffer(&nhg_child->nexthops.nexthops[0], nexthop_buf,
					  sizeof(nexthop_buf));
		zlog_debug("NHG %u: detaching ID %u nexthop (%s)", nhg->id, nhg_child->id,
			   nexthop_buf);
	}

	for (i = 0; i < nhg->childs.child_num; i++) {
		if (nhg->childs.childs[i] == nhg_child->id)
			break;
	}
	assert(i != nhg->childs.child_num);

	if (i < nhg->childs.child_num - 1) {
		for (j = i + 1; j < nhg->childs.child_num; j++)
			nhg->childs.childs[j - 1] = nhg->childs.childs[j];
	}
	nhg->childs.childs[nhg->childs.child_num - 1] = 0;
	nhg->childs.child_num--;

	LIST_FOREACH_SAFE (path, &(nhg->paths), nhg_cache_thread, safe) {
		if (!path->bgp_nhg_nexthop) {
			LIST_REMOVE(path, nhg_cache_thread);
			path->bgp_nhg = NULL;
			nhg->path_count--;
		}
	}

	/* remove it from original nhg */
	bgp_nhg_parents_del(nhg_child, nhg);
	bgp_nhg_childs_del(nhg, nhg_child);

	/* sort to always send ordered information to zebra */
	bgp_nhg_parent_sort(nhg->childs.childs, nhg->childs.child_num);

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP)) {
		zlog_debug("NHG %u: detached ID %u nexthop (%s) (%u -> %u)", nhg->id, nhg_child->id,
			   nexthop_buf, nhg->childs.child_num + 1, nhg->childs.child_num);
	}

	if (nhg->childs.child_num) {
		SET_FLAG(nhg->state, BGP_NHG_STATE_UPDATED);
		bgp_nhg_add_or_update_nhg(nhg);
	}
}

static void bgp_nhg_connected_del(struct bgp_nhg_cache *nhg)
{
	struct bgp_nhg_connected *rb_node_dep = NULL;

	frr_each_safe (bgp_nhg_connected_tree, &(nhg->nhg_parents), rb_node_dep) {
		bgp_nhg_childs_del(rb_node_dep->nhg, nhg);
		bgp_nhg_parents_del(nhg, rb_node_dep->nhg);
	}

	frr_each_safe (bgp_nhg_connected_tree, &(nhg->nhg_childs), rb_node_dep) {
		bgp_nhg_parents_del(rb_node_dep->nhg, nhg);
		bgp_nhg_childs_del(nhg, rb_node_dep->nhg);
	}
}

void bgp_nhg_free(struct bgp_nhg_cache *nhg)
{
	struct zapi_nhg api_nhg = {};

	bgp_nhg_connected_del(nhg);

	api_nhg.id = nhg->id;

	if (api_nhg.id)
		zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		bgp_nhg_debug(nhg, "removal");

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT))
		bgp_nhg_parent_cache_del(&nhg_parent_cache_table, nhg);
	else
		bgp_nhg_cache_del(&nhg_cache_table, nhg);
	XFREE(MTYPE_BGP_NHG_CACHE, nhg);
}

/* Used to sync the BGP NHG Parent hash table with the BGP NHG hash table. After a
 * child group is removed, some BGP NHG group may be empty. This function detects it
 * and frees it
 */
static void bgp_nhg_parent_unused_clean(void)
{
	struct bgp_nhg_cache *nhg;

	frr_each_safe (bgp_nhg_parent_cache, &nhg_parent_cache_table, nhg) {
		if (nhg->childs.child_num)
			continue;
		if (LIST_EMPTY(&(nhg->paths)))
			bgp_nhg_free(nhg);
	}
}

void bgp_nhg_path_nexthop_unlink(struct bgp_path_info *pi, bool force)
{
	struct bgp_nhg_cache *nhg_nexthop;

	nhg_nexthop = pi->bgp_nhg_nexthop;
	if (nhg_nexthop) {
		/* detach nexthop */
		LIST_REMOVE(pi, nhg_nexthop_cache_thread);
		pi->bgp_nhg_nexthop->path_count--;
		if (force && LIST_EMPTY(&(nhg_nexthop->paths)))
			bgp_nhg_free(nhg_nexthop);
		pi->bgp_nhg_nexthop = NULL;
	}
}

static void bgp_nhg_path_unlink_internal(struct bgp_path_info *pi, bool free_nhg)
{
	struct bgp_nhg_cache *nhg;

	if (!pi)
		return;

	nhg = pi->bgp_nhg;

	bgp_nhg_path_nexthop_unlink(pi, true);

	if (!nhg)
		return;

	LIST_REMOVE(pi, nhg_cache_thread);
	nhg->path_count--;
	pi->bgp_nhg = NULL;
	if (LIST_EMPTY(&(nhg->paths)) && free_nhg)
		bgp_nhg_free(nhg);
}

void bgp_nhg_path_unlink(struct bgp_path_info *pi)
{
	return bgp_nhg_path_unlink_internal(pi, true);
}

void bgp_nhg_parent_link(struct bgp_nhg_cache *nhg_childs[], int nexthop_num,
			 struct bgp_nhg_cache *nhg_parent)
{
	int i;

	/* updates NHG dependencies */
	for (i = 0; i < nexthop_num; i++) {
		bgp_nhg_connected_tree_add_nhg(&nhg_parent->nhg_childs, nhg_childs[i]);
		bgp_nhg_connected_tree_add_nhg(&nhg_childs[i]->nhg_parents, nhg_parent);
	}
}

/* called when ZEBRA notified the BGP NHG id is installed */
void bgp_nhg_id_set_installed(uint32_t id)
{
	static struct bgp_nhg_cache *nhg;
	struct bgp_path_info *path;
	struct bgp_table *table;
	struct bgp_nhg_connected *rb_node_dep = NULL;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	SET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u: ID is installed, update dependent NHGs", nhg->id);

	frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_parents, rb_node_dep) {
		bgp_nhg_add_or_update_nhg(rb_node_dep->nhg);
	}

	if (!CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT))
		return;

	/* only update routes if it is a parent nhg */
	if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_UPDATED)) {
		UNSET_FLAG(nhg->state, BGP_NHG_STATE_UPDATED);
		return;
	}

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u: ID is installed, update dependent routes", nhg->id);
	LIST_FOREACH (path, &(nhg->paths), nhg_cache_thread) {
		table = bgp_dest_table(path->net);
		if (table)
			bgp_zebra_route_install(path->net, path, table->bgp, true, NULL, false);
	}
}

/* called when ZEBRA notified the BGP NHG id is removed */
void bgp_nhg_id_set_removed(uint32_t id)
{
	static struct bgp_nhg_cache *nhg;
	struct bgp_nhg_connected *rb_node_dep = NULL;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u: ID is uninstalled, update dependent NHGs", nhg->id);
	UNSET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	SET_FLAG(nhg->state, BGP_NHG_STATE_REMOVED);
	frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_parents, rb_node_dep)
		bgp_nhg_add_or_update_nhg(rb_node_dep->nhg);
}

static void bgp_nhg_remove_nexthops(struct bgp_nhg_cache *nhg)
{
	struct bgp_nhg_connected *rb_node_dep = NULL;
	struct bgp_nhg_cache *parent_nhg;
	struct bgp_path_info *path, *safe;

	frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_parents, rb_node_dep) {
		parent_nhg = rb_node_dep->nhg;
		LIST_FOREACH_SAFE (path, &(parent_nhg->paths), nhg_cache_thread, safe) {
			if (path->bgp_nhg_nexthop == nhg) {
				LIST_REMOVE(path, nhg_cache_thread);
				path->bgp_nhg = NULL;
				parent_nhg->path_count--;
				LIST_REMOVE(path, nhg_nexthop_cache_thread);
				path->bgp_nhg_nexthop = NULL;
				nhg->path_count--;
			}
		}
		bgp_nhg_detach_child_from_parent(parent_nhg, nhg);
	}
	if (LIST_EMPTY(&(nhg->paths)))
		bgp_nhg_free(nhg);
}

/* This function unlinks the BGP nexthop group cache of BGP paths in some cases:
 * - when a BGP NHG is resolved over a default route
 * - if the passed resolved_prefix is the prefix of the path (case recursive loop)
 *
 * Without BGP NHG, those checks are done in ZEBRA, function nexthop_active(),
 * leading to not installing the route:
 * - if resolve-via-default is unconfigured
 * - if a recursive loop happens for non host route
 *
 * With BGP NHG, those checks are done in BGP in this function,
 * the routes will not use the BGP nexthop-groups, and will use the old ZEBRA code check,
 * if the prefix paths meet the unlink conditions explained previously.
 *
 * in: nhg, the bgp nexthop group cache entry
 * in: resolved_prefix, the resolved prefix of the nexthop: NULL if default route.
 * in: child, the child nexthop-group of the path
 * out: return true if the nexthop group has no more paths and is freed, false otherwise
 */
static void bgp_nhg_detach_paths_resolved_over_prefix_internal(struct bgp_nhg_cache *nhg,
							       struct prefix *resolved_prefix,
							       struct bgp_nhg_cache *child)
{
	struct bgp_path_info *path, *safe;
	const struct prefix *p;
	bool is_default_path;
	struct bgp_table *table;

	if (!resolved_prefix)
		return;

	is_default_path = is_default_prefix(resolved_prefix);

	LIST_FOREACH_SAFE (path, &(nhg->paths), nhg_cache_thread, safe) {
		if (path->bgp_nhg_nexthop != child)
			continue;
		p = bgp_dest_get_prefix(path->net);
		if (is_default_path) {
			/* disallow routes which resolve over default route
			 */
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_debug("        :%s: %pFX Resolved against default route",
					   __func__, p);
		} else if (prefix_same(resolved_prefix, p) && !is_host_route(p)) {
			/* disallow non host routes with resolve over themselves
			 */
			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP_DETAIL))
				zlog_debug("        %s: %pFX, Matched against ourself and prefix length is not max bit length",
					   __func__, p);
		} else
			continue;
		/* nhg = pi->nhg is detached,
		 * nhg will not be suppressed when bgp_nhg_path_unlink() is called
		 */
		bgp_nhg_path_nexthop_unlink(path, false);
		bgp_nhg_path_unlink_internal(path, false);
		/* path should still be active */
		table = bgp_dest_get_bgp_table_info(path->net);
		if (table->bgp)
			bgp_zebra_route_install(path->net, path, table->bgp, true, NULL, false);
	}
}

static bool bgp_nhg_detach_paths_resolved_over_prefix(struct bgp_nhg_cache *nhg,
						      struct prefix *resolved_prefix)
{
	struct bgp_nhg_connected *rb_node_dep = NULL;
	struct bgp_nhg_cache *parent_nhg;

	frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_parents, rb_node_dep) {
		parent_nhg = rb_node_dep->nhg;
		bgp_nhg_detach_paths_resolved_over_prefix_internal(parent_nhg, resolved_prefix, nhg);
	}
	if (LIST_EMPTY(&(nhg->paths))) {
		bgp_nhg_free(nhg);
		return true;
	}
	return false;
}

void bgp_nhg_refresh_by_nexthop(struct bgp_nexthop_cache *bnc)
{
	struct bgp_nhg_cache *nhg;
	int i;
	struct zapi_nexthop *zapi_nh;
	uint32_t srte_color = bnc->srte_color;
	struct prefix *p = &bnc->prefix;
	vrf_id_t vrf_id = bnc->bgp->vrf_id;
	bool found;

	frr_each_safe (bgp_nhg_cache, &nhg_cache_table, nhg) {
		found = false;
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED))
			continue;
		if (!CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION))
			continue;
		if ((srte_color && !CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)) ||
		    (!srte_color && CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)))
			continue;
		for (i = 0; i < nhg->nexthops.nexthop_num; i++) {
			zapi_nh = &nhg->nexthops.nexthops[i];
			if (zapi_nh->type == NEXTHOP_TYPE_IFINDEX ||
			    zapi_nh->type == NEXTHOP_TYPE_BLACKHOLE)
				continue;
			if (srte_color && zapi_nh->srte_color != srte_color)
				continue;
			if (p->family == AF_INET &&
			    (zapi_nh->type == NEXTHOP_TYPE_IPV4 ||
			     zapi_nh->type == NEXTHOP_TYPE_IPV4_IFINDEX) &&
			    IPV4_ADDR_SAME(&zapi_nh->gate.ipv4, &p->u.prefix4)) {
				found = true;
				break;
			}
			if (p->family == AF_INET6 &&
			    (zapi_nh->type == NEXTHOP_TYPE_IPV6 ||
			     zapi_nh->type == NEXTHOP_TYPE_IPV6_IFINDEX) &&
			    IPV6_ADDR_SAME(&zapi_nh->gate.ipv6, &p->u.prefix6)) {
				found = true;
				break;
			}
		}
		if (found) {
			if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)) {
				if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
					zlog_debug("NHG %u, VRF %u : nexthop %pFX SRTE %u is invalid.",
						   nhg->id, vrf_id, p, srte_color);
				bgp_nhg_remove_nexthops(nhg);
				continue;
			}

			if (bgp_nhg_detach_paths_resolved_over_prefix(nhg, &bnc->resolved_prefix))
				continue;

			if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
				zlog_debug("NHG %u, VRF %u : nexthop %pFX SRTE %u has changed.",
					   nhg->id, vrf_id, p, srte_color);
			bgp_nhg_add_or_update_nhg(nhg);
		}
	}
	bgp_nhg_parent_unused_clean();
}

static void show_bgp_nhg_path_helper(struct vty *vty, json_object *paths, struct bgp_path_info *path)
{
	json_object *json_path = NULL;

	if (paths)
		json_path = json_object_new_object();
	bgp_path_info_display(path, vty, json_path);
	if (paths)
		json_object_array_add(paths, json_path);
}

static void show_bgp_nhg_id_helper_detail(struct vty *vty, struct bgp_nhg_cache *nhg,
					  json_object *json)
{
	struct bgp_path_info *path;
	json_object *paths = NULL;

	if (json)
		paths = json_object_new_array();
	else
		vty_out(vty, "  Paths:\n");

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		LIST_FOREACH (path, &(nhg->paths), nhg_cache_thread)
			show_bgp_nhg_path_helper(vty, paths, path);
	} else {
		LIST_FOREACH (path, &(nhg->paths), nhg_nexthop_cache_thread)
			show_bgp_nhg_path_helper(vty, paths, path);
	}

	if (json)
		json_object_object_add(json, "paths", paths);
}

static void show_bgp_nhg_id_helper(struct vty *vty, struct bgp_nhg_cache *nhg, json_object *json,
				   bool detail)
{
	struct nexthop *nexthop;
	json_object *json_entry;
	json_object *json_array = NULL;
	int i;
	bool first;
	struct bgp_nhg_connected *rb_node_dep = NULL;

	if (json) {
		json_object_int_add(json, "nhgId", nhg->id);
		json_object_int_add(json, "pathCount", nhg->path_count);
		json_object_int_add(json, "flagAllowRecursion",
				    CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION));
		json_object_boolean_add(json, "flagAllowRecursion",
					CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION));
		json_object_boolean_add(json, "flagInternalBgp",
					CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_IBGP));
		json_object_boolean_add(json, "flagSrtePresence",
					CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE));
		json_object_boolean_add(json, "flagTypeParent",
					CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT));
		json_object_boolean_add(json, "stateInstalled",
					CHECK_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED));
		json_object_boolean_add(json, "stateRemoved",
					CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED));
	} else {
		vty_out(vty, "ID: %u", nhg->id);
		if (nhg->path_count)
			vty_out(vty, ", #paths %u", nhg->path_count);
		vty_out(vty, "\n");
		vty_out(vty, "  Flags: 0x%04x", nhg->flags);
		first = true;
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION)) {
			vty_out(vty, " (allowRecursion");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_IBGP)) {
			vty_out(vty, "%sinternalBgp", first ? " (" : ", ");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)) {
			vty_out(vty, "%sSrtePresence", first ? " (" : ", ");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT))
			vty_out(vty, "%sTypeParent", first ? " (" : ", ");
		if (nhg->flags)
			vty_out(vty, ")");
		vty_out(vty, "\n");

		vty_out(vty, "  State: 0x%04x", nhg->state);
		first = true;
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED)) {
			vty_out(vty, " (Installed");
			first = false;
		}
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED)) {
			vty_out(vty, "%sRemoved", first ? " (" : ", ");
			first = false;
		}
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_UPDATED)) {
			vty_out(vty, "%sUpdated", first ? " (" : ", ");
			first = false;
		}
		if (nhg->state)
			vty_out(vty, ")");
		vty_out(vty, "\n");
	}

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_PARENT)) {
		if (bgp_nhg_childs_count(nhg)) {
			if (json) {
				json_object_int_add(json, "childListCount",
						    bgp_nhg_childs_count(nhg));
				json_array = json_object_new_array();
			} else {
				vty_out(vty, "          child list count %u\n",
					bgp_nhg_childs_count(nhg));
				vty_out(vty, "          child(s)");
			}
			frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_childs, rb_node_dep) {
				if (json) {
					json_entry = json_object_new_object();
					json_object_int_add(json_entry, "Id", rb_node_dep->nhg->id);
					json_object_array_add(json_array, json_entry);
				} else {
					vty_out(vty, " %u", rb_node_dep->nhg->id);
				}
			}
			if (json_array)
				json_object_object_add(json, "childList", json_array);
			else
				vty_out(vty, "\n");
		}
		if (detail)
			show_bgp_nhg_id_helper_detail(vty, nhg, json);
		return;
	}

	if (nhg->nexthops.nexthop_num && json)
		json_array = json_object_new_array();

	for (i = 0; i < nhg->nexthops.nexthop_num; i++) {
		nexthop = nexthop_from_zapi_nexthop(&nhg->nexthops.nexthops[i]);
		if (json) {
			json_entry = json_object_new_object();
			nexthop_json_helper(json_entry, nexthop, true, AF_UNSPEC);
			json_object_string_add(json_entry, "vrf", vrf_id_to_name(nexthop->vrf_id));
			json_object_array_add(json_array, json_entry);
		} else {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				vty_out(vty, "          ");
			else
				/* Make recursive nexthops a bit more clear */
				vty_out(vty, "       ");
			nexthop_vty_helper(vty, nexthop, true, AF_UNSPEC);
			vty_out(vty, "\n");
		}
		nexthops_free(nexthop);
	}
	if (json_array)
		json_object_object_add(json, "nexthops", json_array);

	if (bgp_nhg_parents_count(nhg)) {
		if (json) {
			json_object_int_add(json, "parentListCount", bgp_nhg_parents_count(nhg));
			json_array = json_object_new_array();
		} else {
			vty_out(vty, "          parent list count %u\n", bgp_nhg_parents_count(nhg));
			vty_out(vty, "          parent(s)");
		}
		frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_parents, rb_node_dep) {
			if (json) {
				json_entry = json_object_new_object();
				json_object_int_add(json_entry, "Id", rb_node_dep->nhg->id);
				json_object_array_add(json_array, json_entry);
			} else {
				vty_out(vty, " %u", rb_node_dep->nhg->id);
			}
		}
		if (json_array)
			json_object_object_add(json, "parentList", json_array);
		else
			vty_out(vty, "\n");
	}

	if (detail)
		show_bgp_nhg_id_helper_detail(vty, nhg, json);
}

static void show_bgp_nhg_id_list_helper(struct vty *vty, struct bgp_nhg_cache *nhg,
					json_object *json_list, bool detail)
{
	json_object *json = NULL;

	if (json_list)
		json = json_object_new_object();
	show_bgp_nhg_id_helper(vty, nhg, json, detail);
	if (json_list)
		json_object_array_add(json_list, json);
}

DEFPY(show_ip_bgp_nhg, show_ip_bgp_nhg_cmd,
      "show [ip] bgp [vrf <NAME$vrf_name|all$vrf_all>] nexthop-group [<(0-4294967295)>$id] [detail$detail] [json$uj]",
      SHOW_STR IP_STR BGP_STR VRF_FULL_CMD_HELP_STR
      "BGP nexthop-group table\n"
      "Nexthop Group ID\n"
      "Show detailed information\n" JSON_STR)
{
	json_object *json = NULL;
	json_object *json_list = NULL;
	struct vrf *vrf = NULL;
	static struct bgp_nhg_cache *nhg;

	if (id) {
		nhg = bgp_nhg_find_per_id(id);
		if (!nhg)
			return CMD_SUCCESS;
		if (uj)
			json = json_object_new_object();
		show_bgp_nhg_id_helper(vty, nhg, json, !!detail);
		if (json)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (vrf_is_backend_netns() && (vrf_name || vrf_all)) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty,
				"VRF subcommand does not make any sense in netns based vrf's\n");
		return CMD_WARNING;
	}
	if (vrf_name)
		vrf = vrf_lookup_by_name(vrf_name);

	if (uj)
		json_list = json_object_new_array();


	frr_each_safe (bgp_nhg_cache, &nhg_cache_table, nhg) {
		if (vrf && vrf->vrf_id != bgp_nhg_get_vrfid(nhg))
			continue;
		show_bgp_nhg_id_list_helper(vty, nhg, json_list, !!detail);
	}
	frr_each_safe (bgp_nhg_parent_cache, &nhg_parent_cache_table, nhg) {
		if (vrf && vrf->vrf_id != bgp_nhg_get_vrfid(nhg))
			continue;
		show_bgp_nhg_id_list_helper(vty, nhg, json_list, !!detail);
	}
	if (json_list)
		vty_json(vty, json_list);
	return CMD_SUCCESS;
}

/* remove nexthop nhg that are no more used */
void bgp_nhg_clear_nhg_nexthop(void)
{
	struct bgp_nhg_connected *rb_node_dep = NULL;
	struct bgp_nhg_cache *nhg, *child_nhg;
	struct bgp_path_info *path, *safe;

	frr_each_safe (bgp_nhg_parent_cache, &nhg_parent_cache_table, nhg) {
		frr_each_safe (bgp_nhg_connected_tree, &nhg->nhg_childs, rb_node_dep) {
			child_nhg = rb_node_dep->nhg;
			if (child_nhg && LIST_EMPTY(&(child_nhg->paths))) {
				/* sync bgp_nhg paths */
				LIST_FOREACH_SAFE (path, &(nhg->paths), nhg_cache_thread, safe) {
					if (!path->bgp_nhg_nexthop) {
						LIST_REMOVE(path, nhg_cache_thread);
						path->bgp_nhg = NULL;
						nhg->path_count--;
					}
				}

				bgp_nhg_detach_child_from_parent(nhg, child_nhg);
			}
		}
	}
	bgp_nhg_parent_unused_clean();
}

void bgp_nhg_vty_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_nhg_cmd);
}

static int bgp_nhg_parent_compare(const void *a, const void *b)
{
	uint32_t *num1 = (uint32_t *)a, *num2 = (uint32_t *)b;

	return *num1 - *num2;
}
void bgp_nhg_parent_sort(uint32_t grp[], uint16_t nhg_num)
{
	qsort(grp, nhg_num, sizeof(uint32_t), &bgp_nhg_parent_compare);
}
