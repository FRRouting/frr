// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Neighbor gleaning throttle API.
 *
 * Copyright (C) 2021  Mark Stapp
 */

#include "lib/zebra.h"
#include "lib/frrevent.h"
#include "lib/typesafe.h"
#include "lib/vty.h"
#include "lib/command.h"
#include "lib/zclient.h"
#include "lib/json.h"

#include "zebra/debug.h"
#include "zebra/zebra_neigh_throttle.h"
#include "zebra/zebra_router.h"
#include "zebra/rib.h"

PREDECL_DLIST(nt_entry_list);
PREDECL_RBTREE_UNIQ(nt_entry_rb);

/*
 * Object representing one neighbor entry.
 */
struct nt_entry {
	vrf_id_t vrfid;
	struct ipaddr addr;
	time_t create_time;
	time_t expiration;

	/* List linkage */
	struct nt_entry_list_item link;

	/* rbtree linkage */
	struct nt_entry_rb_item rblink;
};

DECLARE_DLIST(nt_entry_list, struct nt_entry, link);

/* Comparison function for rbtree */
static int nt_entry_cmp(const struct nt_entry *a, const struct nt_entry *b);
DECLARE_RBTREE_UNIQ(nt_entry_rb, struct nt_entry, rblink, nt_entry_cmp);

/* Memory type */
DEFINE_MTYPE_STATIC(ZEBRA, NTHROTTLE, "Neigh Throttle");

/* Globals */
static struct nt_globals {
	/* Inited */
	bool init_p;

	/* Configured */
	bool enabled_p;

	/* Periodic timer event */
	struct event *t_periodic_timer;

	/* Current timeout */
	time_t timeout_secs;

	/* Current limit on entries */
	uint32_t max_entries;

	/* Limit number of expirations per attempt */
	uint32_t max_expirations;

	/* List of active entries, sorted by expiration time. */
	struct nt_entry_list_head entry_list;

	/* rbtree of entries, sorted by vrf + addr */
	struct nt_entry_rb_head entry_rb;

} nt_globals;

/* Prototypes. */
static void nt_handle_timer(struct event *event);

/*
 * Allocator for an entry object
 */
static struct nt_entry *nt_entry_alloc(vrf_id_t vrfid, const struct ipaddr *addr)
{
	struct nt_entry *p;

	p = XCALLOC(MTYPE_NTHROTTLE, sizeof(struct nt_entry));

	p->vrfid = vrfid;
	p->addr = *addr;
	p->create_time = time(NULL);

	return p;
}

/*
 * Dtor for an entry object (in case we want to manage a pool of them.)
 */
static void nt_entry_free(struct nt_entry **entry)
{
	XFREE(MTYPE_NTHROTTLE, *entry);
}

/*
 * Comparison function for rbtree
 */
static int nt_entry_cmp(const struct nt_entry *a, const struct nt_entry *b)
{
	int ret;

	ret = a->vrfid - b->vrfid;
	if (ret != 0)
		return ret;

	return ipaddr_cmp(&(a->addr), &(b->addr));
}

/*
 * Utility to set up for install or uninstall
 */
static void route_prep(const struct nt_entry *entry, afi_t *afi, struct prefix *p,
		       struct nexthop *nh)
{
	if (entry->addr.ipa_type == IPADDR_V4) {
		*afi = AFI_IP;
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		ipv4_addr_copy(&p->u.prefix4, &entry->addr.ipaddr_v4);
	} else {
		*afi = AFI_IP6;
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		IPV6_ADDR_COPY(&p->u.prefix6, &entry->addr.ipaddr_v6);
	}

	nh->weight = 1;
	nh->vrf_id = VRF_DEFAULT;
	nh->type = NEXTHOP_TYPE_BLACKHOLE;
	nh->bh_type = BLACKHOLE_NULL;
}

/*
 * Install blackhole route associated with a neighbor entry
 */
static void nt_install_route(const struct nt_entry *entry)
{
	struct prefix p = {};
	struct nexthop nh = {};
	struct zebra_vrf *zvrf;
	afi_t afi;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %u: %pIA", __func__, entry->vrfid, &entry->addr);

	route_prep(entry, &afi, &p, &nh);

	zvrf = zebra_vrf_lookup_by_id(entry->vrfid);

	rib_add(afi, SAFI_UNICAST, entry->vrfid, ZEBRA_ROUTE_FRR, 0, 0, &p,
		NULL, &nh, 0, zvrf->table_id, 0, 0, 0, 0, false);
}

/*
 * Uninstall route associated with a neighbor entry
 */
static void nt_uninstall_route(const struct nt_entry *entry)
{
	struct prefix p = {};
	struct nexthop nh = {};
	struct zebra_vrf *zvrf;
	afi_t afi;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %u: %pIA", __func__, entry->vrfid, &entry->addr);

	route_prep(entry, &afi, &p, &nh);

	zvrf = zebra_vrf_lookup_by_id(entry->vrfid);
	if (zvrf == NULL)
		return;

	rib_delete(afi, SAFI_UNICAST, entry->vrfid, ZEBRA_ROUTE_FRR, 0, 0, &p,
		   NULL, &nh, 0, zvrf->table_id, 0, 0, false);
}

/*
 * Clear one existing entry, and optionally uninstall associated route.
 */
static void clear_one_entry(struct nt_entry **entry, bool uninstall_p)
{
	assert(entry && *entry);

	nt_entry_rb_del(&nt_globals.entry_rb, *entry);
	nt_entry_list_del(&nt_globals.entry_list, *entry);

	/* Uninstall associated route */
	if (uninstall_p)
		nt_uninstall_route(*entry);

	nt_entry_free(entry);
}

/*
 * Clear all existing entries, and optionally uninstall associated routes.
 */
static void clear_all_entries(bool uninstall_p)
{
	struct nt_entry *entry;

	/* Clear all entries */
	while ((entry = nt_entry_list_first(&nt_globals.entry_list)) != NULL)
		clear_one_entry(&entry, uninstall_p);
}

/*
 * Reschedule the timer event.
 */
static void nt_resched_timer(uint32_t timeout)
{
	if (timeout > 0)
		event_add_timer(zrouter.master, nt_handle_timer, NULL, timeout,
				&nt_globals.t_periodic_timer);
}

/*
 * Periodic timer handler; check for expired entries.
 */
static void nt_handle_timer(struct event *event)
{
	struct nt_entry *entry;
	time_t now, resched = 0;
	uint32_t counter = 0;

	now = time(NULL);

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: called at %u", __func__, (uint32_t)now);

	/* Process expired entries */
	frr_each_safe (nt_entry_list, &nt_globals.entry_list, entry) {
		if (entry->expiration <= now) {
			if (IS_ZEBRA_DEBUG_RIB)
				zlog_debug("%s: expired entry %u: %pIA",
					   __func__, entry->vrfid,
					   &entry->addr);

			clear_one_entry(&entry, true /*uninstall*/);
			counter++;
		} else {
			/* Capture next timer expiration */
			resched = entry->expiration;
			break;
		}

		/* Limit expirations per callback cycle */
		if (nt_globals.max_expirations > 0 &&
		    counter >= nt_globals.max_expirations) {
			resched = now;
			break;
		}
	}

	/* Compute remaining timeout */
	if (resched > 0)
		resched -= (now - 1);

	/* Reschedule */
	if (resched > 0) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s: rescheduling for %u secs", __func__,
				   (uint32_t)resched);

		nt_resched_timer(resched);
	}
}

/*
 * Add a single neighbor address entry; don't extend the timeout if the
 * entry exists.
 */
int zebra_neigh_throttle_add(vrf_id_t vrfid, const struct ipaddr *addr)
{
	struct nt_entry *entry, *prev;
	struct nt_entry key = {};

	if (!nt_globals.enabled_p)
		return 0;

	/* Apply limit */
	if (nt_globals.max_entries > 0 &&
	    (nt_entry_list_count(&nt_globals.entry_list) >= nt_globals.max_entries))
		return 0;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %u: %pIA", __func__, vrfid, addr);

	/* Start timer, if this is the first entry */
	if (nt_entry_list_const_first(&nt_globals.entry_list) == NULL)
		nt_resched_timer(nt_globals.timeout_secs);

	/* Look for existing entry */
	key.vrfid = vrfid;
	key.addr = *addr;
	entry = nt_entry_rb_find(&nt_globals.entry_rb, &key);

	if (entry)
		goto done;

	/* Alloc new entry */
	entry = nt_entry_alloc(vrfid, addr);

	/* Set expiration time */
	if (nt_globals.timeout_secs > 0)
		entry->expiration = time(NULL) + nt_globals.timeout_secs;

	/* Enqueue; try end of the timer list */
	prev = nt_entry_list_last(&nt_globals.entry_list);
	while (prev) {
		if (prev->expiration <= entry->expiration) {
			nt_entry_list_add_after(&nt_globals.entry_list, prev, entry);
			break;
		}

		prev = nt_entry_list_prev(&nt_globals.entry_list, prev);
	}

	if (prev == NULL)
		nt_entry_list_add_head(&nt_globals.entry_list, entry);

	/* Add new object to rbtree also */
	nt_entry_rb_add(&nt_globals.entry_rb, entry);

	/* And install blackhole route */
	nt_install_route(entry);

done:
	return 0;
}

/*
 * Delete a single neighbor entry
 */
int zebra_neigh_throttle_delete(vrf_id_t vrfid, const struct ipaddr *addr)
{
	struct nt_entry *entry;
	struct nt_entry key = {};

	if (!nt_globals.enabled_p)
		return 0;

	key.vrfid = vrfid;
	key.addr = *addr;
	entry = nt_entry_rb_find(&nt_globals.entry_rb, &key);

	if (entry) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s: %u: %pIA", __func__, vrfid, addr);

		clear_one_entry(&entry, true /*uninstall*/);
	}

	/* If no entries, stop the timer */
	if (nt_entry_list_const_first(&nt_globals.entry_list) == NULL)
		event_cancel(&nt_globals.t_periodic_timer);

	return 0;
}

/*
 * Set limit on number of blackhole entries permitted; if 'reset', reset to
 * default.
 */
void zebra_neigh_throttle_set_limit(uint32_t limit, bool reset)
{
	if (reset)
		nt_globals.max_entries = ZEBRA_NEIGH_THROTTLE_DEFAULT_MAX;
	else
		nt_globals.max_entries = limit;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: max_entries set to %u", __func__,
			   nt_globals.max_entries);
}

/*
 * Set limit on number of entries permitted to expire per callback;
 * if 'reset', reset to default.
 */
void zebra_neigh_throttle_set_expire_limit(uint32_t limit, bool reset)
{
	if (reset)
		nt_globals.max_expirations = ZEBRA_NEIGH_THROTTLE_EXPIRE_MAX;
	else
		nt_globals.max_expirations = limit;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: max_expirations set to %u", __func__,
			   nt_globals.max_expirations);
}

/*
 * Set timeout for blackhole entries (in seconds); if 'reset', reset to
 * default.
 */
void zebra_neigh_throttle_set_timeout(uint32_t timeout, bool reset)
{
	if (reset)
		nt_globals.timeout_secs = ZEBRA_NEIGH_THROTTLE_DEFAULT_TIMEOUT;
	else
		nt_globals.timeout_secs = timeout;

	/* TODO -- if timeout changes, should we fix-up existing entries? */

	/* Reset timer event */
	if (nt_globals.t_periodic_timer) {
		if ((uint32_t)event_timer_remain_second(nt_globals.t_periodic_timer) >
		    (uint32_t)nt_globals.timeout_secs)
			event_cancel(&nt_globals.t_periodic_timer);
	}

	/* Start the timer if necessary: not previously running, or shortened
	 * in the clause above. This won't affect the timer if it's already
	 * running.
	 */
	if (nt_entry_list_const_first(&nt_globals.entry_list) != NULL)
		nt_resched_timer(nt_globals.timeout_secs);

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: timeout set to %u secs", __func__,
			   (uint32_t)nt_globals.timeout_secs);
}

/*
 * Enable or disable the feature
 */
void zebra_neigh_throttle_enable(bool enable)
{
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %s", __func__, enable ? "ENABLED" : "DISABLED");

	if (enable) {
		if (nt_globals.enabled_p)
			return;

		zlog_info("Neighbor throttling feature enabled.");

		nt_globals.enabled_p = true;

	} else if (nt_globals.enabled_p) {
		zlog_info("Neighbor throttling feature disabled.");

		/* Cancel timer */
		event_cancel(&nt_globals.t_periodic_timer);

		/* Empty/free any existing entries */
		clear_all_entries(true /*uninstall*/);

		nt_globals.enabled_p = false;
	}
}

/*
 * Is the feature enabled?
 */
bool zebra_neigh_throttle_is_enabled(void)
{
	return nt_globals.enabled_p;
}

/*
 * Shutdown/cleanup function
 */
void zebra_neigh_throttle_fini(void)
{
	if (!nt_globals.init_p)
		return;

	/* Cancel timer */
	event_cancel(&nt_globals.t_periodic_timer);

	/* Empty/free any existing entries - don't need to explicitly
	 * uninstall, zebra rib code will do this for us.
	 */
	clear_all_entries(false /*uninstall*/);

	nt_globals.init_p = false;
}

/*
 * Init/startup function
 */
void zebra_neigh_throttle_init(void)
{
	if (nt_globals.init_p)
		return;

	/* Init globals */
	memset(&nt_globals, 0, sizeof(nt_globals));

	nt_entry_list_init(&nt_globals.entry_list);
	nt_entry_rb_init(&nt_globals.entry_rb);

	nt_globals.timeout_secs = ZEBRA_NEIGH_THROTTLE_DEFAULT_TIMEOUT;
	nt_globals.max_entries = ZEBRA_NEIGH_THROTTLE_DEFAULT_MAX;
	nt_globals.max_expirations = ZEBRA_NEIGH_THROTTLE_EXPIRE_MAX;

	nt_globals.init_p = true;
}

/*
 * Show output
 */
int zebra_neigh_throttle_show(struct vty *vty, bool detail, bool use_json)
{
	const struct nt_entry *entry;
	time_t now;
	uint32_t expires;
	json_object *json = NULL;
	json_object *jarray = NULL;
	json_object *jobj = NULL;

	if (use_json) {
		json = json_object_new_object();

		/* Individual attributes */
		if (nt_globals.enabled_p)
			json_object_boolean_true_add(json, "enabled");
		else {
			json_object_boolean_false_add(json, "enabled");
			goto json_done;
		}

		json_object_int_add(json, "timeout", (uint32_t)nt_globals.timeout_secs);
		json_object_int_add(json, "limit", (uint32_t)nt_globals.max_entries);
		json_object_int_add(json, "max_expirations",
				    (uint32_t)nt_globals.max_expirations);
		json_object_int_add(json, "entryCount",
				    nt_entry_list_count(&nt_globals.entry_list));

		if (!detail)
			goto json_done;

		/* Array/list of entries */
		jarray = json_object_new_array();

		entry = nt_entry_rb_const_first(&nt_globals.entry_rb);
		while (entry) {
			jobj = json_object_new_object();

			json_object_int_add(jobj, "expiration", entry->expiration);

			if (entry->addr.ipa_type == IPADDR_V4) {
				json_object_string_add(jobj, "afi", "ipv4");
				json_object_string_addf(jobj, "ipaddr", "%pI4",
							&entry->addr.ipaddr_v4);
			} else if (entry->addr.ipa_type == IPADDR_V6) {
				json_object_string_add(jobj, "afi", "ipv6");
				json_object_string_addf(jobj, "ipaddr", "%pI6",
							&entry->addr.ipaddr_v6);
			}

			json_object_array_add(jarray, jobj);

			entry = nt_entry_rb_const_next(&nt_globals.entry_rb, entry);
		}

		json_object_object_add(json, "entries", jarray);

json_done:
		/* This formats and then frees the json object */
		return vty_json(vty, json);
	}

	vty_out(vty, "Throttled neighbor entries: %s\n",
		nt_globals.enabled_p ? "enabled" : "disabled");

	if (nt_globals.enabled_p) {
		now = time(NULL);

		vty_out(vty, "Timeout: %u secs, limit: %u, exp: %u\n",
			(uint32_t)nt_globals.timeout_secs, nt_globals.max_entries,
			nt_globals.max_expirations);
		vty_out(vty, "Entries: (%zu)\n",
			nt_entry_list_count(&nt_globals.entry_list));

		if (detail) {
			/* Show output sorted by ip */
			entry = nt_entry_rb_const_first(&nt_globals.entry_rb);
			while (entry) {
				/* Compute remaining timeout */
				if (entry->expiration >= now)
					expires = entry->expiration - now;
				else
					expires = 0;

				vty_out(vty, "  %pIA, expires in %u secs\n",
					&entry->addr, expires);

				entry = nt_entry_rb_const_next(
					&nt_globals.entry_rb, entry);
			}
		}
	}

	return CMD_SUCCESS;
}

/*
 * Emit config output
 */
int zebra_neigh_throttle_config_write(struct vty *vty)
{
	if (nt_globals.enabled_p)
		vty_out(vty, ZEBRA_NEIGH_THROTTLE_STR "\n");

	if (nt_globals.max_entries != ZEBRA_NEIGH_THROTTLE_DEFAULT_MAX)
		vty_out(vty, ZEBRA_NEIGH_THROTTLE_STR " limit %u\n",
			nt_globals.max_entries);

	if (nt_globals.timeout_secs != ZEBRA_NEIGH_THROTTLE_DEFAULT_TIMEOUT)
		vty_out(vty, ZEBRA_NEIGH_THROTTLE_STR " timeout %u\n",
			(uint32_t)nt_globals.timeout_secs);

	return CMD_SUCCESS;
}
