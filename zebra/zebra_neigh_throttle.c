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

#include "zebra/debug.h"
#include "zebra/zebra_neigh_throttle.h"
#include "zebra/zebra_router.h"
#include "zebra/rib.h"

PREDECL_DLIST(nt_entry_list);

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
};

DECLARE_DLIST(nt_entry_list, struct nt_entry, link);

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

	/*
	 * List of active entries, sorted by expiration time.
	 */
	struct nt_entry_list_head entry_list;

} nt_globals;

/* TODO -- hash also, or rbtree, for direct lookup? */

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

	if (entry->addr.ipa_type == IPADDR_V4) {
		afi = AFI_IP;
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		ipv4_addr_copy(&p.u.prefix4, &entry->addr.ipaddr_v4);
	} else {
		afi = AFI_IP6;
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		IPV6_ADDR_COPY(&p.u.prefix6, &entry->addr.ipaddr_v6);
	}

	zvrf = zebra_vrf_lookup_by_id(entry->vrfid);

	nh.weight = 1;
	nh.vrf_id = VRF_DEFAULT;
	nh.type = NEXTHOP_TYPE_BLACKHOLE;
	nh.bh_type = BLACKHOLE_ADMINPROHIB;

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

	if (entry->addr.ipa_type == IPADDR_V4) {
		afi = AFI_IP;
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		ipv4_addr_copy(&p.u.prefix4, &entry->addr.ipaddr_v4);
	} else {
		afi = AFI_IP6;
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		IPV6_ADDR_COPY(&p.u.prefix6, &entry->addr.ipaddr_v6);
	}

	nh.weight = 1;
	nh.vrf_id = VRF_DEFAULT;
	nh.type = NEXTHOP_TYPE_BLACKHOLE;
	nh.bh_type = BLACKHOLE_ADMINPROHIB;

	zvrf = zebra_vrf_lookup_by_id(entry->vrfid);
	if (zvrf == NULL)
		return;

	rib_delete(afi, SAFI_UNICAST, entry->vrfid, ZEBRA_ROUTE_FRR, 0, 0, &p,
		   NULL, &nh, 0, zvrf->table_id, 0, 0, false);
}

/*
 * Clear one existing entry, and optionally uninstall associated route.
 */
static void clear_one_entry(struct nt_entry *entry, bool uninstall_p)
{
	nt_entry_list_del(&nt_globals.entry_list, entry);

	/* Uninstall associated route */
	if (uninstall_p)
		nt_uninstall_route(entry);

	XFREE(MTYPE_NTHROTTLE, entry);
}

/*
 * Clear all existing entries, and optionally uninstall associated routes.
 */
static void clear_all_entries(bool uninstall_p)
{
	struct nt_entry *entry;

	/* Clear all entries */
	frr_each_safe (nt_entry_list, &nt_globals.entry_list, entry) {
		clear_one_entry(entry, uninstall_p);
	}
}

/*
 * Periodic timer handler; check for expired entries.
 */
static void nt_handle_timer(struct event *event)
{
	struct nt_entry *entry;
	time_t now;

	/* Reschedule */
	if (nt_globals.timeout_secs)
		event_add_timer(zrouter.master, nt_handle_timer,
				NULL, nt_globals.timeout_secs,
				&nt_globals.t_periodic_timer);

	now = time(NULL);

	/* Process expired entries */
	frr_each_safe (nt_entry_list, &nt_globals.entry_list, entry) {
		if (entry->expiration <= now) {
			clear_one_entry(entry, true);
		} else {
			break;
		}
	}
}

/*
 * Add a single neighbor address entry, or extend the timeout if the
 * entry exists.
 */
int zebra_neigh_throttle_add(vrf_id_t vrfid, const struct ipaddr *addr)
{
	struct nt_entry *entry, *prev;

	if (!nt_globals.enabled_p)
		return 0;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %u: %pIA", __func__, vrfid, addr);

	/* TODO -- brute-force search for now */
	frr_each(nt_entry_list, &nt_globals.entry_list, entry) {
		if (entry->vrfid == vrfid &&
		    ipaddr_cmp(&entry->addr, addr) == 0) {
			/* Dequeue -- we'll requeue after updating timeout */
			nt_entry_list_del(&nt_globals.entry_list, entry);
			break;
		}
	}

	if (entry == NULL)
		entry = nt_entry_alloc(vrfid, addr);

	/* Set expiration time */
	entry->expiration = time(NULL) + nt_globals.timeout_secs;

	/* Enqueue; try end of the timer list */
	prev = nt_entry_list_last(&nt_globals.entry_list);
	while (prev) {
		if (prev->expiration < entry->expiration) {
			nt_entry_list_add_after(&nt_globals.entry_list,
						prev, entry);
			break;
		}

		prev = nt_entry_list_prev(&nt_globals.entry_list, prev);
	}

	if (prev == NULL)
		nt_entry_list_add_head(&nt_globals.entry_list, entry);

	/* And install blackhole route */
	nt_install_route(entry);

	return 0;
}

/*
 * Delete a single neighbor entry
 */
int zebra_neigh_throttle_delete(vrf_id_t vrfid, const struct ipaddr *addr)
{
	struct nt_entry *entry;

	if (!nt_globals.enabled_p)
		return 0;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: %u: %pIA", __func__, vrfid, addr);

	/* TODO -- brute-force search for now */
	frr_each_safe(nt_entry_list, &nt_globals.entry_list, entry) {
		if (entry->vrfid == vrfid &&
		    ipaddr_cmp(&entry->addr, addr) == 0) {
			clear_one_entry(entry, true /*uninstall*/);
			break;
		}
	}

	return 0;
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

		/* Start timer */
		if (nt_globals.timeout_secs)
			event_add_timer(zrouter.master, nt_handle_timer,
					NULL, nt_globals.timeout_secs,
					&nt_globals.t_periodic_timer);

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
	nt_globals.timeout_secs = ZEBRA_NEIGH_THROTTLE_DEFAULT_TIMEOUT;
	nt_globals.max_entries = ZEBRA_NEIGH_THROTTLE_DEFAULT_MAX;

	nt_globals.init_p = true;
}

/*
 * Show output
 */
int zebra_neigh_throttle_show(struct vty *vty, bool detail)
{
	const struct nt_entry *entry;

	vty_out(vty, "Throttled neighbor entries:\n");
	vty_out(vty, "Count: %zu\n",
		nt_entry_list_count(&nt_globals.entry_list));

	frr_each(nt_entry_list_const, &nt_globals.entry_list, entry) {
		vty_out(vty, "  %pIA: exp %u\n",
			&entry->addr, (uint32_t)entry->expiration);
	}

	return CMD_SUCCESS;
}
