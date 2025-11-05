// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - Segment Routing over IPv6 (SRv6) code
 * Copyright (C) 2025 Alibaba Inc.
 *               Yuqing Zhao
 *               Lingyu Zhang
 */
#include <zebra.h>

#include "vrf.h"
#include "nexthop.h"

#include "static_routes.h"
#include "static_srv6.h"
#include "static_vrf.h"
#include "static_zebra.h"
#include "static_debug.h"

/*
 * List of SRv6 SIDs.
 */
struct list *srv6_locators;
struct list *srv6_sids;

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_LOCATOR, "Static SRv6 locator");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_NEIGH, "Static SRv6 Neighbor");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_NEIGH_CACHE, "Static SRv6 Neighbor Cache");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_IF_NEIGH, "Static SRv6 Interface Neighbors");

/* Comparison and hash functions for neighbor table */
static int static_srv6_neigh_table_cmp(const struct static_srv6_if_neigh *n1,
				       const struct static_srv6_if_neigh *n2);
static uint32_t static_srv6_neigh_table_hash(const struct static_srv6_if_neigh *neigh);

DECLARE_HASH(static_srv6_neigh_table, struct static_srv6_if_neigh, item,
	     static_srv6_neigh_table_cmp, static_srv6_neigh_table_hash);

/* Global neighbor cache instance */
struct static_srv6_neigh_cache *neigh_cache;

/*
 * Determines if the specified SID needs to be installed or removed
 * due to a state change (up/down) on the provided interface.
 *
 * Returns:
 *   - true  : The SID is dependent on this interface and should be updated
 *             (installed or uninstalled) when the interface changes state.
 *   - false : The SID does not depend on this interface; no update needed.
 */
static bool is_sid_update_required(struct interface *ifp, struct static_srv6_sid *sid)
{
	/* Check if the SID's behavior is one of the uDT* variants. */
	bool is_udt = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT6 ||
		       sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID ||
		       sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4 ||
		       sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID ||
		       sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46 ||
		       sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID);

	/* Check if the SID's behavior is one of the uDT4/uDT46 variants. */
	bool is_udt4_or_udt46 = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4 ||
				 sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID ||
				 sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46 ||
				 sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID);

	/* Check if the SID's behavior is one of the uA variants. */
	bool is_ua = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X ||
		      sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID);

	/* Check if the SID's behavior is one of the uN variants. */
	bool is_un = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END ||
		      sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID);

	/* Check if the SID requires an update based on behavior and behavior-specific attributes */

	if (is_un) {
		/*
		 * 1. SID is uN. uN SIDs are attached to 'sr0'.
		 *    Therefore, an update is needed if the provided interface 'ifp' is 'sr0'.
		 */
		if (strmatch(ifp->name, DEFAULT_SRV6_IFNAME))
			return true;
	}

	if (is_ua) {
		/*
		 * 2. SID is uA. uA SIDs are associated with a specific interface defined in their attributes.
		 *    Therefore, an update is needed if the provided interface 'ifp' matches the SID's associated interface.
		 */
		if (strmatch(sid->attributes.ifname, ifp->name))
			return true;
	}

	if (is_udt) {
		/*
		 * 3a. SID is uDT*. uDT* SIDs are associated with a VRF interface defined in their attributes.
		 *     Therefore, an update is needed if the provided interface 'ifp' matches the SID's associated VRF.
		 */
		if (strmatch(sid->attributes.vrf_name, ifp->name))
			return true;

		/*
		 * 3b. SID is uDT* and is associated with the default VRF.
		 *     When associated with the default VRF, uDT* SIDs are attached to 'sr0'.
		 *     Therefore, an update is needed if the provided interface 'ifp' is 'sr0'.
		 */
		if (strmatch(ifp->name, DEFAULT_SRV6_IFNAME) &&
		    strmatch(sid->attributes.vrf_name, VRF_DEFAULT_NAME))
			return true;

		/*
		 * 3c. SID is uDT4 or uDT46 and is associated with the default VRF.
		 *     These SIDs rely on any VRF bound to the main routing table (table ID 254) for
		 *     decapsulation and forwarding.
		 *     Therefore, an update is needed if the provided interface 'ifp' is a VRF interface
		 *     bound to the main routing table.
		 */
		if (is_udt4_or_udt46 && strmatch(sid->attributes.vrf_name, VRF_DEFAULT_NAME) &&
		    (ifp->vrf->data.l.table_id == 254))
			return true;
	}

	/* No dependency found */
	return false;
}

/*
 * When an interface is enabled in the kernel, go through all the static SRv6 SIDs in
 * the system that use this interface and install/remove them in the zebra RIB.
 *
 * ifp   - The interface being enabled
 * is_up - Whether the interface is up or down
 */
void static_ifp_srv6_sids_update(struct interface *ifp, bool is_up)
{
	struct static_srv6_sid *sid;
	struct listnode *node;
	bool needs_install = true;

	if (!srv6_sids || !ifp)
		return;

	DEBUGD(&static_dbg_srv6,
	       "%s: Received %s event for interface '%s': %s dependent SRv6 SIDs", __func__,
	       (is_up) ? "UP" : "DOWN", ifp->name, (is_up) ? "installing" : "uninstalling");

	/*
	 * iterate over the list of SRv6 SIDs and remove the SIDs that use this
	 * VRF from the zebra RIB
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!is_sid_update_required(ifp, sid))
			continue;

		if (is_up && !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
			static_zebra_request_srv6_sid(sid);
		} else if (is_up && CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
				static_zebra_srv6_sid_uninstall(sid);
				UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
			}

			if (static_srv6_sid_needs_resolution(sid))
				if (!static_srv6_sid_resolve_nexthop(sid))
					needs_install = false; /* Can't install without neighbor */

			if (needs_install) {
				static_zebra_srv6_sid_install(sid);
				SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
			}
		} else {
			static_zebra_srv6_sid_uninstall(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
		}
	}
}

/*
 * Allocate an SRv6 SID object and initialize the fields common to all the
 * behaviors (i.e., SID address and behavor).
 */
struct static_srv6_sid *static_srv6_sid_alloc(struct prefix_ipv6 *addr)
{
	struct static_srv6_sid *sid = NULL;

	sid = XCALLOC(MTYPE_STATIC_SRV6_SID, sizeof(struct static_srv6_sid));
	sid->addr = *addr;

	return sid;
}

void static_srv6_sid_free(struct static_srv6_sid *sid)
{
	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

struct static_srv6_locator *static_srv6_locator_lookup(const char *name)
{
	struct static_srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

/*
 * Look-up an SRv6 SID in the list of SRv6 SIDs.
 */
struct static_srv6_sid *static_srv6_sid_lookup(struct prefix_ipv6 *sid_addr)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid))
		if (memcmp(&sid->addr, sid_addr, sizeof(struct prefix_ipv6)) == 0)
			return sid;

	return NULL;
}

struct static_srv6_locator *static_srv6_locator_alloc(const char *name)
{
	struct static_srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_STATIC_SRV6_LOCATOR, sizeof(struct static_srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));

	return locator;
}

void static_srv6_locator_free(struct static_srv6_locator *locator)
{
	XFREE(MTYPE_STATIC_SRV6_LOCATOR, locator);
}

void delete_static_srv6_locator(void *val)
{
	static_srv6_locator_free((struct static_srv6_locator *)val);
}

/*
 * Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID.<<<
 */
void static_srv6_sid_del(struct static_srv6_sid *sid)
{
	/* Clean up nexthop resolution flag if set */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION)) {
		static_srv6_neigh_unregister_if_needed();
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
		static_zebra_release_srv6_sid(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
		static_zebra_srv6_sid_uninstall(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
	}

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

void delete_static_srv6_sid(void *val)
{
	static_srv6_sid_free((struct static_srv6_sid *)val);
}

void static_zebra_request_srv6_sids(void)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid))
		static_zebra_request_srv6_sid(sid);
}

/*
 * Neighbor Cache Functions
 */

/* Comparison function for neighbor table */
int static_srv6_neigh_table_cmp(const struct static_srv6_if_neigh *ifn1,
				const struct static_srv6_if_neigh *ifn2)
{
	if (ifn1->ifindex < ifn2->ifindex)
		return -1;

	if (ifn1->ifindex > ifn2->ifindex)
		return 1;

	return 0;
}

/* Hash function for neighbor table */
uint32_t static_srv6_neigh_table_hash(const struct static_srv6_if_neigh *ifn)
{
	return jhash_1word(ifn->ifindex, 0);
}

/* Free neighbor */
static void static_srv6_neigh_free(struct static_srv6_neigh *neigh)
{
	XFREE(MTYPE_STATIC_SRV6_NEIGH, neigh);
}

/*
 * Initialize the neighbor cache
 */
void static_srv6_neigh_cache_init(void)
{
	if (neigh_cache)
		return;

	neigh_cache = XCALLOC(MTYPE_STATIC_SRV6_NEIGH_CACHE,
			      sizeof(struct static_srv6_neigh_cache));

	static_srv6_neigh_table_init(&neigh_cache->neigh_table);
	neigh_cache->resolve_sids_cnt = 0;
	neigh_cache->registered = false;
}

/*
 * Clean up the neighbor cache
 */
void static_srv6_neigh_cache_cleanup(void)
{
	struct static_srv6_if_neigh *ifn;
	struct static_srv6_neigh *neigh;
	struct static_srv6_neigh *next;

	if (!neigh_cache)
		return;

	/* Unregister from neighbor notifications if needed */
	if (neigh_cache->registered)
		static_srv6_neigh_unregister_if_needed();

	/* Clean up hash table - free all interface neighbors */
	while ((ifn = static_srv6_neigh_table_pop(&neigh_cache->neigh_table)) != NULL) {
		neigh = ifn->neighbors;
		while (neigh) {
			next = neigh->next;
			static_srv6_neigh_free(neigh);
			neigh = next;
		}
		XFREE(MTYPE_STATIC_SRV6_IF_NEIGH, ifn);
	}
	static_srv6_neigh_table_fini(&neigh_cache->neigh_table);

	XFREE(MTYPE_STATIC_SRV6_NEIGH_CACHE, neigh_cache);
	neigh_cache = NULL;
}

/*
 * Check if a neighbor state is usable for SID resolution
 * Returns true if the neighbor can be used
 */
static bool static_srv6_neigh_state_is_usable(uint32_t ndm_state)
{
	/* States that indicate the neighbor is reachable/usable */
	if (ndm_state &
	    (ZEBRA_NEIGH_STATE_REACHABLE | ZEBRA_NEIGH_STATE_PERMANENT | ZEBRA_NEIGH_STATE_NOARP))
		return true;

	/* States that indicate problems */
	if (ndm_state & (ZEBRA_NEIGH_STATE_FAILED | ZEBRA_NEIGH_STATE_INCOMPLETE))
		return false;

	/*
	 * For other states (STALE, DELAY, PROBE), be conservative
	 * and consider them usable - the kernel will handle revalidation
	 */
	if (ndm_state &
	    (ZEBRA_NEIGH_STATE_STALE | ZEBRA_NEIGH_STATE_DELAY | ZEBRA_NEIGH_STATE_PROBE))
		return true;

	/* If no state bits set, assume not usable */
	return false;
}

/**
 * Refresh SIDs when a neighbor is added
 * Try to resolve and install previously unresolved SIDs
 */
void static_srv6_refresh_sids_on_neigh_change(struct interface *ifp, struct in6_addr *nexthop,
					      bool is_add)
{
	struct listnode *node;
	struct static_srv6_sid *sid;
	int processed = 0;

	if (!srv6_sids) {
		DEBUGD(&static_dbg_srv6, "%s: No SIDs available for refresh", __func__);
		return;
	}

	DEBUGD(&static_dbg_srv6, "%s: Refreshing SIDs after neighbor %s to interface %u", __func__,
	       is_add ? "added" : "removed", ifp->ifindex);

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		/* Skip SIDs that don't require nexthop resolution */
		if (!static_srv6_sid_needs_resolution(sid))
			continue;

		/* Check if this SID is for this interface */
		if (!strmatch(sid->attributes.ifname, ifp->name))
			continue;

		processed++;

		/* Check if this SID is already resolved */
		if (is_add && !IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.resolved_nh6))
			continue;

		/* Check if this SID was using the removed neighbor */
		if (!is_add && nexthop && !IPV6_ADDR_SAME(&sid->attributes.resolved_nh6, nexthop))
			continue;

		/* If neighbor has been removed and SID was using it, uninstall the SID from zebra */
		if (!is_add) {
			/* Uninstall SID that was using the removed neighbor */
			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
				if (nexthop)
					DEBUGD(&static_dbg_srv6,
					       "%s: Uninstalling SID %pFX - using removed neighbor %pI6",
					       __func__, &sid->addr, nexthop);
				else
					DEBUGD(&static_dbg_srv6, "%s: Uninstalling SID %pFX",
					       __func__, &sid->addr);
				static_zebra_srv6_sid_uninstall(sid);
			}

			/* Clear resolved nexthop */
			memset(&sid->attributes.resolved_nh6, 0, sizeof(struct in6_addr));
		}

		/* Try to resolve with the new neighbor */
		if (static_srv6_sid_resolve_nexthop(sid)) {
			/* Install with resolved nexthop */
			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID) &&
			    !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
				DEBUGD(&static_dbg_srv6,
				       "%s: Installing previously unresolved SID %pFX with nexthop %pI6",
				       __func__, &sid->addr, &sid->attributes.resolved_nh6);
				static_zebra_srv6_sid_install(sid);
			}
		} else {
			DEBUGD(&static_dbg_srv6, "%s: No alternative neighbor for SID %pFX",
			       __func__, &sid->addr);
		}
	}

	DEBUGD(&static_dbg_srv6, "%s: Refresh complete after neighbor %s - processed %d SIDs",
	       __func__, is_add ? "add" : "delete", processed);
}

/*
 * Check if there are any SIDs that need auto-resolution for this interface
 */
static bool static_srv6_has_sids_for_interface(ifindex_t ifindex)
{
	struct listnode *node;
	struct static_srv6_sid *sid;
	struct interface *ifp;

	if (!srv6_sids)
		return false;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!static_srv6_sid_needs_resolution(sid))
			continue;

		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (ifp && ifp->ifindex == ifindex)
			return true;
	}

	return false;
}

/*
 * Add a neighbor to the cache
 */
void static_srv6_neigh_add(struct interface *ifp, struct in6_addr *addr, uint32_t ndm_state)
{
	struct static_srv6_neigh *new_neigh, *existing;
	struct static_srv6_if_neigh *ifn;
	bool state_changed = false;
	uint32_t old_state = 0;
	bool is_new = false;
	struct static_srv6_if_neigh lookup_key = { .ifindex = ifp->ifindex };

	if (!neigh_cache) {
		DEBUGD(&static_dbg_srv6, "%s: Cache not initialized, ignoring neighbor add",
		       __func__);
		return;
	}

	DEBUGD(&static_dbg_srv6,
	       "%s: Adding neighbor %pI6 on interface %s (index %u) with state 0x%x", __func__,
	       addr, ifp->name, ifp->ifindex, ndm_state);

	/* Look up bucket for this interface */
	ifn = static_srv6_neigh_table_find(&neigh_cache->neigh_table, &lookup_key);

	/* Create bucket if it doesn't exist */
	if (!ifn) {
		ifn = XCALLOC(MTYPE_STATIC_SRV6_IF_NEIGH, sizeof(struct static_srv6_if_neigh));
		ifn->ifindex = ifp->ifindex;
		ifn->neighbors = NULL;
		static_srv6_neigh_table_add(&neigh_cache->neigh_table, ifn);
		DEBUGD(&static_dbg_srv6, "%s: Created new bucket for interface %s (index %u)",
		       __func__, ifp->name, ifp->ifindex);
	}

	/* Check if neighbor already exists - update state if so */
	existing = ifn->neighbors;
	while (existing) {
		if (IPV6_ADDR_SAME(&existing->addr, addr)) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Neighbor %pI6 already exists on interface %s (index %u), updating state 0x%x->0x%x",
			       __func__, addr, ifp->name, ifp->ifindex, existing->ndm_state,
			       ndm_state);

			/* Update state if changed */
			if (existing->ndm_state != ndm_state) {
				old_state = existing->ndm_state;
				existing->ndm_state = ndm_state;
				state_changed = true;
			}

			/*
			 * If neighbor is STALE and we have SIDs using this interface,
			 * request neighbor discovery to verify if neighbor is still alive
			 */
			if (ndm_state & ZEBRA_NEIGH_STATE_STALE) {
				if (static_srv6_has_sids_for_interface(ifp->ifindex)) {
					struct ipaddr ipaddr;

					DEBUGD(&static_dbg_srv6,
					       "%s: Requesting neighbor discovery for STALE neighbor %pI6 on interface %s (index %u)",
					       __func__, addr, ifp->name, ifp->ifindex);

					SET_IPADDR_V6(&ipaddr);
					ipaddr.ipaddr_v6 = *addr;

					static_zebra_send_neigh_discovery_req(ifp, &ipaddr);
				}
			}

			/* Refresh SIDs if state changed to a usable or unusable state */
			if (state_changed) {
				/* Refresh if transitioning to/from usable state */
				bool was_usable = static_srv6_neigh_state_is_usable(old_state);
				bool is_usable = static_srv6_neigh_state_is_usable(ndm_state);

				if (was_usable != is_usable)
					static_srv6_refresh_sids_on_neigh_change(ifp, addr, true);
			}
			return;
		}
		if (!existing->next)
			break;
		existing = existing->next;
	}

	/* Create new neighbor entry */
	new_neigh = XCALLOC(MTYPE_STATIC_SRV6_NEIGH, sizeof(struct static_srv6_neigh));
	new_neigh->addr = *addr;
	new_neigh->ifindex = ifp->ifindex;
	new_neigh->ndm_state = ndm_state;
	new_neigh->next = NULL;

	if (!existing) {
		/* First neighbor for this interface */
		ifn->neighbors = new_neigh;
		DEBUGD(&static_dbg_srv6,
		       "%s: Added first neighbor %pI6 for interface %s (index %u) with state 0x%x",
		       __func__, addr, ifp->name, ifp->ifindex, ndm_state);
		is_new = true;
	} else {
		/* Add to existing list */
		existing->next = new_neigh;
		DEBUGD(&static_dbg_srv6,
		       "%s: Added additional neighbor %pI6 for interface %s (index %u) with state 0x%x",
		       __func__, addr, ifp->name, ifp->ifindex, ndm_state);
		is_new = true;
	}

	/* Refresh SIDs for this interface if new usable neighbor */
	if (is_new && static_srv6_neigh_state_is_usable(ndm_state)) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Refreshing SIDs for interface %s (index %u) after neighbor add",
		       __func__, ifp->name, ifp->ifindex);
		static_srv6_refresh_sids_on_neigh_change(ifp, addr, true);
	}
}

/*
 * Remove a neighbor from the cache
 */
void static_srv6_neigh_remove(struct interface *ifp, struct in6_addr *addr)
{
	struct static_srv6_neigh *neigh, *prev = NULL;
	struct static_srv6_if_neigh *ifn;
	struct static_srv6_if_neigh lookup_key = { .ifindex = ifp->ifindex };

	if (!neigh_cache) {
		DEBUGD(&static_dbg_srv6, "%s: Cache not initialized, ignoring neighbor remove",
		       __func__);
		return;
	}

	DEBUGD(&static_dbg_srv6, "%s: Removing neighbor %pI6 from interface %s (index %u)",
	       __func__, addr, ifp->name, ifp->ifindex);

	ifn = static_srv6_neigh_table_find(&neigh_cache->neigh_table, &lookup_key);
	if (!ifn) {
		DEBUGD(&static_dbg_srv6, "%s: No neighbors found for interface %s (index %u)",
		       __func__, ifp->name, ifp->ifindex);
		return;
	}

	neigh = ifn->neighbors;
	while (neigh) {
		if (IPV6_ADDR_SAME(&neigh->addr, addr)) {
			/* Found the entry to remove */
			DEBUGD(&static_dbg_srv6,
			       "%s: Found neighbor %pI6 to remove from interface %s (index %u)",
			       __func__, addr, ifp->name, ifp->ifindex);
			if (prev) {
				prev->next = neigh->next;
			} else {
				/* First entry in the list */
				ifn->neighbors = neigh->next;
			}
			static_srv6_neigh_free(neigh);

			/* If no more neighbors, remove the bucket */
			if (!ifn->neighbors) {
				DEBUGD(&static_dbg_srv6,
				       "%s: No more neighbors for interface %s (index %u), removing bucket",
				       __func__, ifp->name, ifp->ifindex);
				static_srv6_neigh_table_del(&neigh_cache->neigh_table, ifn);
				XFREE(MTYPE_STATIC_SRV6_IF_NEIGH, ifn);
			}
			break;
		}
		prev = neigh;
		neigh = neigh->next;
	}

	/* Refresh SIDs for this interface after neighbor removal */
	DEBUGD(&static_dbg_srv6,
	       "%s: Refreshing SIDs for interface %s (index %u) after neighbor remove", __func__,
	       ifp->name, ifp->ifindex);
	static_srv6_refresh_sids_on_neigh_change(ifp, addr, false);
}

/*
 * Look up best neighbor for an interface based on state and type
 * Priority:
 * 1. REACHABLE/PERMANENT state neighbors
 * 2. Link-local addresses (preferred for SRv6)
 * 3. First usable neighbor found
 */
struct in6_addr *static_srv6_neigh_lookup(struct interface *ifp)
{
	struct static_srv6_if_neigh *ifn;
	struct static_srv6_neigh *neigh;
	struct static_srv6_neigh *best = NULL;
	struct static_srv6_neigh *best_linklocal = NULL;
	struct static_srv6_neigh *best_reachable = NULL;
	struct static_srv6_if_neigh lookup_key = { .ifindex = ifp->ifindex };

	if (!neigh_cache)
		return NULL;

	ifn = static_srv6_neigh_table_find(&neigh_cache->neigh_table, &lookup_key);
	/* If no neighbors cached for this interface, request from zebra */
	if (!ifn) {
		ifn = XCALLOC(MTYPE_STATIC_SRV6_IF_NEIGH, sizeof(struct static_srv6_if_neigh));
		ifn->ifindex = ifp->ifindex;
		ifn->neighbors = NULL;
		static_srv6_neigh_table_add(&neigh_cache->neigh_table, ifn);
	}

	if (!ifn->neighbors) {
		/* No neighbors available, request from zebra */
		if (!ifn->neigh_request_sent) {
			DEBUGD(&static_dbg_srv6,
			       "%s: No cached neighbors for interface %s (index %u), requesting from zebra",
			       __func__, ifp->name, ifp->ifindex);
			static_zebra_neigh_get(ifp, AFI_IP6);
			ifn->neigh_request_sent = true;
		} else {
			/* Neighbors request already sent, waiting for response */
			DEBUGD(&static_dbg_srv6,
			       "%s: Neighbors request already sent for interface %s (index %u), waiting for response",
			       __func__, ifp->name, ifp->ifindex);
		}

		return NULL;
	}

	DEBUGD(&static_dbg_srv6, "%s: Looking up best neighbor for interface %s (index %u)",
	       __func__, ifp->name, ifp->ifindex);

	/* Scan all neighbors and categorize them */
	for (neigh = ifn->neighbors; neigh; neigh = neigh->next) {
		DEBUGD(&static_dbg_srv6, "%s:   Candidate %pI6 state=0x%x", __func__, &neigh->addr,
		       neigh->ndm_state);

		/* Skip neighbors with failed/incomplete state */
		if (!static_srv6_neigh_state_is_usable(neigh->ndm_state)) {
			DEBUGD(&static_dbg_srv6, "%s:   Skipping %pI6 - unusable state 0x%x",
			       __func__, &neigh->addr, neigh->ndm_state);
			continue;
		}

		/* Track best reachable/permanent neighbor */
		if (neigh->ndm_state & (ZEBRA_NEIGH_STATE_REACHABLE | ZEBRA_NEIGH_STATE_PERMANENT)) {
			if (IN6_IS_ADDR_LINKLOCAL(&neigh->addr)) {
				if (!best_linklocal) {
					best_linklocal = neigh;
					DEBUGD(&static_dbg_srv6, "%s:   New best link-local: %pI6",
					       __func__, &neigh->addr);
				}
			} else if (!best_reachable) {
				best_reachable = neigh;
				DEBUGD(&static_dbg_srv6, "%s:   New best reachable: %pI6",
				       __func__, &neigh->addr);
			}
		}

		/* Track first usable neighbor as fallback */
		if (!best)
			best = neigh;
	}

	/* Return best match in priority order */
	if (best_linklocal) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Selected link-local neighbor %pI6 for interface %s (index %u)",
		       __func__, &best_linklocal->addr, ifp->name, ifp->ifindex);
		return &best_linklocal->addr;
	}

	if (best_reachable) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Selected reachable neighbor %pI6 for interface %s (index %u)",
		       __func__, &best_reachable->addr, ifp->name, ifp->ifindex);
		return &best_reachable->addr;
	}

	if (best) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Selected fallback neighbor %pI6 (state=0x%x) for interface %s (index %u)",
		       __func__, &best->addr, best->ndm_state, ifp->name, ifp->ifindex);
		return &best->addr;
	}

	DEBUGD(&static_dbg_srv6, "%s: No usable neighbor found for interface %s (index %u)",
	       __func__, ifp->name, ifp->ifindex);
	return NULL;
}

/*
 * Clean up all neighbors for a specific interface (when interface goes down)
 */
void static_srv6_neigh_cleanup_interface(struct interface *ifp)
{
	struct static_srv6_if_neigh *ifn;
	struct static_srv6_neigh *neighbor;
	struct static_srv6_neigh *next;
	struct static_srv6_if_neigh lookup_key = { .ifindex = ifp->ifindex };

	if (!neigh_cache)
		return;

	DEBUGD(&static_dbg_srv6, "%s: Cleaning up neighbors for interface %s (index %u)", __func__,
	       ifp->name, ifp->ifindex);

	ifn = static_srv6_neigh_table_find(&neigh_cache->neigh_table, &lookup_key);
	if (!ifn)
		return;

	/* Remove all neighbors for this interface */
	neighbor = ifn->neighbors;
	while (neighbor) {
		next = neighbor->next;
		DEBUGD(&static_dbg_srv6, "%s: Removing neighbor %pI6 from interface %s (index %u)",
		       __func__, &neighbor->addr, ifp->name, ifp->ifindex);
		XFREE(MTYPE_STATIC_SRV6_NEIGH, neighbor);
		neighbor = next;
	}
	ifn->neighbors = NULL;

	/* Refresh all SIDs that might be using this interface for auto-resolution */
	static_srv6_refresh_sids_on_neigh_change(ifp, NULL, false);
}

/*
 * Register for neighbor notifications if we have SIDs requiring nexthop resolution
 */
void static_srv6_neigh_register_if_needed(void)
{
	if (!neigh_cache) {
		DEBUGD(&static_dbg_srv6, "%s: Initializing neighbor cache", __func__);
		static_srv6_neigh_cache_init();
	}

	neigh_cache->resolve_sids_cnt++;
	DEBUGD(&static_dbg_srv6, "%s: SRv6 SID resolve count increased to %u", __func__,
	       neigh_cache->resolve_sids_cnt);

	if (!neigh_cache->registered && neigh_cache->resolve_sids_cnt > 0) {
		DEBUGD(&static_dbg_srv6, "%s: Registering for IPv6 neighbor notifications",
		       __func__);
		static_zebra_neigh_register(AFI_IP6, true);
		neigh_cache->registered = true;
	} else if (neigh_cache->registered) {
		DEBUGD(&static_dbg_srv6, "%s: Already registered for neighbor notifications",
		       __func__);
	}
}

/*
 * Unregister from neighbor notifications if there are no other SIDs requiring
 * nexthop resolution
 */
void static_srv6_neigh_unregister_if_needed(void)
{
	if (!neigh_cache) {
		DEBUGD(&static_dbg_srv6, "%s: Cache not initialized during unregister", __func__);
		return;
	}

	if (neigh_cache->resolve_sids_cnt > 0) {
		neigh_cache->resolve_sids_cnt--;
		DEBUGD(&static_dbg_srv6, "%s: SRv6 SID resolve count decreased to %u", __func__,
		       neigh_cache->resolve_sids_cnt);
	}

	if (neigh_cache->registered && neigh_cache->resolve_sids_cnt == 0) {
		DEBUGD(&static_dbg_srv6, "%s: Unregistering from IPv6 neighbor notifications",
		       __func__);
		static_zebra_neigh_register(AFI_IP6, false);
		neigh_cache->registered = false;
	}
}

/**
 * Get the effective nexthop to use for SID installation
 * Returns pointer to attributes.resolved_nh6 for SIDs
 * requiring nexthop resolution, or attributes.nh6 for SIDs
 * that provide an explicit nexthop.
 */
const struct in6_addr *static_srv6_sid_get_nexthop(const struct static_srv6_sid *sid)
{
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION)) {
		return IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.resolved_nh6)
			       ? NULL
			       : &sid->attributes.resolved_nh6;
	}

	return &sid->attributes.nh6;
}

/**
 * Check if a SID needs nexthop resolution
 */
bool static_srv6_sid_needs_resolution(const struct static_srv6_sid *sid)
{
	bool is_ua = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X ||
		      sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID);

	return is_ua && CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION) &&
	       sid->attributes.ifname[0] != '\0' && IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.nh6);
}

/**
 * Resolve nexthop for a SID
 * Returns true if resolution succeeded, false otherwise
 */
bool static_srv6_sid_resolve_nexthop(struct static_srv6_sid *sid)
{
	struct interface *ifp;
	struct in6_addr *resolved_addr;

	if (!static_srv6_sid_needs_resolution(sid))
		return false;

	/* If already resolved, nothing to do */
	if (!IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.resolved_nh6)) {
		DEBUGD(&static_dbg_srv6, "%s: SID %pFX already has resolved nexthop %pI6",
		       __func__, &sid->addr, &sid->attributes.resolved_nh6);
		return true;
	}

	/* Look up interface */
	ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
	if (!ifp) {
		DEBUGD(&static_dbg_srv6, "%s: Interface %s not found for SID %pFX", __func__,
		       sid->attributes.ifname, &sid->addr);
		return false;
	}

	/* Look up best neighbor */
	resolved_addr = static_srv6_neigh_lookup(ifp);
	if (!resolved_addr) {
		DEBUGD(&static_dbg_srv6,
		       "%s: No usable neighbor found for SID %pFX on interface %s", __func__,
		       &sid->addr, sid->attributes.ifname);
		return false;
	}

	/* Update resolved nexthop */
	sid->attributes.resolved_nh6 = *resolved_addr;

	DEBUGD(&static_dbg_srv6, "%s: Resolved SID %pFX nexthop to %pI6 on interface %s", __func__,
	       &sid->addr, &sid->attributes.resolved_nh6, sid->attributes.ifname);

	return true;
}

/**
 * Clear resolved nexthop for a SID
 */
void static_srv6_sid_clear_resolution(struct static_srv6_sid *sid)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.resolved_nh6))
		return;

	DEBUGD(&static_dbg_srv6, "%s: Clearing resolved nexthop for SID %pFX", __func__,
	       &sid->addr);

	sid->attributes.resolved_nh6 = in6addr_any;
}

/*
 * Initialize SRv6 data structures.
 */
void static_srv6_init(void)
{
	srv6_locators = list_new();
	srv6_locators->del = delete_static_srv6_locator;
	srv6_sids = list_new();
	srv6_sids->del = delete_static_srv6_sid;
	static_srv6_neigh_cache_init();
}

/*
 * Clean up all the SRv6 data structures.
 */
void static_srv6_cleanup(void)
{
	static_srv6_neigh_cache_cleanup();
	list_delete(&srv6_locators);
	list_delete(&srv6_sids);
}
