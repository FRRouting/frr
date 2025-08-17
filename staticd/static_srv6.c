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

			static_zebra_srv6_sid_install(sid);
			SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
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
 * release the memory previously allocated for the SID.
 */
void static_srv6_sid_del(struct static_srv6_sid *sid)
{
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
 * Initialize SRv6 data structures.
 */
void static_srv6_init(void)
{
	srv6_locators = list_new();
	srv6_locators->del = delete_static_srv6_locator;
	srv6_sids = list_new();
	srv6_sids->del = delete_static_srv6_sid;
}

/*
 * Clean up all the SRv6 data structures.
 */
void static_srv6_cleanup(void)
{
	list_delete(&srv6_locators);
	list_delete(&srv6_sids);
}
