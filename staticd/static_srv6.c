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

/*
 * List of SRv6 SIDs.
 */
struct list *srv6_locators;
struct list *srv6_sids;

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_LOCATOR, "Static SRv6 locator");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID");

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
