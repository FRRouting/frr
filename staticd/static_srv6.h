// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - Segment Routing over IPv6 (SRv6) header
 * Copyright (C) 2025 Alibaba Inc.
 *               Yuqing Zhao
 *               Lingyu Zhang
 */
#ifndef __STATIC_SRV6_H__
#define __STATIC_SRV6_H__

#include "vrf.h"
#include "srv6.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attributes for an SRv6 SID */
struct static_srv6_sid_attributes {
	/* VRF name */
	char vrf_name[VRF_NAMSIZ];
	char ifname[IFNAMSIZ];
	struct in6_addr nh6;
};

/* Static SRv6 SID */
struct static_srv6_sid {
	/* SRv6 SID address */
	struct prefix_ipv6 addr;
	/* behavior bound to the SRv6 SID */
	enum srv6_endpoint_behavior_codepoint behavior;
	/* SID attributes */
	struct static_srv6_sid_attributes attributes;

	/* SRv6 SID flags */
	uint8_t flags;
/*
 * this SRv6 SID has been allocated by SID Manager
 * and can be installed in the zebra RIB
 */
#define STATIC_FLAG_SRV6_SID_VALID (1 << 0)
/* this SRv6 SID has been installed in the zebra RIB */
#define STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA (1 << 1)

	char locator_name[SRV6_LOCNAME_SIZE];
	struct static_srv6_locator *locator;
};

/* Hash table to keep per-interface neighbors used for SRv6 SID nexthop resolution */
PREDECL_HASH(static_srv6_neigh_table);

/*
 * Neighbor information.
 */
struct static_srv6_neigh {
	struct in6_addr addr; /* IPv6 address */
	ifindex_t ifindex;    /* Interface index */
	uint32_t ndm_state;   /* Neighbor state */

	/* For linked list: next neighbor on the same interface */
	struct static_srv6_neigh *next;
};

/*
 * Per-interface neighbor list container for hash table.
 * Maps interface index to list of neighbors on that interface.
 */
struct static_srv6_if_neigh {
	/* Linkage for neighbors hash table */
	struct static_srv6_neigh_table_item item;

	/* Interface index (hash key) */
	ifindex_t ifindex;

	/* Linked list of neighbors on this interface */
	struct static_srv6_neigh *neighbors;

	/* Flag to indicate if a neighbor request has been sent */
	bool neigh_request_sent;
};

/*
 * Neighbor cache for SRv6 SID nexthop resolution.
 * Maintains per-interface neighbor lists.
 */
struct static_srv6_neigh_cache {
	/* Hash table: ifindex -> neighbor list */
	struct static_srv6_neigh_table_head neigh_table;
	/* Number of SIDs requiring nexthop resolution */
	uint32_t resolve_sids_cnt;
	/* Whether we are registered for neighbor notifications */
	bool registered;
};

struct static_srv6_locator {
	char name[SRV6_LOCNAME_SIZE];
	struct prefix_ipv6 prefix;

	/*
	 * Bit length of SRv6 locator described in
	 * draft-ietf-bess-srv6-services-05#section-3.2.1
	 */
	uint8_t block_bits_length;
	uint8_t node_bits_length;
	uint8_t function_bits_length;
	uint8_t argument_bits_length;

	uint8_t flags;
};

/* List of SRv6 SIDs. */
extern struct list *srv6_locators;
extern struct list *srv6_sids;

/*
 * Allocate an SRv6 SID object and initialize its fields, SID address and
 * behavor.
 */
extern struct static_srv6_sid *static_srv6_sid_alloc(struct prefix_ipv6 *addr);
extern void static_srv6_sid_free(struct static_srv6_sid *sid);
/* Look-up an SRv6 SID in the list of SRv6 SIDs. */
extern struct static_srv6_sid *static_srv6_sid_lookup(struct prefix_ipv6 *sid_addr);
/*
 * Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID.
 */
extern void static_srv6_sid_del(struct static_srv6_sid *sid);

/* Initialize SRv6 data structures. */
extern void static_srv6_init(void);
/* Clean up all the SRv6 data structures. */
extern void static_srv6_cleanup(void);

/*
 * When an interface is enabled in the kernel, go through all the static SRv6 SIDs in
 * the system that use this interface and install/remove them in the zebra RIB.
 *
 * ifp   - The interface being enabled
 * is_up - Whether the interface is up or down
 */
void static_ifp_srv6_sids_update(struct interface *ifp, bool is_up);

struct static_srv6_locator *static_srv6_locator_alloc(const char *name);
void static_srv6_locator_free(struct static_srv6_locator *locator);
struct static_srv6_locator *static_srv6_locator_lookup(const char *name);

void delete_static_srv6_sid(void *val);
void delete_static_srv6_locator(void *val);

void static_zebra_request_srv6_sids(void);

void static_srv6_neigh_cache_init(void);
void static_srv6_neigh_cache_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __STATIC_SRV6_H__ */
