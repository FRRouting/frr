// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 SR-L2 (srl2) tunnel interface management.
 *
 * An srl2 interface is a Linux virtual interface of type "srl2" that performs
 * RFC 8986 H.Encaps.L2.Red encapsulation.  When an Ethernet frame exits via
 * an srl2-N interface the kernel prepends an outer IPv6 header whose
 * Destination Address is the SID bound to that interface (no Segment Routing
 * Header is inserted because only one segment is present - "reduced"
 * encapsulation).
 *
 * Zebra creates one srl2 interface per unique remote SRv6 SID received via
 * EVPN Type-2 routes.  The interface is added as a bridge slave so that bridge
 * FDB entries can use it as the outgoing port.  A reference count is
 * maintained; the interface is deleted when the last remote MAC using it is
 * withdrawn.
 */

#ifndef _ZEBRA_SRL2_H
#define _ZEBRA_SRL2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include "if.h"
#include "vlan.h"
#include "hash.h"
#include "typesafe.h"

PREDECL_HASH(srl2_htab);

/*
 * Per-SID srl2 interface descriptor.
 */
struct zebra_srl2 {
	/* Intrusive linkage for the SID-keyed typesafe hash (srl2_htab). */
	struct srl2_htab_item htab_item;

	/* SRv6 SID this interface encapsulates toward. */
	struct in6_addr sid;

	/* Kernel ifindex of the srl2 interface. */
	ifindex_t ifindex;

	/* Bridge ifindex the srl2 interface is slaved to. */
	ifindex_t bridge_ifindex;

	/* Interface name, e.g. "srl2-0". */
	char ifname[IFNAMSIZ];

	/* Number of remote MACs that reference this interface. */
	uint32_t refcnt;

	/* true -> BUM-purpose srl2 (flood-target, no FDB) */
	bool is_bum;
};

/* Initialise/tear down global srl2 tracking table. */
extern void zebra_srl2_init(void);
extern void zebra_srl2_terminate(void);

/* Delete every srl2/bum-srl2 kernel interface (graceful-shutdown cleanup). */
extern void zebra_srl2_delete_all_kernel(void);

/*
 * Return (or create) the srl2 interface for @sid on bridge @bridge_ifindex.
 * Increments the reference count.  Returns NULL on failure.
 */
extern struct zebra_srl2 *zebra_srl2_get_or_create(const struct in6_addr *sid,
						   ifindex_t bridge_ifindex, bool is_bum,
						   vlanid_t vid);

/*
 * Decrement the reference count for the srl2 entry bound to @sid.
 * When the count reaches zero the kernel interface is deleted.
 */
extern void zebra_srl2_release(const struct in6_addr *sid);

/*
 * Reprogram an existing srl2 entry's encap SID in place (kernel interface and
 * ifindex preserved, hash re-keyed old_sid -> new_sid).  Returns the entry on
 * success, NULL on failure.
 */
extern struct zebra_srl2 *zebra_srl2_update_sid(const struct in6_addr *old_sid,
						const struct in6_addr *new_sid);

/* Lookup without reference-count change. */
extern struct zebra_srl2 *zebra_srl2_lookup(const struct in6_addr *sid);

extern void zebra_srl2_walk(void (*cb)(struct zebra_srl2 *srl2, void *arg), void *arg);

/* Find the unicast (is_bum=false) or BUM (is_bum=true) srl2 slaved to a
 * given bridge ifindex.  Returns NULL if none.
 */
extern struct zebra_srl2 *zebra_srl2_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum);

/*
 * Force-delete every srl2/bum-srl2 interface slaved to @bridge_ifindex,
 * regardless of reference count, and free their table entries.  Used on EVI
 * teardown so the EVI's srl2 interfaces don't linger (and collide with a
 * later re-add).  Safe to call with no matching entries.
 */
extern void zebra_srl2_release_all_on_bridge(ifindex_t bridge_ifindex);

/*
 * (Re)bind the EVI VLAN (tagged, non-PVID) onto every srl2/bum-srl2 slaved to
 * @bridge_ifindex.  Idempotent.  Repairs peer ports created while the EVI vid
 * was still 0.
 */
extern void zebra_srl2_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid);

#ifdef __cplusplus
}
#endif
#endif /* _ZEBRA_SRL2_H */
