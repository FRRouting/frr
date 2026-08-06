// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 SR-L2 (sr6) tunnel interface management.
 *
 * Copyright (C) 2026 Aviz Networks
 *
 * An sr6 interface is a Linux virtual interface of type "sr6" that performs
 * RFC 8986 H.Encaps.L2.Red encapsulation.  When an Ethernet frame exits via
 * an sr6-N interface the kernel prepends an outer IPv6 header whose
 * Destination Address is the SID bound to that interface (no Segment Routing
 * Header is inserted because only one segment is present - "reduced"
 * encapsulation).
 *
 * Zebra creates one sr6 interface per unique remote SRv6 SID received via
 * EVPN Type-2 routes.  The interface is added as a bridge slave so that bridge
 * FDB entries can use it as the outgoing port.  A reference count is
 * maintained; the interface is deleted when the last remote MAC using it is
 * withdrawn.
 */

#ifndef _ZEBRA_SR6_H
#define _ZEBRA_SR6_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include "if.h"
#include "vlan.h"
#include "hash.h"
#include "typesafe.h"

PREDECL_HASH(sr6_htab);

/*
 * Per-SID sr6 interface descriptor.
 */
struct zebra_sr6 {
	/* Intrusive linkage for the SID-keyed typesafe hash (sr6_htab). */
	struct sr6_htab_item htab_item;

	/* SRv6 SID this interface encapsulates toward. */
	struct in6_addr sid;

	/* Kernel ifindex of the sr6 interface. */
	ifindex_t ifindex;

	/* Bridge ifindex the sr6 interface is slaved to. */
	ifindex_t bridge_ifindex;

	/* Interface name, e.g. "sr6-0". */
	char ifname[IFNAMSIZ];

	/* Number of remote MACs that reference this interface. */
	uint32_t refcnt;

	/* true -> BUM-purpose sr6 (flood-target, no FDB) */
	bool is_bum;

	/* EVI VLAN to (re)bind once the netdev appears (0 = vlan-bundle). */
	vlanid_t vid;
};

/*
 * Device-wide SRv6 L2 (sr6) encapsulation policy applied to every sr6 tunnel
 * interface zebra creates.  The values intentionally match the kernel's
 * enum sr6_encap_mode (FULL=0, REDUCED=1); rt_netlink.c maps them explicitly
 * when building IFLA_SR6_ENCAP_MODE.
 *
 *   FULL    - keep the SRH on the wire (default).
 *   REDUCED - single-SID H.Encaps.L2.Red: SID in the outer IPv6 DA, no SRH.
 *
 * A change takes effect for sr6 interfaces created afterwards; interfaces
 * already in the kernel keep their mode until they are recreated (the sr6
 * driver has no changelink to reprogram it in place).
 */
enum zebra_sr6_encap_mode {
	ZEBRA_SR6_ENCAP_MODE_FULL = 0,
	ZEBRA_SR6_ENCAP_MODE_REDUCED = 1,
};

extern void zebra_sr6_set_encap_mode(enum zebra_sr6_encap_mode mode);
extern enum zebra_sr6_encap_mode zebra_sr6_get_encap_mode(void);
extern const char *zebra_sr6_encap_mode2str(enum zebra_sr6_encap_mode mode);
/* Kernel-reported encap mode of the operator-owned sr6 @ifindex (cached on
 * zebra_if), or @fallback if unknown.  No software default.
 */
extern uint8_t zebra_sr6_kernel_encap_mode(ifindex_t ifindex, uint8_t fallback);
/* Discover the operator-owned sr6 (is_bum=false)/bum-sr6 (is_bum=true) on a
 * bridge by name prefix; 0 if not present.  namebuf (optional) gets the name.
 */
extern ifindex_t zebra_sr6_discover_on_bridge(ifindex_t bridge_ifindex, bool is_bum,
					       char *namebuf);

/*
 * Device-wide MTU applied to every sr6 tunnel interface.  0 = unset: zebra
 * omits IFLA_MTU at create time so the kernel sr6 driver picks its default
 * (underlay 1500 - SRv6 encap overhead = 1422).  A non-zero value is emitted
 * as IFLA_MTU at create time and pushed live onto existing interfaces via the
 * dplane thread.  The value is the sr6 (inner-facing) device MTU: to carry an
 * inner frame of N bytes the underlay path must carry N + SRv6 overhead
 * (~78 bytes FULL, ~54 REDUCED), so size the transport accordingly.
 */
#define ZEBRA_SR6_MTU_UNSET 0
/*
 * The sr6 driver's own default MTU for a freshly created sr6 netdev (underlay
 * 1500 - SRv6 encap overhead 78 = 1422).  On `no l2-mtu` we push this value
 * back onto existing interfaces so the dataplane actually reverts, matching
 * what a newly created interface would get when IFLA_MTU is omitted.
 */
#define ZEBRA_SR6_DEFAULT_MTU 1422
extern uint32_t zebra_sr6_get_mtu(void);

/* Initialise/tear down global sr6 tracking table. */
extern void zebra_sr6_init(void);
extern void zebra_sr6_if_add(struct interface *ifp);
extern void zebra_sr6_terminate(void);

/* Delete every sr6/bum-sr6 kernel interface (graceful-shutdown cleanup). */

/*
 * Return (or create) the sr6 interface for @sid on bridge @bridge_ifindex.
 * Increments the reference count.  Returns NULL on failure.
 */
extern struct zebra_sr6 *zebra_sr6_get_or_create(const struct in6_addr *sid,
						   ifindex_t bridge_ifindex, bool is_bum,
						   vlanid_t vid);

/*
 * Decrement the reference count for the sr6 entry bound to @sid.
 * When the count reaches zero the kernel interface is deleted.
 */
extern void zebra_sr6_release(const struct in6_addr *sid);

/*
 * Reprogram an existing sr6 entry's encap SID in place (kernel interface and
 * ifindex preserved, hash re-keyed old_sid -> new_sid).  Returns the entry on
 * success, NULL on failure.
 */
extern struct zebra_sr6 *zebra_sr6_update_sid(const struct in6_addr *old_sid,
						const struct in6_addr *new_sid);

/* Lookup without reference-count change. */
extern struct zebra_sr6 *zebra_sr6_lookup(const struct in6_addr *sid);

extern void zebra_sr6_walk(void (*cb)(struct zebra_sr6 *sr6, void *arg), void *arg);

/* Find the unicast (is_bum=false) or BUM (is_bum=true) sr6 slaved to a
 * given bridge ifindex.  Returns NULL if none.
 */
extern struct zebra_sr6 *zebra_sr6_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum);

/*
 * Force-delete every sr6/bum-sr6 interface slaved to @bridge_ifindex,
 * regardless of reference count, and free their table entries.  Used on EVI
 * teardown so the EVI's sr6 interfaces don't linger (and collide with a
 * later re-add).  Safe to call with no matching entries.
 */
extern void zebra_sr6_release_all_on_bridge(ifindex_t bridge_ifindex);

/*
 * (Re)bind the EVI VLAN (tagged, non-PVID) onto every sr6/bum-sr6 slaved to
 * @bridge_ifindex.  Idempotent.  Repairs peer ports created while the EVI vid
 * was still 0.
 */
extern void zebra_sr6_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid);

#ifdef __cplusplus
}
#endif
#endif /* _ZEBRA_SR6_H */
