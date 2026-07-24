// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * bgp_evpn_vpws.h: EVPN-VPWS service object for single-homed VPWS
 * over SRv6 with End.DX2.
 * The cross-connect SID (End.DX2) is allocated per VPWS instance via
 * `interface <ac> sid auto` and stored on the vpws object.
 *
 * Each `vpws-instance NAME` block under address-family l2vpn evpn
 * creates one of these. The service drives EAD-per-EVI (Type-1)
 * origination using the Ethernet Tag = source AC-ID, and matches
 * inbound EAD-per-EVI with Ethernet Tag = target AC-ID for peer
 * binding.
 *
 */
#ifndef _FRR_BGP_EVPN_VPWS_H
#define _FRR_BGP_EVPN_VPWS_H

#include <zebra.h>
#include "lib/prefix.h"
#include "lib/if.h"
#include "lib/qobj.h"
#include "lib/srv6.h" /* SRV6_LOCNAME_SIZE */
#include "bgpd/bgpd.h"

struct bgp;
struct prefix_evpn;
struct bgp_attr_srv6_l3service;
struct ecommunity;
struct srv6_locator;

/* Per-instance configuration plus runtime state. */
struct bgp_evpn_vpws {
	struct evpn_vpws_list_item list_item;

	struct bgp *bgp;

	/* operator-facing name (key) */
	char name[64];

	/* required config */
	uint32_t evi;	       /* used as VNI in label / scoping */
	uint32_t source_ac_id; /* local AC-ID, advertised in Eth-Tag */
	uint32_t target_ac_id; /* remote AC-ID, matched on import */
	struct prefix_rd prd;
	bool prd_set;
	struct ecommunity *import_rtl;
	struct ecommunity *export_rtl;

	/* Attachment circuit binding (per-instance) */
	char ac_ifname[IFNAMSIZ];
	ifindex_t ac_ifindex;
	bool ac_ifindex_valid;

	/* Per-instance End.DX2 SID, allocated via zebra */
	bool sid_auto;	    /* `sid auto` was configured */
	bool sid_requested; /* request sent, awaiting notify */
	bool sid_allocated; /* notify received, SID is valid */
	struct in6_addr local_sid;
	struct srv6_locator *sid_locator;
	bool decap_installed; /* End.DX2 decap route installed via the RIB */

	/* Optional per-instance SRv6 locator (mirrors `evi N locator X`).
	 * When set, the End.DX2 SID is drawn from this locator instead of the
	 * BGP-instance-wide locator (bgp->srv6_locator_name).  Empty => use the
	 * instance-wide locator (backward compatible).
	 */
	char locator_name[SRV6_LOCNAME_SIZE];

	/* runtime state */
	bool advertised; /* EAD-EVI installed in BGP RIB */
	bool peer_present;
	struct in6_addr peer_sid; /* learned from inbound EAD-EVI */
	uint16_t peer_behavior;

	/* Snapshot of the attr/peer that delivered our peer_sid, used at
	 * delete/withdraw time to uninstall the IPv6 underlay /128.
	 * peer_attr_snap is bgp_attr_intern'd to survive bgp_withdraw on
	 * the originating path-info.
	 */
	struct attr *peer_attr_snap;
	struct peer *peer_peer_snap;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(bgp_evpn_vpws);
DECLARE_DLIST(evpn_vpws_list, struct bgp_evpn_vpws, list_item);

/* --------- lifecycle (called from bgpd.c bgp_create/bgp_free) --------- */
extern int bgp_evpn_vpws_init(struct bgp *bgp);
extern void bgp_evpn_vpws_finish(struct bgp *bgp);

/* --------- find/create/delete (called from VTY) --------- */
extern struct bgp_evpn_vpws *bgp_evpn_vpws_find(struct bgp *bgp, const char *name);
extern struct bgp_evpn_vpws *bgp_evpn_vpws_find_by_target(struct bgp *bgp, uint32_t evi,
							  uint32_t eth_tag);
extern struct bgp_evpn_vpws *bgp_evpn_vpws_create(struct bgp *bgp, const char *name);
extern void bgp_evpn_vpws_delete(struct bgp_evpn_vpws *vpws);

/*
 * True if @sid belongs to this PE locally: it equals a configured
 * vpws-instance's own End.DX2 SID, or falls under that instance's per-instance
 * SRv6 locator (e.g. LOC-R2/LOC-R3).  Used to suppress installing an underlay
 * /128 for our own SID — which would otherwise mask the local seg6local decap
 * route (lower metric) and create an NS1<->NS2 forwarding loop.  The
 * BGP-instance-wide locator is checked separately by the caller.
 */
extern bool bgp_evpn_vpws_sid_is_local(struct bgp *bgp, const struct in6_addr *sid);

/* --------- setters (called from VTY) --------- */
extern int bgp_evpn_vpws_set_ac_ids(struct bgp_evpn_vpws *vpws, uint32_t source, uint32_t target);
extern int bgp_evpn_vpws_set_evi(struct bgp_evpn_vpws *vpws, uint32_t evi);
extern int bgp_evpn_vpws_set_rd(struct bgp_evpn_vpws *vpws, const struct prefix_rd *prd);
/* direction: 1=import, 2=export, 3=both */
extern int bgp_evpn_vpws_set_rt(struct bgp_evpn_vpws *vpws, struct ecommunity *rt, int direction);
extern int bgp_evpn_vpws_clear_rt(struct bgp_evpn_vpws *vpws, int direction);

/* --------- origination / withdraw --------- */
extern int bgp_evpn_vpws_originate(struct bgp_evpn_vpws *vpws);
extern void bgp_evpn_vpws_withdraw(struct bgp_evpn_vpws *vpws);

/*
 * Re-evaluate every vpws-instance on this bgp instance and (re-)originate
 * or withdraw as appropriate. Called when the cross-connect SID becomes
 * available, when router-id changes, or when EVPN encap mode flips.
 */
extern void bgp_evpn_vpws_reorigin_all(struct bgp *bgp);

/* --------- inbound EAD-EVI hook (called from bgp_evpn_mh.c) --------- */
extern void bgp_evpn_vpws_handle_remote_ead(struct bgp *bgp, const struct prefix_evpn *p,
					    const struct bgp_attr_srv6_l3service *svc,
					    struct attr *attr, struct peer *peer);
extern void bgp_evpn_vpws_handle_remote_ead_withdraw(struct bgp *bgp, const struct prefix_evpn *p);

/* --------- vty init (called from bgp_main.c) --------- */
extern void bgp_evpn_vpws_vty_init(void);

/* --------- config write (called from bgp_config_write_evpn_info) ---------
 * Emits one `vpws-instance NAME` block per configured VPWS service.
 * Called from bgp_evpn_vty.c::bgp_config_write_evpn_info().
 */
extern void bgp_evpn_vpws_config_write_all(struct vty *vty, struct bgp *bgp);

/* --------- per-instance AC + SID setters (called from VTY) --------- */
extern int bgp_evpn_vpws_set_interface(struct bgp_evpn_vpws *vpws, const char *ifname,
				       bool sid_auto);
extern int bgp_evpn_vpws_clear_interface(struct bgp_evpn_vpws *vpws);

/* Per-instance SRv6 locator binding (NULL/empty name clears it). Re-requests
 * the End.DX2 SID from the new locator.
 */
extern int bgp_evpn_vpws_set_locator(struct bgp_evpn_vpws *vpws, const char *locname);

/* --------- ZAPI SID notify dispatch (called from bgp_zebra.c) ---------
 * @return true if the notification was consumed by a VPWS instance,
 *         false if no VPWS matched (caller should continue with the
 *         existing per-AFI handling).
 */
extern bool bgp_evpn_vpws_handle_sid_notify(struct bgp *bgp, ifindex_t oif, uint32_t evi,
					    uint16_t behavior, const struct in6_addr *sid_addr,
					    const struct srv6_locator *locator, bool allocated);

/*
 * Called when the SRv6 locator format changes (legacy <-> uSID).
 * Releases every auto-managed VPWS DX2 SID and re-requests from the new
 * locator so the correct function range (uSID LIB vs standard) is used.
 */
extern void bgp_evpn_vpws_on_locator_update(struct bgp *bgp);
extern void bgp_evpn_vpws_request_missing_sids(struct bgp *bgp);
extern void bgp_evpn_vpws_on_interface_up(struct bgp *bgp, struct interface *ifp);

#endif /* _FRR_BGP_EVPN_VPWS_H */
