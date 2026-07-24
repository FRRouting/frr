// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 L2 EVPN — Multi-VLAN-to-EVI mapping (VXLAN-decoupled).
 *
 * Implements the "SRv6 L2 EVPN — Multi-VLAN-to-EVI Mapping (VXLAN-Decoupled)"
 * design: a per-EVI dataplane-backend abstraction so the VXLAN EVPN path is
 * untouched while SRv6 L2 EVPN instances are created directly from a
 * VLAN->EVI binding (zebra SRv6 global block) with no VXLAN netdev.
 *
 * Phase 1 (this file): the backend-abstraction + EVI-bundle data model and the
 * in-memory EVI table.  Dataplane backend ops and BGP/ZAPI wiring are filled in
 * by later phases (see srv6_l2evpn_vlan_to_evi_design.md, sections 9 and 11).
 *
 * Copyright (C) 2026 FRR contributors.
 */

#ifndef _ZEBRA_SRV6_L2EVPN_H
#define _ZEBRA_SRV6_L2EVPN_H

#include <zebra.h>

#include "if.h"
#include "vlan.h"  /* vlanid_t */
#include "vxlan.h" /* vni_t */
#include "linklist.h"
#include "hash.h"
#include "typesafe.h"
#include "qobj.h" /* QOBJ vty context */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — avoid pulling the full EVPN/MAC headers here. */
struct zebra_evpn;
struct zebra_mac;
struct zebra_neigh;
struct interface;
struct vty;

/*
 * Dataplane backend that an EVI is realized on.
 *
 * VXLAN keeps the existing behavior verbatim (the EVI is anchored on a VXLAN
 * netdev + access VLAN).  SRV6 is the new backend: the EVI is anchored on a
 * VLAN-aware bridge + srl2 encap + an SRv6 locator, with no VXLAN device.
 */
enum zevpn_dp_backend {
	ZEVPN_DP_VXLAN = 0,
	ZEVPN_DP_SRV6,
};

/*
 * L2 service type for an SRv6 EVI (per-EVI, selectable via config).
 *
 *  VLAN_AWARE_BUNDLE  N VLANs in one EVI; per-VLAN bridge-domain/FDB;
 *                     Ethernet Tag ID = VLAN.  (default / preferred)
 *  VLAN_BASED         1 VLAN = 1 EVI; Ethernet Tag ID = 0.  (subset)
 *  VLAN_BUNDLE        N VLANs collapsed into one BD/FDB; Ethernet Tag ID = 0.
 */
enum zevpn_l2_service {
	ZEVPN_SVC_VLAN_AWARE_BUNDLE = 0,
	ZEVPN_SVC_VLAN_BASED,
	ZEVPN_SVC_VLAN_BUNDLE,
};

/*
 * Per-backend operation vtable.  Every former direct use of zevpn->vxlan_if in
 * the shared EVPN code is migrated to a call through this vtable (design §11).
 * The VXLAN backend's ops wrap the existing functions (no behavior change); the
 * SRv6 backend's ops use the bridge + vid + srl2/DT2U path.
 *
 * Phase 1 declares the vtable; the op bodies are wired in later phases.
 */
struct zevpn_dp_ops {
	const char *name;

	/* MAC / neigh program + withdraw on the backend dataplane.
	 * Signatures match the existing VXLAN functions so the VXLAN backend
	 * ops are true pass-throughs (design §11.4 step 1):
	 *   mac_install   <- zebra_evpn_rem_mac_install(zevpn, mac, was_static)
	 *   mac_uninstall <- zebra_evpn_rem_mac_uninstall(zevpn, mac, force)
	 *   neigh_install <- zebra_evpn_rem_neigh_install(zevpn, n, was_static)
	 * SRv6 backend ignores the trailing bool.
	 */
	int (*mac_install)(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool was_static);
	int (*mac_uninstall)(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool force);
	int (*neigh_install)(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool was_static);
	int (*neigh_uninstall)(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool force);

	/* BUM / flood endpoint setup (vxlan HER vs srl2 DT2M/DT2U) */
	int (*flood_setup)(struct zebra_evpn *zevpn, void *arg);
	int (*flood_teardown)(struct zebra_evpn *zevpn, void *arg);

	/* Resolve the bridge the EVI lives on (vxlan_if's master vs bridge_if) */
	struct interface *(*bridge)(struct zebra_evpn *zevpn);
};

extern const struct zevpn_dp_ops zevpn_dp_ops_vxlan;
extern const struct zevpn_dp_ops zevpn_dp_ops_srv6;

#define SRV6_L2EVPN_LOCNAME_SIZE 64

PREDECL_DLIST(evi_bds);

/*
 * Member bridge-domain of an EVI bundle.
 *
 * For VLAN_AWARE_BUNDLE there is one member per VLAN, each backed by its own
 * struct zebra_evpn (reusing the existing per-EVPN MAC/neigh machinery).  For
 * VLAN_BASED there is exactly one member.  For VLAN_BUNDLE the members share a
 * single zebra_evpn (eth_tag = 0).
 */
struct zebra_srv6_evi_bd {
	struct evi_bds_item bds_item;

	vlanid_t vid; /* member VLAN */
	/* EVPN Ethernet Tag ID carried in NLRI: = vid for
	 * VLAN_AWARE_BUNDLE, else 0.
	 */
	uint32_t eth_tag;
	struct zebra_evpn *zevpn; /* backing per-BD EVPN object */
};
DECLARE_DLIST(evi_bds, struct zebra_srv6_evi_bd, bds_item);

/*
 * The EVI bundle — the unit BGP keys on (RD/RT/VNI/SID).  One per configured
 * `evi` under the zebra SRv6 `l2-evpn` block.
 */
PREDECL_HASH(srv6_evi_htab);

struct zebra_srv6_evi {
	/* Intrusive linkage for the VNI-keyed typesafe hash (srv6_evi_htab). */
	struct srv6_evi_htab_item htab_item;

	vni_t vni; /* EVI id (shares BGP VNI value space) */
	enum zevpn_dp_backend dp_backend;
	enum zevpn_l2_service svc_type;
	/* True once service-type has been explicitly configured at least once.
	 * Used to allow the first `service-type` command (the initial value is
	 * only a default placeholder) while blocking a later in-place CHANGE,
	 * which would require a different Linux bridge model (delete+recreate).
	 */
	bool svc_type_set;
	const struct zevpn_dp_ops *dp_ops;

	/* SRv6 backend anchor (unused for the VXLAN backend) */
	char locator[SRV6_L2EVPN_LOCNAME_SIZE];
	struct interface *bridge_if; /* VLAN-aware (vlan_filtering) bridge */
	struct in6_addr dt2u_sid;    /* per-EVI unicast SID */
	struct in6_addr dt2m_sid;    /* per-EVI BUM SID */
	bool dt2u_sid_valid;
	bool dt2m_sid_valid;

	/*
	 * Dedicated, locally-owned decap interface (flood-off srl2) used as the
	 * l2dev for BOTH this EVI's local End.DT2U and End.DT2M decap routes.
	 * Lifetime = local EVI config (created in realize, deleted in evi_del),
	 * decoupled from the peer-keyed srl2/bum-srl2 (which serve FDB/flood and
	 * follow peer Type-2/Type-3).  See design doc §13.
	 */
	ifindex_t local_decap_oif;
	/*
	 * The dt2u_sid value the local decap interface was created for.  Used to
	 * detect a SID change (e.g. locator legacy<->uSID reallocation): when
	 * dt2u_sid changes, the decap srl2 must be rebuilt keyed by the new SID
	 * and a fresh VNI_ADD re-sent, otherwise bgpd keeps a stale/dead oif and
	 * never installs the new End.DT2U/DT2M decap.
	 */
	struct in6_addr local_decap_sid;

	struct evi_bds_head bds; /* member BDs: struct zebra_srv6_evi_bd* */

	QOBJ_FIELDS; /* vty config-context registration */
};
DECLARE_QOBJ_TYPE(zebra_srv6_evi);

/* ----- lifecycle / table API (Phase 1) ----- */

extern void zebra_srv6_l2evpn_init(void);
extern void zebra_srv6_l2evpn_terminate(void);

extern struct zebra_srv6_evi *zebra_srv6_evi_lookup(vni_t vni);
extern struct zebra_srv6_evi *zebra_srv6_evi_get_or_create(vni_t vni);
extern void zebra_srv6_evi_del(struct zebra_srv6_evi *evi);

/* Member-VLAN management. Returns the BD, or NULL on error/duplicate. */
extern struct zebra_srv6_evi_bd *zebra_srv6_evi_vlan_add(struct zebra_srv6_evi *evi, vlanid_t vid);
extern int zebra_srv6_evi_vlan_del(struct zebra_srv6_evi *evi, vlanid_t vid);
extern struct zebra_srv6_evi_bd *zebra_srv6_evi_vlan_find(struct zebra_srv6_evi *evi, vlanid_t vid);

/* Config helpers */
extern void zebra_srv6_evi_set_locator(struct zebra_srv6_evi *evi, const char *locator);
extern void zebra_srv6_evi_set_bridge(struct zebra_srv6_evi *evi, struct interface *bridge_if);
extern int zebra_srv6_evi_set_service(struct zebra_srv6_evi *evi, enum zevpn_l2_service svc);

/*
 * Materialize the per-EVI zebra_evpn (SRv6 backend) and announce to BGP.
 * Idempotent; safe to call after any config change once vni + bridge are set.
 */
extern void zebra_srv6_evi_realize(struct zebra_srv6_evi *evi);

/*
 * Handle a remote VTEP/peer BUM (Type-3) update for an SRv6 EVI: create /
 * refresh / release the bum-srl2 flood port on the EVI bridge.  struct ipaddr
 * is forward-used via pointer.
 */
struct ipaddr;
extern void zebra_srv6_evi_remote_bum(struct zebra_evpn *zevpn, struct ipaddr *vtep_ip,
				      const struct in6_addr *bum_sid);

/* (Re)announce all configured SRv6 EVIs to BGP (e.g. on advertise-all-vni). */
extern void zebra_srv6_l2evpn_replay(void);

/*
 * Re-allocate per-EVI DT2U/DT2M service SIDs for every EVI anchored on the
 * named locator after its encoding changed (legacy <-> uSID).  Must be called
 * after the locator's parent block is (re)allocated and re-notified.
 */
extern void zebra_srv6_evi_on_locator_update(const char *locname);

/* Map a (bridge, vlan) to an SRv6 EVI VNI for local MAC association; 0 if none. */
extern vni_t zebra_srv6_evi_vni_by_bridge_vlan(const struct interface *br_if, vlanid_t vid);

extern const char *zevpn_l2_service2str(enum zevpn_l2_service svc);
extern int zevpn_l2_service_str2enum(const char *s, enum zevpn_l2_service *out);

/* config-write hook for the `l2-evpn` block (called from zebra_srv6_vty.c) */
extern int zebra_srv6_l2evpn_config_write(struct vty *vty);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SRV6_L2EVPN_H */
