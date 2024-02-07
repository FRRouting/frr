// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN MH Data structures and definitions
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 */

#ifndef _ZEBRA_EVPN_MH_H
#define _ZEBRA_EVPN_MH_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "bitfield.h"
#include "zebra_vxlan.h"
#include "zebra_vxlan_private.h"
#include "zebra_nhg.h"
#include "zebra_nb.h"

/* Ethernet Segment entry -
 * - Local and remote ESs are maintained in a global RB tree,
 * zmh_info->es_rb_tree using ESI as key
 * - Local ESs are added via zebra config (ZEBRA_EVPNES_LOCAL) when an
 *   access port is associated with an ES-ID
 * - Remotes ESs are added by BGP based on received/remote EAD/Type-1 routes
 *   (ZEBRA_EVPNES_REMOTE)
 * - An ES can be simultaneously LOCAL and REMOTE; infact all LOCAL ESs are
 *   expected to have REMOTE ES peers.
 */
struct zebra_evpn_es {
	esi_t esi;
	char esi_str[ESI_STR_LEN];

	/* ES flags */
	uint32_t flags;
#define ZEBRA_EVPNES_LOCAL         (1 << 0) /* configured in zebra */
#define ZEBRA_EVPNES_REMOTE        (1 << 1) /* added by bgp */
#define ZEBRA_EVPNES_OPER_UP       (1 << 2) /* es->ifp is oper-up */
#define ZEBRA_EVPNES_READY_FOR_BGP (1 << 3) /* ready to be sent to BGP */
#define ZEBRA_EVPNES_NHG_ACTIVE    (1 << 4) /* NHG has been installed */
/* This flag is only applicable to local ESs and signifies that this
 * VTEP is not the DF
 */
#define ZEBRA_EVPNES_NON_DF (1 << 5)
/* When the ES becomes a bridge port we need to activate the BUM non-DF
 * filter, SPH filter and backup NHG for fast-failover
 */
#define ZEBRA_EVPNES_BR_PORT (1 << 6)
/* ES is in bypass mode i.e. must not be advertised. ES-bypass is set
 * when the associated host bond goes into LACP bypass
 */
#define ZEBRA_EVPNES_BYPASS (1 << 7)

	/* memory used for adding the es to zmh_info->es_rb_tree */
	RB_ENTRY(zebra_evpn_es) rb_node;

	/* [EVPNES_LOCAL] memory used for linking the es to
	 * zmh_info->local_es_list
	 */
	struct listnode local_es_listnode;

	/* [EVPNES_LOCAL] corresponding interface */
	struct zebra_if *zif;

	/* list of ES-EVIs associated with the ES */
	struct list *es_evi_list;

	/* [!EVPNES_LOCAL] List of remote VTEPs (zebra_evpn_es_vtep) */
	struct list *es_vtep_list;

	/* list of zebra_mac entries using this ES as destination */
	struct list *mac_list;

	/* Nexthop group id */
	uint32_t nhg_id;

	/* Preference config for BUM-DF election. Sent to BGP and
	 * advertised via the ESR
	 */
	uint16_t df_pref;

	/* When a new ES is configured it is held in a non-DF state
	 * for 3 seconds. This allows the peer Type-4 routes to be
	 * imported before running the DF election.
	 */
#define ZEBRA_EVPN_MH_DF_DELAY_TIME 3 /* seconds */
	struct event *df_delay_timer;
};
RB_HEAD(zebra_es_rb_head, zebra_evpn_es);
RB_PROTOTYPE(zebra_es_rb_head, zebra_evpn_es, rb_node, zebra_es_rb_cmp);

/* ES per-EVI info
 * - ES-EVIs are maintained per-EVPN (vni->es_evi_rb_tree)
 * - Local ES-EVIs are linked to per-EVPN list for quick access
 * - Although some infrastucture is present for remote ES-EVIs, currently
 *   BGP does NOT send remote ES-EVIs to zebra. This may change in the
 *   future (but must be changed thoughtfully and only if needed as ES-EVI
 *   can get prolific and come in the way of rapid failovers)
 */
struct zebra_evpn_es_evi {
	struct zebra_evpn_es *es;
	struct zebra_evpn *zevpn;

	/* ES-EVI flags */
	uint32_t flags;
	/* local ES-EVI */
#define ZEBRA_EVPNES_EVI_LOCAL         (1 << 0) /* created by zebra */
#define ZEBRA_EVPNES_EVI_READY_FOR_BGP (1 << 1) /* ready to be sent to BGP */

	/* memory used for adding the es_evi to
	 * es_evi->zevpn->es_evi_rb_tree
	 */
	RB_ENTRY(zebra_evpn_es_evi) rb_node;
	/* memory used for linking the es_evi to
	 * es_evi->zevpn->local_es_evi_list
	 */
	struct listnode l2vni_listnode;
	/* memory used for linking the es_evi to
	 * es_evi->es->es_evi_list
	 */
	struct listnode es_listnode;
};

/* A single L2 nexthop is allocated across all ESs with the same PE/VTEP
 * nexthop
 */
struct zebra_evpn_l2_nh {
	struct in_addr vtep_ip;

	/* MAC nexthop id */
	uint32_t nh_id;

	/* es_vtep entries using this nexthop */
	uint32_t ref_cnt;
};

/* PE attached to an ES */
struct zebra_evpn_es_vtep {
	struct zebra_evpn_es *es; /* parent ES */
	struct in_addr vtep_ip;

	uint32_t flags;
	/* Rxed Type-4 route from this VTEP */
#define ZEBRA_EVPNES_VTEP_RXED_ESR (1 << 0)
#define ZEBRA_EVPNES_VTEP_DEL_IN_PROG (1 << 1)

	/* MAC nexthop info */
	struct zebra_evpn_l2_nh *nh;

	/* memory used for adding the entry to es->es_vtep_list */
	struct listnode es_listnode;

	/* Parameters for DF election */
	uint8_t df_alg;
	uint16_t df_pref;

	/* XXX - maintain a backpointer to struct zebra_vtep */
};

/* Local/access-side broadcast domain - zebra_evpn_access_bd is added to -
 * zrouter->evpn_vlan_table (for VLAN aware bridges) OR
 * zrouter->evpn_bridge_table (for VLAN unaware bridges)
 * XXX - support for VLAN unaware bridges is yet to be flushed out
 */
struct zebra_evpn_access_bd {
	vlanid_t vid;

	ifindex_t bridge_ifindex;
	struct zebra_if *bridge_zif; /* associated bridge */

	vni_t vni;		    /* vni associated with the vxlan device */
	struct zebra_if *vxlan_zif; /* vxlan device */
	/* list of members associated with the BD i.e. (potential) ESs */
	struct list *mbr_zifs;
	/* presence of zevpn activates the EVI on all the ESs in mbr_zifs */
	struct zebra_evpn *zevpn;
	/* SVI associated with the VLAN */
	struct zebra_if *vlan_zif;
};

/* multihoming information stored in zrouter */
#define zmh_info (zrouter.mh_info)
struct zebra_evpn_mh_info {
	uint32_t flags;
/* If the dataplane is not capable of handling a backup NHG on an access
 * port we will need to explicitly failover each MAC entry on
 * local ES down
 */
#define ZEBRA_EVPN_MH_REDIRECT_OFF (1 << 0)
/* DAD support for EVPN-MH is yet to be added. So on detection of
 * first local ES, DAD is turned off
 */
#define ZEBRA_EVPN_MH_DUP_ADDR_DETECT_OFF (1 << 1)
/* If EVPN MH is enabled we only advertise REACHABLE neigh entries as Type-2
 * routes. As there is no global config knob for enabling EVPN MH we turn
 * this flag when the first local ES is detected.
 */
#define ZEBRA_EVPN_MH_ADV_REACHABLE_NEIGH_ONLY (1 << 2)
/* If EVPN MH is enabled we advertise the SVI MAC address to avoid
 * flooding of ARP replies rxed from the multi-homed host
 */
#define ZEBRA_EVPN_MH_ADV_SVI_MAC (1 << 3)

	/* RB tree of Ethernet segments (used for EVPN-MH)  */
	struct zebra_es_rb_head es_rb_tree;
	/* List of local ESs */
	struct list *local_es_list;

	/* EVPN MH broadcast domains indexed by the VID */
	struct hash *evpn_vlan_table;

	/* A base L2-VNI is maintained to derive parameters such as
	 * ES originator-IP.
	 * XXX: once single vxlan device model becomes available this will
	 * not be necessary
	 */
	struct zebra_evpn *es_base_evpn;
	struct in_addr es_originator_ip;

	/* L2 NH and NHG ids -
	 * Most significant 4 bits is type. Lower 28 bits is the value
	 * allocated from the nh_id_bitmap.
	 */
	bitfield_t nh_id_bitmap;
#define EVPN_NH_ID_MAX       (16*1024)
#define EVPN_NH_ID_VAL_MASK  0xffffff
/* The purpose of using different types for NHG and NH is NOT to manage the
 * id space separately. It is simply to make debugging easier.
 */
#define EVPN_NH_ID_TYPE_BIT (NHG_TYPE_L2_NH << NHG_ID_TYPE_POS)
#define EVPN_NHG_ID_TYPE_BIT (NHG_TYPE_L2 << NHG_ID_TYPE_POS)
	/* L2-NHG table - key: nhg_id, data: zebra_evpn_es */
	struct hash *nhg_table;
	/* L2-NH table - key: vtep_up, data: zebra_evpn_nh */
	struct hash *nh_ip_table;

	/* XXX - re-visit the default hold timer value */
	int mac_hold_time;
#define ZEBRA_EVPN_MH_MAC_HOLD_TIME_DEF (18 * 60)
	int neigh_hold_time;
#define ZEBRA_EVPN_MH_NEIGH_HOLD_TIME_DEF (18 * 60)

	/* During this period access ports will be held in a protodown
	 * state
	 */
	int startup_delay_time; /* seconds */
#define ZEBRA_EVPN_MH_STARTUP_DELAY_DEF (3 * 60)
	struct event *startup_delay_timer;

	/* Number of configured uplinks */
	uint32_t uplink_cfg_cnt;
	/* Number of operationally-up uplinks */
	uint32_t uplink_oper_up_cnt;

	/* These protodown bits are inherited by all ES bonds */
	uint32_t protodown_rc;
};

/* returns TRUE if the EVPN is ready to be sent to BGP */
static inline bool zebra_evpn_send_to_client_ok(struct zebra_evpn *zevpn)
{
	return !!(zevpn->flags & ZEVPN_READY_FOR_BGP);
}

static inline bool zebra_evpn_mac_is_es_local(struct zebra_mac *mac)
{
	return mac->es && (mac->es->flags & ZEBRA_EVPNES_LOCAL);
}

/* Returns true if the id is of L2-NHG or L2-NH type */
static inline bool zebra_evpn_mh_is_fdb_nh(uint32_t id)
{
	return ((id & EVPN_NHG_ID_TYPE_BIT) ||
			(id & EVPN_NH_ID_TYPE_BIT));
}

static inline bool
zebra_evpn_es_local_mac_via_network_port(struct zebra_evpn_es *es)
{
	return !(es->flags & ZEBRA_EVPNES_OPER_UP)
	       && (zmh_info->flags & ZEBRA_EVPN_MH_REDIRECT_OFF);
}

static inline bool zebra_evpn_mh_do_dup_addr_detect(void)
{
	return !(zmh_info->flags & ZEBRA_EVPN_MH_DUP_ADDR_DETECT_OFF);
}

static inline bool zebra_evpn_mh_do_adv_reachable_neigh_only(void)
{
	return !!(zmh_info->flags & ZEBRA_EVPN_MH_ADV_REACHABLE_NEIGH_ONLY);
}

static inline bool zebra_evpn_mh_do_adv_svi_mac(void)
{
	return zmh_info && (zmh_info->flags & ZEBRA_EVPN_MH_ADV_SVI_MAC);
}

/*****************************************************************************/
extern esi_t *zero_esi;
extern void zebra_evpn_mh_init(void);
extern void zebra_evpn_mh_terminate(void);
extern bool zebra_evpn_is_if_es_capable(struct zebra_if *zif);
extern void zebra_evpn_if_init(struct zebra_if *zif);
extern void zebra_evpn_if_cleanup(struct zebra_if *zif);
extern void zebra_evpn_es_evi_init(struct zebra_evpn *zevpn);
extern void zebra_evpn_es_evi_cleanup(struct zebra_evpn *zevpn);
extern void zebra_evpn_vxl_evpn_set(struct zebra_if *zif,
				    struct zebra_evpn *zevpn, bool set);
extern void zebra_evpn_es_set_base_evpn(struct zebra_evpn *zevpn);
extern void zebra_evpn_es_clear_base_evpn(struct zebra_evpn *zevpn);
extern void zebra_evpn_vl_vxl_ref(uint16_t vid, vni_t vni_id,
				  struct zebra_if *vxlan_zif);
extern void zebra_evpn_vl_vxl_deref(uint16_t vid, vni_t vni_id,
				    struct zebra_if *vxlan_zif);
extern void zebra_evpn_vl_mbr_ref(uint16_t vid, struct zebra_if *zif);
extern void zebra_evpn_vl_mbr_deref(uint16_t vid, struct zebra_if *zif);
extern void zebra_evpn_es_send_all_to_client(bool add);
extern void zebra_evpn_es_if_oper_state_change(struct zebra_if *zif, bool up);
extern void zebra_evpn_es_show(struct vty *vty, bool uj);
extern void zebra_evpn_es_show_detail(struct vty *vty, bool uj);
extern void zebra_evpn_es_show_esi(struct vty *vty, bool uj, esi_t *esi);
extern void zebra_evpn_update_all_es(struct zebra_evpn *zevpn);
extern void zebra_evpn_proc_remote_es(ZAPI_HANDLER_ARGS);
int zebra_evpn_remote_es_add(const esi_t *esi, struct in_addr vtep_ip,
			     bool esr_rxed, uint8_t df_alg, uint16_t df_pref);
int zebra_evpn_remote_es_del(const esi_t *esi, struct in_addr vtep_ip);
extern void zebra_evpn_es_evi_show(struct vty *vty, bool uj, int detail);
extern void zebra_evpn_es_evi_show_vni(struct vty *vty, bool uj,
		vni_t vni, int detail);
extern void zebra_evpn_es_mac_deref_entry(struct zebra_mac *mac);
extern bool zebra_evpn_es_mac_ref_entry(struct zebra_mac *mac,
					struct zebra_evpn_es *es);
extern bool zebra_evpn_es_mac_ref(struct zebra_mac *mac, const esi_t *esi);
extern struct zebra_evpn_es *zebra_evpn_es_find(const esi_t *esi);
extern void zebra_evpn_acc_vl_show(struct vty *vty, bool uj);
extern void zebra_evpn_acc_vl_show_detail(struct vty *vty, bool uj);
extern void zebra_evpn_if_es_print(struct vty *vty, json_object *json,
				   struct zebra_if *zif);
extern struct zebra_evpn_access_bd *
zebra_evpn_acc_vl_find(vlanid_t vid, struct interface *br_if);
struct zebra_evpn_access_bd *
zebra_evpn_acc_vl_find_index(vlanid_t vid, ifindex_t bridge_ifindex);
extern void zebra_evpn_acc_vl_show_vid(struct vty *vty, bool uj, vlanid_t vid,
				       struct interface *br_if);
extern void zebra_evpn_es_cleanup(void);
extern int zebra_evpn_mh_mac_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default);
void zebra_evpn_mh_config_write(struct vty *vty);
int zebra_evpn_mh_neigh_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default);
void zebra_evpn_es_local_br_port_update(struct zebra_if *zif);
extern int zebra_evpn_mh_startup_delay_update(struct vty *vty,
					      uint32_t duration,
					      bool set_default);
extern void zebra_evpn_mh_uplink_oper_update(struct zebra_if *zif);
extern void zebra_evpn_mh_update_protodown_bond_mbr(struct zebra_if *zif,
						    bool clear,
						    const char *caller);
extern bool zebra_evpn_is_es_bond(struct interface *ifp);
extern bool zebra_evpn_is_es_bond_member(struct interface *ifp);
extern void zebra_evpn_mh_print(struct vty *vty);
extern void zebra_evpn_mh_json(json_object *json);
extern bool zebra_evpn_nhg_is_local_es(uint32_t nhg_id,
				       struct zebra_evpn_es **local_es);
extern int zebra_evpn_mh_redirect_off(struct vty *vty, bool redirect_off);
extern void zebra_evpn_l2_nh_show(struct vty *vty, bool uj);
extern void zebra_evpn_acc_bd_svi_set(struct zebra_if *vlan_zif,
				      struct zebra_if *br_zif, bool is_up);
extern void zebra_evpn_acc_bd_svi_mac_add(struct interface *vlan_if);
extern void
zebra_evpn_access_bd_bridge_cleanup(vlanid_t vid, struct interface *br_if,
				    struct zebra_evpn_access_bd *acc_bd);
extern void zebra_evpn_es_bypass_update(struct zebra_evpn_es *es,
					struct interface *ifp, bool bypass);
extern void zebra_evpn_proc_remote_nh(ZAPI_HANDLER_ARGS);
extern struct zebra_evpn_es_evi *
zebra_evpn_es_evi_find(struct zebra_evpn_es *es, struct zebra_evpn *zevpn);

void zebra_build_type3_esi(uint32_t lid, struct ethaddr *mac, esi_t *esi);

void zebra_evpn_es_sys_mac_update(struct zebra_if *zif, struct ethaddr *sysmac);
void zebra_evpn_es_lid_update(struct zebra_if *zif, uint32_t lid);
void zebra_evpn_es_type0_esi_update(struct zebra_if *zif, esi_t *esi);

void zebra_evpn_es_df_pref_update(struct zebra_if *zif, uint16_t df_pref);
void zebra_evpn_es_bypass_cfg_update(struct zebra_if *zif, bool bypass);
void zebra_evpn_mh_uplink_cfg_update(struct zebra_if *zif, bool set);

void zebra_evpn_mh_if_init(struct zebra_if *zif);

#endif /* _ZEBRA_EVPN_MH_H */
