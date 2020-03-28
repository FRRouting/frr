/*
 * Zebra EVPN MH Data structures and definitions
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef _ZEBRA_EVPN_MH_H
#define _ZEBRA_EVPN_MH_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "bitfield.h"
#include "zebra_vxlan.h"
#include "zebra_vxlan_private.h"

#define EVPN_MH_VTY_STR "Multihoming\n"

/* Ethernet Segment entry -
 * - Local and remote ESs are maintained in a global RB tree,
 * zmh_info->es_rb_tree using ESI as key
 * - Local ESs are added via zebra config (ZEBRA_EVPNES_LOCAL) when an
 *   access port is associated with an ES-ID
 * - Remotes ESs are added by BGP based on received/remote EAD/Type-1 routes
 *   (ZEBRA_EVPNES_REMOTE)
 * - An ES can be simulatenously LOCAL and REMOTE; infact all LOCAL ESs are
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

	/* zebra_mac_t entries using this ES as destination */
	uint32_t mac_cnt;

	/* Nexthop group id */
	uint32_t nhg_id;
};
RB_HEAD(zebra_es_rb_head, zebra_evpn_es);
RB_PROTOTYPE(zebra_es_rb_head, zebra_evpn_es, rb_node, zebra_es_rb_cmp);

/* ES per-EVI info
 * - ES-EVIs are maintained per-VNI (vni->es_evi_rb_tree)
 * - Local ES-EVIs are linked to per-VNI list for quick access
 * - Although some infrastucture is present for remote ES-EVIs, currently
 *   BGP does NOT send remote ES-EVIs to zebra. This may change in the
 *   future (but must be changed thoughtfully and only if needed as ES-EVI
 *   can get prolific and come in the way of rapid failovers)
 */
struct zebra_evpn_es_evi {
	struct zebra_evpn_es *es;
	zebra_vni_t *zvni;

	/* ES-EVI flags */
	uint32_t flags;
	/* local ES-EVI */
#define ZEBRA_EVPNES_EVI_LOCAL         (1 << 0) /* created by zebra */
#define ZEBRA_EVPNES_EVI_READY_FOR_BGP (1 << 1) /* ready to be sent to BGP */

	/* memory used for adding the es_evi to
	 * es_evi->zvni->es_evi_rb_tree
	 */
	RB_ENTRY(zebra_evpn_es_evi) rb_node;
	/* memory used for linking the es_evi to
	 * es_evi->zvni->local_es_evi_list
	 */
	struct listnode l2vni_listnode;
	/* memory used for linking the es_evi to
	 * es_evi->es->es_evi_list
	 */
	struct listnode es_listnode;
};

/* PE attached to an ES */
struct zebra_evpn_es_vtep {
	struct zebra_evpn_es *es; /* parent ES */
	struct in_addr vtep_ip;

	/* memory used for adding the entry to es->es_vtep_list */
	struct listnode es_listnode;

	/* MAC nexthop */
	uint32_t nh_id;

	/* XXX - maintain a backpointer to zebra_vtep_t */
};

/* Local/access-side broadcast domain - zebra_evpn_access_bd is added to -
 * zrouter->evpn_vlan_table (for VLAN aware bridges) OR
 * zrouter->evpn_bridge_table (for VLAN unaware bridges)
 * XXX - support for VLAN unaware bridges is yet to be flushed out
 */
struct zebra_evpn_access_bd {
	vlanid_t vid;

	struct zebra_if *vxlan_zif; /* vxlan device */
	/* list of members associated with the BD i.e. (potential) ESs */
	struct list *mbr_zifs;
	/* presence of zvni activates the EVI on all the ESs in mbr_zifs */
	zebra_vni_t *zvni;
};

/* multihoming information stored in zrouter */
#define zmh_info (zrouter.mh_info)
struct zebra_evpn_mh_info {
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
	zebra_vni_t *es_base_vni;
	struct in_addr es_originator_ip;

	/* L2 NH and NHG ids -
	 * Most significant 8 bits is type. Lower 24 bits is the value
	 * allocated from the nh_id_bitmap.
	 */
	bitfield_t nh_id_bitmap;
#define EVPN_NH_ID_MAX       (16*1024)
#define EVPN_NH_ID_VAL_MASK  0xffffff
#define EVPN_NH_ID_TYPE_POS  24
/* The purpose of using different types for NHG and NH is NOT to manage the
 * id space separately. It is simply to make debugging easier.
 */
#define EVPN_NH_ID_TYPE_BIT  (1 << EVPN_NH_ID_TYPE_POS)
#define EVPN_NHG_ID_TYPE_BIT (2 << EVPN_NH_ID_TYPE_POS)
};

static inline bool zebra_evpn_mac_is_es_local(zebra_mac_t *mac)
{
	return mac->es && (mac->es->flags & ZEBRA_EVPNES_LOCAL);
}

/* Returns true if the id is of L2-NHG or L2-NH type */
static inline bool zebra_evpn_mh_is_fdb_nh(uint32_t id)
{
	return ((id & EVPN_NHG_ID_TYPE_BIT) ||
			(id & EVPN_NH_ID_TYPE_BIT));
}

/*****************************************************************************/
extern esi_t *zero_esi;
extern void zebra_evpn_mh_init(void);
extern void zebra_evpn_mh_terminate(void);
extern bool zebra_evpn_is_if_es_capable(struct zebra_if *zif);
extern void zebra_evpn_if_init(struct zebra_if *zif);
extern void zebra_evpn_if_cleanup(struct zebra_if *zif);
extern void zebra_evpn_vni_es_init(zebra_vni_t *zvni);
extern void zebra_evpn_vni_es_cleanup(zebra_vni_t *zvni);
extern void zebra_evpn_vxl_vni_set(struct zebra_if *zif, zebra_vni_t *zvni,
		bool set);
extern void zebra_evpn_es_set_base_vni(zebra_vni_t *zvni);
extern void zebra_evpn_es_clear_base_vni(zebra_vni_t *zvni);
extern void zebra_evpn_vl_vxl_ref(uint16_t vid, struct zebra_if *vxlan_zif);
extern void zebra_evpn_vl_vxl_deref(uint16_t vid, struct zebra_if *vxlan_zif);
extern void zebra_evpn_vl_mbr_ref(uint16_t vid, struct zebra_if *zif);
extern void zebra_evpn_vl_mbr_deref(uint16_t vid, struct zebra_if *zif);
extern void zebra_evpn_es_send_all_to_client(bool add);
extern void zebra_evpn_es_if_oper_state_change(struct zebra_if *zif, bool up);
extern void zebra_evpn_es_show(struct vty *vty, bool uj);
extern void zebra_evpn_es_show_detail(struct vty *vty, bool uj);
extern void zebra_evpn_es_show_esi(struct vty *vty, bool uj, esi_t *esi);
extern void zebra_evpn_vni_update_all_es(zebra_vni_t *zvni);
extern void zebra_evpn_proc_remote_es(ZAPI_HANDLER_ARGS);
extern void zebra_evpn_es_evi_show(struct vty *vty, bool uj, int detail);
extern void zebra_evpn_es_evi_show_vni(struct vty *vty, bool uj,
		vni_t vni, int detail);
extern void zebra_evpn_es_mac_deref_entry(zebra_mac_t *mac);
extern bool zebra_evpn_es_mac_ref_entry(zebra_mac_t *mac,
		struct zebra_evpn_es *es);
extern void zebra_evpn_es_mac_ref(zebra_mac_t *mac, esi_t *esi);
extern struct zebra_evpn_es *zebra_evpn_es_find(esi_t *esi);
extern void zebra_evpn_interface_init(void);
extern int zebra_evpn_mh_if_write(struct vty *vty, struct interface *ifp);
extern void zebra_evpn_acc_vl_show(struct vty *vty, bool uj);
extern void zebra_evpn_acc_vl_show_detail(struct vty *vty, bool uj);
extern void zebra_evpn_acc_vl_show_vid(struct vty *vty, bool uj, vlanid_t vid);
extern void zebra_evpn_if_es_print(struct vty *vty, struct zebra_if *zif);
extern void zebra_evpn_es_cleanup(void);

#endif /* _ZEBRA_EVPN_MH_H */
