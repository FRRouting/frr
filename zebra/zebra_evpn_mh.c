/*
 * Zebra EVPN multihoming code
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

#include <zebra.h>

#include "command.h"
#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "vlan.h"
#include "vxlan.h"

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_nhg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZACC_BD, "Access Broadcast Domain");
DEFINE_MTYPE_STATIC(ZEBRA, ZES, "Ethernet Segment");
DEFINE_MTYPE_STATIC(ZEBRA, ZES_EVI, "ES info per-EVI");
DEFINE_MTYPE_STATIC(ZEBRA, ZMH_INFO, "MH global info");
DEFINE_MTYPE_STATIC(ZEBRA, ZES_VTEP, "VTEP attached to the ES");

static void zebra_evpn_es_get_one_base_evpn(void);
static int zebra_evpn_es_evi_send_to_client(struct zebra_evpn_es *es,
		zebra_evpn_t *zevpn, bool add);
static void zebra_evpn_local_es_del(struct zebra_evpn_es *es);
static int zebra_evpn_local_es_update(struct zebra_if *zif, uint32_t lid,
		struct ethaddr *sysmac);
static bool zebra_evpn_es_br_port_dplane_update(struct zebra_evpn_es *es,
		const char *caller);

esi_t zero_esi_buf, *zero_esi = &zero_esi_buf;

/*****************************************************************************/
/* Ethernet Segment to EVI association -
 * 1. The ES-EVI entry is maintained as a RB tree per L2-VNI
 * (zebra_evpn_t.es_evi_rb_tree).
 * 2. Each local ES-EVI entry is sent to BGP which advertises it as an
 * EAD-EVI (Type-1 EVPN) route
 * 3. Local ES-EVI setup is re-evaluated on the following triggers -
 *    a. When an ESI is set or cleared on an access port.
 *    b. When an access port associated with an ESI is deleted.
 *    c. When VLAN member ship changes on an access port.
 *    d. When a VXLAN_IF is set or cleared on an access broadcast domain.
 *    e. When a L2-VNI is added or deleted for a VxLAN_IF.
 * 4. Currently zebra doesn't remote ES-EVIs. Those are managed and maintained
 * entirely in BGP which consolidates them into a remote ES. The remote ES
 * is then sent to zebra which allocates a NHG for it.
 */

/* compare ES-IDs for the ES-EVI RB tree maintained per-EVPN */
static int zebra_es_evi_rb_cmp(const struct zebra_evpn_es_evi *es_evi1,
		const struct zebra_evpn_es_evi *es_evi2)
{
	return memcmp(&es_evi1->es->esi, &es_evi2->es->esi, ESI_BYTES);
}
RB_GENERATE(zebra_es_evi_rb_head, zebra_evpn_es_evi,
		rb_node, zebra_es_evi_rb_cmp);

/* allocate a new ES-EVI and insert it into the per-L2-VNI and per-ES
 * tables.
 */
static struct zebra_evpn_es_evi *zebra_evpn_es_evi_new(struct zebra_evpn_es *es,
		zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;

	es_evi = XCALLOC(MTYPE_ZES_EVI, sizeof(struct zebra_evpn_es_evi));

	es_evi->es = es;
	es_evi->zevpn = zevpn;

	/* insert into the EVPN-ESI rb tree */
	if (RB_INSERT(zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree, es_evi)) {
		XFREE(MTYPE_ZES_EVI, es_evi);
		return NULL;
	}

	/* add to the ES's VNI list */
	listnode_init(&es_evi->es_listnode, es_evi);
	listnode_add(es->es_evi_list, &es_evi->es_listnode);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s evi %d new",
				es_evi->es->esi_str, es_evi->zevpn->vni);

	return es_evi;
}

/* returns TRUE if the EVPN is ready to be sent to BGP */
static inline bool zebra_evpn_send_to_client_ok(zebra_evpn_t *zevpn)
{
	return !!(zevpn->flags & ZEVPN_READY_FOR_BGP);
}

/* Evaluate if the es_evi is ready to be sent BGP -
 * 1. If it is ready an add is sent to BGP
 * 2. If it is not ready a del is sent (if the ES had been previously added
 *   to BGP).
 */
static void zebra_evpn_es_evi_re_eval_send_to_client(
		struct zebra_evpn_es_evi *es_evi)
{
	bool old_ready;
	bool new_ready;

	old_ready = !!(es_evi->flags & ZEBRA_EVPNES_EVI_READY_FOR_BGP);

	/* ES and L2-VNI have to be individually ready for BGP */
	if ((es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL) &&
			(es_evi->es->flags & ZEBRA_EVPNES_READY_FOR_BGP) &&
			zebra_evpn_send_to_client_ok(es_evi->zevpn))
		es_evi->flags |= ZEBRA_EVPNES_EVI_READY_FOR_BGP;
	else
		es_evi->flags &= ~ZEBRA_EVPNES_EVI_READY_FOR_BGP;

	new_ready = !!(es_evi->flags & ZEBRA_EVPNES_EVI_READY_FOR_BGP);

	if (old_ready == new_ready)
		return;

	if (new_ready)
		zebra_evpn_es_evi_send_to_client(es_evi->es, es_evi->zevpn,
				true /* add */);
	else
		zebra_evpn_es_evi_send_to_client(es_evi->es, es_evi->zevpn,
				false /* add */);
}

/* remove the ES-EVI from the per-L2-VNI and per-ES tables and free
 * up the memory.
 */
static void zebra_evpn_es_evi_free(struct zebra_evpn_es_evi *es_evi)
{
	struct zebra_evpn_es *es = es_evi->es;
	zebra_evpn_t *zevpn = es_evi->zevpn;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s evi %d free",
				es_evi->es->esi_str, es_evi->zevpn->vni);

	/* remove from the ES's VNI list */
	list_delete_node(es->es_evi_list, &es_evi->es_listnode);

	/* remove from the VNI-ESI rb tree */
	RB_REMOVE(zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree, es_evi);

	/* remove from the VNI-ESI rb tree */
	XFREE(MTYPE_ZES_EVI, es_evi);
}

/* find the ES-EVI in the per-L2-VNI RB tree */
static struct zebra_evpn_es_evi *zebra_evpn_es_evi_find(
		struct zebra_evpn_es *es, zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi es_evi;

	es_evi.es = es;

	return RB_FIND(zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree, &es_evi);
}

/* Tell BGP about an ES-EVI deletion and then delete it */
static void zebra_evpn_local_es_evi_do_del(struct zebra_evpn_es_evi *es_evi)
{
	if (!(es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("local es %s evi %d del",
				es_evi->es->esi_str, es_evi->zevpn->vni);

	if (es_evi->flags & ZEBRA_EVPNES_EVI_READY_FOR_BGP) {
		/* send a del only if add was sent for it earlier */
		zebra_evpn_es_evi_send_to_client(es_evi->es,
				es_evi->zevpn, false /* add */);
	}

	/* delete it from the EVPN's local list */
	list_delete_node(es_evi->zevpn->local_es_evi_list,
			&es_evi->l2vni_listnode);

	es_evi->flags &= ~ZEBRA_EVPNES_EVI_LOCAL;
	zebra_evpn_es_evi_free(es_evi);
}
static void zebra_evpn_local_es_evi_del(struct zebra_evpn_es *es,
		zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;

	es_evi = zebra_evpn_es_evi_find(es, zevpn);
	if (es_evi)
		zebra_evpn_local_es_evi_do_del(es_evi);
}

/* Create an ES-EVI if it doesn't already exist and tell BGP */
static void zebra_evpn_local_es_evi_add(struct zebra_evpn_es *es,
		zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;

	es_evi = zebra_evpn_es_evi_find(es, zevpn);
	if (!es_evi) {
		es_evi = zebra_evpn_es_evi_new(es, zevpn);
		if (!es_evi)
			return;

		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("local es %s evi %d add",
					es_evi->es->esi_str, es_evi->zevpn->vni);
		es_evi->flags |= ZEBRA_EVPNES_EVI_LOCAL;
		/* add to the EVPN's local list */
		listnode_init(&es_evi->l2vni_listnode, es_evi);
		listnode_add(zevpn->local_es_evi_list, &es_evi->l2vni_listnode);

		zebra_evpn_es_evi_re_eval_send_to_client(es_evi);
	}
}

static void zebra_evpn_es_evi_show_entry(struct vty *vty,
		struct zebra_evpn_es_evi *es_evi, json_object *json)
{
	char type_str[4];

	if (json) {
		/* XXX */
	} else {
		type_str[0] = '\0';
		if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
			strcpy(type_str + strlen(type_str), "L");

		vty_out(vty, "%-8d %-30s %-4s\n",
				es_evi->zevpn->vni, es_evi->es->esi_str,
				type_str);
	}
}

static void zebra_evpn_es_evi_show_entry_detail(struct vty *vty,
		struct zebra_evpn_es_evi *es_evi, json_object *json)
{
	char type_str[4];

	if (json) {
		/* XXX */
	} else {
		type_str[0] = '\0';
		if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
			strcpy(type_str + strlen(type_str), "L");

		vty_out(vty, "VNI %d ESI: %s\n",
				es_evi->zevpn->vni, es_evi->es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " Ready for BGP: %s\n",
				(es_evi->flags &
				 ZEBRA_EVPNES_EVI_READY_FOR_BGP) ?
				"yes" : "no");
		vty_out(vty, "\n");
	}
}

static void zebra_evpn_es_evi_show_one_evpn(zebra_evpn_t *zevpn,
		struct vty *vty, json_object *json, int detail)
{
	struct zebra_evpn_es_evi *es_evi;

	RB_FOREACH(es_evi, zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree) {
		if (detail)
			zebra_evpn_es_evi_show_entry_detail(vty, es_evi, json);
		else
			zebra_evpn_es_evi_show_entry(vty, es_evi, json);
	}
}

struct evpn_mh_show_ctx {
	struct vty *vty;
	json_object *json;
	int detail;
};

static void zebra_evpn_es_evi_show_one_evpn_hash_cb(struct hash_bucket *bucket,
		void *ctxt)
{
	zebra_evpn_t *zevpn = (zebra_evpn_t *)bucket->data;
	struct evpn_mh_show_ctx *wctx = (struct evpn_mh_show_ctx *)ctxt;

	zebra_evpn_es_evi_show_one_evpn(zevpn, wctx->vty,
			wctx->json, wctx->detail);
}

void zebra_evpn_es_evi_show(struct vty *vty, bool uj, int detail)
{
	json_object *json = NULL;
	struct zebra_vrf *zvrf;
	struct evpn_mh_show_ctx wctx;

	zvrf = zebra_vrf_get_evpn();

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	wctx.detail = detail;

	if (!detail && !json) {
		vty_out(vty, "Type: L local, R remote\n");
		vty_out(vty, "%-8s %-30s %-4s\n", "VNI", "ESI", "Type");
	}
	/* Display all L2-VNIs */
	hash_iterate(zvrf->evpn_table, zebra_evpn_es_evi_show_one_evpn_hash_cb,
			&wctx);
}

void zebra_evpn_es_evi_show_vni(struct vty *vty, bool uj, vni_t vni, int detail)
{
	json_object *json = NULL;
	zebra_evpn_t *zevpn;

	zevpn = zebra_evpn_lookup(vni);
	if (zevpn) {
		if (!detail && !json) {
			vty_out(vty, "Type: L local, R remote\n");
			vty_out(vty, "%-8s %-30s %-4s\n", "VNI", "ESI", "Type");
		}
	} else {
		if (!uj)
			vty_out(vty, "VNI %d doesn't exist\n", zevpn->vni);
	}
	zebra_evpn_es_evi_show_one_evpn(zevpn, vty, json, detail);
}

/* Initialize the ES tables maintained per-L2_VNI */
void zebra_evpn_evpn_es_init(zebra_evpn_t *zevpn)
{
	/* Initialize the ES-EVI RB tree */
	RB_INIT(zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree);

	/* Initialize the local and remote ES lists maintained for quick
	 * walks by type
	 */
	zevpn->local_es_evi_list = list_new();
	listset_app_node_mem(zevpn->local_es_evi_list);
}

/* Cleanup the ES info maintained per- EVPN */
void zebra_evpn_evpn_es_cleanup(zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;
	struct zebra_evpn_es_evi *es_evi_next;

	RB_FOREACH_SAFE(es_evi, zebra_es_evi_rb_head,
			&zevpn->es_evi_rb_tree, es_evi_next) {
		zebra_evpn_local_es_evi_do_del(es_evi);
	}

	list_delete(&zevpn->local_es_evi_list);
	zebra_evpn_es_clear_base_evpn(zevpn);
}

/* called when the oper state or bridge membership changes for the
 * vxlan device
 */
void zebra_evpn_update_all_es(zebra_evpn_t *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;
	struct listnode *node;

	/* the EVPN is now elgible as a base for EVPN-MH */
	if (zebra_evpn_send_to_client_ok(zevpn))
		zebra_evpn_es_set_base_evpn(zevpn);
	else
		zebra_evpn_es_clear_base_evpn(zevpn);

	for (ALL_LIST_ELEMENTS_RO(zevpn->local_es_evi_list, node, es_evi))
		zebra_evpn_es_evi_re_eval_send_to_client(es_evi);
}

/*****************************************************************************/
/* Access broadcast domains (BD)
 * 1. These broadcast domains can be VLAN aware (in which case
 * the key is VID) or VLAN unaware (in which case the key is
 * 2. A VID-BD is created when a VLAN is associated with an access port or
 *    when the VLAN is associated with VXLAN_IF
 * 3. A BD is translated into ES-EVI entries when a VNI is associated
 *  with the broadcast domain
 */
/* Hash key for VLAN based broadcast domains */
static unsigned int zebra_evpn_acc_vl_hash_keymake(const void *p)
{
	const struct zebra_evpn_access_bd *acc_bd = p;

	return jhash_1word(acc_bd->vid, 0);
}

/* Compare two VLAN based broadcast domains */
static bool zebra_evpn_acc_vl_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn_access_bd *acc_bd1 = p1;
	const struct zebra_evpn_access_bd *acc_bd2 = p2;

	if (acc_bd1 == NULL && acc_bd2 == NULL)
		return true;

	if (acc_bd1 == NULL || acc_bd2 == NULL)
		return false;

	return (acc_bd1->vid == acc_bd2->vid);
}

/* Lookup VLAN based broadcast domain */
static struct zebra_evpn_access_bd *zebra_evpn_acc_vl_find(vlanid_t vid)
{
	struct zebra_evpn_access_bd *acc_bd;
	struct zebra_evpn_access_bd tmp;

	tmp.vid = vid;
	acc_bd = hash_lookup(zmh_info->evpn_vlan_table, &tmp);

	return acc_bd;
}

/* A new broadcast domain can be created when a VLAN member or VLAN<=>VxLAN_IF
 * mapping is added.
 */
static struct zebra_evpn_access_bd *zebra_evpn_acc_vl_new(vlanid_t vid)
{
	struct zebra_evpn_access_bd *acc_bd;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d add", vid);

	acc_bd = XCALLOC(MTYPE_ZACC_BD, sizeof(struct zebra_evpn_access_bd));

	acc_bd->vid = vid;

	/* Initialize the mbr list */
	acc_bd->mbr_zifs = list_new();

	/* Add to hash */
	if (!hash_get(zmh_info->evpn_vlan_table, acc_bd, hash_alloc_intern)) {
		XFREE(MTYPE_ZACC_BD, acc_bd);
		return NULL;
	}

	return acc_bd;
}

/* Free VLAN based broadcast domain -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static void zebra_evpn_acc_vl_free(struct zebra_evpn_access_bd *acc_bd)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d del", acc_bd->vid);

	/* cleanup resources maintained against the ES */
	list_delete(&acc_bd->mbr_zifs);

	/* remove EVI from various tables */
	hash_release(zmh_info->evpn_vlan_table, acc_bd);

	XFREE(MTYPE_ZACC_BD, acc_bd);
}

static void zebra_evpn_acc_vl_cleanup_all(struct hash_bucket *bucket, void *arg)
{
	struct zebra_evpn_access_bd *acc_bd = bucket->data;

	zebra_evpn_acc_vl_free(acc_bd);
}

/* called when a bd mbr is removed or VxLAN_IF is diassociated from the access
 * VLAN
 */
static void zebra_evpn_acc_bd_free_on_deref(struct zebra_evpn_access_bd *acc_bd)
{
	if (!list_isempty(acc_bd->mbr_zifs) || acc_bd->vxlan_zif)
		return;

	/* if there are no references free the EVI */
	zebra_evpn_acc_vl_free(acc_bd);
}

/* called when a EVPN-L2VNI is set or cleared against a BD */
static void zebra_evpn_acc_bd_evpn_set(struct zebra_evpn_access_bd *acc_bd,
		zebra_evpn_t *zevpn, zebra_evpn_t *old_zevpn)
{
	struct zebra_if *zif;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d l2-vni %u set",
				acc_bd->vid, zevpn ? zevpn->vni : 0);

	for (ALL_LIST_ELEMENTS_RO(acc_bd->mbr_zifs, node, zif)) {
		if (!zif->es_info.es)
			continue;

		if (zevpn)
			zebra_evpn_local_es_evi_add(zif->es_info.es, zevpn);
		else if (old_zevpn)
			zebra_evpn_local_es_evi_del(zif->es_info.es, old_zevpn);
	}
}

/* handle VLAN->VxLAN_IF association */
void zebra_evpn_vl_vxl_ref(uint16_t vid, struct zebra_if *vxlan_zif)
{
	struct zebra_evpn_access_bd *acc_bd;
	struct zebra_if *old_vxlan_zif;
	zebra_evpn_t *old_zevpn;

	if (!vid)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid);
	if (!acc_bd)
		acc_bd = zebra_evpn_acc_vl_new(vid);

	old_vxlan_zif = acc_bd->vxlan_zif;
	acc_bd->vxlan_zif = vxlan_zif;
	if (vxlan_zif == old_vxlan_zif)
		return;

	old_zevpn = acc_bd->zevpn;
	acc_bd->zevpn = zebra_evpn_lookup(vxlan_zif->l2info.vxl.vni);
	if (acc_bd->zevpn == old_zevpn)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d vni %u ref",
				acc_bd->vid, vxlan_zif->l2info.vxl.vni);

	if (old_zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, old_zevpn);

	if (acc_bd->zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, acc_bd->zevpn, NULL);
}

/* handle VLAN->VxLAN_IF deref */
void zebra_evpn_vl_vxl_deref(uint16_t vid, struct zebra_if *vxlan_zif)
{
	struct zebra_evpn_access_bd *acc_bd;

	if (!vid)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid);
	if (!acc_bd)
		return;

	/* clear vxlan_if only if it matches */
	if (acc_bd->vxlan_zif != vxlan_zif)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d vni %u deref",
				acc_bd->vid, vxlan_zif->l2info.vxl.vni);

	if (acc_bd->zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, acc_bd->zevpn);

	acc_bd->zevpn = NULL;
	acc_bd->vxlan_zif = NULL;

	/* if there are no other references the access_bd can be freed */
	zebra_evpn_acc_bd_free_on_deref(acc_bd);
}

/* handle EVPN add/del */
void zebra_evpn_vxl_evpn_set(struct zebra_if *zif, zebra_evpn_t *zevpn,
		bool set)
{
	struct zebra_l2info_vxlan *vxl;
	struct zebra_evpn_access_bd *acc_bd;

	if (!zif)
		return;

	/* locate access_bd associated with the vxlan device */
	vxl = &zif->l2info.vxl;
	acc_bd = zebra_evpn_acc_vl_find(vxl->access_vlan);
	if (!acc_bd)
		return;

	if (set) {
		zebra_evpn_es_set_base_evpn(zevpn);
		if (acc_bd->zevpn != zevpn) {
			acc_bd->zevpn = zevpn;
			zebra_evpn_acc_bd_evpn_set(acc_bd, zevpn, NULL);
		}
	} else {
		if (acc_bd->zevpn) {
			zebra_evpn_t *old_zevpn = acc_bd->zevpn;
			acc_bd->zevpn = NULL;
			zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, old_zevpn);
		}
	}
}

/* handle addition of new VLAN members */
void zebra_evpn_vl_mbr_ref(uint16_t vid, struct zebra_if *zif)
{
	struct zebra_evpn_access_bd *acc_bd;

	if (!vid)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid);
	if (!acc_bd)
		acc_bd = zebra_evpn_acc_vl_new(vid);

	if (listnode_lookup(acc_bd->mbr_zifs, zif))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d mbr %s ref",
				vid, zif->ifp->name);

	listnode_add(acc_bd->mbr_zifs, zif);
	if (acc_bd->zevpn && zif->es_info.es)
		zebra_evpn_local_es_evi_add(zif->es_info.es, acc_bd->zevpn);
}

/* handle deletion of VLAN members */
void zebra_evpn_vl_mbr_deref(uint16_t vid, struct zebra_if *zif)
{
	struct zebra_evpn_access_bd *acc_bd;
	struct listnode *node;

	if (!vid)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid);
	if (!acc_bd)
		return;

	node = listnode_lookup(acc_bd->mbr_zifs, zif);
	if (!node)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d mbr %s deref",
				vid, zif->ifp->name);

	list_delete_node(acc_bd->mbr_zifs, node);

	if (acc_bd->zevpn && zif->es_info.es)
		zebra_evpn_local_es_evi_del(zif->es_info.es, acc_bd->zevpn);

	/* if there are no other references the access_bd can be freed */
	zebra_evpn_acc_bd_free_on_deref(acc_bd);
}

static void zebra_evpn_acc_vl_show_entry_detail(struct vty *vty,
		struct zebra_evpn_access_bd *acc_bd, json_object *json)
{
	struct zebra_if *zif;
	struct listnode	*node;

	if (json) {
		/* XXX */
	} else {
		vty_out(vty, "VLAN: %u\n", acc_bd->vid);
		vty_out(vty, " VxLAN Interface: %s\n",
				acc_bd->vxlan_zif ?
				acc_bd->vxlan_zif->ifp->name : "-");
		vty_out(vty, " L2-VNI: %d\n",
				acc_bd->zevpn ? acc_bd->zevpn->vni : 0);
		vty_out(vty, " Member Count: %d\n",
				listcount(acc_bd->mbr_zifs));
		vty_out(vty, " Members: \n");
		for (ALL_LIST_ELEMENTS_RO(acc_bd->mbr_zifs, node, zif))
			vty_out(vty, "    %s\n", zif->ifp->name);
		vty_out(vty, "\n");
	}
}

static void zebra_evpn_acc_vl_show_entry(struct vty *vty,
		struct zebra_evpn_access_bd *acc_bd, json_object *json)
{
	if (!json)
		vty_out(vty, "%-5u %21s %-8d %u\n",
				acc_bd->vid,
				acc_bd->vxlan_zif ?
				acc_bd->vxlan_zif->ifp->name : "-",
				acc_bd->zevpn ? acc_bd->zevpn->vni : 0,
				listcount(acc_bd->mbr_zifs));
}

static void zebra_evpn_acc_vl_show_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct evpn_mh_show_ctx *wctx = ctxt;
	struct zebra_evpn_access_bd *acc_bd = bucket->data;

	if (wctx->detail)
		zebra_evpn_acc_vl_show_entry_detail(wctx->vty,
				acc_bd, wctx->json);
	else
		zebra_evpn_acc_vl_show_entry(wctx->vty,
				acc_bd, wctx->json);
}

void zebra_evpn_acc_vl_show(struct vty *vty, bool uj)
{
	json_object *json = NULL;
	struct evpn_mh_show_ctx wctx;

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	wctx.detail = false;

	if (!json)
		vty_out(vty, "%-5s %21s %-8s %s\n",
				"VLAN", "VxLAN-IF", "L2-VNI", "# Members");

	hash_iterate(zmh_info->evpn_vlan_table, zebra_evpn_acc_vl_show_hash,
			&wctx);
}

void zebra_evpn_acc_vl_show_detail(struct vty *vty, bool uj)
{
	json_object *json = NULL;
	struct evpn_mh_show_ctx wctx;

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	wctx.detail = true;

	hash_iterate(zmh_info->evpn_vlan_table, zebra_evpn_acc_vl_show_hash,
			&wctx);
}

void zebra_evpn_acc_vl_show_vid(struct vty *vty, bool uj, vlanid_t vid)
{
	json_object *json = NULL;
	struct zebra_evpn_access_bd *acc_bd;

	acc_bd = zebra_evpn_acc_vl_find(vid);
	if (!acc_bd) {
		if (!json) {
			vty_out(vty, "VLAN %u not present\n", vid);
			return;
		}
	}
	zebra_evpn_acc_vl_show_entry_detail(vty, acc_bd, json);
}

/* Initialize VLAN member bitmap on an interface. Although VLAN membership
 * is independent of EVPN we only process it if its of interest to EVPN-MH
 * i.e. on access ports that can be setup as Ethernet Segments. And that is
 * intended as an optimization.
 */
void zebra_evpn_if_init(struct zebra_if *zif)
{
	if (!zebra_evpn_is_if_es_capable(zif))
		return;

	if (!bf_is_inited(zif->vlan_bitmap))
		bf_init(zif->vlan_bitmap, IF_VLAN_BITMAP_MAX);

	/* if an es_id and sysmac are already present against the interface
	 * activate it
	 */
	zebra_evpn_local_es_update(zif, zif->es_info.lid, &zif->es_info.sysmac);
}

/* handle deletion of an access port by removing it from all associated
 * broadcast domains.
 */
void zebra_evpn_if_cleanup(struct zebra_if *zif)
{
	vlanid_t vid;

	if (!bf_is_inited(zif->vlan_bitmap))
		return;

	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX) {
		zebra_evpn_vl_mbr_deref(vid, zif);
	}

	bf_free(zif->vlan_bitmap);

	/* Delete associated Ethernet Segment */
	if (zif->es_info.es)
		zebra_evpn_local_es_del(zif->es_info.es);
}

/*****************************************************************************
 * L2 NH/NHG Management
 *   A L2 NH entry is programmed in the kernel for every ES-VTEP entry. This
 * NH is then added to the L2-ECMP-NHG associated with the ES.
 */
static uint32_t zebra_evpn_nhid_alloc(bool is_nhg)
{
	uint32_t id;
	int type;

	bf_assign_index(zmh_info->nh_id_bitmap, id);

	if (!id)
		return 0;

	type = is_nhg ? EVPN_NHG_ID_TYPE_BIT : EVPN_NH_ID_TYPE_BIT;
	return (id | type);
}

static void zebra_evpn_nhid_free(uint32_t nh_id)
{
	uint32_t id = (nh_id & EVPN_NH_ID_VAL_MASK);

	if (!id)
		return;

	bf_release_index(zmh_info->nh_id_bitmap, id);
}

/* update remote macs associated with the ES */
static void zebra_evpn_nhg_mac_update(struct zebra_evpn_es *es)
{
	zebra_mac_t *mac;
	struct listnode	*node;

	for (ALL_LIST_ELEMENTS_RO(es->mac_list, node, mac)) {
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
			continue;

		if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE)
			zebra_evpn_rem_mac_install(mac->zevpn, mac,
					false /*was_static*/);
		else
			zebra_evpn_rem_mac_uninstall(mac->zevpn, mac, true /*force*/);
	}
}

/* The MAC ECMP group is activated on the first VTEP */
static void zebra_evpn_nhg_update(struct zebra_evpn_es *es)
{
	uint32_t nh_cnt = 0;
	struct nh_grp nh_ids[ES_VTEP_MAX_CNT];
	struct zebra_evpn_es_vtep *es_vtep;
	struct listnode	*node;

	if (!es->nhg_id)
		return;

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (!es_vtep->nh_id)
			continue;

		if (nh_cnt >= ES_VTEP_MAX_CNT)
			break;

		memset(&nh_ids[nh_cnt], 0, sizeof(struct nh_grp));
		nh_ids[nh_cnt].id = es_vtep->nh_id;
		++nh_cnt;
	}

	if (nh_cnt) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_NH) {
			char nh_str[ES_VTEP_LIST_STR_SZ];
			uint32_t i;

			nh_str[0] = '\0';
			for (i = 0; i < nh_cnt; ++i)
				sprintf(nh_str + strlen(nh_str),
						"0x%x ", nh_ids[i].id);
			zlog_debug("es %s nhg 0x%x add %s",
					es->esi_str, es->nhg_id, nh_str);
		}

		kernel_upd_mac_nhg(es->nhg_id, nh_cnt, nh_ids);
		if (!(es->flags & ZEBRA_EVPNES_NHG_ACTIVE)) {
			es->flags |= ZEBRA_EVPNES_NHG_ACTIVE;
			/* add backup NHG to the br-port */
			if ((es->flags & ZEBRA_EVPNES_LOCAL))
				zebra_evpn_es_br_port_dplane_update(es,
					__func__);
			zebra_evpn_nhg_mac_update(es);
		}
	} else {
		if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
				zlog_debug("es %s nhg 0x%x del",
						es->esi_str, es->nhg_id);
			es->flags &= ~ZEBRA_EVPNES_NHG_ACTIVE;
			/* remove backup NHG from the br-port */
			if ((es->flags & ZEBRA_EVPNES_LOCAL))
				zebra_evpn_es_br_port_dplane_update(es,
					__func__);
			zebra_evpn_nhg_mac_update(es);
			kernel_del_mac_nhg(es->nhg_id);
		}
	}

}

static void zebra_evpn_nh_add(struct zebra_evpn_es_vtep *es_vtep)
{
	if (es_vtep->nh_id)
		return;

	es_vtep->nh_id = zebra_evpn_nhid_alloc(false);

	if (!es_vtep->nh_id)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
		zlog_debug("es %s vtep %s nh 0x%x add",
				es_vtep->es->esi_str,
				inet_ntoa(es_vtep->vtep_ip), es_vtep->nh_id);
	/* install the NH */
	kernel_upd_mac_nh(es_vtep->nh_id, es_vtep->vtep_ip);
	/* add the NH to the parent NHG */
	zebra_evpn_nhg_update(es_vtep->es);
}

static void zebra_evpn_nh_del(struct zebra_evpn_es_vtep *es_vtep)
{
	uint32_t nh_id;

	if (!es_vtep->nh_id)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
		zlog_debug("es %s vtep %s nh 0x%x del",
				es_vtep->es->esi_str,
				inet_ntoa(es_vtep->vtep_ip), es_vtep->nh_id);

	nh_id = es_vtep->nh_id;
	es_vtep->nh_id = 0;

	/* remove the NH from the parent NHG */
	zebra_evpn_nhg_update(es_vtep->es);
	/* uninstall the NH */
	kernel_del_mac_nh(nh_id);
	zebra_evpn_nhid_free(nh_id);

}

/*****************************************************************************/
/* Ethernet Segment Management
 * 1. Ethernet Segment is a collection of links attached to the same
 *    server (MHD) or switch (MHN)
 * 2. An Ethernet Segment can span multiple PEs and is identified by the
 *    10-byte ES-ID.
 * 3. Zebra manages the local ESI configuration.
 * 4. It also maintains the aliasing that maps an ESI (local or remote)
 *    to one or more PEs/VTEPs.
 * 5. remote ESs are added by BGP (on rxing EAD Type-1 routes)
 */
/* A list of remote VTEPs is maintained for each ES. This list includes -
 * 1. VTEPs for which we have imported the ESR i.e. ES-peers
 * 2. VTEPs that have an "active" ES-EVI VTEP i.e. EAD-per-ES and EAD-per-EVI
 *    have been imported into one or more EVPNs
 */
static int zebra_evpn_es_vtep_cmp(void *p1, void *p2)
{
	const struct zebra_evpn_es_vtep *es_vtep1 = p1;
	const struct zebra_evpn_es_vtep *es_vtep2 = p2;

	return es_vtep1->vtep_ip.s_addr - es_vtep2->vtep_ip.s_addr;
}

static struct zebra_evpn_es_vtep *zebra_evpn_es_vtep_new(
		struct zebra_evpn_es *es, struct in_addr vtep_ip)
{
	struct zebra_evpn_es_vtep *es_vtep;

	es_vtep = XCALLOC(MTYPE_ZES_VTEP, sizeof(*es_vtep));

	es_vtep->es = es;
	es_vtep->vtep_ip.s_addr = vtep_ip.s_addr;
	listnode_init(&es_vtep->es_listnode, es_vtep);
	listnode_add_sort(es->es_vtep_list, &es_vtep->es_listnode);

	return es_vtep;
}

static void zebra_evpn_es_vtep_free(struct zebra_evpn_es_vtep *es_vtep)
{
	struct zebra_evpn_es *es = es_vtep->es;

	list_delete_node(es->es_vtep_list, &es_vtep->es_listnode);
	/* update the L2-NHG associated with the ES */
	zebra_evpn_nh_del(es_vtep);
	XFREE(MTYPE_ZES_VTEP, es_vtep);
}


/* check if VTEP is already part of the list */
static struct zebra_evpn_es_vtep *zebra_evpn_es_vtep_find(
		struct zebra_evpn_es *es, struct in_addr vtep_ip)
{
	struct listnode *node = NULL;
	struct zebra_evpn_es_vtep *es_vtep;

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (es_vtep->vtep_ip.s_addr == vtep_ip.s_addr)
			return es_vtep;
	}
	return NULL;
}

/* flush all the dataplane br-port info associated with the ES */
static bool zebra_evpn_es_br_port_dplane_clear(struct zebra_evpn_es *es)
{
	struct in_addr sph_filters[ES_VTEP_MAX_CNT];

	if (!(es->flags & ZEBRA_EVPNES_BR_PORT))
		return false;

	zlog_debug("es %s br-port dplane clear", es->esi_str);

	memset(&sph_filters, 0, sizeof(sph_filters));
	dplane_br_port_update(es->zif->ifp,
			false /* non_df */,
			0, sph_filters, 0 /* backup_nhg_id */);
	return true;
}

static inline bool zebra_evpn_es_br_port_dplane_update_needed(
		struct zebra_evpn_es *es)
{
	return (es->flags & ZEBRA_EVPNES_NON_DF) ||
		(es->flags & ZEBRA_EVPNES_NHG_ACTIVE) ||
		listcount(es->es_vtep_list);
}

/* returns TRUE if dplane entry was updated */
static bool zebra_evpn_es_br_port_dplane_update(struct zebra_evpn_es *es,
		const char *caller)
{
	uint32_t backup_nhg_id;
	struct in_addr sph_filters[ES_VTEP_MAX_CNT];
	struct listnode *node = NULL;
	struct zebra_evpn_es_vtep *es_vtep;
	uint32_t sph_filter_cnt = 0;

	if (!(es->flags & ZEBRA_EVPNES_LOCAL))
		return zebra_evpn_es_br_port_dplane_clear(es);

	/* If the ES is not a bridge port there is nothing
	 * in the dataplane
	 */
	if (!(es->flags & ZEBRA_EVPNES_BR_PORT))
		return false;

	zlog_debug("es %s br-port dplane update by %s",
			es->esi_str, caller);
	backup_nhg_id = (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) ?
		es->nhg_id : 0;

	memset(&sph_filters, 0, sizeof(sph_filters));
	if (listcount(es->es_vtep_list) > ES_VTEP_MAX_CNT) {
		zlog_warn("es %s vtep count %d exceeds filter cnt %d",
				es->esi_str, listcount(es->es_vtep_list),
				ES_VTEP_MAX_CNT);
	} else {
		for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
			if (es_vtep->flags & ZEBRA_EVPNES_VTEP_DEL_IN_PROG)
				continue;
			sph_filters[sph_filter_cnt] = es_vtep->vtep_ip;
			++sph_filter_cnt;
		}
	}

	dplane_br_port_update(es->zif->ifp,
			!!(es->flags & ZEBRA_EVPNES_NON_DF),
			sph_filter_cnt, sph_filters, backup_nhg_id);

	return true;
}

/* returns TRUE if dplane entry was updated */
static bool zebra_evpn_es_df_change(struct zebra_evpn_es *es, bool new_non_df,
		const char *caller)
{
	bool old_non_df;

	old_non_df = !!(es->flags & ZEBRA_EVPNES_NON_DF);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("df-change(%s) es %s old %s new %s",
				caller, es->esi_str,
				old_non_df ? "non-df" : "df",
				new_non_df ? "non-df" : "df");

	if (old_non_df == new_non_df)
		return false;

	if (new_non_df)
		es->flags |= ZEBRA_EVPNES_NON_DF;
	else
		es->flags &= ~ZEBRA_EVPNES_NON_DF;

	/* update non-DF block filter in the dataplane */
	return zebra_evpn_es_br_port_dplane_update(es, __func__);
}

/* returns TRUE if dplane entry was updated */
static bool zebra_evpn_es_run_df_election(struct zebra_evpn_es *es,
		const char *caller)
{
	struct listnode *node = NULL;
	struct zebra_evpn_es_vtep *es_vtep;
	bool new_non_df = false;

	/* If the ES is not ready (i.e. not completely configured) there
	 * is no need to setup the BUM block filter
	 */
	if (!(es->flags & ZEBRA_EVPNES_LOCAL) ||
		!zmh_info->es_originator_ip.s_addr) {
		return zebra_evpn_es_df_change(es, new_non_df, caller);
	}

	/* if oper-state is down DF filtering must be on. when the link comes
	 * up again dataplane should block BUM till FRR has had the chance
	 * to run DF election again
	 */
	if (!(es->flags & ZEBRA_EVPNES_OPER_UP)) {
		new_non_df = true;
		return zebra_evpn_es_df_change(es, new_non_df, caller);
	}

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		/* Only VTEPs that have advertised the ESR can participate
		 * in DF election
		 */
		if (!(es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR))
			continue;

		/* If the DF alg is not the same we should fall back to
		 * service-carving. But as service-carving is not supported
		 * we will stop forwarding BUM
		 */
		if (es_vtep->df_alg != EVPN_MH_DF_ALG_PREF) {
			new_non_df = true;
			break;
		}

		/* Peer VTEP wins DF election if -
		 * the peer-VTEP has higher preference (or)
		 * the pref is the same but peer's IP address is lower
		 */
		if ((es_vtep->df_pref > es->df_pref) ||
				((es_vtep->df_pref == es->df_pref) &&
				 (es_vtep->vtep_ip.s_addr <
				  zmh_info->es_originator_ip.s_addr))) {
			new_non_df = true;
			break;
		}
	}

	return zebra_evpn_es_df_change(es, new_non_df, caller);
}

static void zebra_evpn_es_vtep_add(struct zebra_evpn_es *es,
		struct in_addr vtep_ip, bool esr_rxed,
		uint8_t df_alg, uint16_t df_pref)
{
	struct zebra_evpn_es_vtep *es_vtep;
	bool old_esr_rxed;
	bool dplane_updated = false;

	es_vtep = zebra_evpn_es_vtep_find(es, vtep_ip);

	if (!es_vtep) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es %s vtep %s add",
					es->esi_str, inet_ntoa(vtep_ip));
		es_vtep = zebra_evpn_es_vtep_new(es, vtep_ip);
		/* update the L2-NHG associated with the ES */
		zebra_evpn_nh_add(es_vtep);
	}

	old_esr_rxed = !!(es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR);
	if ((old_esr_rxed != esr_rxed) ||
			(es_vtep->df_alg != df_alg) ||
			(es_vtep->df_pref != df_pref)) {
		/* If any of the DF election params changed we need to re-run
		 * DF election
		 */
		if (esr_rxed)
			es_vtep->flags |= ZEBRA_EVPNES_VTEP_RXED_ESR;
		else
			es_vtep->flags &= ~ZEBRA_EVPNES_VTEP_RXED_ESR;
		es_vtep->df_alg = df_alg;
		es_vtep->df_pref = df_pref;
		dplane_updated = zebra_evpn_es_run_df_election(es, __func__);
	}
	/* add the vtep to the SPH list */
	if (!dplane_updated && (es->flags & ZEBRA_EVPNES_LOCAL))
		zebra_evpn_es_br_port_dplane_update(es, __func__);
}

static void zebra_evpn_es_vtep_del(struct zebra_evpn_es *es,
		struct in_addr vtep_ip)
{
	struct zebra_evpn_es_vtep *es_vtep;
	bool dplane_updated = false;

	es_vtep = zebra_evpn_es_vtep_find(es, vtep_ip);

	if (es_vtep) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es %s vtep %s del",
					es->esi_str, inet_ntoa(vtep_ip));
		es_vtep->flags |= ZEBRA_EVPNES_VTEP_DEL_IN_PROG;
		if (es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR) {
			es_vtep->flags &= ~ZEBRA_EVPNES_VTEP_RXED_ESR;
			dplane_updated =
				zebra_evpn_es_run_df_election(es, __func__);
		}
		/* remove the vtep from the SPH list */
		if (!dplane_updated && (es->flags & ZEBRA_EVPNES_LOCAL))
			zebra_evpn_es_br_port_dplane_update(es, __func__);
		zebra_evpn_es_vtep_free(es_vtep);
	}
}

/* compare ES-IDs for the global ES RB tree */
static int zebra_es_rb_cmp(const struct zebra_evpn_es *es1,
		const struct zebra_evpn_es *es2)
{
	return memcmp(&es1->esi, &es2->esi, ESI_BYTES);
}
RB_GENERATE(zebra_es_rb_head, zebra_evpn_es, rb_node, zebra_es_rb_cmp);

/* Lookup ES */
struct zebra_evpn_es *zebra_evpn_es_find(esi_t *esi)
{
	struct zebra_evpn_es tmp;

	memcpy(&tmp.esi, esi, sizeof(esi_t));
	return RB_FIND(zebra_es_rb_head, &zmh_info->es_rb_tree, &tmp);
}

/* A new local es is created when a local-es-id and sysmac is configured
 * against an interface.
 */
static struct zebra_evpn_es *zebra_evpn_es_new(esi_t *esi)
{
	struct zebra_evpn_es *es;

	es = XCALLOC(MTYPE_ZES, sizeof(struct zebra_evpn_es));

	/* fill in ESI */
	memcpy(&es->esi, esi, sizeof(esi_t));
	esi_to_str(&es->esi, es->esi_str, sizeof(es->esi_str));

	/* Add to rb_tree */
	if (RB_INSERT(zebra_es_rb_head, &zmh_info->es_rb_tree, es)) {
		XFREE(MTYPE_ZES, es);
		return NULL;
	}

	/* Initialise the ES-EVI list */
	es->es_evi_list = list_new();
	listset_app_node_mem(es->es_evi_list);

	/* Initialise the VTEP list */
	es->es_vtep_list = list_new();
	listset_app_node_mem(es->es_vtep_list);
	es->es_vtep_list->cmp = zebra_evpn_es_vtep_cmp;

	/* mac entries associated with the ES */
	es->mac_list = list_new();
	listset_app_node_mem(es->mac_list);

	/* reserve a NHG  */
	es->nhg_id = zebra_evpn_nhid_alloc(true);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s nhg 0x%x new", es->esi_str, es->nhg_id);

	return es;
}

/* Free a given ES -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static struct zebra_evpn_es *zebra_evpn_es_free(struct zebra_evpn_es *es)
{
	/* If the ES has a local or remote reference it cannot be freed.
	 * Free is also prevented if there are MAC entries referencing
	 * it.
	 */
	if ((es->flags & (ZEBRA_EVPNES_LOCAL | ZEBRA_EVPNES_REMOTE)) ||
			listcount(es->mac_list))
		return es;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s free", es->esi_str);

	/* If the NHG is still installed uninstall it and free the id */
	if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) {
		es->flags &= ~ZEBRA_EVPNES_NHG_ACTIVE;
		kernel_del_mac_nhg(es->nhg_id);
	}
	zebra_evpn_nhid_free(es->nhg_id);

	/* cleanup resources maintained against the ES */
	list_delete(&es->es_evi_list);
	list_delete(&es->es_vtep_list);
	list_delete(&es->mac_list);

	/* remove from the VNI-ESI rb tree */
	RB_REMOVE(zebra_es_rb_head, &zmh_info->es_rb_tree, es);

	XFREE(MTYPE_ZES, es);

	return NULL;
}

/* Inform BGP about local ES addition */
static int zebra_evpn_es_send_add_to_client(struct zebra_evpn_es *es)
{
	struct zserv *client;
	struct stream *s;
	uint8_t oper_up;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_LOCAL_ES_ADD, zebra_vrf_get_evpn_id());
	stream_put(s, &es->esi, sizeof(esi_t));
	stream_put_ipv4(s, zmh_info->es_originator_ip.s_addr);
	oper_up = !!(es->flags & ZEBRA_EVPNES_OPER_UP);
	stream_putc(s, oper_up);
	stream_putw(s, es->df_pref);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("send add local es %s %s active %u df_pref %u to %s",
				es->esi_str,
				inet_ntoa(zmh_info->es_originator_ip),
				oper_up, es->df_pref,
				zebra_route_string(client->proto));

	client->local_es_add_cnt++;
	return zserv_send_message(client, s);
}

/* Inform BGP about local ES deletion */
static int zebra_evpn_es_send_del_to_client(struct zebra_evpn_es *es)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_LOCAL_ES_DEL, zebra_vrf_get_evpn_id());
	stream_put(s, &es->esi, sizeof(esi_t));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("send del local es %s to %s", es->esi_str,
				zebra_route_string(client->proto));

	client->local_es_del_cnt++;
	return zserv_send_message(client, s);
}

/* XXX - call any time ZEBRA_EVPNES_LOCAL gets set or cleared */
static void zebra_evpn_es_re_eval_send_to_client(struct zebra_evpn_es *es,
		bool es_evi_re_reval)
{
	bool old_ready;
	bool new_ready;
	struct listnode *node;
	struct zebra_evpn_es_evi *es_evi;

	old_ready = !!(es->flags & ZEBRA_EVPNES_READY_FOR_BGP);

	if ((es->flags & ZEBRA_EVPNES_LOCAL) &&
			zmh_info->es_originator_ip.s_addr)
		es->flags |= ZEBRA_EVPNES_READY_FOR_BGP;
	else
		es->flags &= ~ZEBRA_EVPNES_READY_FOR_BGP;

	new_ready = !!(es->flags & ZEBRA_EVPNES_READY_FOR_BGP);
	if (old_ready == new_ready)
		return;

	if (new_ready)
		zebra_evpn_es_send_add_to_client(es);
	else
		zebra_evpn_es_send_del_to_client(es);

	/* re-eval associated EVIs */
	if (es_evi_re_reval) {
		for (ALL_LIST_ELEMENTS_RO(es->es_evi_list, node, es_evi)) {
			if (!(es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL))
				continue;
			zebra_evpn_es_evi_re_eval_send_to_client(es_evi);
		}
	}
}

void zebra_evpn_es_send_all_to_client(bool add)
{
	struct listnode *es_node;
	struct listnode *evi_node;
	struct zebra_evpn_es *es;
	struct zebra_evpn_es_evi *es_evi;

	if (!zmh_info)
		return;

	for (ALL_LIST_ELEMENTS_RO(zmh_info->local_es_list, es_node, es)) {
		if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP) {
			if (add)
				zebra_evpn_es_send_add_to_client(es);
			for (ALL_LIST_ELEMENTS_RO(es->es_evi_list,
						evi_node, es_evi)) {
				if (!(es_evi->flags &
					ZEBRA_EVPNES_EVI_READY_FOR_BGP))
					continue;

				if (add)
					zebra_evpn_es_evi_send_to_client(
						es, es_evi->zevpn,
						true /* add */);
				else
					zebra_evpn_es_evi_send_to_client(
						es, es_evi->zevpn,
						false /* add */);
			}
			if (!add)
				zebra_evpn_es_send_del_to_client(es);
		}
	}
}

/* walk the vlan bitmap associated with the zif and create or delete
 * es_evis for all vlans associated with a VNI.
 * XXX: This API is really expensive. optimize later if possible.
 */
static void zebra_evpn_es_setup_evis(struct zebra_evpn_es *es)
{
	struct zebra_if *zif = es->zif;
	uint16_t vid;
	struct zebra_evpn_access_bd *acc_bd;


	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX) {
		acc_bd = zebra_evpn_acc_vl_find(vid);
		if (acc_bd->zevpn)
			zebra_evpn_local_es_evi_add(es, acc_bd->zevpn);
	}
}

static void zebra_evpn_es_local_mac_update(struct zebra_evpn_es *es,
		bool force_clear_static)
{
	zebra_mac_t *mac;
	struct listnode	*node;

	for (ALL_LIST_ELEMENTS_RO(es->mac_list, node, mac)) {
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE)) {
			zebra_evpn_sync_mac_dp_install(
				mac, false /* set_inactive */,
				force_clear_static, __func__);
		}
	}
}

void zebra_evpn_es_local_br_port_update(struct zebra_if *zif)
{
	struct zebra_evpn_es *es = zif->es_info.es;
	bool old_br_port = !!(es->flags & ZEBRA_EVPNES_BR_PORT);
	bool new_br_port;

	if (zif->brslave_info.bridge_ifindex != IFINDEX_INTERNAL)
		es->flags |= ZEBRA_EVPNES_BR_PORT;
	else
		es->flags &= ~ZEBRA_EVPNES_BR_PORT;

	new_br_port = !!(es->flags & ZEBRA_EVPNES_BR_PORT);
	if (old_br_port == new_br_port)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s br_port change old %u new %u",
				es->esi_str, old_br_port, new_br_port);

	/* update the dataplane br_port attrs */
	if (new_br_port &&
			zebra_evpn_es_br_port_dplane_update_needed(es))
		zebra_evpn_es_br_port_dplane_update(es, __func__);
}

static void zebra_evpn_es_local_info_set(struct zebra_evpn_es *es,
		struct zebra_if *zif)
{
	if (es->flags & ZEBRA_EVPNES_LOCAL)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("local es %s add; nhg 0x%x if %s",
				es->esi_str, es->nhg_id, zif->ifp->name);

	es->flags |= ZEBRA_EVPNES_LOCAL;
	listnode_init(&es->local_es_listnode, es);
	listnode_add(zmh_info->local_es_list, &es->local_es_listnode);

	/* attach es to interface */
	zif->es_info.es = es;
	es->df_pref = zif->es_info.df_pref ?
		zif->es_info.df_pref : EVPN_MH_DF_PREF_DEFAULT;

	/* attach interface to es */
	es->zif = zif;
	if (if_is_operative(zif->ifp))
		es->flags |= ZEBRA_EVPNES_OPER_UP;

	if (zif->brslave_info.bridge_ifindex != IFINDEX_INTERNAL)
		es->flags |= ZEBRA_EVPNES_BR_PORT;

	/* setup base-vni if one doesn't already exist; the ES will get sent
	 * to BGP as a part of that process
	 */
	if (!zmh_info->es_base_evpn)
		zebra_evpn_es_get_one_base_evpn();
	else
		/* send notification to bgp */
		zebra_evpn_es_re_eval_send_to_client(es,
			false /* es_evi_re_reval */);

	/* See if the local VTEP can function as DF on the ES */
	if (!zebra_evpn_es_run_df_election(es, __func__)) {
		/* check if the dplane entry needs to be re-programmed as a
		 * result of some thing other than DF status change
		 */
		if (zebra_evpn_es_br_port_dplane_update_needed(es))
			zebra_evpn_es_br_port_dplane_update(es, __func__);
	}


	/* Setup ES-EVIs for all VxLAN stretched VLANs associated with
	 * the zif
	 */
	zebra_evpn_es_setup_evis(es);
	/* if there any local macs referring to the ES as dest we
	 * need to set the static reference on them if the MAC is
	 * synced from an ES peer
	 */
	zebra_evpn_es_local_mac_update(es,
			false /* force_clear_static */);
}

static void zebra_evpn_es_local_info_clear(struct zebra_evpn_es *es)
{
	struct zebra_if *zif;
	bool dplane_updated = false;

	if (!(es->flags & ZEBRA_EVPNES_LOCAL))
		return;

	es->flags &= ~(ZEBRA_EVPNES_LOCAL |
					ZEBRA_EVPNES_READY_FOR_BGP);

	/* remove the DF filter */
	dplane_updated = zebra_evpn_es_run_df_election(es, __func__);

	/* if there any local macs referring to the ES as dest we
	 * need to clear the static reference on them
	 */
	zebra_evpn_es_local_mac_update(es,
			true /* force_clear_static */);

	/* flush the BUM filters and backup NHG */
	if (!dplane_updated)
		zebra_evpn_es_br_port_dplane_clear(es);

	/* clear the es from the parent interface */
	zif = es->zif;
	zif->es_info.es = NULL;
	es->zif = NULL;

	/* clear all local flags associated with the ES */
	es->flags &= ~(ZEBRA_EVPNES_OPER_UP | ZEBRA_EVPNES_BR_PORT);

	/* remove from the ES list */
	list_delete_node(zmh_info->local_es_list, &es->local_es_listnode);

	/* free up the ES if there is no remote reference */
	es = zebra_evpn_es_free(es);
}

/* Delete an ethernet segment and inform BGP */
static void zebra_evpn_local_es_del(struct zebra_evpn_es *es)
{
	struct zebra_evpn_es_evi *es_evi;
	struct listnode *node = NULL;
	struct listnode *nnode = NULL;
	struct zebra_if *zif;

	if (!CHECK_FLAG(es->flags, ZEBRA_EVPNES_LOCAL))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES) {
		zif = es->zif;
		zlog_debug("local es %s del; nhg 0x%x if %s",
				es->esi_str, es->nhg_id,
				zif ? zif->ifp->name : "-");
	}

	/* remove all ES-EVIs associated with the ES */
	for (ALL_LIST_ELEMENTS(es->es_evi_list, node, nnode, es_evi))
		zebra_evpn_local_es_evi_do_del(es_evi);

	/* send a del if the ES had been sent to BGP earlier */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_del_to_client(es);

	zebra_evpn_es_local_info_clear(es);
}

/* eval remote info associated with the ES */
static void zebra_evpn_es_remote_info_re_eval(struct zebra_evpn_es *es)
{
	/* if there are remote VTEPs the ES-EVI is classified as "remote" */
	if (listcount(es->es_vtep_list)) {
		if (!(es->flags & ZEBRA_EVPNES_REMOTE)) {
			es->flags |= ZEBRA_EVPNES_REMOTE;
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
				zlog_debug("remote es %s add; nhg 0x%x",
						es->esi_str, es->nhg_id);
		}
	} else {
		if (es->flags & ZEBRA_EVPNES_REMOTE) {
			es->flags &= ~ZEBRA_EVPNES_REMOTE;
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
				zlog_debug("remote es %s del; nhg 0x%x",
						es->esi_str, es->nhg_id);
			zebra_evpn_es_free(es);
		}
	}
}

/* A new local es is created when a local-es-id and sysmac is configured
 * against an interface.
 */
static int zebra_evpn_local_es_update(struct zebra_if *zif, uint32_t lid,
		struct ethaddr *sysmac)
{
	struct zebra_evpn_es *old_es = zif->es_info.es;
	struct zebra_evpn_es *es;
	esi_t esi;
	int offset = 0;
	int field_bytes = 0;

	/* Complete config of the ES-ID bootstraps the ES */
	if (!lid || is_zero_mac(sysmac)) {
		/* if in ES is attached to zif delete it */
		if (old_es)
			zebra_evpn_local_es_del(old_es);
		return 0;
	}

	/* build 10-byte type-3-ESI -
	 * Type(1-byte), MAC(6-bytes), ES-LID (3-bytes)
	 */
	field_bytes = 1;
	esi.val[offset] = ESI_TYPE_MAC;
	offset += field_bytes;

	field_bytes = 6;
	memcpy(&esi.val[offset], (uint8_t *)sysmac, field_bytes);
	offset += field_bytes;

	esi.val[offset++] = (uint8_t)(lid >> 16);
	esi.val[offset++] = (uint8_t)(lid >> 8);
	esi.val[offset++] = (uint8_t)lid;

	if (old_es && !memcmp(&old_es->esi, &esi, sizeof(esi_t)))
		/* dup - nothing to be done */
		return 0;

	/* release the old_es against the zif */
	if (old_es)
		zebra_evpn_local_es_del(old_es);

	es = zebra_evpn_es_find(&esi);
	if (es) {
		/* if it exists against another interface flag an error */
		if (es->zif && es->zif != zif)
			return -1;
	} else {
		/* create new es */
		es = zebra_evpn_es_new(&esi);
	}

	zebra_evpn_es_local_info_set(es, zif);

	return 0;
}

static int zebra_evpn_remote_es_del(esi_t *esi, struct in_addr vtep_ip)
{
	char buf[ESI_STR_LEN];
	struct zebra_evpn_es *es;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("remote es %s vtep %s del",
				esi_to_str(esi, buf, sizeof(buf)),
				inet_ntoa(vtep_ip));

	es = zebra_evpn_es_find(esi);
	if (!es) {
		/* XXX - error log */
		return -1;
	}

	zebra_evpn_es_vtep_del(es, vtep_ip);
	zebra_evpn_es_remote_info_re_eval(es);

	return 0;
}

/* force delete a remote ES on the way down */
static void zebra_evpn_remote_es_flush(struct zebra_evpn_es *es)
{
	struct zebra_evpn_es_vtep *es_vtep;
	struct listnode	*node;
	struct listnode	*nnode;

	for (ALL_LIST_ELEMENTS(es->es_vtep_list, node, nnode, es_vtep)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es %s vtep %s flush",
					es->esi_str,
					inet_ntoa(es_vtep->vtep_ip));
		zebra_evpn_es_vtep_free(es_vtep);
		zebra_evpn_es_remote_info_re_eval(es);
	}
}

static int zebra_evpn_remote_es_add(esi_t *esi, struct in_addr vtep_ip,
		bool esr_rxed, uint8_t df_alg, uint16_t df_pref)
{
	char buf[ESI_STR_LEN];
	struct zebra_evpn_es *es;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("remote es %s vtep %s add %s df_alg %d df_pref %d",
				esi_to_str(esi, buf, sizeof(buf)),
				inet_ntoa(vtep_ip),
				esr_rxed ? "esr" : "",
				df_alg, df_pref);

	es = zebra_evpn_es_find(esi);
	if (!es) {
		es = zebra_evpn_es_new(esi);
		if (!es) {
			/* XXX - error log */
			return -1;
		}
	}

	zebra_evpn_es_vtep_add(es, vtep_ip, esr_rxed, df_alg, df_pref);
	zebra_evpn_es_remote_info_re_eval(es);

	return 0;
}

void zebra_evpn_proc_remote_es(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct in_addr vtep_ip;
	esi_t esi;

	if (!is_evpn_enabled()) {
		zlog_debug(
				"%s: EVPN not enabled yet we received a es_add zapi call",
				__PRETTY_FUNCTION__);
		return;
	}

	memset(&esi, 0, sizeof(esi_t));
	s = msg;

	stream_get(&esi, s, sizeof(esi_t));
	vtep_ip.s_addr = stream_get_ipv4(s);

	if (hdr->command == ZEBRA_REMOTE_ES_VTEP_ADD) {
		uint32_t zapi_flags;
		uint8_t df_alg;
		uint16_t df_pref;
		bool esr_rxed;

		zapi_flags = stream_getl(s);
		esr_rxed = (zapi_flags & ZAPI_ES_VTEP_FLAG_ESR_RXED) ?
			true : false;
		df_alg = stream_getc(s);
		df_pref = stream_getw(s);
		zebra_evpn_remote_es_add(&esi, vtep_ip, esr_rxed,
				df_alg, df_pref);
	} else {
		zebra_evpn_remote_es_del(&esi, vtep_ip);
	}
}

void zebra_evpn_es_mac_deref_entry(zebra_mac_t *mac)
{
	struct zebra_evpn_es *es = mac->es;

	mac->es = NULL;
	if (!es)
		return;

	list_delete_node(es->mac_list, &mac->es_listnode);
	if (!listcount(es->mac_list))
		zebra_evpn_es_free(es);
}

/* Associate a MAC entry with a local or remote ES. Returns false if there
 * was no ES change.
 */
bool zebra_evpn_es_mac_ref_entry(zebra_mac_t *mac, struct zebra_evpn_es *es)
{
	if (mac->es == es)
		return false;

	if (mac->es)
		zebra_evpn_es_mac_deref_entry(mac);

	if (!es)
		return true;

	mac->es = es;
	listnode_init(&mac->es_listnode, mac);
	listnode_add(es->mac_list, &mac->es_listnode);

	return true;
}

bool zebra_evpn_es_mac_ref(zebra_mac_t *mac, esi_t *esi)
{
	struct zebra_evpn_es *es;

	es = zebra_evpn_es_find(esi);
	if (!es) {
		/* If non-zero esi remove the mac entry */
		if (memcmp(esi, zero_esi, sizeof(esi_t))) {
			es = zebra_evpn_es_new(esi);
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
				zlog_debug("auto es %s add on mac ref",
						es->esi_str);
		}
	}

	return zebra_evpn_es_mac_ref_entry(mac, es);
}

/* Inform BGP about local ES-EVI add or del */
static int zebra_evpn_es_evi_send_to_client(struct zebra_evpn_es *es,
		zebra_evpn_t *zevpn, bool add)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s,
			add ? ZEBRA_LOCAL_ES_EVI_ADD : ZEBRA_LOCAL_ES_EVI_DEL,
			zebra_vrf_get_evpn_id());
	stream_put(s, &es->esi, sizeof(esi_t));
	stream_putl(s, zevpn->vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("send %s local es %s evi %u to %s",
				add ? "add" : "del",
				es->esi_str, zevpn->vni,
				zebra_route_string(client->proto));

	client->local_es_add_cnt++;
	return zserv_send_message(client, s);
}

/* sysmac part of a local ESI has changed */
static int zebra_evpn_es_sys_mac_update(struct zebra_if *zif,
		struct ethaddr *sysmac)
{
	int rv;

	rv = zebra_evpn_local_es_update(zif, zif->es_info.lid, sysmac);
	if (!rv)
		memcpy(&zif->es_info.sysmac, sysmac, sizeof(struct ethaddr));

	return rv;
}

/* local-ID part of ESI has changed */
static int zebra_evpn_es_lid_update(struct zebra_if *zif, uint32_t lid)
{
	int rv;

	rv = zebra_evpn_local_es_update(zif, lid, &zif->es_info.sysmac);
	if (!rv)
		zif->es_info.lid = lid;

	return rv;
}

void zebra_evpn_es_cleanup(void)
{
	struct zebra_evpn_es *es;
	struct zebra_evpn_es *es_next;

	RB_FOREACH_SAFE(es, zebra_es_rb_head,
			&zmh_info->es_rb_tree, es_next) {
		zebra_evpn_local_es_del(es);
		zebra_evpn_remote_es_flush(es);
	}
}

static void zebra_evpn_es_df_pref_update(struct zebra_if *zif,
		uint16_t df_pref)
{
	struct zebra_evpn_es *es;
	uint16_t tmp_pref;

	if (zif->es_info.df_pref == df_pref)
		return;

	zif->es_info.df_pref = df_pref;
	es = zif->es_info.es;

	if (!es)
		return;

	tmp_pref = zif->es_info.df_pref ?
		zif->es_info.df_pref : EVPN_MH_DF_PREF_DEFAULT;

	if (es->df_pref == tmp_pref)
		return;

	es->df_pref = tmp_pref;
	/* run df election */
	zebra_evpn_es_run_df_election(es, __func__);
	/* notify bgp */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_add_to_client(es);
}


/* Only certain types of access ports can be setup as an Ethernet Segment */
bool zebra_evpn_is_if_es_capable(struct zebra_if *zif)
{
	if (zif->zif_type == ZEBRA_IF_BOND)
		return true;

	/* XXX: allow swpX i.e. a regular ethernet port to be an ES link too */
	return false;
}

void zebra_evpn_if_es_print(struct vty *vty, struct zebra_if *zif)
{
	char buf[ETHER_ADDR_STRLEN];

	if (zif->es_info.lid || !is_zero_mac(&zif->es_info.sysmac))
		vty_out(vty, "  EVPN MH: ES id %u ES sysmac %s\n",
				zif->es_info.lid,
				prefix_mac2str(&zif->es_info.sysmac,
					buf, sizeof(buf)));
}

void zebra_evpn_es_if_oper_state_change(struct zebra_if *zif, bool up)
{
	struct zebra_evpn_es *es = zif->es_info.es;
	bool old_up = !!(es->flags & ZEBRA_EVPNES_OPER_UP);

	if (old_up == up)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s state changed to %s ",
				es->esi_str,
				up ? "up" : "down");
	if (up)
		es->flags |= ZEBRA_EVPNES_OPER_UP;
	else
		es->flags &= ~ZEBRA_EVPNES_OPER_UP;

	zebra_evpn_es_run_df_election(es, __func__);

	/* inform BGP of the ES oper state change */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_add_to_client(es);
}

static char *zebra_evpn_es_vtep_str(char *vtep_str,
		struct zebra_evpn_es *es)
{
	struct zebra_evpn_es_vtep *zvtep;
	struct listnode	*node;
	bool first = true;

	vtep_str[0] = '\0';
	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, zvtep)) {
		if (first) {
			first = false;
			sprintf(vtep_str + strlen(vtep_str), "%s",
					inet_ntoa(zvtep->vtep_ip));
		} else {
			sprintf(vtep_str + strlen(vtep_str), ",%s",
					inet_ntoa(zvtep->vtep_ip));
		}
	}
	return vtep_str;
}

static void zebra_evpn_es_show_entry(struct vty *vty,
		struct zebra_evpn_es *es, json_object *json)
{
	char type_str[4];
	char vtep_str[ES_VTEP_LIST_STR_SZ];

	if (json) {
		/* XXX */
	} else {
		type_str[0] = '\0';
		if (es->flags & ZEBRA_EVPNES_LOCAL)
			strcpy(type_str + strlen(type_str), "L");
		if (es->flags & ZEBRA_EVPNES_REMOTE)
			strcpy(type_str + strlen(type_str), "R");
		if (es->flags & ZEBRA_EVPNES_NON_DF)
			strcpy(type_str + strlen(type_str), "N");

		zebra_evpn_es_vtep_str(vtep_str, es);

		vty_out(vty, "%-30s %-4s %-21s %s\n",
				es->esi_str, type_str,
				es->zif ? es->zif->ifp->name : "-",
				vtep_str);
	}
}

static void zebra_evpn_es_show_entry_detail(struct vty *vty,
		struct zebra_evpn_es *es, json_object *json)
{
	char type_str[80];
	char alg_buf[EVPN_DF_ALG_STR_LEN];
	struct zebra_evpn_es_vtep *es_vtep;
	struct listnode	*node;

	if (json) {
		/* XXX */
	} else {
		type_str[0] = '\0';
		if (es->flags & ZEBRA_EVPNES_LOCAL)
			strcpy(type_str + strlen(type_str), "Local");
		if (es->flags & ZEBRA_EVPNES_REMOTE) {
			if (strlen(type_str))
				strcpy(type_str + strlen(type_str), ",");
			strcpy(type_str + strlen(type_str), "Remote");
		}

		vty_out(vty, "ESI: %s\n", es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " Interface: %s\n",
				(es->zif) ?
				es->zif->ifp->name : "-");
		if (es->flags & ZEBRA_EVPNES_LOCAL) {
			vty_out(vty, " State: %s\n",
					(es->flags & ZEBRA_EVPNES_OPER_UP) ?
					"up" : "down");
			vty_out(vty, " Bridge port: %s\n",
					(es->flags & ZEBRA_EVPNES_BR_PORT) ?
					"yes" : "no");
		}
		vty_out(vty, " Ready for BGP: %s\n",
				(es->flags & ZEBRA_EVPNES_READY_FOR_BGP) ?
				"yes" : "no");
		vty_out(vty, " VNI Count: %d\n", listcount(es->es_evi_list));
		vty_out(vty, " MAC Count: %d\n", listcount(es->mac_list));
		vty_out(vty, " DF: status: %s preference: %u\n",
				(es->flags & ZEBRA_EVPNES_NON_DF) ?
				"non-df" : "df", es->df_pref);
		vty_out(vty, " Nexthop group: 0x%x\n", es->nhg_id);
		vty_out(vty, " VTEPs:\n");
		for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
			vty_out(vty, "     %s",
					inet_ntoa(es_vtep->vtep_ip));
			if (es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR)
				vty_out(vty, " df_alg: %s df_pref: %d",
					evpn_es_df_alg2str(es_vtep->df_alg,
						alg_buf, sizeof(alg_buf)),
					es_vtep->df_pref);
			vty_out(vty, " nh: 0x%x\n",
					es_vtep->nh_id);
		}

		vty_out(vty, "\n");
	}
}

void zebra_evpn_es_show(struct vty *vty, bool uj)
{
	struct zebra_evpn_es *es;
	json_object *json = NULL;

	if (uj) {
		/* XXX */
	} else {
		vty_out(vty, "Type: L local, R remote, N non-DF\n");
		vty_out(vty, "%-30s %-4s %-21s %s\n",
				"ESI", "Type", "ES-IF", "VTEPs");
	}

	RB_FOREACH(es, zebra_es_rb_head, &zmh_info->es_rb_tree)
		zebra_evpn_es_show_entry(vty, es, json);
}

void zebra_evpn_es_show_detail(struct vty *vty, bool uj)
{
	struct zebra_evpn_es *es;
	json_object *json = NULL;

	RB_FOREACH(es, zebra_es_rb_head, &zmh_info->es_rb_tree)
		zebra_evpn_es_show_entry_detail(vty, es, json);
}

void zebra_evpn_es_show_esi(struct vty *vty, bool uj, esi_t *esi)
{
	struct zebra_evpn_es *es;
	char esi_str[ESI_STR_LEN];
	json_object *json = NULL;

	es = zebra_evpn_es_find(esi);

	if (!es) {
		esi_to_str(esi, esi_str, sizeof(esi_str));
		vty_out(vty, "ESI %s does not exist\n", esi_str);
		return;
	}

	zebra_evpn_es_show_entry_detail(vty, es, json);
}

int zebra_evpn_mh_if_write(struct vty *vty, struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	char buf[ETHER_ADDR_STRLEN];

	if (zif->es_info.lid)
		vty_out(vty, " evpn mh es-id %u\n", zif->es_info.lid);

	if (!is_zero_mac(&zif->es_info.sysmac))
		vty_out(vty, " evpn mh es-sys-mac %s\n",
				prefix_mac2str(&zif->es_info.sysmac,
					buf, sizeof(buf)));

	if (zif->es_info.df_pref)
		vty_out(vty, " evpn mh es-df-pref %u\n",
				zif->es_info.df_pref);

	return 0;
}

#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_evpn_mh_clippy.c"
#endif
/* CLI for configuring DF preference part for an ES */
DEFPY(zebra_evpn_es_pref,
      zebra_evpn_es_pref_cmd,
      "[no$no] evpn mh es-df-pref [(1-65535)$df_pref]",
      NO_STR
      "EVPN\n"
      EVPN_MH_VTY_STR
      "preference value used for DF election\n"
      "ID\n"
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct zebra_if *zif;

	zif = ifp->info;

	if (no) {
		zebra_evpn_es_df_pref_update(zif, 0);
	} else {
		if (!zebra_evpn_is_if_es_capable(zif)) {
			vty_out(vty,
				"%%DF preference cannot be associated with this interface type\n");
			return CMD_WARNING;
		}
		zebra_evpn_es_df_pref_update(zif, df_pref);
	}
	return CMD_SUCCESS;
}

/* CLI for setting up sysmac part of ESI on an access port */
DEFPY(zebra_evpn_es_sys_mac,
      zebra_evpn_es_sys_mac_cmd,
      "[no$no] evpn mh es-sys-mac [X:X:X:X:X:X$mac]",
      NO_STR
      "EVPN\n"
      EVPN_MH_VTY_STR
      "Ethernet segment system MAC\n"
      MAC_STR
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct zebra_if *zif;
	int ret = 0;

	zif = ifp->info;

	if (no) {
		static struct ethaddr zero_mac;

		ret = zebra_evpn_es_sys_mac_update(zif, &zero_mac);
		if (ret == -1) {
			vty_out(vty, "%%Failed to clear ES sysmac\n");
			return CMD_WARNING;
		}
	} else {

		if (!zebra_evpn_is_if_es_capable(zif)) {
			vty_out(vty,
				"%%ESI cannot be associated with this interface type\n");
			return CMD_WARNING;
		}

		if  (!mac || is_zero_mac(&mac->eth_addr)) {
			vty_out(vty, "%%ES sysmac value is invalid\n");
			return CMD_WARNING;
		}

		ret = zebra_evpn_es_sys_mac_update(zif, &mac->eth_addr);
		if (ret == -1) {
			vty_out(vty, "%%ESI already exists on a different interface\n");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

/* CLI for setting up local-ID part of ESI on an access port */
DEFPY(zebra_evpn_es_id,
      zebra_evpn_es_id_cmd,
      "[no$no] evpn mh es-id [(1-16777215)$es_lid]",
      NO_STR
      "EVPN\n"
      EVPN_MH_VTY_STR
      "Ethernet segment local identifier\n"
      "ID\n"
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct zebra_if *zif;
	int ret;

	zif = ifp->info;

	if (no) {
		ret = zebra_evpn_es_lid_update(zif, 0);
		if (ret == -1) {
			vty_out(vty, "%%Failed to clear ES local id\n");
			return CMD_WARNING;
		}
	} else {
		if (!zebra_evpn_is_if_es_capable(zif)) {
			vty_out(vty,
				"%%ESI cannot be associated with this interface type\n");
			return CMD_WARNING;
		}

		if  (!es_lid) {
			vty_out(vty, "%%Specify local ES ID\n");
			return CMD_WARNING;
		}
		ret = zebra_evpn_es_lid_update(zif, es_lid);
		if (ret == -1) {
			vty_out(vty,
				"%%ESI already exists on a different interface\n");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

/*****************************************************************************/
/* A base L2-VNI is maintained to derive parameters such as ES originator-IP.
 * XXX: once single vxlan device model becomes available this will not be
 * necessary
 */
/* called when a new vni is added or becomes oper up or becomes a bridge port */
void zebra_evpn_es_set_base_evpn(zebra_evpn_t *zevpn)
{
	struct listnode *node;
	struct zebra_evpn_es *es;

	if (zmh_info->es_base_evpn) {
		if (zmh_info->es_base_evpn != zevpn) {
			/* unrelated EVPN; ignore it */
			return;
		}
		/* check if the local vtep-ip has changed */
	} else {
		/* check if the EVPN can be used as base EVPN */
		if (!zebra_evpn_send_to_client_ok(zevpn))
			return;

		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es base vni set to %d",
					zevpn->vni);
		zmh_info->es_base_evpn = zevpn;
	}

	/* update local VTEP-IP */
	if (zmh_info->es_originator_ip.s_addr ==
			zmh_info->es_base_evpn->local_vtep_ip.s_addr)
		return;

	zmh_info->es_originator_ip.s_addr =
		zmh_info->es_base_evpn->local_vtep_ip.s_addr;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es originator ip set to %s",
			inet_ntoa(zmh_info->es_base_evpn->local_vtep_ip));

	/* if originator ip changes we need to update bgp */
	for (ALL_LIST_ELEMENTS_RO(zmh_info->local_es_list, node, es)) {
		zebra_evpn_es_run_df_election(es, __func__);

		if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
			zebra_evpn_es_send_add_to_client(es);
		else
			zebra_evpn_es_re_eval_send_to_client(es,
					true /* es_evi_re_reval */);
	}
}

/* called when a vni is removed or becomes oper down or is removed from a
 * bridge
 */
void zebra_evpn_es_clear_base_evpn(zebra_evpn_t *zevpn)
{
	struct listnode *node;
	struct zebra_evpn_es *es;

	if (zmh_info->es_base_evpn != zevpn)
		return;

	zmh_info->es_base_evpn = NULL;
	/* lost current base EVPN; try to find a new one */
	zebra_evpn_es_get_one_base_evpn();

	/* couldn't locate an eligible base evpn */
	if (!zmh_info->es_base_evpn && zmh_info->es_originator_ip.s_addr) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es originator ip cleared");

		zmh_info->es_originator_ip.s_addr = 0;
		/* lost originator ip */
		for (ALL_LIST_ELEMENTS_RO(zmh_info->local_es_list, node, es)) {
			zebra_evpn_es_re_eval_send_to_client(es,
					true /* es_evi_re_reval */);
		}
	}
}

/* Locate an "eligible" L2-VNI to follow */
static int zebra_evpn_es_get_one_base_evpn_cb(struct hash_bucket *b, void *data)
{
	zebra_evpn_t *zevpn = b->data;

	zebra_evpn_es_set_base_evpn(zevpn);

	if (zmh_info->es_base_evpn)
		return HASHWALK_ABORT;

	return HASHWALK_CONTINUE;
}

/* locate a base_evpn to follow for the purposes of common params like
 * originator IP
 */
static void zebra_evpn_es_get_one_base_evpn(void)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();
	hash_walk(zvrf->evpn_table, zebra_evpn_es_get_one_base_evpn_cb, NULL);
}

/*****************************************************************************/
void zebra_evpn_mh_config_write(struct vty *vty)
{
	if (zmh_info->mac_hold_time != EVPN_MH_MAC_HOLD_TIME_DEF)
		vty_out(vty, "evpn mh mac-holdtime %ld\n",
			zmh_info->mac_hold_time);

	if (zmh_info->neigh_hold_time != EVPN_MH_NEIGH_HOLD_TIME_DEF)
		vty_out(vty, "evpn mh neigh-holdtime %ld\n",
			zmh_info->neigh_hold_time);
}

int zebra_evpn_mh_neigh_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default)
{
	if (set_default)
		zmh_info->neigh_hold_time = EVPN_MH_NEIGH_HOLD_TIME_DEF;

	zmh_info->neigh_hold_time = duration;

	return 0;
}

int zebra_evpn_mh_mac_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default)
{
	if (set_default)
		duration = EVPN_MH_MAC_HOLD_TIME_DEF;

	zmh_info->mac_hold_time = duration;

	return 0;
}

void zebra_evpn_interface_init(void)
{
	install_element(INTERFACE_NODE, &zebra_evpn_es_id_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_es_sys_mac_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_es_pref_cmd);
}

void zebra_evpn_mh_init(void)
{
	zrouter.mh_info = XCALLOC(MTYPE_ZMH_INFO, sizeof(*zrouter.mh_info));

	zmh_info->mac_hold_time = EVPN_MH_MAC_HOLD_TIME_DEF;
	zmh_info->neigh_hold_time = EVPN_MH_NEIGH_HOLD_TIME_DEF;
	/* setup ES tables */
	RB_INIT(zebra_es_rb_head, &zmh_info->es_rb_tree);
	zmh_info->local_es_list = list_new();
	listset_app_node_mem(zmh_info->local_es_list);

	bf_init(zmh_info->nh_id_bitmap, EVPN_NH_ID_MAX);
	bf_assign_zero_index(zmh_info->nh_id_bitmap);

	/* setup broadcast domain tables */
	zmh_info->evpn_vlan_table = hash_create(zebra_evpn_acc_vl_hash_keymake,
			zebra_evpn_acc_vl_cmp, "access VLAN hash table");
}

void zebra_evpn_mh_terminate(void)
{
	list_delete(&zmh_info->local_es_list);

	hash_iterate(zmh_info->evpn_vlan_table,
			zebra_evpn_acc_vl_cleanup_all, NULL);
	hash_free(zmh_info->evpn_vlan_table);
}
