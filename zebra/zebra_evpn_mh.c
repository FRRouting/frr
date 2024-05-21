// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN multihoming code
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Anuradha Karuppiah
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
#include "zebra/if_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_nhg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZACC_BD, "Access Broadcast Domain");
DEFINE_MTYPE_STATIC(ZEBRA, ZES, "Ethernet Segment");
DEFINE_MTYPE_STATIC(ZEBRA, ZES_EVI, "ES info per-EVI");
DEFINE_MTYPE_STATIC(ZEBRA, ZMH_INFO, "MH global info");
DEFINE_MTYPE_STATIC(ZEBRA, ZES_VTEP, "VTEP attached to the ES");
DEFINE_MTYPE_STATIC(ZEBRA, L2_NH, "L2 nexthop");

static void zebra_evpn_es_get_one_base_evpn(void);
static int zebra_evpn_es_evi_send_to_client(struct zebra_evpn_es *es,
					    struct zebra_evpn *zevpn, bool add);
static void zebra_evpn_local_es_del(struct zebra_evpn_es **esp);
static void zebra_evpn_local_es_update(struct zebra_if *zif);
static bool zebra_evpn_es_br_port_dplane_update(struct zebra_evpn_es *es,
						const char *caller);
static void zebra_evpn_mh_update_protodown_es(struct zebra_evpn_es *es,
					      bool resync_dplane);
static void zebra_evpn_mh_clear_protodown_es(struct zebra_evpn_es *es);
static void zebra_evpn_mh_startup_delay_timer_start(const char *rc);

esi_t zero_esi_buf, *zero_esi = &zero_esi_buf;

/*****************************************************************************/
/* Ethernet Segment to EVI association -
 * 1. The ES-EVI entry is maintained as a RB tree per L2-VNI
 * (struct zebra_evpn.es_evi_rb_tree).
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
						       struct zebra_evpn *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;

	es_evi = XCALLOC(MTYPE_ZES_EVI, sizeof(struct zebra_evpn_es_evi));

	es_evi->es = es;
	es_evi->zevpn = zevpn;

	/* insert into the EVPN-ESI rb tree */
	RB_INSERT(zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree, es_evi);

	/* add to the ES's VNI list */
	listnode_init(&es_evi->es_listnode, es_evi);
	listnode_add(es->es_evi_list, &es_evi->es_listnode);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s evi %d new",
				es_evi->es->esi_str, es_evi->zevpn->vni);

	return es_evi;
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
	struct zebra_evpn *zevpn = es_evi->zevpn;

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
struct zebra_evpn_es_evi *zebra_evpn_es_evi_find(struct zebra_evpn_es *es,
						 struct zebra_evpn *zevpn)
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
					struct zebra_evpn *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;

	es_evi = zebra_evpn_es_evi_find(es, zevpn);
	if (es_evi)
		zebra_evpn_local_es_evi_do_del(es_evi);
}

/* If there are any existing MAC entries for this es/zevpn we need
 * to install it in the dataplane.
 *
 * Note: primary purpose of this is to handle es del/re-add windows where
 * sync MAC entries may be added by bgpd before the es-evi membership is
 * created in the dataplane and in zebra
 */
static void zebra_evpn_es_evi_mac_install(struct zebra_evpn_es_evi *es_evi)
{
	struct zebra_mac *mac;
	struct listnode *node;
	struct zebra_evpn_es *es = es_evi->es;

	if (listcount(es->mac_list) && IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("dp-mac install on es %s evi %d add", es->esi_str,
			   es_evi->zevpn->vni);

	for (ALL_LIST_ELEMENTS_RO(es->mac_list, node, mac)) {
		if (mac->zevpn != es_evi->zevpn)
			continue;

		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
			continue;

		zebra_evpn_sync_mac_dp_install(mac, false, false, __func__);
	}
}

/* Create an ES-EVI if it doesn't already exist and tell BGP */
static void zebra_evpn_local_es_evi_add(struct zebra_evpn_es *es,
					struct zebra_evpn *zevpn)
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

		zebra_evpn_es_evi_mac_install(es_evi);
	}
}

static void zebra_evpn_es_evi_show_entry(struct vty *vty,
					 struct zebra_evpn_es_evi *es_evi,
					 json_object *json_array)
{
	char type_str[4];

	if (json_array) {
		json_object *json;
		json_object *json_types;

		/* Separate JSON object for each es-evi entry */
		json = json_object_new_object();

		json_object_string_add(json, "esi", es_evi->es->esi_str);
		json_object_int_add(json, "vni", es_evi->zevpn->vni);
		if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL) {
			json_types = json_object_new_array();
			if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
				json_array_string_add(json_types, "local");
			json_object_object_add(json, "type", json_types);
		}

		/* Add es-evi entry to json array */
		json_object_array_add(json_array, json);
	} else {
		type_str[0] = '\0';
		if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));

		vty_out(vty, "%-8d %-30s %-4s\n",
				es_evi->zevpn->vni, es_evi->es->esi_str,
				type_str);
	}
}

static void
zebra_evpn_es_evi_show_entry_detail(struct vty *vty,
				    struct zebra_evpn_es_evi *es_evi,
				    json_object *json_array)
{
	char type_str[4];

	if (json_array) {
		json_object *json;
		json_object *json_flags;

		/* Separate JSON object for each es-evi entry */
		json = json_object_new_object();

		json_object_string_add(json, "esi", es_evi->es->esi_str);
		json_object_int_add(json, "vni", es_evi->zevpn->vni);
		if (es_evi->flags
		    & (ZEBRA_EVPNES_EVI_LOCAL
		       | ZEBRA_EVPNES_EVI_READY_FOR_BGP)) {
			json_flags = json_object_new_array();
			if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
				json_array_string_add(json_flags, "local");
			if (es_evi->flags & ZEBRA_EVPNES_EVI_READY_FOR_BGP)
				json_array_string_add(json_flags,
						      "readyForBgp");
			json_object_object_add(json, "flags", json_flags);
		}

		/* Add es-evi entry to json array */
		json_object_array_add(json_array, json);
	} else {
		type_str[0] = '\0';
		if (es_evi->flags & ZEBRA_EVPNES_EVI_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));

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

static void zebra_evpn_es_evi_show_one_evpn(struct zebra_evpn *zevpn,
					    struct vty *vty,
					    json_object *json_array, int detail)
{
	struct zebra_evpn_es_evi *es_evi;

	RB_FOREACH(es_evi, zebra_es_evi_rb_head, &zevpn->es_evi_rb_tree) {
		if (detail)
			zebra_evpn_es_evi_show_entry_detail(vty, es_evi,
							    json_array);
		else
			zebra_evpn_es_evi_show_entry(vty, es_evi, json_array);
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
	struct zebra_evpn *zevpn = (struct zebra_evpn *)bucket->data;
	struct evpn_mh_show_ctx *wctx = (struct evpn_mh_show_ctx *)ctxt;

	zebra_evpn_es_evi_show_one_evpn(zevpn, wctx->vty,
			wctx->json, wctx->detail);
}

void zebra_evpn_es_evi_show(struct vty *vty, bool uj, int detail)
{
	json_object *json_array = NULL;
	struct zebra_vrf *zvrf;
	struct evpn_mh_show_ctx wctx;

	zvrf = zebra_vrf_get_evpn();
	if (uj)
		json_array = json_object_new_array();

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_array;
	wctx.detail = detail;

	if (!detail && !json_array) {
		vty_out(vty, "Type: L local, R remote\n");
		vty_out(vty, "%-8s %-30s %-4s\n", "VNI", "ESI", "Type");
	}
	/* Display all L2-VNIs */
	hash_iterate(zvrf->evpn_table, zebra_evpn_es_evi_show_one_evpn_hash_cb,
			&wctx);

	if (uj)
		vty_json(vty, json_array);
}

void zebra_evpn_es_evi_show_vni(struct vty *vty, bool uj, vni_t vni, int detail)
{
	json_object *json_array = NULL;
	struct zebra_evpn *zevpn;

	zevpn = zebra_evpn_lookup(vni);
	if (uj)
		json_array = json_object_new_array();

	if (zevpn) {
		if (!detail && !json_array) {
			vty_out(vty, "Type: L local, R remote\n");
			vty_out(vty, "%-8s %-30s %-4s\n", "VNI", "ESI", "Type");
		}
		zebra_evpn_es_evi_show_one_evpn(zevpn, vty, json_array, detail);
	} else {
		if (!uj)
			vty_out(vty, "VNI %d doesn't exist\n", vni);
	}

	if (uj)
		vty_json(vty, json_array);
}

/* Initialize the ES tables maintained per-L2_VNI */
void zebra_evpn_es_evi_init(struct zebra_evpn *zevpn)
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
void zebra_evpn_es_evi_cleanup(struct zebra_evpn *zevpn)
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
void zebra_evpn_update_all_es(struct zebra_evpn *zevpn)
{
	struct zebra_evpn_es_evi *es_evi;
	struct listnode *node;
	struct interface *vlan_if;
	struct interface *vxlan_if;
	struct zebra_if *vxlan_zif;
	struct zebra_vxlan_vni *vni;

	/* the EVPN is now elgible as a base for EVPN-MH */
	if (zebra_evpn_send_to_client_ok(zevpn))
		zebra_evpn_es_set_base_evpn(zevpn);
	else
		zebra_evpn_es_clear_base_evpn(zevpn);

	for (ALL_LIST_ELEMENTS_RO(zevpn->local_es_evi_list, node, es_evi))
		zebra_evpn_es_evi_re_eval_send_to_client(es_evi);

	/* reinstall SVI MAC */
	vxlan_if = zevpn->vxlan_if;
	if (vxlan_if) {
		vxlan_zif = vxlan_if->info;
		if (if_is_operative(vxlan_if)
		    && vxlan_zif->brslave_info.br_if) {
			vni = zebra_vxlan_if_vni_find(vxlan_zif, zevpn->vni);
			/* VLAN-VNI mappings may not exist */
			if (vni) {
				vlan_if = zvni_map_to_svi(
					vni->access_vlan,
					vxlan_zif->brslave_info.br_if);
				if (vlan_if)
					zebra_evpn_acc_bd_svi_mac_add(vlan_if);
			}
		}
	}
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

	return jhash_2words(acc_bd->vid, acc_bd->bridge_ifindex, 0);
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

	return ((acc_bd1->vid == acc_bd2->vid) &&
		(acc_bd1->bridge_ifindex == acc_bd2->bridge_ifindex));
}

/* Lookup VLAN based broadcast domain */
struct zebra_evpn_access_bd *
zebra_evpn_acc_vl_find_index(vlanid_t vid, ifindex_t bridge_ifindex)
{
	struct zebra_evpn_access_bd *acc_bd;
	struct zebra_evpn_access_bd tmp;

	tmp.vid = vid;
	tmp.bridge_ifindex = bridge_ifindex;
	acc_bd = hash_lookup(zmh_info->evpn_vlan_table, &tmp);

	return acc_bd;
}

/* Lookup VLAN based broadcast domain */
struct zebra_evpn_access_bd *zebra_evpn_acc_vl_find(vlanid_t vid,
						    struct interface *br_if)
{
	return zebra_evpn_acc_vl_find_index(vid, br_if->ifindex);
}

/* A new broadcast domain can be created when a VLAN member or VLAN<=>VxLAN_IF
 * mapping is added.
 */
static struct zebra_evpn_access_bd *
zebra_evpn_acc_vl_new(vlanid_t vid, struct interface *br_if)
{
	struct zebra_evpn_access_bd *acc_bd;
	struct interface *vlan_if;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s access vlan %d bridge %s add", __func__, vid,
			   br_if->name);

	acc_bd = XCALLOC(MTYPE_ZACC_BD, sizeof(struct zebra_evpn_access_bd));

	acc_bd->vid = vid;
	acc_bd->bridge_ifindex = br_if->ifindex;
	acc_bd->bridge_zif = (struct zebra_if *)br_if->info;

	/* Initialize the mbr list */
	acc_bd->mbr_zifs = list_new();

	/* Add to hash */
	(void)hash_get(zmh_info->evpn_vlan_table, acc_bd, hash_alloc_intern);

	/* check if an svi exists for the vlan */
	vlan_if = zvni_map_to_svi(vid, br_if);
	if (vlan_if) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("%s vlan %d bridge %s SVI %s set", __func__,
				   vid, br_if->name, vlan_if->name);
		acc_bd->vlan_zif = vlan_if->info;
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

	if (acc_bd->vlan_zif && acc_bd->zevpn && acc_bd->zevpn->mac_table)
		zebra_evpn_mac_svi_del(acc_bd->vlan_zif->ifp, acc_bd->zevpn);

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

	/* Remove this access_bd from bridge hash table */
	zebra_l2_bridge_if_vlan_access_bd_deref(acc_bd);

	/* if there are no references free the EVI */
	zebra_evpn_acc_vl_free(acc_bd);
}

static struct zebra_evpn_access_bd *
zebra_evpn_acc_bd_alloc_on_ref(vlanid_t vid, struct interface *br_if)
{
	struct zebra_evpn_access_bd *acc_bd = NULL;

	assert(br_if && br_if->info);
	acc_bd = zebra_evpn_acc_vl_new(vid, br_if);
	if (acc_bd)
		/* Add this access_bd to bridge hash table */
		zebra_l2_bridge_if_vlan_access_bd_ref(acc_bd);

	return acc_bd;
}

/* called when a SVI is goes up/down */
void zebra_evpn_acc_bd_svi_set(struct zebra_if *vlan_zif,
			       struct zebra_if *br_zif, bool is_up)
{
	struct zebra_evpn_access_bd *acc_bd;
	uint16_t vid;
	struct zebra_if *tmp_br_zif = br_zif;

	if (!tmp_br_zif) {
		if (!vlan_zif->link || !vlan_zif->link->info)
			return;

		tmp_br_zif = vlan_zif->link->info;
	}

	/* ignore vlan unaware bridges */
	if (!IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(tmp_br_zif))
		return;

	vid = vlan_zif->l2info.vl.vid;
	acc_bd = zebra_evpn_acc_vl_find(vid, tmp_br_zif->ifp);
	if (!acc_bd)
		return;

	if (is_up) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("vlan %d bridge %s SVI %s set", vid,
				   tmp_br_zif->ifp->name, vlan_zif->ifp->name);

		acc_bd->vlan_zif = vlan_zif;
		if (acc_bd->zevpn)
			zebra_evpn_mac_svi_add(acc_bd->vlan_zif->ifp,
					       acc_bd->zevpn);
	} else if (acc_bd->vlan_zif) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("vlan %d bridge %s SVI clear", vid,
				   tmp_br_zif->ifp->name);
		acc_bd->vlan_zif = NULL;
		if (acc_bd->zevpn && acc_bd->zevpn->mac_table)
			zebra_evpn_mac_svi_del(vlan_zif->ifp, acc_bd->zevpn);
	}
}

/* On some events macs are force-flushed. This api can be used to reinstate
 * the svi-mac after such cleanup-events.
 */
void zebra_evpn_acc_bd_svi_mac_add(struct interface *vlan_if)
{
	zebra_evpn_acc_bd_svi_set(vlan_if->info, NULL,
				  if_is_operative(vlan_if));
}

/* called when a EVPN-L2VNI is set or cleared against a BD */
static void zebra_evpn_acc_bd_evpn_set(struct zebra_evpn_access_bd *acc_bd,
				       struct zebra_evpn *zevpn,
				       struct zebra_evpn *old_zevpn)
{
	struct zebra_if *zif;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d bridge %s l2-vni %u set",
			   acc_bd->vid, acc_bd->bridge_zif->ifp->name,
			   zevpn ? zevpn->vni : 0);

	for (ALL_LIST_ELEMENTS_RO(acc_bd->mbr_zifs, node, zif)) {
		if (!zif->es_info.es)
			continue;

		if (zevpn)
			zebra_evpn_local_es_evi_add(zif->es_info.es, zevpn);
		else if (old_zevpn)
			zebra_evpn_local_es_evi_del(zif->es_info.es, old_zevpn);
	}

	if (acc_bd->vlan_zif) {
		if (zevpn)
			zebra_evpn_mac_svi_add(acc_bd->vlan_zif->ifp,
					       acc_bd->zevpn);
		else if (old_zevpn && old_zevpn->mac_table)
			zebra_evpn_mac_svi_del(acc_bd->vlan_zif->ifp,
					       old_zevpn);
	}
}

/* Lookup API for  VxLAN_IF's Bridge, VLAN in EVPN cache */
int zebra_evpn_vl_vxl_bridge_lookup(uint16_t vid, struct zebra_if *vxlan_zif)
{
	struct interface *br_if;
	struct zebra_evpn_access_bd *acc_bd;

	if (!vid)
		return -1;

	br_if = vxlan_zif->brslave_info.br_if;

	if (!br_if)
		return -1;

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);

	if (!acc_bd)
		return 0;

	return 1;
}


/* handle VLAN->VxLAN_IF association */
void zebra_evpn_vl_vxl_ref(uint16_t vid, vni_t vni_id,
			   struct zebra_if *vxlan_zif)
{
	vni_t old_vni;
	struct zebra_evpn_access_bd *acc_bd;
	struct zebra_evpn *old_zevpn;
	struct interface *br_if;

	if (!vid)
		return;

	if (!vni_id)
		return;

	br_if = vxlan_zif->brslave_info.br_if;

	if (!br_if)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
	if (!acc_bd)
		acc_bd = zebra_evpn_acc_bd_alloc_on_ref(vid, br_if);

	old_vni = acc_bd->vni;

	if (vni_id == old_vni)
		return;

	acc_bd->vni = vni_id;
	acc_bd->vxlan_zif = vxlan_zif;

	old_zevpn = acc_bd->zevpn;
	acc_bd->zevpn = zebra_evpn_lookup(vni_id);
	if (acc_bd->zevpn == old_zevpn)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s bridge %s access vlan %d vni %u ref", __func__,
			   br_if->name, acc_bd->vid, vni_id);

	if (old_zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, old_zevpn);

	if (acc_bd->zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, acc_bd->zevpn, NULL);
}

/* handle VLAN->VxLAN_IF deref */
void zebra_evpn_vl_vxl_deref(uint16_t vid, vni_t vni_id,
			     struct zebra_if *vxlan_zif)
{
	struct interface *br_if;
	struct zebra_evpn_access_bd *acc_bd;

	if (!vid)
		return;

	if (!vni_id)
		return;

	br_if = vxlan_zif->brslave_info.br_if;
	if (!br_if)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
	if (!acc_bd)
		return;

	/* clear vxlan_if only if it matches */
	if (acc_bd->vni != vni_id)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d bridge %s vni %u deref", acc_bd->vid,
			   br_if->name, vni_id);

	if (acc_bd->zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, acc_bd->zevpn);

	acc_bd->zevpn = NULL;
	acc_bd->vxlan_zif = NULL;
	acc_bd->vni = 0;

	/* if there are no other references the access_bd can be freed */
	zebra_evpn_acc_bd_free_on_deref(acc_bd);
}

/* handle BridgeIf<->AccessBD cleanup */
void zebra_evpn_access_bd_bridge_cleanup(vlanid_t vid, struct interface *br_if,
					 struct zebra_evpn_access_bd *acc_bd)
{
	struct zebra_evpn *zevpn;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access bd vlan %d bridge %s cleanup", acc_bd->vid,
			   br_if->name);

	zevpn = acc_bd->zevpn;
	if (zevpn)
		zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, zevpn);

	/* cleanup resources maintained against the ES */
	list_delete_all_node(acc_bd->mbr_zifs);

	acc_bd->zevpn = NULL;
	acc_bd->vxlan_zif = NULL;
	acc_bd->vni = 0;
	acc_bd->bridge_zif = NULL;

	/* if there are no other references the access_bd can be freed */
	zebra_evpn_acc_bd_free_on_deref(acc_bd);
}

/* handle EVPN add/del */
void zebra_evpn_vxl_evpn_set(struct zebra_if *zif, struct zebra_evpn *zevpn,
			     bool set)
{
	struct zebra_vxlan_vni *vni;
	struct zebra_evpn_access_bd *acc_bd;
	ifindex_t br_ifindex;

	if (!zif)
		return;

	/* locate access_bd associated with the vxlan device */
	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return;

	/* Use the index as the pointer can be stale (deleted) */
	br_ifindex = zif->brslave_info.bridge_ifindex;
	if (!zif->brslave_info.br_if || br_ifindex == IFINDEX_INTERNAL)
		return;

	acc_bd = zebra_evpn_acc_vl_find_index(vni->access_vlan, br_ifindex);
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
			struct zebra_evpn *old_zevpn = acc_bd->zevpn;
			acc_bd->zevpn = NULL;
			zebra_evpn_acc_bd_evpn_set(acc_bd, NULL, old_zevpn);
		}
	}
}

/* handle addition of new VLAN members */
void zebra_evpn_vl_mbr_ref(uint16_t vid, struct zebra_if *zif)
{
	struct interface *br_if;
	struct zebra_evpn_access_bd *acc_bd;

	if (!vid)
		return;

	br_if = zif->brslave_info.br_if;
	if (!br_if)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
	if (!acc_bd)
		acc_bd = zebra_evpn_acc_bd_alloc_on_ref(vid, br_if);

	if (listnode_lookup(acc_bd->mbr_zifs, zif))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d bridge %s mbr %s ref", vid,
			   br_if->name, zif->ifp->name);

	listnode_add(acc_bd->mbr_zifs, zif);
	if (acc_bd->zevpn && zif->es_info.es)
		zebra_evpn_local_es_evi_add(zif->es_info.es, acc_bd->zevpn);
}

/* handle deletion of VLAN members */
void zebra_evpn_vl_mbr_deref(uint16_t vid, struct zebra_if *zif)
{
	struct interface *br_if;
	struct zebra_evpn_access_bd *acc_bd;
	struct listnode *node;

	if (!vid)
		return;

	br_if = zif->brslave_info.br_if;
	if (!br_if)
		return;

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
	if (!acc_bd)
		return;

	node = listnode_lookup(acc_bd->mbr_zifs, zif);
	if (!node)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("access vlan %d bridge %s mbr %s deref", vid,
			   br_if->name, zif->ifp->name);

	list_delete_node(acc_bd->mbr_zifs, node);

	if (acc_bd->zevpn && zif->es_info.es)
		zebra_evpn_local_es_evi_del(zif->es_info.es, acc_bd->zevpn);

	/* if there are no other references the access_bd can be freed */
	zebra_evpn_acc_bd_free_on_deref(acc_bd);
}

static void zebra_evpn_acc_vl_adv_svi_mac_cb(struct hash_bucket *bucket,
					     void *ctxt)
{
	struct zebra_evpn_access_bd *acc_bd = bucket->data;

	if (acc_bd->vlan_zif && acc_bd->zevpn)
		zebra_evpn_mac_svi_add(acc_bd->vlan_zif->ifp, acc_bd->zevpn);
}

/* called when advertise SVI MAC is enabled on the switch */
static void zebra_evpn_acc_vl_adv_svi_mac_all(void)
{
	hash_iterate(zmh_info->evpn_vlan_table,
		     zebra_evpn_acc_vl_adv_svi_mac_cb, NULL);
}

static void zebra_evpn_acc_vl_json_fill(struct zebra_evpn_access_bd *acc_bd,
					json_object *json, bool detail)
{
	json_object_int_add(json, "vlan", acc_bd->vid);
	if (acc_bd->vxlan_zif)
		json_object_string_add(json, "vxlanIf",
				       acc_bd->vxlan_zif->ifp->name);
	if (acc_bd->zevpn)
		json_object_int_add(json, "vni", acc_bd->zevpn->vni);
	if (acc_bd->mbr_zifs)
		json_object_int_add(json, "memberIfCount",
				    listcount(acc_bd->mbr_zifs));

	if (detail) {
		json_object *json_mbrs;
		json_object *json_mbr;
		struct zebra_if *zif;
		struct listnode *node;


		json_mbrs = json_object_new_array();
		for (ALL_LIST_ELEMENTS_RO(acc_bd->mbr_zifs, node, zif)) {
			json_mbr = json_object_new_object();
			json_object_string_add(json_mbr, "ifName",
					       zif->ifp->name);
			json_object_array_add(json_mbrs, json_mbr);
		}
		json_object_object_add(json, "members", json_mbrs);
	}
}

static void zebra_evpn_acc_vl_show_entry_detail(struct vty *vty,
		struct zebra_evpn_access_bd *acc_bd, json_object *json)
{
	struct zebra_if *zif;
	struct listnode	*node;

	if (json) {
		zebra_evpn_acc_vl_json_fill(acc_bd, json, true);
	} else {
		vty_out(vty, "VLAN: %s.%u\n", acc_bd->bridge_zif->ifp->name,
			acc_bd->vid);
		vty_out(vty, " VxLAN Interface: %s\n",
				acc_bd->vxlan_zif ?
				acc_bd->vxlan_zif->ifp->name : "-");
		vty_out(vty, " SVI: %s\n",
			acc_bd->vlan_zif ? acc_bd->vlan_zif->ifp->name : "-");
		if (acc_bd->zevpn)
			vty_out(vty, " L2-VNI: %d\n", acc_bd->zevpn->vni);
		else {
			vty_out(vty, " L2-VNI: 0\n");
			vty_out(vty, " L3-VNI: %d\n", acc_bd->vni);
		}
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
	if (json) {
		zebra_evpn_acc_vl_json_fill(acc_bd, json, false);
	} else {
		vty_out(vty, "%-5s.%-5u %-15s %-8d %-15s %u\n",
			acc_bd->bridge_zif->ifp->name, acc_bd->vid,
			acc_bd->vlan_zif ? acc_bd->vlan_zif->ifp->name : "-",
			acc_bd->zevpn ? acc_bd->zevpn->vni : 0,
			acc_bd->vxlan_zif ? acc_bd->vxlan_zif->ifp->name : "-",
			listcount(acc_bd->mbr_zifs));
	}
}

static void zebra_evpn_acc_vl_show_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct evpn_mh_show_ctx *wctx = ctxt;
	struct zebra_evpn_access_bd *acc_bd = bucket->data;
	json_object *json = NULL;

	if (wctx->json)
		json = json_object_new_object();
	if (wctx->detail)
		zebra_evpn_acc_vl_show_entry_detail(wctx->vty, acc_bd, json);
	else
		zebra_evpn_acc_vl_show_entry(wctx->vty, acc_bd, json);
	if (json)
		json_object_array_add(wctx->json, json);
}

void zebra_evpn_acc_vl_show(struct vty *vty, bool uj)
{
	struct evpn_mh_show_ctx wctx;
	json_object *json_array = NULL;

	if (uj)
		json_array = json_object_new_array();

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_array;
	wctx.detail = false;

	if (!uj)
		vty_out(vty, "%-12s %-15s %-8s %-15s %s\n", "VLAN", "SVI",
			"L2-VNI", "VXLAN-IF", "# Members");

	hash_iterate(zmh_info->evpn_vlan_table, zebra_evpn_acc_vl_show_hash,
			&wctx);

	if (uj)
		vty_json(vty, json_array);
}

void zebra_evpn_acc_vl_show_detail(struct vty *vty, bool uj)
{
	struct evpn_mh_show_ctx wctx;
	json_object *json_array = NULL;

	if (uj)
		json_array = json_object_new_array();
	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_array;
	wctx.detail = true;

	hash_iterate(zmh_info->evpn_vlan_table, zebra_evpn_acc_vl_show_hash,
			&wctx);

	if (uj)
		vty_json(vty, json_array);
}

void zebra_evpn_acc_vl_show_vid(struct vty *vty, bool uj, vlanid_t vid,
				struct interface *br_if)
{
	json_object *json = NULL;
	struct zebra_evpn_access_bd *acc_bd;

	if (uj)
		json = json_object_new_object();

	acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
	if (acc_bd) {
		zebra_evpn_acc_vl_show_entry_detail(vty, acc_bd, json);
	} else {
		if (!json)
			vty_out(vty, "VLAN %s.%u not present\n", br_if->name,
				vid);
	}

	if (uj)
		vty_json(vty, json);
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
	zebra_evpn_local_es_update(zif);
}

/* handle deletion of an access port by removing it from all associated
 * broadcast domains.
 */
void zebra_evpn_if_cleanup(struct zebra_if *zif)
{
	vlanid_t vid;
	struct zebra_evpn_es *es;

	if (bf_is_inited(zif->vlan_bitmap)) {
		bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX)
		{
			zebra_evpn_vl_mbr_deref(vid, zif);
		}

		bf_free(zif->vlan_bitmap);
	}

	/* Delete associated Ethernet Segment */
	es = zif->es_info.es;
	if (es)
		zebra_evpn_local_es_del(&es);
}

/*****************************************************************************
 * L2 NH/NHG Management
 *   A L2 NH entry is programmed in the kernel for every ES-VTEP entry. This
 * NH is then added to the L2-ECMP-NHG associated with the ES.
 */
static uint32_t zebra_evpn_nhid_alloc(struct zebra_evpn_es *es)
{
	uint32_t id;
	uint32_t nh_id;

	bf_assign_index(zmh_info->nh_id_bitmap, id);

	if (!id)
		return 0;

	if (es) {
		nh_id = id | EVPN_NHG_ID_TYPE_BIT;
		/* Add to NHG hash */
		es->nhg_id = nh_id;
		(void)hash_get(zmh_info->nhg_table, es, hash_alloc_intern);
	} else {
		nh_id = id | EVPN_NH_ID_TYPE_BIT;
	}

	return nh_id;
}

static void zebra_evpn_nhid_free(uint32_t nh_id, struct zebra_evpn_es *es)
{
	uint32_t id = (nh_id & EVPN_NH_ID_VAL_MASK);

	if (!id)
		return;

	if (es) {
		hash_release(zmh_info->nhg_table, es);
		es->nhg_id = 0;
	}

	bf_release_index(zmh_info->nh_id_bitmap, id);
}

static unsigned int zebra_evpn_nh_ip_hash_keymake(const void *p)
{
	const struct zebra_evpn_l2_nh *nh = p;

	return jhash_1word(nh->vtep_ip.s_addr, 0);
}

static bool zebra_evpn_nh_ip_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn_l2_nh *nh1 = p1;
	const struct zebra_evpn_l2_nh *nh2 = p2;

	if (nh1 == NULL && nh2 == NULL)
		return true;

	if (nh1 == NULL || nh2 == NULL)
		return false;

	return (nh1->vtep_ip.s_addr == nh2->vtep_ip.s_addr);
}

static unsigned int zebra_evpn_nhg_hash_keymake(const void *p)
{
	const struct zebra_evpn_es *es = p;

	return jhash_1word(es->nhg_id, 0);
}

static bool zebra_evpn_nhg_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn_es *es1 = p1;
	const struct zebra_evpn_es *es2 = p2;

	if (es1 == NULL && es2 == NULL)
		return true;

	if (es1 == NULL || es2 == NULL)
		return false;

	return (es1->nhg_id == es2->nhg_id);
}

/* Lookup ES using the NHG id associated with it */
static struct zebra_evpn_es *zebra_evpn_nhg_find(uint32_t nhg_id)
{
	struct zebra_evpn_es *es;
	struct zebra_evpn_es tmp;

	tmp.nhg_id = nhg_id;
	es = hash_lookup(zmh_info->nhg_table, &tmp);

	return es;
}

/* Returns TRUE if the NHG is associated with a local ES */
bool zebra_evpn_nhg_is_local_es(uint32_t nhg_id,
				struct zebra_evpn_es **local_es)
{
	struct zebra_evpn_es *es;

	es = zebra_evpn_nhg_find(nhg_id);
	if (es && (es->flags & ZEBRA_EVPNES_LOCAL)) {
		*local_es = es;
		return true;
	}

	*local_es = NULL;
	return false;
}

/* update remote macs associated with the ES */
static void zebra_evpn_nhg_mac_update(struct zebra_evpn_es *es)
{
	struct zebra_mac *mac;
	struct listnode *node;
	bool local_via_nw;

	local_via_nw = zebra_evpn_es_local_mac_via_network_port(es);
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("mac update on es %s nhg %s", es->esi_str,
			   (es->flags & ZEBRA_EVPNES_NHG_ACTIVE)
				   ? "activate"
				   : "de-activate");

	for (ALL_LIST_ELEMENTS_RO(es->mac_list, node, mac)) {
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
		    || (local_via_nw && CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
			&& zebra_evpn_mac_is_static(mac))) {
			if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) {
				if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
					zlog_debug(
						"%smac %pEA install via es %s nhg 0x%x",
						(mac->flags & ZEBRA_MAC_REMOTE)
							? "rem"
							: "local-nw",
						&mac->macaddr, es->esi_str,
						es->nhg_id);
				zebra_evpn_rem_mac_install(
					mac->zevpn, mac, false /*was_static*/);
			} else {
				if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
					zlog_debug(
						"%smac %pEA un-install es %s",
						(mac->flags & ZEBRA_MAC_REMOTE)
							? "rem"
							: "local-nw",
						&mac->macaddr, es->esi_str);
				zebra_evpn_rem_mac_uninstall(mac->zevpn, mac,
							     true /*force*/);
			}
		}
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
		if (!es_vtep->nh)
			continue;

		if (nh_cnt >= ES_VTEP_MAX_CNT)
			break;

		memset(&nh_ids[nh_cnt], 0, sizeof(struct nh_grp));
		nh_ids[nh_cnt].id = es_vtep->nh->nh_id;
		++nh_cnt;
	}

	if (nh_cnt) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_NH) {
			char nh_str[ES_VTEP_LIST_STR_SZ];
			uint32_t i;
			char nh_buf[16];

			nh_str[0] = '\0';
			for (i = 0; i < nh_cnt; ++i) {
				snprintf(nh_buf, sizeof(nh_buf), "%u ",
					 nh_ids[i].id);
				strlcat(nh_str, nh_buf, sizeof(nh_str));
			}
			zlog_debug("es %s nhg %u add %s", es->esi_str,
				   es->nhg_id, nh_str);
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
				zlog_debug("es %s nhg %u del", es->esi_str,
					   es->nhg_id);
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

static void zebra_evpn_es_l2_nh_show_entry(struct zebra_evpn_l2_nh *nh,
					   struct vty *vty,
					   json_object *json_array)
{
	if (json_array) {
		json_object *json = NULL;

		json = json_object_new_object();
		json_object_string_addf(json, "vtep", "%pI4", &nh->vtep_ip);
		json_object_int_add(json, "nhId", nh->nh_id);
		json_object_int_add(json, "refCnt", nh->ref_cnt);

		json_object_array_add(json_array, json);
	} else {
		vty_out(vty, "%-16pI4 %-10u %u\n", &nh->vtep_ip, nh->nh_id,
			nh->ref_cnt);
	}
}

static void zebra_evpn_l2_nh_show_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_evpn_l2_nh *nh = (struct zebra_evpn_l2_nh *)bucket->data;
	struct evpn_mh_show_ctx *wctx = (struct evpn_mh_show_ctx *)ctxt;

	zebra_evpn_es_l2_nh_show_entry(nh, wctx->vty, wctx->json);
}

void zebra_evpn_l2_nh_show(struct vty *vty, bool uj)
{
	struct evpn_mh_show_ctx wctx;
	json_object *json_array = NULL;

	if (uj) {
		json_array = json_object_new_array();
	} else {
		vty_out(vty, "%-16s %-10s %s\n", "VTEP", "NH id", "#ES");
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_array;

	hash_iterate(zmh_info->nh_ip_table, zebra_evpn_l2_nh_show_cb, &wctx);

	if (uj)
		vty_json(vty, json_array);
}

static struct zebra_evpn_l2_nh *zebra_evpn_l2_nh_find(struct in_addr vtep_ip)
{
	struct zebra_evpn_l2_nh *nh;
	struct zebra_evpn_l2_nh tmp;

	tmp.vtep_ip.s_addr = vtep_ip.s_addr;
	nh = hash_lookup(zmh_info->nh_ip_table, &tmp);

	return nh;
}

static struct zebra_evpn_l2_nh *zebra_evpn_l2_nh_alloc(struct in_addr vtep_ip)
{
	struct zebra_evpn_l2_nh *nh;

	nh = XCALLOC(MTYPE_L2_NH, sizeof(*nh));
	nh->vtep_ip = vtep_ip;
	(void)hash_get(zmh_info->nh_ip_table, nh, hash_alloc_intern);

	nh->nh_id = zebra_evpn_nhid_alloc(NULL);
	if (!nh->nh_id) {
		hash_release(zmh_info->nh_ip_table, nh);
		XFREE(MTYPE_L2_NH, nh);
		return NULL;
	}

	/* install the NH in the dataplane */
	kernel_upd_mac_nh(nh->nh_id, nh->vtep_ip);

	return nh;
}

static void zebra_evpn_l2_nh_free(struct zebra_evpn_l2_nh *nh)
{
	/* delete the NH from the dataplane */
	kernel_del_mac_nh(nh->nh_id);

	zebra_evpn_nhid_free(nh->nh_id, NULL);
	hash_release(zmh_info->nh_ip_table, nh);
	XFREE(MTYPE_L2_NH, nh);
}

static void zebra_evpn_l2_nh_es_vtep_ref(struct zebra_evpn_es_vtep *es_vtep)
{
	if (es_vtep->nh)
		return;

	es_vtep->nh = zebra_evpn_l2_nh_find(es_vtep->vtep_ip);
	if (!es_vtep->nh)
		es_vtep->nh = zebra_evpn_l2_nh_alloc(es_vtep->vtep_ip);

	if (!es_vtep->nh) {
		zlog_warn("es %s vtep %pI4 nh ref failed", es_vtep->es->esi_str,
			  &es_vtep->vtep_ip);
		return;
	}

	++es_vtep->nh->ref_cnt;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
		zlog_debug("es %s vtep %pI4 nh %u ref %u", es_vtep->es->esi_str,
			   &es_vtep->vtep_ip, es_vtep->nh->nh_id,
			   es_vtep->nh->ref_cnt);

	/* add the NH to the parent NHG */
	zebra_evpn_nhg_update(es_vtep->es);
}

static void zebra_evpn_l2_nh_es_vtep_deref(struct zebra_evpn_es_vtep *es_vtep)
{
	struct zebra_evpn_l2_nh *nh = es_vtep->nh;

	if (!nh)
		return;

	es_vtep->nh = NULL;
	if (nh->ref_cnt)
		--nh->ref_cnt;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
		zlog_debug("es %s vtep %pI4 nh %u deref %u",
			   es_vtep->es->esi_str, &es_vtep->vtep_ip, nh->nh_id,
			   nh->ref_cnt);

	/* remove the NH from the parent NHG */
	zebra_evpn_nhg_update(es_vtep->es);

	/* uninstall the NH */
	if (!nh->ref_cnt)
		zebra_evpn_l2_nh_free(nh);
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
	zebra_evpn_l2_nh_es_vtep_deref(es_vtep);
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

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s br-port dplane clear", es->esi_str);

	memset(&sph_filters, 0, sizeof(sph_filters));
	dplane_br_port_update(es->zif->ifp, false /* non_df */, 0, sph_filters,
			      0 /* backup_nhg_id */);
	return true;
}

static inline bool
zebra_evpn_es_br_port_dplane_update_needed(struct zebra_evpn_es *es)
{
	return (es->flags & ZEBRA_EVPNES_NON_DF)
	       || (es->flags & ZEBRA_EVPNES_NHG_ACTIVE)
	       || listcount(es->es_vtep_list);
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

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s br-port dplane update by %s", es->esi_str,
			   caller);
	backup_nhg_id = (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) ? es->nhg_id : 0;

	memset(&sph_filters, 0, sizeof(sph_filters));
	if (es->flags & ZEBRA_EVPNES_BYPASS) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug(
				"es %s SPH filter disabled as it is in bypass",
				es->esi_str);
	} else {
		if (listcount(es->es_vtep_list) > ES_VTEP_MAX_CNT) {
			zlog_warn("es %s vtep count %d exceeds filter cnt %d",
				  es->esi_str, listcount(es->es_vtep_list),
				  ES_VTEP_MAX_CNT);
		} else {
			for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node,
						  es_vtep)) {
				if (es_vtep->flags
				    & ZEBRA_EVPNES_VTEP_DEL_IN_PROG)
					continue;
				sph_filters[sph_filter_cnt] = es_vtep->vtep_ip;
				++sph_filter_cnt;
			}
		}
	}

	dplane_br_port_update(es->zif->ifp, !!(es->flags & ZEBRA_EVPNES_NON_DF),
			      sph_filter_cnt, sph_filters, backup_nhg_id);

	return true;
}

/* returns TRUE if dplane entry was updated */
static bool zebra_evpn_es_df_change(struct zebra_evpn_es *es, bool new_non_df,
				    const char *caller, const char *reason)
{
	bool old_non_df;

	old_non_df = !!(es->flags & ZEBRA_EVPNES_NON_DF);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("df-change es %s %s to %s; %s: %s", es->esi_str,
			   old_non_df ? "non-df" : "df",
			   new_non_df ? "non-df" : "df", caller, reason);

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
	if (!(es->flags & ZEBRA_EVPNES_LOCAL)
	    || (es->flags & ZEBRA_EVPNES_BYPASS)
	    || !zmh_info->es_originator_ip.s_addr)
		return zebra_evpn_es_df_change(es, new_non_df, caller,
					       "not-ready");

	/* if oper-state is down DF filtering must be on. when the link comes
	 * up again dataplane should block BUM till FRR has had the chance
	 * to run DF election again
	 */
	if (!(es->flags & ZEBRA_EVPNES_OPER_UP)) {
		new_non_df = true;
		return zebra_evpn_es_df_change(es, new_non_df, caller,
					       "oper-down");
	}

	/* ES was just created; we need to wait for the peers to rx the
	 * our Type-4 routes and for the switch to import the peers' Type-4
	 * routes
	 */
	if (es->df_delay_timer) {
		new_non_df = true;
		return zebra_evpn_es_df_change(es, new_non_df, caller,
					       "df-delay");
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
		if ((es_vtep->df_pref > es->df_pref)
		    || ((es_vtep->df_pref == es->df_pref)
			&& (es_vtep->vtep_ip.s_addr
			    < zmh_info->es_originator_ip.s_addr))) {
			new_non_df = true;
			break;
		}
	}

	return zebra_evpn_es_df_change(es, new_non_df, caller, "elected");
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
			zlog_debug("es %s vtep %pI4 add",
					es->esi_str, &vtep_ip);
		es_vtep = zebra_evpn_es_vtep_new(es, vtep_ip);
		/* update the L2-NHG associated with the ES */
		zebra_evpn_l2_nh_es_vtep_ref(es_vtep);
	}

	old_esr_rxed = !!(es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR);
	if ((old_esr_rxed != esr_rxed) || (es_vtep->df_alg != df_alg)
	    || (es_vtep->df_pref != df_pref)) {
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
			zlog_debug("es %s vtep %pI4 del",
					es->esi_str, &vtep_ip);
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
struct zebra_evpn_es *zebra_evpn_es_find(const esi_t *esi)
{
	struct zebra_evpn_es tmp;

	memcpy(&tmp.esi, esi, sizeof(esi_t));
	return RB_FIND(zebra_es_rb_head, &zmh_info->es_rb_tree, &tmp);
}

/* A new local es is created when a local-es-id and sysmac is configured
 * against an interface.
 */
static struct zebra_evpn_es *zebra_evpn_es_new(const esi_t *esi)
{
	struct zebra_evpn_es *es;

	if (!memcmp(esi, zero_esi, sizeof(esi_t)))
		return NULL;

	es = XCALLOC(MTYPE_ZES, sizeof(struct zebra_evpn_es));

	/* fill in ESI */
	memcpy(&es->esi, esi, sizeof(esi_t));
	esi_to_str(&es->esi, es->esi_str, sizeof(es->esi_str));

	/* Add to rb_tree */
	RB_INSERT(zebra_es_rb_head, &zmh_info->es_rb_tree, es);

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
	es->nhg_id = zebra_evpn_nhid_alloc(es);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s nhg %u new", es->esi_str, es->nhg_id);

	return es;
}

/* Free a given ES -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static void zebra_evpn_es_free(struct zebra_evpn_es **esp)
{
	struct zebra_evpn_es *es = *esp;

	/* If the ES has a local or remote reference it cannot be freed.
	 * Free is also prevented if there are MAC entries referencing
	 * it.
	 */
	if ((es->flags & (ZEBRA_EVPNES_LOCAL | ZEBRA_EVPNES_REMOTE)) ||
			listcount(es->mac_list))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s free", es->esi_str);

	/* If the NHG is still installed uninstall it and free the id */
	if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE) {
		es->flags &= ~ZEBRA_EVPNES_NHG_ACTIVE;
		kernel_del_mac_nhg(es->nhg_id);
	}
	zebra_evpn_nhid_free(es->nhg_id, es);

	/* cleanup resources maintained against the ES */
	list_delete(&es->es_evi_list);
	list_delete(&es->es_vtep_list);
	list_delete(&es->mac_list);

	/* remove from the VNI-ESI rb tree */
	RB_REMOVE(zebra_es_rb_head, &zmh_info->es_rb_tree, es);

	XFREE(MTYPE_ZES, es);

	*esp = NULL;
}

/* Inform BGP about local ES addition */
static int zebra_evpn_es_send_add_to_client(struct zebra_evpn_es *es)
{
	struct zserv *client;
	struct stream *s;
	uint8_t oper_up;
	bool bypass;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	zclient_create_header(s, ZEBRA_LOCAL_ES_ADD, zebra_vrf_get_evpn_id());
	stream_put(s, &es->esi, sizeof(esi_t));
	stream_put_ipv4(s, zmh_info->es_originator_ip.s_addr);
	oper_up = !!(es->flags & ZEBRA_EVPNES_OPER_UP);
	stream_putc(s, oper_up);
	stream_putw(s, es->df_pref);
	bypass = !!(es->flags & ZEBRA_EVPNES_BYPASS);
	stream_putc(s, bypass);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug(
			"send add local es %s %pI4 active %u df_pref %u%s to %s",
			es->esi_str, &zmh_info->es_originator_ip, oper_up,
			es->df_pref, bypass ? " bypass" : "",
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

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);
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

	if (!bf_is_inited(zif->vlan_bitmap))
		return;

	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX) {
		acc_bd = zebra_evpn_acc_vl_find(vid, zif->brslave_info.br_if);
		if (acc_bd->zevpn)
			zebra_evpn_local_es_evi_add(es, acc_bd->zevpn);
	}
}

static void zebra_evpn_flush_local_mac(struct zebra_mac *mac,
				       struct interface *ifp)
{
	vlanid_t vid;
	struct zebra_if *zif;
	struct interface *br_ifp;
	struct zebra_vxlan_vni *vni;

	zif = ifp->info;
	br_ifp = zif->brslave_info.br_if;
	if (!br_ifp)
		return;

	if (mac->zevpn->vxlan_if) {
		zif = mac->zevpn->vxlan_if->info;
		vni = zebra_vxlan_if_vni_find(zif, mac->zevpn->vni);
		vid = vni->access_vlan;
	} else {
		vid = 0;
	}

	/* delete the local mac from the dataplane */
	dplane_local_mac_del(ifp, br_ifp, vid, &mac->macaddr);
	/* delete the local mac in zebra */
	zebra_evpn_del_local_mac(mac->zevpn, mac, true);
}

static void zebra_evpn_es_flush_local_macs(struct zebra_evpn_es *es,
					   struct interface *ifp, bool add)
{
	struct zebra_mac *mac;
	struct listnode	*node;
	struct listnode *nnode;

	for (ALL_LIST_ELEMENTS(es->mac_list, node, nnode, mac)) {
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
			continue;

		/* If ES is being attached/detached from the access port we
		 * need to clear local activity and peer activity and start
		 * over */
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("VNI %u mac %pEA update; local ES %s %s",
				   mac->zevpn->vni,
				   &mac->macaddr,
				   es->esi_str, add ? "add" : "del");
		zebra_evpn_flush_local_mac(mac, ifp);
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
		zlog_debug("es %s br_port change old %u new %u", es->esi_str,
			   old_br_port, new_br_port);

	/* update the dataplane br_port attrs */
	if (new_br_port && zebra_evpn_es_br_port_dplane_update_needed(es))
		zebra_evpn_es_br_port_dplane_update(es, __func__);
}

/* On config of first local-ES turn off DAD */
static void zebra_evpn_mh_dup_addr_detect_off(void)
{
	struct zebra_vrf *zvrf;
	bool old_detect;
	bool new_detect;

	if (zmh_info->flags & ZEBRA_EVPN_MH_DUP_ADDR_DETECT_OFF)
		return;

	zvrf = zebra_vrf_get_evpn();
	old_detect = zebra_evpn_do_dup_addr_detect(zvrf);
	zmh_info->flags |= ZEBRA_EVPN_MH_DUP_ADDR_DETECT_OFF;
	new_detect = zebra_evpn_do_dup_addr_detect(zvrf);

	if (old_detect && !new_detect) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug(
				"evpn-mh config caused DAD addr detect chg from %s to %s",
				old_detect ? "on" : "off",
				new_detect ? "on" : "off");
		zebra_vxlan_clear_dup_detect_vni_all(zvrf);
	}
}

/* On config of first local-ES turn off advertisement of STALE/DELAY/PROBE
 * neighbors
 */
static void zebra_evpn_mh_advertise_reach_neigh_only(void)
{
	if (zmh_info->flags & ZEBRA_EVPN_MH_ADV_REACHABLE_NEIGH_ONLY)
		return;

	zmh_info->flags |= ZEBRA_EVPN_MH_ADV_REACHABLE_NEIGH_ONLY;
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("evpn-mh: only REACHABLE neigh advertised");

	/* XXX - if STALE/DELAY/PROBE neighs were previously advertised we
	 * need to withdraw them
	 */
}

/* On config of first local-ES turn on advertisement of local SVI-MAC */
static void zebra_evpn_mh_advertise_svi_mac(void)
{
	if (zmh_info->flags & ZEBRA_EVPN_MH_ADV_SVI_MAC)
		return;

	zmh_info->flags |= ZEBRA_EVPN_MH_ADV_SVI_MAC;
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("evpn-mh: advertise SVI MAC");

	/* walk through all SVIs and see if we need to advertise the MAC */
	zebra_evpn_acc_vl_adv_svi_mac_all();
}

static void zebra_evpn_es_df_delay_exp_cb(struct event *t)
{
	struct zebra_evpn_es *es;

	es = EVENT_ARG(t);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("es %s df-delay expired", es->esi_str);

	zebra_evpn_es_run_df_election(es, __func__);
}

/* currently there is no global config to turn on MH instead we use
 * the addition of the first local Ethernet Segment as the trigger to
 * init MH specific processing
 */
static void zebra_evpn_mh_on_first_local_es(void)
{
	zebra_evpn_mh_dup_addr_detect_off();
	zebra_evpn_mh_advertise_reach_neigh_only();
	zebra_evpn_mh_advertise_svi_mac();
}

static void zebra_evpn_es_local_info_set(struct zebra_evpn_es *es,
		struct zebra_if *zif)
{
	if (es->flags & ZEBRA_EVPNES_LOCAL)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("local es %s add; nhg %u if %s", es->esi_str,
			   es->nhg_id, zif->ifp->name);

	zebra_evpn_mh_on_first_local_es();

	es->flags |= ZEBRA_EVPNES_LOCAL;
	listnode_init(&es->local_es_listnode, es);
	listnode_add(zmh_info->local_es_list, &es->local_es_listnode);

	/* attach es to interface */
	zif->es_info.es = es;
	es->df_pref = zif->es_info.df_pref;

	/* attach interface to es */
	es->zif = zif;
	if (if_is_operative(zif->ifp))
		es->flags |= ZEBRA_EVPNES_OPER_UP;

	if (zif->brslave_info.bridge_ifindex != IFINDEX_INTERNAL)
		es->flags |= ZEBRA_EVPNES_BR_PORT;

	/* inherit the bypass flag from the interface */
	if (zif->flags & ZIF_FLAG_LACP_BYPASS)
		es->flags |= ZEBRA_EVPNES_BYPASS;

	/* setup base-vni if one doesn't already exist; the ES will get sent
	 * to BGP as a part of that process
	 */
	if (!zmh_info->es_base_evpn)
		zebra_evpn_es_get_one_base_evpn();
	else
		/* send notification to bgp */
		zebra_evpn_es_re_eval_send_to_client(es,
			false /* es_evi_re_reval */);

	/* Start the DF delay timer on the local ES */
	if (!es->df_delay_timer)
		event_add_timer(zrouter.master, zebra_evpn_es_df_delay_exp_cb,
				es, ZEBRA_EVPN_MH_DF_DELAY_TIME,
				&es->df_delay_timer);

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
	 * need to clear the contents and start over
	 */
	zebra_evpn_es_flush_local_macs(es, zif->ifp, true);

	/* inherit EVPN protodown flags on the access port */
	zebra_evpn_mh_update_protodown_es(es, true /*resync_dplane*/);
}

static void zebra_evpn_es_local_info_clear(struct zebra_evpn_es **esp)
{
	struct zebra_if *zif;
	struct zebra_evpn_es *es = *esp;
	bool dplane_updated = false;

	if (!(es->flags & ZEBRA_EVPNES_LOCAL))
		return;

	zif = es->zif;

	/* if there any local macs referring to the ES as dest we
	 * need to clear the contents and start over
	 */
	zebra_evpn_es_flush_local_macs(es, zif->ifp, false);

	es->flags &= ~(ZEBRA_EVPNES_LOCAL | ZEBRA_EVPNES_READY_FOR_BGP);

	EVENT_OFF(es->df_delay_timer);

	/* clear EVPN protodown flags on the access port */
	zebra_evpn_mh_clear_protodown_es(es);

	/* remove the DF filter */
	dplane_updated = zebra_evpn_es_run_df_election(es, __func__);

	/* flush the BUM filters and backup NHG */
	if (!dplane_updated)
		zebra_evpn_es_br_port_dplane_clear(es);

	/* clear the es from the parent interface */
	zif->es_info.es = NULL;
	es->zif = NULL;

	/* clear all local flags associated with the ES */
	es->flags &= ~(ZEBRA_EVPNES_OPER_UP | ZEBRA_EVPNES_BR_PORT
		       | ZEBRA_EVPNES_BYPASS);

	/* remove from the ES list */
	list_delete_node(zmh_info->local_es_list, &es->local_es_listnode);

	/* free up the ES if there is no remote reference */
	zebra_evpn_es_free(esp);
}

/* Delete an ethernet segment and inform BGP */
static void zebra_evpn_local_es_del(struct zebra_evpn_es **esp)
{
	struct zebra_evpn_es_evi *es_evi;
	struct listnode *node = NULL;
	struct listnode *nnode = NULL;
	struct zebra_if *zif;
	struct zebra_evpn_es *es = *esp;

	if (!CHECK_FLAG(es->flags, ZEBRA_EVPNES_LOCAL))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES) {
		zif = es->zif;
		zlog_debug("local es %s del; nhg %u if %s", es->esi_str,
			   es->nhg_id, zif ? zif->ifp->name : "-");
	}

	/* remove all ES-EVIs associated with the ES */
	for (ALL_LIST_ELEMENTS(es->es_evi_list, node, nnode, es_evi))
		zebra_evpn_local_es_evi_do_del(es_evi);

	/* send a del if the ES had been sent to BGP earlier */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_del_to_client(es);

	zebra_evpn_es_local_info_clear(esp);
}

/* eval remote info associated with the ES */
static void zebra_evpn_es_remote_info_re_eval(struct zebra_evpn_es **esp)
{
	struct zebra_evpn_es *es = *esp;

	/* if there are remote VTEPs the ES-EVI is classified as "remote" */
	if (listcount(es->es_vtep_list)) {
		if (!(es->flags & ZEBRA_EVPNES_REMOTE)) {
			es->flags |= ZEBRA_EVPNES_REMOTE;
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
				zlog_debug("remote es %s add; nhg %u",
					   es->esi_str, es->nhg_id);
		}
	} else {
		if (es->flags & ZEBRA_EVPNES_REMOTE) {
			es->flags &= ~ZEBRA_EVPNES_REMOTE;
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
				zlog_debug("remote es %s del; nhg %u",
					   es->esi_str, es->nhg_id);
			zebra_evpn_es_free(esp);
		}
	}
}

void zebra_build_type3_esi(uint32_t lid, struct ethaddr *mac, esi_t *esi)
{
	int offset = 0;
	int field_bytes = 0;

	/* build 10-byte type-3-ESI -
	 * Type(1-byte), MAC(6-bytes), ES-LID (3-bytes)
	 */
	field_bytes = 1;
	esi->val[offset] = ESI_TYPE_MAC;
	offset += field_bytes;

	field_bytes = ETH_ALEN;
	memcpy(&esi->val[offset], (uint8_t *)mac, field_bytes);
	offset += field_bytes;

	esi->val[offset++] = (uint8_t)(lid >> 16);
	esi->val[offset++] = (uint8_t)(lid >> 8);
	esi->val[offset++] = (uint8_t)lid;
}

/* A new local es is created when a local-es-id and sysmac is configured
 * against an interface.
 */
static void zebra_evpn_local_es_update(struct zebra_if *zif)
{
	struct zebra_evpn_es *old_es = zif->es_info.es;
	struct zebra_evpn_es *es;
	esi_t _esi, *esi;

	if (!zebra_evpn_is_if_es_capable(zif))
		return;

	if (memcmp(&zif->es_info.esi, zero_esi, sizeof(*zero_esi))) {
		esi = &zif->es_info.esi;
	} else if (zif->es_info.lid && !is_zero_mac(&zif->es_info.sysmac)) {
		zebra_build_type3_esi(zif->es_info.lid, &zif->es_info.sysmac,
				      &_esi);
		esi = &_esi;
	} else {
		esi = zero_esi;
	}

	if (old_es && !memcmp(&old_es->esi, esi, sizeof(*esi)))
		/* dup - nothing to be done */
		return;

	/* release the old_es against the zif */
	if (old_es)
		zebra_evpn_local_es_del(&old_es);

	es = zebra_evpn_es_find(esi);
	if (!es)
		es = zebra_evpn_es_new(esi);

	if (es)
		zebra_evpn_es_local_info_set(es, zif);
}

int zebra_evpn_remote_es_del(const esi_t *esi, struct in_addr vtep_ip)
{
	char buf[ESI_STR_LEN];
	struct zebra_evpn_es *es;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("remote es %s vtep %pI4 del",
			   esi_to_str(esi, buf, sizeof(buf)), &vtep_ip);

	es = zebra_evpn_es_find(esi);
	if (!es) {
		zlog_warn("remote es %s vtep %pI4 del failed, es missing",
			  esi_to_str(esi, buf, sizeof(buf)), &vtep_ip);
		return -1;
	}

	zebra_evpn_es_vtep_del(es, vtep_ip);
	zebra_evpn_es_remote_info_re_eval(&es);

	return 0;
}

/* force delete a remote ES on the way down */
static void zebra_evpn_remote_es_flush(struct zebra_evpn_es **esp)
{
	struct zebra_evpn_es_vtep *es_vtep;
	struct listnode	*node;
	struct listnode	*nnode;
	struct zebra_evpn_es *es = *esp;

	for (ALL_LIST_ELEMENTS(es->es_vtep_list, node, nnode, es_vtep)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("es %s vtep %pI4 flush",
					es->esi_str,
					&es_vtep->vtep_ip);
		zebra_evpn_es_vtep_free(es_vtep);
	}
	zebra_evpn_es_remote_info_re_eval(esp);
}

int zebra_evpn_remote_es_add(const esi_t *esi, struct in_addr vtep_ip,
			     bool esr_rxed, uint8_t df_alg, uint16_t df_pref)
{
	char buf[ESI_STR_LEN];
	struct zebra_evpn_es *es;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("remote es %s vtep %pI4 add %s df_alg %d df_pref %d",
			   esi_to_str(esi, buf, sizeof(buf)),
			   &vtep_ip, esr_rxed ? "esr" : "", df_alg,
			   df_pref);

	es = zebra_evpn_es_find(esi);
	if (!es) {
		es = zebra_evpn_es_new(esi);
		if (!es) {
			zlog_warn(
				"remote es %s vtep %pI4 add failed, es missing",
				esi_to_str(esi, buf, sizeof(buf)), &vtep_ip);
			return -1;
		}
	}

	if (df_alg != EVPN_MH_DF_ALG_PREF)
		zlog_warn(
			"remote es %s vtep %pI4 add %s with unsupported df_alg %d",
			esi_to_str(esi, buf, sizeof(buf)), &vtep_ip,
			esr_rxed ? "esr" : "", df_alg);

	zebra_evpn_es_vtep_add(es, vtep_ip, esr_rxed, df_alg, df_pref);
	zebra_evpn_es_remote_info_re_eval(&es);

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
			__func__);
		return;
	}

	memset(&esi, 0, sizeof(esi_t));
	s = msg;

	STREAM_GET(&esi, s, sizeof(esi_t));
	STREAM_GET(&vtep_ip.s_addr, s, sizeof(vtep_ip.s_addr));

	if (hdr->command == ZEBRA_REMOTE_ES_VTEP_ADD) {
		uint32_t zapi_flags;
		uint8_t df_alg;
		uint16_t df_pref;
		bool esr_rxed;

		STREAM_GETL(s, zapi_flags);
		esr_rxed = (zapi_flags & ZAPI_ES_VTEP_FLAG_ESR_RXED) ? true
								     : false;
		STREAM_GETC(s, df_alg);
		STREAM_GETW(s, df_pref);
		zebra_rib_queue_evpn_rem_es_add(&esi, &vtep_ip, esr_rxed,
						df_alg, df_pref);
	} else {
		zebra_rib_queue_evpn_rem_es_del(&esi, &vtep_ip);
	}

stream_failure:
	return;
}

void zebra_evpn_es_mac_deref_entry(struct zebra_mac *mac)
{
	struct zebra_evpn_es *es = mac->es;

	mac->es = NULL;
	if (!es)
		return;

	list_delete_node(es->mac_list, &mac->es_listnode);
	if (!listcount(es->mac_list))
		zebra_evpn_es_free(&es);
}

/* Associate a MAC entry with a local or remote ES. Returns false if there
 * was no ES change.
 */
bool zebra_evpn_es_mac_ref_entry(struct zebra_mac *mac,
				 struct zebra_evpn_es *es)
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

bool zebra_evpn_es_mac_ref(struct zebra_mac *mac, const esi_t *esi)
{
	struct zebra_evpn_es *es;

	es = zebra_evpn_es_find(esi);
	if (!es) {
		/* If non-zero esi implicitly create a new ES */
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
					    struct zebra_evpn *zevpn, bool add)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

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
void zebra_evpn_es_sys_mac_update(struct zebra_if *zif, struct ethaddr *sysmac)
{
	if (sysmac)
		memcpy(&zif->es_info.sysmac, sysmac, sizeof(struct ethaddr));
	else
		memset(&zif->es_info.sysmac, 0, sizeof(struct ethaddr));

	zebra_evpn_local_es_update(zif);
}

/* local-ID part of ESI has changed */
void zebra_evpn_es_lid_update(struct zebra_if *zif, uint32_t lid)
{
	zif->es_info.lid = lid;

	zebra_evpn_local_es_update(zif);
}

/* type-0 esi has changed */
void zebra_evpn_es_type0_esi_update(struct zebra_if *zif, esi_t *esi)
{
	if (esi)
		memcpy(&zif->es_info.esi, esi, sizeof(*esi));
	else
		memset(&zif->es_info.esi, 0, sizeof(*esi));

	zebra_evpn_local_es_update(zif);
}

void zebra_evpn_es_cleanup(void)
{
	struct zebra_evpn_es *es;
	struct zebra_evpn_es *es_next;

	RB_FOREACH_SAFE(es, zebra_es_rb_head,
			&zmh_info->es_rb_tree, es_next) {
		zebra_evpn_local_es_del(&es);
		if (es)
			zebra_evpn_remote_es_flush(&es);
	}
}

void zebra_evpn_es_df_pref_update(struct zebra_if *zif, uint16_t df_pref)
{
	struct zebra_evpn_es *es;

	if (zif->es_info.df_pref == df_pref)
		return;

	zif->es_info.df_pref = df_pref;
	es = zif->es_info.es;

	if (!es)
		return;

	if (es->df_pref == zif->es_info.df_pref)
		return;

	es->df_pref = zif->es_info.df_pref;
	/* run df election */
	zebra_evpn_es_run_df_election(es, __func__);
	/* notify bgp */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_add_to_client(es);
}

/* If bypass mode on an es changed we set all local macs to
 * inactive and drop the sync info
 */
static void zebra_evpn_es_bypass_update_macs(struct zebra_evpn_es *es,
					     struct interface *ifp, bool bypass)
{
	struct zebra_mac *mac;
	struct listnode *node;
	struct listnode *nnode;
	struct zebra_if *zif;

	/* Flush all MACs linked to the ES */
	for (ALL_LIST_ELEMENTS(es->mac_list, node, nnode, mac)) {
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
			continue;

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("VNI %u mac %pEA %s update es %s",
				   mac->zevpn->vni,
				   &mac->macaddr,
				   bypass ? "bypass" : "non-bypass",
				   es->esi_str);
		zebra_evpn_flush_local_mac(mac, ifp);
	}

	/* While in bypass-mode locally learnt MACs are linked
	 * to the access port instead of the ES
	 */
	zif = ifp->info;
	if (!zif->mac_list)
		return;

	for (ALL_LIST_ELEMENTS(zif->mac_list, node, nnode, mac)) {
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
			continue;

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("VNI %u mac %pEA %s update ifp %s",
				   mac->zevpn->vni,
				   &mac->macaddr,
				   bypass ? "bypass" : "non-bypass", ifp->name);
		zebra_evpn_flush_local_mac(mac, ifp);
	}
}

void zebra_evpn_es_bypass_update(struct zebra_evpn_es *es,
				 struct interface *ifp, bool bypass)
{
	bool old_bypass;
	bool dplane_updated;

	old_bypass = !!(es->flags & ZEBRA_EVPNES_BYPASS);
	if (old_bypass == bypass)
		return;

	if (bypass)
		es->flags |= ZEBRA_EVPNES_BYPASS;
	else
		es->flags &= ~ZEBRA_EVPNES_BYPASS;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("bond %s es %s lacp bypass changed to %s", ifp->name,
			   es->esi_str, bypass ? "on" : "off");

	/* send bypass update to BGP */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_add_to_client(es);

	zebra_evpn_es_bypass_update_macs(es, ifp, bypass);

	/* re-run DF election */
	dplane_updated = zebra_evpn_es_run_df_election(es, __func__);

	/* disable SPH filter */
	if (!dplane_updated && (es->flags & ZEBRA_EVPNES_LOCAL)
	    && (listcount(es->es_vtep_list) > ES_VTEP_MAX_CNT))
		zebra_evpn_es_br_port_dplane_update(es, __func__);
}

void zebra_evpn_es_bypass_cfg_update(struct zebra_if *zif, bool bypass)
{
	bool old_bypass = !!(zif->es_info.flags & ZIF_CFG_ES_FLAG_BYPASS);

	if (old_bypass == bypass)
		return;

	if (bypass)
		zif->es_info.flags |= ZIF_CFG_ES_FLAG_BYPASS;
	else
		zif->es_info.flags &= ~ZIF_CFG_ES_FLAG_BYPASS;


	if (zif->es_info.es)
		zebra_evpn_es_bypass_update(zif->es_info.es, zif->ifp, bypass);
}


/* Only certain types of access ports can be setup as an Ethernet Segment */
bool zebra_evpn_is_if_es_capable(struct zebra_if *zif)
{
	if (zif->zif_type == ZEBRA_IF_BOND)
		return true;

	/* relax the checks to allow config to be applied in zebra
	 * before interface is rxed from the kernel
	 */
	if (zif->ifp->ifindex == IFINDEX_INTERNAL)
		return true;

	/* XXX: allow swpX i.e. a regular ethernet port to be an ES link too */
	return false;
}

void zebra_evpn_if_es_print(struct vty *vty, json_object *json,
			    struct zebra_if *zif)
{
	char buf[ETHER_ADDR_STRLEN];
	char esi_buf[ESI_STR_LEN];

	if (json) {
		json_object *json_evpn;

		json_evpn = json_object_new_object();
		json_object_object_add(json, "evpnMh", json_evpn);

		if (zif->es_info.lid || !is_zero_mac(&zif->es_info.sysmac)) {
			json_object_int_add(json_evpn, "esId",
					    zif->es_info.lid);
			json_object_string_add(
				json_evpn, "esSysmac",
				prefix_mac2str(&zif->es_info.sysmac, buf,
					       sizeof(buf)));
		} else if (memcmp(&zif->es_info.esi, zero_esi,
				  sizeof(*zero_esi))) {
			json_object_string_add(json_evpn, "esId",
					       esi_to_str(&zif->es_info.esi,
							  esi_buf,
							  sizeof(esi_buf)));
		}

		if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK)
			json_object_string_add(
				json_evpn, "uplink",
				CHECK_FLAG(zif->flags,
					   ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP)
					? "up"
					: "down");
	} else {
		char mh_buf[80];
		bool vty_print = false;

		mh_buf[0] = '\0';
		strlcat(mh_buf, "  EVPN-MH:", sizeof(mh_buf));
		if (zif->es_info.lid || !is_zero_mac(&zif->es_info.sysmac)) {
			vty_print = true;
			snprintf(mh_buf + strlen(mh_buf),
				 sizeof(mh_buf) - strlen(mh_buf),
				 " ES id %u ES sysmac %s", zif->es_info.lid,
				 prefix_mac2str(&zif->es_info.sysmac, buf,
						sizeof(buf)));
		} else if (memcmp(&zif->es_info.esi, zero_esi,
				  sizeof(*zero_esi))) {
			vty_print = true;
			snprintf(mh_buf + strnlen(mh_buf, sizeof(mh_buf)),
				 sizeof(mh_buf)
					 - strnlen(mh_buf, sizeof(mh_buf)),
				 " ES id %s",
				 esi_to_str(&zif->es_info.esi, esi_buf,
					    sizeof(esi_buf)));
		}

		if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK) {
			vty_print = true;
			if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP)
				strlcat(mh_buf, " uplink (up)", sizeof(mh_buf));
			else
				strlcat(mh_buf, " uplink (down)",
					sizeof(mh_buf));
		}

		if (vty_print)
			vty_out(vty, "%s\n", mh_buf);
	}
}

static void zebra_evpn_local_mac_oper_state_change(struct zebra_evpn_es *es)
{
	struct zebra_mac *mac;
	struct listnode *node;

	/* If fast-failover is supported by the dataplane via the use
	 * of an ES backup NHG there is nothing to be done in the
	 * control plane
	 */
	if (!(zmh_info->flags & ZEBRA_EVPN_MH_REDIRECT_OFF))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("mac slow-fail on es %s %s ", es->esi_str,
			   (es->flags & ZEBRA_EVPNES_OPER_UP) ? "up" : "down");

	for (ALL_LIST_ELEMENTS_RO(es->mac_list, node, mac)) {
		if (!(mac->flags & ZEBRA_MAC_LOCAL)
		    || !zebra_evpn_mac_is_static(mac))
			continue;

		if (es->flags & ZEBRA_EVPNES_OPER_UP) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
				zlog_debug(
					"VNI %u mac %pEA move to acc %s es %s %s ",
					mac->zevpn->vni,
					&mac->macaddr,
					es->zif->ifp->name, es->esi_str,
					(es->flags & ZEBRA_EVPNES_OPER_UP)
						? "up"
						: "down");
			/* switch the local macs to access port */
			if (zebra_evpn_sync_mac_dp_install(
				    mac, false /*set_inactive*/,
				    false /*force_clear_static*/, __func__)
			    < 0)
				/* if the local mac install fails get rid of the
				 * old rem entry
				 */
				zebra_evpn_rem_mac_uninstall(mac->zevpn, mac,
							     true /*force*/);
		} else {
			/* switch the local macs to network port. if there
			 * is no active NHG we don't bother deleting the MAC;
			 * that is left up to the dataplane to handle.
			 */
			if (!(es->flags & ZEBRA_EVPNES_NHG_ACTIVE))
				continue;
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
				zlog_debug(
					"VNI %u mac %pEA move to nhg %u es %s %s ",
					mac->zevpn->vni,
					&mac->macaddr,
					es->nhg_id, es->esi_str,
					(es->flags & ZEBRA_EVPNES_OPER_UP)
						? "up"
						: "down");
			zebra_evpn_rem_mac_install(mac->zevpn, mac,
						   true /*was_static*/);
		}
	}
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
	zebra_evpn_local_mac_oper_state_change(es);

	/* inform BGP of the ES oper state change */
	if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
		zebra_evpn_es_send_add_to_client(es);
}

static char *zebra_evpn_es_vtep_str(char *vtep_str, struct zebra_evpn_es *es,
				    size_t vtep_str_size)
{
	struct zebra_evpn_es_vtep *zvtep;
	struct listnode	*node;
	bool first = true;
	char ip_buf[INET6_ADDRSTRLEN];

	vtep_str[0] = '\0';
	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, zvtep)) {
		if (first) {
			first = false;
			strlcat(vtep_str,
				inet_ntop(AF_INET, &zvtep->vtep_ip, ip_buf,
					  sizeof(ip_buf)),
				vtep_str_size);
		} else {
			strlcat(vtep_str, ",", vtep_str_size);
			strlcat(vtep_str,
				inet_ntop(AF_INET, &zvtep->vtep_ip, ip_buf,
					  sizeof(ip_buf)),
				vtep_str_size);
		}
	}
	return vtep_str;
}

static void zebra_evpn_es_json_vtep_fill(struct zebra_evpn_es *es,
					 json_object *json_vteps)
{
	struct zebra_evpn_es_vtep *es_vtep;
	struct listnode *node;
	json_object *json_vtep_entry;
	char alg_buf[EVPN_DF_ALG_STR_LEN];

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		json_vtep_entry = json_object_new_object();
		json_object_string_addf(json_vtep_entry, "vtep", "%pI4",
					&es_vtep->vtep_ip);
		if (es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR) {
			json_object_string_add(
				json_vtep_entry, "dfAlgorithm",
				evpn_es_df_alg2str(es_vtep->df_alg, alg_buf,
						   sizeof(alg_buf)));
			json_object_int_add(json_vtep_entry, "dfPreference",
					    es_vtep->df_pref);
		}
		if (es_vtep->nh)
			json_object_int_add(json_vtep_entry, "nexthopId",
					    es_vtep->nh->nh_id);
		json_object_array_add(json_vteps, json_vtep_entry);
	}
}

static void zebra_evpn_es_show_entry(struct vty *vty, struct zebra_evpn_es *es,
				     json_object *json_array)
{
	char type_str[5];
	char vtep_str[ES_VTEP_LIST_STR_SZ];

	if (json_array) {
		json_object *json = NULL;
		json_object *json_vteps;
		json_object *json_flags;

		json = json_object_new_object();
		json_object_string_add(json, "esi", es->esi_str);

		if (es->flags
		    & (ZEBRA_EVPNES_LOCAL | ZEBRA_EVPNES_REMOTE
		       | ZEBRA_EVPNES_NON_DF)) {
			json_flags = json_object_new_array();
			if (es->flags & ZEBRA_EVPNES_LOCAL)
				json_array_string_add(json_flags, "local");
			if (es->flags & ZEBRA_EVPNES_REMOTE)
				json_array_string_add(json_flags, "remote");
			if (es->flags & ZEBRA_EVPNES_NON_DF)
				json_array_string_add(json_flags, "nonDF");
			if (es->flags & ZEBRA_EVPNES_BYPASS)
				json_array_string_add(json_flags, "bypass");
			json_object_object_add(json, "flags", json_flags);
		}

		if (es->zif)
			json_object_string_add(json, "accessPort",
					       es->zif->ifp->name);

		if (listcount(es->es_vtep_list)) {
			json_vteps = json_object_new_array();
			zebra_evpn_es_json_vtep_fill(es, json_vteps);
			json_object_object_add(json, "vteps", json_vteps);
		}
		json_object_array_add(json_array, json);
	} else {
		type_str[0] = '\0';
		if (es->flags & ZEBRA_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & ZEBRA_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));
		if (es->flags & ZEBRA_EVPNES_NON_DF)
			strlcat(type_str, "N", sizeof(type_str));
		if (es->flags & ZEBRA_EVPNES_BYPASS)
			strlcat(type_str, "B", sizeof(type_str));

		zebra_evpn_es_vtep_str(vtep_str, es, sizeof(vtep_str));

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
	char thread_buf[EVENT_TIMER_STRLEN];

	if (json) {
		json_object *json_vteps;
		json_object *json_flags;

		json_object_string_add(json, "esi", es->esi_str);
		if (es->zif)
			json_object_string_add(json, "accessPort",
					       es->zif->ifp->name);


		if (es->flags) {
			json_flags = json_object_new_array();
			if (es->flags & ZEBRA_EVPNES_LOCAL)
				json_array_string_add(json_flags, "local");
			if (es->flags & ZEBRA_EVPNES_REMOTE)
				json_array_string_add(json_flags, "remote");
			if (es->flags & ZEBRA_EVPNES_LOCAL &&
			    !(es->flags & ZEBRA_EVPNES_NON_DF))
				json_array_string_add(json_flags, "df");
			if (es->flags & ZEBRA_EVPNES_NON_DF)
				json_array_string_add(json_flags, "nonDF");
			if (es->flags & ZEBRA_EVPNES_BYPASS)
				json_array_string_add(json_flags, "bypass");
			if (es->flags & ZEBRA_EVPNES_READY_FOR_BGP)
				json_array_string_add(json_flags,
						      "readyForBgp");
			if (es->flags & ZEBRA_EVPNES_BR_PORT)
				json_array_string_add(json_flags, "bridgePort");
			if (es->flags & ZEBRA_EVPNES_OPER_UP)
				json_array_string_add(json_flags, "operUp");
			if (es->flags & ZEBRA_EVPNES_NHG_ACTIVE)
				json_array_string_add(json_flags,
						      "nexthopGroupActive");
			json_object_object_add(json, "flags", json_flags);
		}

		json_object_int_add(json, "vniCount",
				    listcount(es->es_evi_list));
		json_object_int_add(json, "macCount", listcount(es->mac_list));
		json_object_int_add(json, "dfPreference", es->df_pref);
		if (es->df_delay_timer)
			json_object_string_add(
				json, "dfDelayTimer",
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      es->df_delay_timer));
		json_object_int_add(json, "nexthopGroup", es->nhg_id);
		if (listcount(es->es_vtep_list)) {
			json_vteps = json_object_new_array();
			zebra_evpn_es_json_vtep_fill(es, json_vteps);
			json_object_object_add(json, "vteps", json_vteps);
		}
	} else {
		type_str[0] = '\0';
		if (es->flags & ZEBRA_EVPNES_LOCAL)
			strlcat(type_str, "Local", sizeof(type_str));
		if (es->flags & ZEBRA_EVPNES_REMOTE) {
			if (strnlen(type_str, sizeof(type_str)))
				strlcat(type_str, ",", sizeof(type_str));
			strlcat(type_str, "Remote", sizeof(type_str));
		}

		vty_out(vty, "ESI: %s\n", es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " Interface: %s\n",
				(es->zif) ?
				es->zif->ifp->name : "-");
		if (es->flags & ZEBRA_EVPNES_LOCAL) {
			vty_out(vty, " State: %s\n",
				(es->flags & ZEBRA_EVPNES_OPER_UP) ? "up"
								   : "down");
			vty_out(vty, " Bridge port: %s\n",
				(es->flags & ZEBRA_EVPNES_BR_PORT) ? "yes"
								   : "no");
		}
		vty_out(vty, " Ready for BGP: %s\n",
				(es->flags & ZEBRA_EVPNES_READY_FOR_BGP) ?
				"yes" : "no");
		if (es->flags & ZEBRA_EVPNES_BYPASS)
			vty_out(vty, " LACP bypass: on\n");
		vty_out(vty, " VNI Count: %d\n", listcount(es->es_evi_list));
		vty_out(vty, " MAC Count: %d\n", listcount(es->mac_list));
		if (es->flags & ZEBRA_EVPNES_LOCAL)
			vty_out(vty, " DF status: %s \n",
				(es->flags & ZEBRA_EVPNES_NON_DF) ? "non-df"
								  : "df");
		if (es->df_delay_timer)
			vty_out(vty, " DF delay: %s\n",
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      es->df_delay_timer));
		vty_out(vty, " DF preference: %u\n", es->df_pref);
		vty_out(vty, " Nexthop group: %u\n", es->nhg_id);
		vty_out(vty, " VTEPs:\n");
		for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
			vty_out(vty, "     %pI4",
					&es_vtep->vtep_ip);
			if (es_vtep->flags & ZEBRA_EVPNES_VTEP_RXED_ESR)
				vty_out(vty, " df_alg: %s df_pref: %d",
					evpn_es_df_alg2str(es_vtep->df_alg,
							   alg_buf,
							   sizeof(alg_buf)),
					es_vtep->df_pref);
			vty_out(vty, " nh: %u\n",
				es_vtep->nh ? es_vtep->nh->nh_id : 0);
		}

		vty_out(vty, "\n");
	}
}

void zebra_evpn_es_show(struct vty *vty, bool uj)
{
	struct zebra_evpn_es *es;
	json_object *json_array = NULL;

	if (uj) {
		json_array = json_object_new_array();
	} else {
		vty_out(vty, "Type: B bypass, L local, R remote, N non-DF\n");
		vty_out(vty, "%-30s %-4s %-21s %s\n",
				"ESI", "Type", "ES-IF", "VTEPs");
	}

	RB_FOREACH(es, zebra_es_rb_head, &zmh_info->es_rb_tree)
		zebra_evpn_es_show_entry(vty, es, json_array);

	if (uj)
		vty_json(vty, json_array);
}

void zebra_evpn_es_show_detail(struct vty *vty, bool uj)
{
	struct zebra_evpn_es *es;
	json_object *json_array = NULL;

	if (uj)
		json_array = json_object_new_array();

	RB_FOREACH (es, zebra_es_rb_head, &zmh_info->es_rb_tree) {
		json_object *json = NULL;

		if (uj)
			json = json_object_new_object();
		zebra_evpn_es_show_entry_detail(vty, es, json);
		if (uj)
			json_object_array_add(json_array, json);
	}

	if (uj)
		vty_json(vty, json_array);
}

void zebra_evpn_es_show_esi(struct vty *vty, bool uj, esi_t *esi)
{
	struct zebra_evpn_es *es;
	char esi_str[ESI_STR_LEN];
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	es = zebra_evpn_es_find(esi);

	if (es) {
		zebra_evpn_es_show_entry_detail(vty, es, json);
	} else {
		if (!uj) {
			esi_to_str(esi, esi_str, sizeof(esi_str));
			vty_out(vty, "ESI %s does not exist\n", esi_str);
		}
	}

	if (uj)
		vty_json(vty, json);
}

void zebra_evpn_mh_if_init(struct zebra_if *zif)
{
	zif->es_info.df_pref = EVPN_MH_DF_PREF_DEFAULT;
}

void zebra_evpn_mh_json(json_object *json)
{
	json_object *json_array;
	char thread_buf[EVENT_TIMER_STRLEN];

	json_object_int_add(json, "macHoldtime", zmh_info->mac_hold_time);
	json_object_int_add(json, "neighHoldtime", zmh_info->neigh_hold_time);
	json_object_int_add(json, "startupDelay", zmh_info->startup_delay_time);
	json_object_string_add(
		json, "startupDelayTimer",
		event_timer_to_hhmmss(thread_buf, sizeof(thread_buf),
				      zmh_info->startup_delay_timer));
	json_object_int_add(json, "uplinkConfigCount",
			    zmh_info->uplink_cfg_cnt);
	json_object_int_add(json, "uplinkActiveCount",
			    zmh_info->uplink_oper_up_cnt);

	if (zmh_info->protodown_rc) {
		json_array = json_object_new_array();
		if (CHECK_FLAG(zmh_info->protodown_rc,
			       ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY))
			json_object_array_add(
				json_array,
				json_object_new_string("startupDelay"));
		if (CHECK_FLAG(zmh_info->protodown_rc,
			       ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN))
			json_object_array_add(
				json_array,
				json_object_new_string("uplinkDown"));
		json_object_object_add(json, "protodownReasons", json_array);
	}
}

void zebra_evpn_mh_print(struct vty *vty)
{
	char pd_buf[ZEBRA_PROTODOWN_RC_STR_LEN];
	char thread_buf[EVENT_TIMER_STRLEN];

	vty_out(vty, "EVPN MH:\n");
	vty_out(vty, "  mac-holdtime: %ds, neigh-holdtime: %ds\n",
		zmh_info->mac_hold_time, zmh_info->neigh_hold_time);
	vty_out(vty, "  startup-delay: %ds, start-delay-timer: %s\n",
		zmh_info->startup_delay_time,
		event_timer_to_hhmmss(thread_buf, sizeof(thread_buf),
				      zmh_info->startup_delay_timer));
	vty_out(vty, "  uplink-cfg-cnt: %u, uplink-active-cnt: %u\n",
		zmh_info->uplink_cfg_cnt, zmh_info->uplink_oper_up_cnt);
	if (zmh_info->protodown_rc)
		vty_out(vty, "  protodown reasons: %s\n",
			zebra_protodown_rc_str(zmh_info->protodown_rc, pd_buf,
					       sizeof(pd_buf)));
}

/*****************************************************************************/
/* A base L2-VNI is maintained to derive parameters such as ES originator-IP.
 * XXX: once single vxlan device model becomes available this will not be
 * necessary
 */
/* called when a new vni is added or becomes oper up or becomes a bridge port */
void zebra_evpn_es_set_base_evpn(struct zebra_evpn *zevpn)
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
		zlog_debug("es originator ip set to %pI4",
			&zmh_info->es_base_evpn->local_vtep_ip);

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
void zebra_evpn_es_clear_base_evpn(struct zebra_evpn *zevpn)
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
	struct zebra_evpn *zevpn = b->data;

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

/*****************************************************************************
 * local ethernet segments can be error-disabled if the switch is not
 * ready to start transmitting traffic via the VxLAN overlay
 */
bool zebra_evpn_is_es_bond(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	return !!(struct zebra_if *)zif->es_info.es;
}

bool zebra_evpn_is_es_bond_member(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	return IS_ZEBRA_IF_BOND_SLAVE(zif->ifp) && zif->bondslave_info.bond_if
	       && ((struct zebra_if *)zif->bondslave_info.bond_if->info)
			  ->es_info.es;
}

void zebra_evpn_mh_update_protodown_bond_mbr(struct zebra_if *zif, bool clear,
					     const char *caller)
{
	bool new_protodown;
	uint32_t old_protodown_rc = 0;
	uint32_t new_protodown_rc = 0;
	uint32_t protodown_rc = 0;

	if (!clear) {
		struct zebra_if *bond_zif;

		bond_zif = zif->bondslave_info.bond_if->info;
		protodown_rc = bond_zif->protodown_rc;
	}

	old_protodown_rc = zif->protodown_rc;
	new_protodown_rc = (old_protodown_rc & ~ZEBRA_PROTODOWN_EVPN_ALL);
	new_protodown_rc |= (protodown_rc & ZEBRA_PROTODOWN_EVPN_ALL);
	new_protodown = !!new_protodown_rc;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES && (new_protodown_rc != old_protodown_rc))
		zlog_debug(
			"%s bond mbr %s protodown_rc changed; old 0x%x new 0x%x",
			caller, zif->ifp->name, old_protodown_rc,
			new_protodown_rc);

	if (zebra_if_update_protodown_rc(zif->ifp, new_protodown,
					 new_protodown_rc) == 0) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("%s protodown %s", zif->ifp->name,
				   new_protodown ? "on" : "off");
	}
}

/* The bond members inherit the protodown reason code from the bond */
static void zebra_evpn_mh_update_protodown_bond(struct zebra_if *bond_zif)
{
	struct zebra_if *zif;
	struct listnode *node;

	if (!bond_zif->bond_info.mbr_zifs)
		return;

	for (ALL_LIST_ELEMENTS_RO(bond_zif->bond_info.mbr_zifs, node, zif)) {
		zebra_evpn_mh_update_protodown_bond_mbr(zif, false /*clear*/,
							__func__);
	}
}

/* The global EVPN MH protodown rc is applied to all local ESs */
static void zebra_evpn_mh_update_protodown_es(struct zebra_evpn_es *es,
					      bool resync_dplane)
{
	struct zebra_if *zif;
	uint32_t old_protodown_rc;

	zif = es->zif;
	/* if the reason code is the same bail unless it is a new
	 * ES bond in that case we would need to ensure that the
	 * dplane is really in sync with zebra
	 */
	if (!resync_dplane
	    && (zif->protodown_rc & ZEBRA_PROTODOWN_EVPN_ALL)
		       == (zmh_info->protodown_rc & ZEBRA_PROTODOWN_EVPN_ALL))
		return;

	old_protodown_rc = zif->protodown_rc;
	zif->protodown_rc &= ~ZEBRA_PROTODOWN_EVPN_ALL;
	zif->protodown_rc |=
		(zmh_info->protodown_rc & ZEBRA_PROTODOWN_EVPN_ALL);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES
	    && (old_protodown_rc != zif->protodown_rc))
		zlog_debug(
			"es %s ifp %s protodown_rc changed; old 0x%x new 0x%x",
			es->esi_str, zif->ifp->name, old_protodown_rc,
			zif->protodown_rc);

	/* update dataplane with the new protodown setting */
	zebra_evpn_mh_update_protodown_bond(zif);
}

static void zebra_evpn_mh_clear_protodown_es(struct zebra_evpn_es *es)
{
	struct zebra_if *zif;
	uint32_t old_protodown_rc;

	zif = es->zif;
	if (!(zif->protodown_rc & ZEBRA_PROTODOWN_EVPN_ALL))
		return;

	old_protodown_rc = zif->protodown_rc;
	zif->protodown_rc &= ~ZEBRA_PROTODOWN_EVPN_ALL;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug(
			"clear: es %s ifp %s protodown_rc cleared; old 0x%x new 0x%x",
			es->esi_str, zif->ifp->name, old_protodown_rc,
			zif->protodown_rc);

	/* update dataplane with the new protodown setting */
	zebra_evpn_mh_update_protodown_bond(zif);
}

static void zebra_evpn_mh_update_protodown_es_all(void)
{
	struct listnode *node;
	struct zebra_evpn_es *es;

	for (ALL_LIST_ELEMENTS_RO(zmh_info->local_es_list, node, es))
		zebra_evpn_mh_update_protodown_es(es, false /*resync_dplane*/);
}

static void zebra_evpn_mh_update_protodown(uint32_t protodown_rc, bool set)
{
	uint32_t old_protodown_rc = zmh_info->protodown_rc;

	if (set) {
		if ((protodown_rc & zmh_info->protodown_rc) == protodown_rc)
			return;

		zmh_info->protodown_rc |= protodown_rc;
	} else {
		if (!(protodown_rc & zmh_info->protodown_rc))
			return;
		zmh_info->protodown_rc &= ~protodown_rc;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("mh protodown_rc changed; old 0x%x new 0x%x",
			   old_protodown_rc, zmh_info->protodown_rc);
	zebra_evpn_mh_update_protodown_es_all();
}

static inline bool zebra_evpn_mh_is_all_uplinks_down(void)
{
	return zmh_info->uplink_cfg_cnt && !zmh_info->uplink_oper_up_cnt;
}

static void zebra_evpn_mh_uplink_oper_flags_update(struct zebra_if *zif,
						   bool set)
{
	if (set && if_is_operative(zif->ifp)) {
		if (!(zif->flags & ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP)) {
			zif->flags |= ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP;
			++zmh_info->uplink_oper_up_cnt;
		}
	} else {
		if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP) {
			zif->flags &= ~ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP;
			if (zmh_info->uplink_oper_up_cnt)
				--zmh_info->uplink_oper_up_cnt;
		}
	}
}

void zebra_evpn_mh_uplink_cfg_update(struct zebra_if *zif, bool set)
{
	bool old_protodown = zebra_evpn_mh_is_all_uplinks_down();
	bool new_protodown;

	if (set) {
		if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK)
			return;

		zif->flags |= ZIF_FLAG_EVPN_MH_UPLINK;
		++zmh_info->uplink_cfg_cnt;
	} else {
		if (!(zif->flags & ZIF_FLAG_EVPN_MH_UPLINK))
			return;

		zif->flags &= ~ZIF_FLAG_EVPN_MH_UPLINK;
		if (zmh_info->uplink_cfg_cnt)
			--zmh_info->uplink_cfg_cnt;
	}

	zebra_evpn_mh_uplink_oper_flags_update(zif, set);
	new_protodown = zebra_evpn_mh_is_all_uplinks_down();
	if (old_protodown == new_protodown)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug(
			"mh-uplink-cfg-chg on if %s/%d %s uplinks cfg %u up %u",
			zif->ifp->name, zif->ifp->ifindex, set ? "set" : "down",
			zmh_info->uplink_cfg_cnt, zmh_info->uplink_oper_up_cnt);

	zebra_evpn_mh_update_protodown(ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN,
				       new_protodown);
}

void zebra_evpn_mh_uplink_oper_update(struct zebra_if *zif)
{
	bool old_protodown = zebra_evpn_mh_is_all_uplinks_down();
	bool new_protodown;

	zebra_evpn_mh_uplink_oper_flags_update(zif, true /*set*/);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug(
			"mh-uplink-oper-chg on if %s/%d %s; uplinks cfg %u up %u",
			zif->ifp->name, zif->ifp->ifindex,
			if_is_operative(zif->ifp) ? "up" : "down",
			zmh_info->uplink_cfg_cnt, zmh_info->uplink_oper_up_cnt);

	new_protodown = zebra_evpn_mh_is_all_uplinks_down();
	if (old_protodown == new_protodown)
		return;

	/* if protodown_rc XXX_UPLINK_DOWN is about to be cleared
	 * fire up the start-up delay timer to allow the EVPN network
	 * to converge (Type-2 routes need to be advertised and processed)
	 */
	if (!new_protodown && (zmh_info->uplink_oper_up_cnt == 1))
		zebra_evpn_mh_startup_delay_timer_start("uplink-up");

	zebra_evpn_mh_update_protodown(ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN,
				       new_protodown);
}

static void zebra_evpn_mh_startup_delay_exp_cb(struct event *t)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("startup-delay expired");

	zebra_evpn_mh_update_protodown(ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY,
				       false /* set */);
}

static void zebra_evpn_mh_startup_delay_timer_start(const char *rc)
{
	if (zmh_info->startup_delay_timer) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("startup-delay timer cancelled");
		EVENT_OFF(zmh_info->startup_delay_timer);
	}

	if (zmh_info->startup_delay_time) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug(
				"startup-delay timer started for %d sec on %s",
				zmh_info->startup_delay_time, rc);
		event_add_timer(zrouter.master,
				zebra_evpn_mh_startup_delay_exp_cb, NULL,
				zmh_info->startup_delay_time,
				&zmh_info->startup_delay_timer);
		zebra_evpn_mh_update_protodown(
			ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY, true /* set */);
	} else {
		zebra_evpn_mh_update_protodown(
			ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY, false /* set */);
	}
}

/*****************************************************************************
 * Nexthop management: nexthops associated with Type-2 routes that have
 * an ES as destination are consolidated by BGP into a per-VRF nh->rmac
 * mapping which is the installed as a remote neigh/fdb entry with a
 * dummy (type-1) prefix referencing it.
 * This handling is needed because Type-2 routes with ES as dest use NHG
 * that are setup using EAD routes (i.e. such NHGs do not include the
 * RMAC info).
 ****************************************************************************/
void zebra_evpn_proc_remote_nh(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	vrf_id_t vrf_id;
	struct ipaddr nh;
	struct ethaddr rmac;
	struct prefix_evpn dummy_prefix;
	size_t min_len = 4 + sizeof(nh);

	s = msg;

	/*
	 * Ensure that the stream sent to us is long enough
	 */
	if (hdr->command == ZEBRA_EVPN_REMOTE_NH_ADD)
		min_len += sizeof(rmac);
	if (hdr->length < min_len)
		return;

	vrf_id = stream_getl(s);
	stream_get(&nh, s, sizeof(nh));

	memset(&dummy_prefix, 0, sizeof(dummy_prefix));
	dummy_prefix.family = AF_EVPN;
	dummy_prefix.prefixlen = (sizeof(struct evpn_addr) * 8);
	dummy_prefix.prefix.route_type = 1; /* XXX - fixup to type-1 def */
	dummy_prefix.prefix.ead_addr.ip.ipa_type = nh.ipa_type;

	if (hdr->command == ZEBRA_EVPN_REMOTE_NH_ADD) {
		stream_get(&rmac, s, sizeof(rmac));
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug(
				"evpn remote nh %d %pIA rmac %pEA add pfx %pFX",
				vrf_id, &nh, &rmac, &dummy_prefix);
		zebra_rib_queue_evpn_route_add(vrf_id, &rmac, &nh,
					       (struct prefix *)&dummy_prefix);
	} else {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
			zlog_debug("evpn remote nh %d %pIA del pfx %pFX",
				   vrf_id, &nh, &dummy_prefix);
		zebra_rib_queue_evpn_route_del(vrf_id, &nh,
					       (struct prefix *)&dummy_prefix);
	}
}

/*****************************************************************************/
void zebra_evpn_mh_config_write(struct vty *vty)
{
	if (zmh_info->mac_hold_time != ZEBRA_EVPN_MH_MAC_HOLD_TIME_DEF)
		vty_out(vty, "evpn mh mac-holdtime %d\n",
			zmh_info->mac_hold_time);

	if (zmh_info->neigh_hold_time != ZEBRA_EVPN_MH_NEIGH_HOLD_TIME_DEF)
		vty_out(vty, "evpn mh neigh-holdtime %d\n",
			zmh_info->neigh_hold_time);

	if (zmh_info->startup_delay_time != ZEBRA_EVPN_MH_STARTUP_DELAY_DEF)
		vty_out(vty, "evpn mh startup-delay %d\n",
			zmh_info->startup_delay_time);

	if (zmh_info->flags & ZEBRA_EVPN_MH_REDIRECT_OFF)
		vty_out(vty, "evpn mh redirect-off\n");
}

int zebra_evpn_mh_neigh_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default)
{
	if (set_default)
		duration = ZEBRA_EVPN_MH_NEIGH_HOLD_TIME_DEF;

	zmh_info->neigh_hold_time = duration;

	return 0;
}

int zebra_evpn_mh_mac_holdtime_update(struct vty *vty,
		uint32_t duration, bool set_default)
{
	if (set_default)
		duration = ZEBRA_EVPN_MH_MAC_HOLD_TIME_DEF;

	zmh_info->mac_hold_time = duration;

	return 0;
}

int zebra_evpn_mh_startup_delay_update(struct vty *vty, uint32_t duration,
				       bool set_default)
{
	if (set_default)
		duration = ZEBRA_EVPN_MH_STARTUP_DELAY_DEF;

	zmh_info->startup_delay_time = duration;

	/* if startup_delay_timer is running allow it to be adjusted
	 * up or down
	 */
	if (zmh_info->startup_delay_timer)
		zebra_evpn_mh_startup_delay_timer_start("config");

	return 0;
}

int zebra_evpn_mh_redirect_off(struct vty *vty, bool redirect_off)
{
	/* This knob needs to be set before ESs are configured
	 * i.e. cannot be changed on the fly
	 */
	if (redirect_off)
		zmh_info->flags |= ZEBRA_EVPN_MH_REDIRECT_OFF;
	else
		zmh_info->flags &= ~ZEBRA_EVPN_MH_REDIRECT_OFF;

	return 0;
}

void zebra_evpn_mh_init(void)
{
	zrouter.mh_info = XCALLOC(MTYPE_ZMH_INFO, sizeof(*zrouter.mh_info));

	zmh_info->mac_hold_time = ZEBRA_EVPN_MH_MAC_HOLD_TIME_DEF;
	zmh_info->neigh_hold_time = ZEBRA_EVPN_MH_NEIGH_HOLD_TIME_DEF;
	/* setup ES tables */
	RB_INIT(zebra_es_rb_head, &zmh_info->es_rb_tree);
	zmh_info->local_es_list = list_new();
	listset_app_node_mem(zmh_info->local_es_list);

	bf_init(zmh_info->nh_id_bitmap, EVPN_NH_ID_MAX);
	bf_assign_zero_index(zmh_info->nh_id_bitmap);
	zmh_info->nhg_table = hash_create(zebra_evpn_nhg_hash_keymake,
					  zebra_evpn_nhg_cmp, "l2 NHG table");
	zmh_info->nh_ip_table =
		hash_create(zebra_evpn_nh_ip_hash_keymake, zebra_evpn_nh_ip_cmp,
			    "l2 NH IP table");

	/* setup broadcast domain tables */
	zmh_info->evpn_vlan_table = hash_create(zebra_evpn_acc_vl_hash_keymake,
			zebra_evpn_acc_vl_cmp, "access VLAN hash table");

	zmh_info->startup_delay_time = ZEBRA_EVPN_MH_STARTUP_DELAY_DEF;
	zebra_evpn_mh_startup_delay_timer_start("init");
}

void zebra_evpn_mh_terminate(void)
{
	list_delete(&zmh_info->local_es_list);

	hash_iterate(zmh_info->evpn_vlan_table,
			zebra_evpn_acc_vl_cleanup_all, NULL);
	hash_free(zmh_info->evpn_vlan_table);
	hash_free(zmh_info->nhg_table);
	hash_free(zmh_info->nh_ip_table);
	bf_free(zmh_info->nh_id_bitmap);

	XFREE(MTYPE_ZMH_INFO, zrouter.mh_info);
}
