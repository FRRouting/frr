/*
 * Zebra EVPN Data structures and definitions
 * These are "internal" to this function.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 * Copyright (C) 2020 Volta Networks.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_EVPN_H
#define _ZEBRA_EVPN_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "bitfield.h"

#include "zebra/zebra_l2.h"
#include "zebra/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zebra_evpn_t_ zebra_evpn_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;

RB_HEAD(zebra_es_evi_rb_head, zebra_evpn_es_evi);
RB_PROTOTYPE(zebra_es_evi_rb_head, zebra_evpn_es_evi, rb_node,
	     zebra_es_evi_rb_cmp);

/* Private Structure to pass callback data for hash iterator */
struct zebra_evpn_show {
	struct vty *vty;
	json_object *json;
	struct zebra_vrf *zvrf;
	bool use_json;
};

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_ {
	/* Remote IP. */
	/* NOTE: Can only be IPv4 right now. */
	struct in_addr vtep_ip;
	/* Flood mode (one of enum vxlan_flood_control) based on the PMSI
	 * tunnel type advertised by the remote VTEP
	 */
	int flood_control;

	/* Links. */
	struct zebra_vtep_t_ *next;
	struct zebra_vtep_t_ *prev;
};

/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_evpn_t_ {
	/* VNI - key */
	vni_t vni;

	/* ES flags */
	uint32_t flags;
#define ZEVPN_READY_FOR_BGP (1 << 0) /* ready to be sent to BGP */

	/* Flag for advertising gw macip */
	uint8_t advertise_gw_macip;

	/* Flag for advertising svi macip */
	uint8_t advertise_svi_macip;

	/* Flag for advertising gw macip */
	uint8_t advertise_subnet;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* List of remote VTEPs */
	zebra_vtep_t *vteps;

	/* Local IP */
	struct in_addr local_vtep_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* tenant VRF, if any */
	vrf_id_t vrf_id;

	/* List of local or remote MAC */
	struct hash *mac_table;

	/* List of local or remote neighbors (MAC+IP) */
	struct hash *neigh_table;

	/* RB tree of ES-EVIs */
	struct zebra_es_evi_rb_head es_evi_rb_tree;

	/* List of local ESs */
	struct list *local_es_evi_list;
};

struct interface *zvni_map_to_svi(vlanid_t vid, struct interface *br_if);

static inline struct interface *zevpn_map_to_svi(zebra_evpn_t *zevpn)
{
	struct interface *ifp;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return NULL;
	zif = ifp->info;
	if (!zif)
		return NULL;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return NULL;
	zl2_info = zif->l2info.vxl;
	return zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
}

int advertise_gw_macip_enabled(zebra_evpn_t *zevpn);
int advertise_svi_macip_enabled(zebra_evpn_t *zevpn);
void zebra_evpn_print(zebra_evpn_t *zevpn, void **ctxt);
void zebra_evpn_print_hash(struct hash_bucket *bucket, void *ctxt[]);
void zebra_evpn_print_hash_detail(struct hash_bucket *bucket, void *data);
int zebra_evpn_add_macip_for_intf(struct interface *ifp, zebra_evpn_t *zevpn);
int zebra_evpn_del_macip_for_intf(struct interface *ifp, zebra_evpn_t *zevpn);
int zebra_evpn_advertise_subnet(zebra_evpn_t *zevpn, struct interface *ifp,
				int advertise);
int zebra_evpn_gw_macip_add(struct interface *ifp, zebra_evpn_t *zevpn,
			    struct ethaddr *macaddr, struct ipaddr *ip);
int zebra_evpn_gw_macip_del(struct interface *ifp, zebra_evpn_t *zevpn,
			    struct ipaddr *ip);
void zebra_evpn_gw_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt);
void zebra_evpn_gw_macip_add_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt);
void zebra_evpn_svi_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					    void *ctxt);
zebra_evpn_t *zebra_evpn_map_vlan(struct interface *ifp,
				  struct interface *br_if, vlanid_t vid);
zebra_evpn_t *zebra_evpn_from_svi(struct interface *ifp,
				  struct interface *br_if);
struct interface *zebra_evpn_map_to_macvlan(struct interface *br_if,
					    struct interface *svi_if);
void zebra_evpn_install_mac_hash(struct hash_bucket *bucket, void *ctxt);
void zebra_evpn_read_mac_neigh(zebra_evpn_t *zevpn, struct interface *ifp);
unsigned int zebra_evpn_hash_keymake(const void *p);
bool zebra_evpn_hash_cmp(const void *p1, const void *p2);
int zebra_evpn_list_cmp(void *p1, void *p2);
void *zebra_evpn_alloc(void *p);
zebra_evpn_t *zebra_evpn_lookup(vni_t vni);
zebra_evpn_t *zebra_evpn_add(vni_t vni);
int zebra_evpn_del(zebra_evpn_t *zevpn);
int zebra_evpn_send_add_to_client(zebra_evpn_t *zevpn);
int zebra_evpn_send_del_to_client(zebra_evpn_t *zevpn);
zebra_vtep_t *zebra_evpn_vtep_find(zebra_evpn_t *zevpn,
				   struct in_addr *vtep_ip);
zebra_vtep_t *zebra_evpn_vtep_add(zebra_evpn_t *zevpn, struct in_addr *vtep_ip,
				  int flood_control);
int zebra_evpn_vtep_del(zebra_evpn_t *zevpn, zebra_vtep_t *zvtep);
int zebra_evpn_vtep_del_all(zebra_evpn_t *zevpn, int uninstall);
int zebra_evpn_vtep_install(zebra_evpn_t *zevpn, zebra_vtep_t *zvtep);
int zebra_evpn_vtep_uninstall(zebra_evpn_t *zevpn, struct in_addr *vtep_ip);
void zebra_evpn_handle_flooding_remote_vteps(struct hash_bucket *bucket,
					     void *zvrf);
void zebra_evpn_cleanup_all(struct hash_bucket *bucket, void *arg);
void process_remote_macip_add(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      uint8_t flags, uint32_t seq,
			      struct in_addr vtep_ip, esi_t *esi);
void process_remote_macip_del(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      struct in_addr vtep_ip);
void zebra_evpn_cfg_cleanup(struct hash_bucket *bucket, void *ctxt);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_EVPN_H */
