// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN Data structures and definitions
 * These are "internal" to this function.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 * Copyright (C) 2020 Volta Networks.
 */

#ifndef _ZEBRA_EVPN_H
#define _ZEBRA_EVPN_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "bitfield.h"

#include "zebra/zebra_l2.h"
#include "zebra/interface.h"
#include "zebra/zebra_vxlan.h"

#ifdef __cplusplus
extern "C" {
#endif

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
struct zebra_vtep {
	/* Remote IP. */
	/* NOTE: Can only be IPv4 right now. */
	struct in_addr vtep_ip;
	/* Flood mode (one of enum vxlan_flood_control) based on the PMSI
	 * tunnel type advertised by the remote VTEP
	 */
	int flood_control;

	/* Links. */
	struct zebra_vtep *next;
	struct zebra_vtep *prev;
};

/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_evpn {
	/* VNI - key */
	vni_t vni;

	/* ES flags */
	uint32_t flags;
#define ZEVPN_READY_FOR_BGP (1 << 0) /* ready to be sent to BGP */

	/* Corresponding Bridge information */
	vlanid_t vid;
	struct interface *bridge_if;

	/* Flag for advertising gw macip */
	uint8_t advertise_gw_macip;

	/* Flag for advertising svi macip */
	uint8_t advertise_svi_macip;

	/* Flag for advertising gw macip */
	uint8_t advertise_subnet;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* Corresponding SVI interface. */
	struct interface *svi_if;

	/* List of remote VTEPs */
	struct zebra_vtep *vteps;

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

/* for parsing evpn and vni contexts */
struct zebra_from_svi_param {
	struct interface *br_if;
	struct interface *svi_if;
	struct zebra_if *zif;
	uint8_t bridge_vlan_aware;
	vlanid_t vid;
};

struct interface *zvni_map_to_svi(vlanid_t vid, struct interface *br_if);

static inline struct interface *zevpn_map_to_svi(struct zebra_evpn *zevpn)
{
	struct interface *ifp;
	struct zebra_if *zif = NULL;
	struct zebra_vxlan_vni *vni;

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return NULL;
	zif = ifp->info;
	if (!zif)
		return NULL;
	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return NULL;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return NULL;

	return zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
}

int advertise_gw_macip_enabled(struct zebra_evpn *zevpn);
int advertise_svi_macip_enabled(struct zebra_evpn *zevpn);
void zebra_evpn_print(struct zebra_evpn *zevpn, void **ctxt);
void zebra_evpn_print_hash(struct hash_bucket *bucket, void *ctxt[]);
void zebra_evpn_print_hash_detail(struct hash_bucket *bucket, void *data);
int zebra_evpn_add_macip_for_intf(struct interface *ifp,
				  struct zebra_evpn *zevpn);
int zebra_evpn_del_macip_for_intf(struct interface *ifp,
				  struct zebra_evpn *zevpn);
int zebra_evpn_advertise_subnet(struct zebra_evpn *zevpn, struct interface *ifp,
				int advertise);
int zebra_evpn_gw_macip_add(struct interface *ifp, struct zebra_evpn *zevpn,
			    struct ethaddr *macaddr, struct ipaddr *ip);
int zebra_evpn_gw_macip_del(struct interface *ifp, struct zebra_evpn *zevpn,
			    struct ipaddr *ip);
void zebra_evpn_gw_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt);
void zebra_evpn_gw_macip_add_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt);
void zebra_evpn_svi_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					    void *ctxt);
struct zebra_evpn *zebra_evpn_map_vlan(struct interface *ifp,
				       struct interface *br_if, vlanid_t vid);
struct zebra_evpn *zebra_evpn_from_svi(struct interface *ifp,
				       struct interface *br_if);
struct interface *zebra_evpn_map_to_macvlan(struct interface *br_if,
					    struct interface *svi_if);
void zebra_evpn_rem_mac_install_all(struct zebra_evpn *zevpn);
void zebra_evpn_rem_mac_uninstall_all(struct zebra_evpn *zevpn);
void zebra_evpn_read_mac_neigh(struct zebra_evpn *zevpn, struct interface *ifp);
unsigned int zebra_evpn_hash_keymake(const void *p);
bool zebra_evpn_hash_cmp(const void *p1, const void *p2);
int zebra_evpn_list_cmp(void *p1, void *p2);
void *zebra_evpn_alloc(void *p);
struct zebra_evpn *zebra_evpn_lookup(vni_t vni);
struct zebra_evpn *zebra_evpn_add(vni_t vni);
int zebra_evpn_del(struct zebra_evpn *zevpn);
int zebra_evpn_send_add_to_client(struct zebra_evpn *zevpn);
int zebra_evpn_send_del_to_client(struct zebra_evpn *zevpn);
struct zebra_vtep *zebra_evpn_vtep_find(struct zebra_evpn *zevpn,
					struct in_addr *vtep_ip);
struct zebra_vtep *zebra_evpn_vtep_add(struct zebra_evpn *zevpn,
				       struct in_addr *vtep_ip,
				       int flood_control);
int zebra_evpn_vtep_del(struct zebra_evpn *zevpn, struct zebra_vtep *zvtep);
int zebra_evpn_vtep_del_all(struct zebra_evpn *zevpn, int uninstall);
int zebra_evpn_vtep_install(struct zebra_evpn *zevpn, struct zebra_vtep *zvtep);
int zebra_evpn_vtep_uninstall(struct zebra_evpn *zevpn,
			      struct in_addr *vtep_ip);
void zebra_evpn_handle_flooding_remote_vteps(struct hash_bucket *bucket,
					     void *zvrf);
void zebra_evpn_cleanup_all(struct hash_bucket *bucket, void *arg);
void zebra_evpn_rem_macip_add(vni_t vni, const struct ethaddr *macaddr,
			      uint16_t ipa_len, const struct ipaddr *ipaddr,
			      uint8_t flags, uint32_t seq,
			      struct in_addr vtep_ip, const esi_t *esi);
void zebra_evpn_rem_macip_del(vni_t vni, const struct ethaddr *macaddr,
			      uint16_t ipa_len, const struct ipaddr *ipaddr,
			      struct in_addr vtep_ip);
void zebra_evpn_cfg_cleanup(struct hash_bucket *bucket, void *ctxt);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_EVPN_H */
