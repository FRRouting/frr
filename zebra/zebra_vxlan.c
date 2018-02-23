/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "vlan.h"
#include "vxlan.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_l2.h"

DEFINE_MTYPE_STATIC(ZEBRA, HOST_PREFIX, "host prefix");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI, "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZL3VNI, "L3 VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI_VTEP, "VNI remote VTEP");
DEFINE_MTYPE_STATIC(ZEBRA, MAC, "VNI MAC");
DEFINE_MTYPE_STATIC(ZEBRA, NEIGH, "VNI Neighbor");

/* definitions */


/* static function declarations */
static int ip_prefix_send_to_client(vrf_id_t vrf_id,
					     struct prefix *p,
					     uint16_t cmd);
static void zvni_print_neigh(zebra_neigh_t *n, void *ctxt, json_object *json);
static void zvni_print_neigh_hash(struct hash_backet *backet, void *ctxt);
static void zvni_print_neigh_hash_all_vni(struct hash_backet *backet,
					  void **args);
static void zl3vni_print_nh(zebra_neigh_t *n, struct vty *vty,
			    json_object *json);
static void zl3vni_print_rmac(zebra_mac_t *zrmac, struct vty *vty,
			      json_object *json);
static void zvni_print_mac(zebra_mac_t *mac, void *ctxt);
static void zvni_print_mac_hash(struct hash_backet *backet, void *ctxt);
static void zvni_print_mac_hash_all_vni(struct hash_backet *backet, void *ctxt);
static void zvni_print(zebra_vni_t *zvni, void **ctxt);
static void zvni_print_hash(struct hash_backet *backet, void *ctxt[]);

static int zvni_macip_send_msg_to_client(vni_t vni,
					 struct ethaddr *macaddr,
					 struct ipaddr *ip, u_char flags,
					 u_int16_t cmd);
static unsigned int neigh_hash_keymake(void *p);
static int neigh_cmp(const void *p1, const void *p2);
static void *zvni_neigh_alloc(void *p);
static zebra_neigh_t *zvni_neigh_add(zebra_vni_t *zvni, struct ipaddr *ip,
				     struct ethaddr *mac);
static int zvni_neigh_del(zebra_vni_t *zvni, zebra_neigh_t *n);
static int zvni_neigh_del_hash_entry(struct hash_backet *backet, void *arg);
static void zvni_neigh_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				     struct in_addr *r_vtep_ip);
static void zvni_neigh_del_all(zebra_vni_t *zvni,
			       int uninstall, int upd_client, u_int32_t flags);
static zebra_neigh_t *zvni_neigh_lookup(zebra_vni_t *zvni, struct ipaddr *ip);
static int zvni_neigh_send_add_to_client(vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr, u_char flags);
static int zvni_neigh_send_del_to_client(vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr, u_char flags);
static int zvni_neigh_install(zebra_vni_t *zvni, zebra_neigh_t *n);
static int zvni_neigh_uninstall(zebra_vni_t *zvni, zebra_neigh_t *n);
static zebra_vni_t *zvni_from_svi(struct interface *ifp,
				 struct interface *br_if);
static struct interface *zvni_map_to_svi(vlanid_t vid,
					 struct interface *br_if);

/* l3-vni next-hop neigh related APIs */
static zebra_neigh_t *zl3vni_nh_lookup(zebra_l3vni_t *zl3vni,
				       struct ipaddr *ip);
static void *zl3vni_nh_alloc(void *p);
static zebra_neigh_t *zl3vni_nh_add(zebra_l3vni_t *zl3vni,
				    struct ipaddr *vtep_ip,
				    struct ethaddr *rmac);
static int zl3vni_nh_del(zebra_l3vni_t *zl3vni, zebra_neigh_t *n);
static int zl3vni_nh_install(zebra_l3vni_t *zl3vni, zebra_neigh_t *n);
static int zl3vni_nh_uninstall(zebra_l3vni_t *zl3vni, zebra_neigh_t *n);

/* l3-vni rmac related APIs */
static void zl3vni_print_rmac_hash(struct hash_backet *, void *);
static zebra_mac_t *zl3vni_rmac_lookup(zebra_l3vni_t *zl3vni,
				       struct ethaddr *rmac);
static void *zl3vni_rmac_alloc(void *p);
static zebra_mac_t *zl3vni_rmac_add(zebra_l3vni_t *zl3vni,
				    struct ethaddr *rmac);
static int zl3vni_rmac_del(zebra_l3vni_t *zl3vni, zebra_mac_t *zrmac);
static int zl3vni_rmac_install(zebra_l3vni_t *zl3vni, zebra_mac_t *zrmac);
static int zl3vni_rmac_uninstall(zebra_l3vni_t *zl3vni,
				 zebra_mac_t *zrmac);

/* l3-vni related APIs*/
static zebra_l3vni_t *zl3vni_lookup(vni_t vni);
static void *zl3vni_alloc(void *p);
static zebra_l3vni_t *zl3vni_add(vni_t vni, vrf_id_t vrf_id);
static int zl3vni_del(zebra_l3vni_t *zl3vni);
static zebra_l3vni_t *zl3vni_from_vrf(vrf_id_t);
static struct interface *zl3vni_map_to_svi_if(zebra_l3vni_t *zl3vni);
static struct interface *zl3vni_map_to_vxlan_if(zebra_l3vni_t *zl3vni);
static void zebra_vxlan_process_l3vni_oper_up(zebra_l3vni_t *zl3vni);
static void zebra_vxlan_process_l3vni_oper_down(zebra_l3vni_t *zl3vni);

static unsigned int mac_hash_keymake(void *p);
static int mac_cmp(const void *p1, const void *p2);
static void *zvni_mac_alloc(void *p);
static zebra_mac_t *zvni_mac_add(zebra_vni_t *zvni, struct ethaddr *macaddr);
static int zvni_mac_del(zebra_vni_t *zvni, zebra_mac_t *mac);
static int zvni_mac_del_hash_entry(struct hash_backet *backet, void *arg);
static void zvni_mac_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				   struct in_addr *r_vtep_ip);
static void zvni_mac_del_all(zebra_vni_t *zvni,
			     int uninstall, int upd_client, u_int32_t flags);
static zebra_mac_t *zvni_mac_lookup(zebra_vni_t *zvni, struct ethaddr *macaddr);
static int zvni_mac_send_add_to_client(vni_t vni,
				       struct ethaddr *macaddr, u_char flags);
static int zvni_mac_send_del_to_client(vni_t vni,
				       struct ethaddr *macaddr, u_char flags);
static zebra_vni_t *zvni_map_vlan(struct interface *ifp,
				  struct interface *br_if, vlanid_t vid);
static int zvni_mac_install(zebra_vni_t *zvni, zebra_mac_t *mac);
static int zvni_mac_uninstall(zebra_vni_t *zvni, zebra_mac_t *mac, int local);
static void zvni_install_mac_hash(struct hash_backet *backet, void *ctxt);

static unsigned int vni_hash_keymake(void *p);
static int vni_hash_cmp(const void *p1, const void *p2);
static void *zvni_alloc(void *p);
static zebra_vni_t *zvni_lookup(vni_t vni);
static zebra_vni_t *zvni_add(vni_t vni);
static int zvni_del(zebra_vni_t *zvni);
static int zvni_send_add_to_client(zebra_vni_t *zvni);
static int zvni_send_del_to_client(vni_t vni);
static void zvni_build_hash_table();
static int zvni_vtep_match(struct in_addr *vtep_ip, zebra_vtep_t *zvtep);
static zebra_vtep_t *zvni_vtep_find(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static zebra_vtep_t *zvni_vtep_add(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int zvni_vtep_del(zebra_vni_t *zvni, zebra_vtep_t *zvtep);
static int zvni_vtep_del_all(zebra_vni_t *zvni, int uninstall);
static int zvni_vtep_install(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int zvni_vtep_uninstall(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int zvni_del_macip_for_intf(struct interface *ifp, zebra_vni_t *zvni);
static int zvni_add_macip_for_intf(struct interface *ifp, zebra_vni_t *zvni);
static int zvni_gw_macip_add(struct interface *ifp, zebra_vni_t *zvni,
			     struct ethaddr *macaddr, struct ipaddr *ip);
static int zvni_gw_macip_del(struct interface *ifp, zebra_vni_t *zvni,
			     struct ipaddr *ip);
struct interface *zebra_get_vrr_intf_for_svi(struct interface *ifp);
static int advertise_gw_macip_enabled(zebra_vni_t *zvni);
static void zvni_deref_ip2mac(zebra_vni_t *zvni, zebra_mac_t *mac,
			      int uninstall);

/* Private functions */

/*
 * Return number of valid MACs in a VNI's MAC hash table - all
 * remote MACs and non-internal (auto) local MACs count.
 */
static u_int32_t num_valid_macs(zebra_vni_t *zvni)
{
	unsigned int i;
	u_int32_t num_macs = 0;
	struct hash *hash;
	struct hash_backet *hb;
	zebra_mac_t *mac;

	hash = zvni->mac_table;
	if (!hash)
		return num_macs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			mac = (zebra_mac_t *)hb->data;
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
			    || !CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
				num_macs++;
		}
	}

	return num_macs;
}

static int advertise_gw_macip_enabled(zebra_vni_t *zvni)
{
	struct zebra_vrf *zvrf;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (zvrf && zvrf->advertise_gw_macip)
		return 1;

	if (zvni && zvni->advertise_gw_macip)
		return 1;

	return 0;
}

/*
 * Helper function to determine maximum width of neighbor IP address for
 * display - just because we're dealing with IPv6 addresses that can
 * widely vary.
 */
static void zvni_find_neigh_addr_width(struct hash_backet *backet, void *ctxt)
{
	zebra_neigh_t *n;
	char buf[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;
	int width;

	n = (zebra_neigh_t *)backet->data;
	if (!n)
		return;

	ipaddr2str(&n->ip, buf, sizeof(buf)), width = strlen(buf);
	if (width > wctx->addr_width)
		wctx->addr_width = width;
}

/*
 * Print a specific neighbor entry.
 */
static void zvni_print_neigh(zebra_neigh_t *n, void *ctxt, json_object *json)
{
	struct vty *vty;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	vty = (struct vty *)ctxt;
	if (json == NULL) {
		vty_out(vty, "IP: %s\n",
			ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		vty_out(vty, " MAC: %s",
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
	} else {
		json_object_string_add(json, "ip", buf2);
		json_object_string_add(json, "mac", buf1);
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		if (json == NULL) {
			vty_out(vty, " Remote VTEP: %s",
				inet_ntoa(n->r_vtep_ip));
		} else
			json_object_string_add(json, "remoteVtep",
					       inet_ntoa(n->r_vtep_ip));
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
		if (!json) {
			vty_out(vty, "\n");
			vty_out(vty, " State: %s",
				IS_ZEBRA_NEIGH_ACTIVE(n) ? "Active"
							 : "Inactive");
		}
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW)) {
		if (!json)
			vty_out(vty, " Default-gateway");
		else
			json_object_boolean_true_add(json, "defaultGateway");
	}
	if (json == NULL)
		vty_out(vty, "\n");
}

/*
 * Print neighbor hash entry - called for display of all neighbors.
 */
static void zvni_print_neigh_hash(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	json_object *json_vni = NULL, *json_row = NULL;
	zebra_neigh_t *n;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;

	vty = wctx->vty;
	json_vni = wctx->json;
	n = (zebra_neigh_t *)backet->data;
	if (!n)
		return;

	if (json_vni)
		json_row = json_object_new_object();

	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)
	    && !(wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)) {
		if (json_vni == NULL) {
			vty_out(vty, "%*s %-6s %-17s\n", -wctx->addr_width,
				buf2, "local", buf1);
		} else {
			json_object_string_add(json_row, "type", "local");
			json_object_string_add(json_row, "mac", buf1);
		}
		wctx->count++;
	} else {
		if (wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP) {
			if (IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip)) {
				if (json_vni == NULL) {
					if (wctx->count == 0)
						vty_out(vty,
							"%*s %-6s %-17s %-21s\n",
							-wctx->addr_width,
							"Neighbor", "Type",
							"MAC", "Remote VTEP");
					vty_out(vty, "%*s %-6s %-17s %-21s\n",
						-wctx->addr_width, buf2,
						"remote", buf1,
						inet_ntoa(n->r_vtep_ip));
				} else {
					json_object_string_add(json_row, "type",
							       "remote");
					json_object_string_add(json_row, "mac",
							       buf1);
					json_object_string_add(
						json_row, "remoteVtep",
						inet_ntoa(n->r_vtep_ip));
				}
				wctx->count++;
			}
		} else {
			if (json_vni == NULL) {
				vty_out(vty, "%*s %-6s %-17s %-21s\n",
					-wctx->addr_width, buf2, "remote", buf1,
					inet_ntoa(n->r_vtep_ip));
			} else {
				json_object_string_add(json_row, "type",
						       "remote");
				json_object_string_add(json_row, "mac", buf1);
				json_object_string_add(json_row, "remoteVtep",
						       inet_ntoa(n->r_vtep_ip));
			}
			wctx->count++;
		}
	}

	if (json_vni)
		json_object_object_add(json_vni, buf2, json_row);
}

/*
 * Print neighbors for all VNI.
 */
static void zvni_print_neigh_hash_all_vni(struct hash_backet *backet,
					  void **args)
{
	struct vty *vty;
	json_object *json = NULL, *json_vni = NULL;
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];

	vty = (struct vty *)args[0];
	json = (json_object *)args[1];

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni) {
		if (json)
			vty_out(vty, "{}\n");
		return;
	}
	num_neigh = hashcount(zvni->neigh_table);
	if (json == NULL)
		vty_out(vty,
			"\nVNI %u #ARP (IPv4 and IPv6, local and remote) %u\n\n",
			zvni->vni, num_neigh);
	else {
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "numArpNd", num_neigh);
		snprintf(vni_str, VNI_STR_LEN, "%u", zvni->vni);
	}
	if (!num_neigh) {
		if (json)
			json_object_object_add(json, vni_str, json_vni);
		return;
	}

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json_vni;
	hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

	if (json == NULL)
		vty_out(vty, "%*s %-6s %-17s %-21s\n", -wctx.addr_width, "IP",
			"Type", "MAC", "Remote VTEP");
	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);

	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

/* print a specific next hop for an l3vni */
static void zl3vni_print_nh(zebra_neigh_t *n,
			    struct vty *vty,
			    json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct listnode *node = NULL;
	struct prefix *p = NULL;
	json_object *json_hosts = NULL;

	if (!json) {
		vty_out(vty, "Ip: %s\n",
			ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		vty_out(vty, "  RMAC: %s\n",
		       prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
		vty_out(vty, "  Refcount: %d\n", listcount(n->host_list));
		vty_out(vty, "  Prefixes:\n");
		for (ALL_LIST_ELEMENTS_RO(n->host_list, node, p))
			vty_out(vty, "    %s\n",
				prefix2str(p, buf2, sizeof(buf2)));
	} else {
		json_hosts = json_object_new_array();
		json_object_string_add(json, "ip",
				       ipaddr2str(&(n->ip), buf2,
						  sizeof(buf2)));
		json_object_string_add(json, "routerMac",
				       prefix_mac2str(&n->emac, buf2,
						      sizeof(buf2)));
		json_object_int_add(json, "refCount", listcount(n->host_list));
		for (ALL_LIST_ELEMENTS_RO(n->host_list, node, p))
			json_object_array_add(json_hosts,
					      json_object_new_string(
							prefix2str(p, buf2,
								sizeof(buf2))));
		json_object_object_add(json, "prefixList", json_hosts);
	}
}

/* Print a specific RMAC entry */
static void zl3vni_print_rmac(zebra_mac_t *zrmac,
			      struct vty *vty,
			      json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[PREFIX_STRLEN];
	struct listnode *node = NULL;
	struct prefix *p = NULL;
	json_object *json_hosts = NULL;

	if (!json) {
		vty_out(vty, "MAC: %s\n",
			prefix_mac2str(&zrmac->macaddr, buf1, sizeof(buf1)));
		vty_out(vty, " Remote VTEP: %s\n",
			inet_ntoa(zrmac->fwd_info.r_vtep_ip));
		vty_out(vty, " Refcount: %d\n", listcount(zrmac->host_list));
		vty_out(vty, "  Prefixes:\n");
		for (ALL_LIST_ELEMENTS_RO(zrmac->host_list, node, p))
			vty_out(vty, "    %s\n",
				prefix2str(p, buf2, sizeof(buf2)));
	} else {
		json_hosts = json_object_new_array();
		json_object_string_add(json, "routerMac",
				       prefix_mac2str(&zrmac->macaddr,
						      buf1,
						      sizeof(buf1)));
		json_object_string_add(json, "vtepIp",
				       inet_ntoa(zrmac->fwd_info.r_vtep_ip));
		json_object_int_add(json, "refCount",
				    listcount(zrmac->host_list));
		for (ALL_LIST_ELEMENTS_RO(zrmac->host_list, node, p))
			json_object_array_add(json_hosts,
					      json_object_new_string(
							prefix2str(p, buf2,
								sizeof(buf2))));
		json_object_object_add(json, "prefixList", json_hosts);
	}
}

/*
 * Print a specific MAC entry.
 */
static void zvni_print_mac(zebra_mac_t *mac, void *ctxt)
{
	struct vty *vty;
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf1[20];
	char buf2[INET6_ADDRSTRLEN];

	vty = (struct vty *)ctxt;
	vty_out(vty, "MAC: %s",
		prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1)));
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		struct zebra_ns *zns;
		struct interface *ifp;
		ifindex_t ifindex;

		ifindex = mac->fwd_info.local.ifindex;
		zns = zebra_ns_lookup(NS_DEFAULT);
		ifp = if_lookup_by_index_per_ns(zns, ifindex);
		if (!ifp) // unexpected
			return;
		vty_out(vty, " Intf: %s(%u)", ifp->name, ifindex);
		if (mac->fwd_info.local.vid)
			vty_out(vty, " VLAN: %u", mac->fwd_info.local.vid);
	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		vty_out(vty, " Remote VTEP: %s",
			inet_ntoa(mac->fwd_info.r_vtep_ip));
	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)) {
		vty_out(vty, " Auto Mac ");
	}

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
		vty_out(vty, " Sticky Mac ");

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW))
		vty_out(vty, " Default-gateway Mac ");

	vty_out(vty, "\n");
	/* print all the associated neigh */
	vty_out(vty, " Neighbors:\n");
	if (!listcount(mac->neigh_list))
		vty_out(vty, "    No Neighbors\n");
	else {
		for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, n)) {
			vty_out(vty, "    %s %s\n",
				ipaddr2str(&n->ip, buf2, sizeof(buf2)),
				CHECK_FLAG(n->flags, ZEBRA_MAC_LOCAL)
					? (IS_ZEBRA_NEIGH_ACTIVE(n)
						   ? "Active"
						   : "Inactive")
					: "");
		}
	}

	vty_out(vty, "\n");
}

/*
 * Print MAC hash entry - called for display of all MACs.
 */
static void zvni_print_mac_hash(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	json_object *json_mac_hdr = NULL, *json_mac = NULL;
	zebra_mac_t *mac;
	char buf1[20];
	struct mac_walk_ctx *wctx = ctxt;

	vty = wctx->vty;
	json_mac_hdr = wctx->json;
	mac = (zebra_mac_t *)backet->data;
	if (!mac)
		return;

	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	if (json_mac_hdr)
		json_mac = json_object_new_object();

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
	    && !(wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP)) {
		struct zebra_ns *zns;
		ifindex_t ifindex;
		struct interface *ifp;
		vlanid_t vid;

		zns = zebra_ns_lookup(NS_DEFAULT);
		ifindex = mac->fwd_info.local.ifindex;
		ifp = if_lookup_by_index_per_ns(zns, ifindex);
		if (!ifp) // unexpected
			return;
		vid = mac->fwd_info.local.vid;
		if (json_mac_hdr == NULL)
			vty_out(vty, "%-17s %-6s %-21s", buf1, "local",
				ifp->name);
		else {
			json_object_string_add(json_mac, "type", "local");
			json_object_string_add(json_mac, "intf", ifp->name);
		}
		if (vid) {
			if (json_mac_hdr == NULL)
				vty_out(vty, " %-5u", vid);
			else
				json_object_int_add(json_mac, "vlan", vid);
		}
		if (json_mac_hdr == NULL)
			vty_out(vty, "\n");
		else
			json_object_object_add(json_mac_hdr, buf1, json_mac);
		wctx->count++;
	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		if (wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP) {
			if (IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
					   &wctx->r_vtep_ip)) {
				if (wctx->count == 0) {
					if (json_mac_hdr == NULL) {
						vty_out(vty, "\nVNI %u\n\n",
							wctx->zvni->vni);
						vty_out(vty,
							"%-17s %-6s %-21s %-5s\n",
							"MAC", "Type",
							"Intf/Remote VTEP",
							"VLAN");
					}
				}
				if (json_mac_hdr == NULL)
					vty_out(vty, "%-17s %-6s %-21s\n", buf1,
						"remote",
						inet_ntoa(mac->fwd_info
								  .r_vtep_ip));
				else {
					json_object_string_add(json_mac, "type",
							       "remote");
					json_object_string_add(
						json_mac, "remoteVtep",
						inet_ntoa(mac->fwd_info
								  .r_vtep_ip));
					json_object_object_add(json_mac_hdr,
							       buf1, json_mac);
				}
				wctx->count++;
			}
		} else {
			if (json_mac_hdr == NULL)
				vty_out(vty, "%-17s %-6s %-21s\n", buf1,
					"remote",
					inet_ntoa(mac->fwd_info.r_vtep_ip));
			else {
				json_object_string_add(json_mac, "type",
						       "remote");
				json_object_string_add(
					json_mac, "remoteVtep",
					inet_ntoa(mac->fwd_info.r_vtep_ip));
				json_object_object_add(json_mac_hdr, buf1,
						       json_mac);
			}
			wctx->count++;
		}
	}
}

/*
 * Print MACs for all VNI.
 */
static void zvni_print_mac_hash_all_vni(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	json_object *json = NULL, *json_vni = NULL;
	json_object *json_mac = NULL;
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx *wctx = ctxt;
	char vni_str[VNI_STR_LEN];

	vty = (struct vty *)wctx->vty;
	json = (struct json_object *)wctx->json;

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni) {
		if (json)
			vty_out(vty, "{}\n");
		return;
	}
	wctx->zvni = zvni;

	/*We are iterating over a new VNI, set the count to 0*/
	wctx->count = 0;

	num_macs = num_valid_macs(zvni);
	if (!num_macs)
		return;

	if (json) {
		json_vni = json_object_new_object();
		json_mac = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zvni->vni);
	}

	if (!CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP)) {
		if (json == NULL) {
			vty_out(vty, "\nVNI %u #MACs (local and remote) %u\n\n",
				zvni->vni, num_macs);
			vty_out(vty, "%-17s %-6s %-21s %-5s\n", "MAC", "Type",
				"Intf/Remote VTEP", "VLAN");
		} else
			json_object_int_add(json_vni, "numMacs", num_macs);
	}
	/* assign per-vni to wctx->json object to fill macs
	 * under the vni. Re-assign primary json object to fill
	 * next vni information.
	 */
	wctx->json = json_mac;
	hash_iterate(zvni->mac_table, zvni_print_mac_hash, wctx);
	wctx->json = json;
	if (json) {
		if (wctx->count)
			json_object_object_add(json_vni, "macs", json_mac);
		json_object_object_add(json, vni_str, json_vni);
	}
}

static void zl3vni_print_nh_hash(struct hash_backet *backet,
				 void *ctx)
{
	struct nh_walk_ctx *wctx = NULL;
	struct vty *vty = NULL;
	struct json_object *json_vni = NULL;
	struct json_object *json_nh = NULL;
	zebra_neigh_t *n = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	wctx = (struct nh_walk_ctx *)ctx;
	vty = wctx->vty;
	json_vni = wctx->json;
	if (json_vni)
		json_nh = json_object_new_object();
	n = (zebra_neigh_t *)backet->data;
	if (!n)
		return;

	if (!json_vni) {
		vty_out(vty, "%-15s %-17s\n",
			ipaddr2str(&(n->ip), buf2, sizeof(buf2)),
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
	} else {
		json_object_string_add(json_nh, "nexthopIp",
				       ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		json_object_string_add(json_nh, "routerMac",
				       prefix_mac2str(&n->emac, buf1,
						      sizeof(buf1)));
		json_object_object_add(json_vni,
				       ipaddr2str(&(n->ip), buf2, sizeof(buf2)),
				       json_nh);
	}
}

static void zl3vni_print_nh_hash_all_vni(struct hash_backet *backet,
					 void **args)
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	json_object *json_vni = NULL;
	zebra_l3vni_t *zl3vni = NULL;
	uint32_t num_nh = 0;
	struct nh_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	zl3vni = (zebra_l3vni_t *)backet->data;
	if (!zl3vni) {
		if (json)
			vty_out(vty, "{}\n");
		return;
	}

	num_nh = hashcount(zl3vni->nh_table);
	if (!num_nh)
		return;

	if (json) {
		json_vni = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zl3vni->vni);
	}

	if (json == NULL) {
		vty_out(vty, "\nVNI %u #Next-Hops %u\n\n",
			zl3vni->vni, num_nh);
		vty_out(vty, "%-15s %-17s\n", "IP", "RMAC");
	} else
		json_object_int_add(json_vni, "numNextHops", num_nh);

	memset(&wctx, 0, sizeof(struct nh_walk_ctx));
	wctx.vty = vty;
	wctx.json = json_vni;
	hash_iterate(zl3vni->nh_table, zl3vni_print_nh_hash, &wctx);
	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

static void zl3vni_print_rmac_hash_all_vni(struct hash_backet *backet,
					   void **args)
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	json_object *json_vni = NULL;
	zebra_l3vni_t *zl3vni = NULL;
	u_int32_t num_rmacs;
	struct rmac_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	zl3vni = (zebra_l3vni_t *)backet->data;
	if (!zl3vni) {
		if (json)
			vty_out(vty, "{}\n");
		return;
	}

	num_rmacs = hashcount(zl3vni->rmac_table);
	if (!num_rmacs)
		return;

	if (json) {
		json_vni = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zl3vni->vni);
	}

	if (json == NULL) {
		vty_out(vty, "\nVNI %u #RMACs %u\n\n",
			zl3vni->vni, num_rmacs);
		vty_out(vty, "%-17s %-21s\n", "RMAC", "Remote VTEP");
	} else
		json_object_int_add(json_vni, "numRmacs", num_rmacs);

	/* assign per-vni to wctx->json object to fill macs
	 * under the vni. Re-assign primary json object to fill
	 * next vni information.
	 */
	memset(&wctx, 0, sizeof(struct rmac_walk_ctx));
	wctx.vty = vty;
	wctx.json = json_vni;
	hash_iterate(zl3vni->rmac_table, zl3vni_print_rmac_hash, &wctx);
	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

static void zl3vni_print_rmac_hash(struct hash_backet *backet,
				   void *ctx)
{
	zebra_mac_t *zrmac = NULL;
	struct rmac_walk_ctx *wctx = NULL;
	struct vty *vty = NULL;
	struct json_object *json = NULL;
	struct json_object *json_rmac = NULL;
	char buf[ETHER_ADDR_STRLEN];

	wctx = (struct rmac_walk_ctx *)ctx;
	vty = wctx->vty;
	json = wctx->json;
	if (json)
		json_rmac = json_object_new_object();
	zrmac = (zebra_mac_t *)backet->data;
	if (!zrmac)
		return;

	if (!json) {
		vty_out(vty, "%-17s %-21s\n",
			prefix_mac2str(&zrmac->macaddr, buf, sizeof(buf)),
					inet_ntoa(zrmac->fwd_info.r_vtep_ip));
	} else {
		json_object_string_add(json_rmac, "routerMac",
				       prefix_mac2str(&zrmac->macaddr, buf,
						      sizeof(buf)));
		json_object_string_add(json_rmac, "vtepIp",
				       inet_ntoa(zrmac->fwd_info.r_vtep_ip));
		json_object_object_add(json,
				       prefix_mac2str(&zrmac->macaddr, buf,
						      sizeof(buf)),
				       json_rmac);
	}
}

/* print a specific L3 VNI entry */
static void zl3vni_print(zebra_l3vni_t *zl3vni, void **ctx)
{
	char buf[ETHER_ADDR_STRLEN];
	struct vty *vty = NULL;
	json_object *json = NULL;
	zebra_vni_t *zvni = NULL;
	json_object *json_vni_list = NULL;
	struct listnode *node = NULL, *nnode = NULL;

	vty = ctx[0];
	json = ctx[1];

	if (!json) {
		vty_out(vty, "VNI: %u\n", zl3vni->vni);
		vty_out(vty, "  Type: %s\n", "L3");
		vty_out(vty, "  Tenant VRF: %s\n",
			zl3vni_vrf_name(zl3vni));
		vty_out(vty, "  Local Vtep Ip: %s\n",
			inet_ntoa(zl3vni->local_vtep_ip));
		vty_out(vty, "  Vxlan-Intf: %s\n",
			zl3vni_vxlan_if_name(zl3vni));
		vty_out(vty, "  SVI-If: %s\n",
			zl3vni_svi_if_name(zl3vni));
		vty_out(vty, "  State: %s\n",
			zl3vni_state2str(zl3vni));
		vty_out(vty, "  Router MAC: %s\n",
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
		vty_out(vty, "  L2 VNIs: ");
		for (ALL_LIST_ELEMENTS(zl3vni->l2vnis, node, nnode, zvni))
			vty_out(vty, "%u ", zvni->vni);
		vty_out(vty, "\n");
	} else {
		json_vni_list = json_object_new_array();
		json_object_int_add(json, "vni", zl3vni->vni);
		json_object_string_add(json, "type", "L3");
		json_object_string_add(json, "localVtepIp",
				       inet_ntoa(zl3vni->local_vtep_ip));
		json_object_string_add(json, "vxlanIntf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_string_add(json, "sviIntf",
				       zl3vni_svi_if_name(zl3vni));
		json_object_string_add(json, "state",
				       zl3vni_state2str(zl3vni));
		json_object_string_add(json, "vrf",
				       zl3vni_vrf_name(zl3vni));
		json_object_string_add(json, "routerMac",
				       zl3vni_rmac2str(zl3vni, buf,
						       sizeof(buf)));
		for (ALL_LIST_ELEMENTS(zl3vni->l2vnis, node, nnode, zvni)) {
			json_object_array_add(json_vni_list,
					      json_object_new_int(zvni->vni));
		}
		json_object_object_add(json, "l2Vnis", json_vni_list);
	}
}

/*
 * Print a specific VNI entry.
 */
static void zvni_print(zebra_vni_t *zvni, void **ctxt)
{
	struct vty *vty;
	zebra_vtep_t *zvtep;
	u_int32_t num_macs;
	u_int32_t num_neigh;
	json_object *json = NULL;
	json_object *json_vtep_list = NULL;
	json_object *json_ip_str = NULL;

	vty = ctxt[0];
	json = ctxt[1];

	if (json == NULL) {
		vty_out(vty, "VNI: %u\n", zvni->vni);
		vty_out(vty, " Type: %s\n", "L2");
		vty_out(vty, " Tenant VRF: %s\n", vrf_id_to_name(zvni->vrf_id));
	} else {
		json_object_int_add(json, "vni", zvni->vni);
		json_object_string_add(json, "type", "L2");
		json_object_string_add(json, "vrf",
				       vrf_id_to_name(zvni->vrf_id));
	}

	if (!zvni->vxlan_if) { // unexpected
		if (json == NULL)
			vty_out(vty, " VxLAN interface: unknown\n");
		return;
	}
	num_macs = num_valid_macs(zvni);
	num_neigh = hashcount(zvni->neigh_table);
	if (json == NULL) {
		vty_out(vty, " VxLAN interface: %s\n",
			zvni->vxlan_if->name);
		vty_out(vty, " VxLAN ifIndex: %u\n", zvni->vxlan_if->ifindex);
		vty_out(vty," Local VTEP IP: %s\n",
			inet_ntoa(zvni->local_vtep_ip));
	} else {
		json_object_string_add(json, "vxlanInterface",
				       zvni->vxlan_if->name);
		json_object_int_add(json, "ifindex", zvni->vxlan_if->ifindex);
		json_object_string_add(json, "vtepIp",
				       inet_ntoa(zvni->local_vtep_ip));
		json_object_string_add(json, "advertiseGatewayMacip",
				       zvni->advertise_gw_macip ? "Yes" : "No");
		json_object_int_add(json, "numMacs", num_macs);
		json_object_int_add(json, "numArpNd", num_neigh);
	}
	if (!zvni->vteps) {
		if (json == NULL)
			vty_out(vty, " No remote VTEPs known for this VNI\n");
	} else {
		if (json == NULL)
			vty_out(vty, " Remote VTEPs for this VNI:\n");
		else
			json_vtep_list = json_object_new_array();
		for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next) {
			if (json == NULL)
				vty_out(vty, "  %s\n",
					inet_ntoa(zvtep->vtep_ip));
			else {
				json_ip_str = json_object_new_string(
					inet_ntoa(zvtep->vtep_ip));
				json_object_array_add(json_vtep_list,
						      json_ip_str);
			}
		}
		if (json)
			json_object_object_add(json, "numRemoteVteps",
					       json_vtep_list);
	}
	if (json == NULL) {
		vty_out(vty,
			" Number of MACs (local and remote) known for this VNI: %u\n",
			num_macs);
		vty_out(vty,
			" Number of ARPs (IPv4 and IPv6, local and remote) "
			"known for this VNI: %u\n",
			num_neigh);
		vty_out(vty, " Advertise-gw-macip: %s\n",
			zvni->advertise_gw_macip ? "Yes" : "No");
	}
}

/* print a L3 VNI hash entry */
static void zl3vni_print_hash(struct hash_backet *backet,
			      void *ctx[])
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	json_object *json_vni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	vty = (struct vty *)ctx[0];
	json = (json_object *)ctx[1];

	zl3vni = (zebra_l3vni_t *)backet->data;
	if (!zl3vni)
		return;

	if (!json) {
		vty_out(vty,
			"%-10u %-4s %-21s %-8lu %-8lu %-15s %-37s\n",
			zl3vni->vni, "L3",
			zl3vni_vxlan_if_name(zl3vni),
			hashcount(zl3vni->rmac_table),
			hashcount(zl3vni->nh_table),
			"n/a",
			zl3vni_vrf_name(zl3vni));
	} else {
		char vni_str[VNI_STR_LEN];

		snprintf(vni_str, VNI_STR_LEN, "%u", zl3vni->vni);
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", zl3vni->vni);
		json_object_string_add(json_vni, "vxlanIf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_int_add(json_vni, "numMacs",
				    hashcount(zl3vni->rmac_table));
		json_object_int_add(json_vni, "numArpNd",
				    hashcount(zl3vni->nh_table));
		json_object_string_add(json_vni, "numRemoteVteps", "n/a");
		json_object_string_add(json_vni, "type", "L3");
		json_object_string_add(json_vni, "tenantVrf",
				       zl3vni_vrf_name(zl3vni));
		json_object_object_add(json, vni_str, json_vni);
	}

}

/*
 * Print a VNI hash entry - called for display of all VNIs.
 */
static void zvni_print_hash(struct hash_backet *backet, void *ctxt[])
{
	struct vty *vty;
	zebra_vni_t *zvni;
	zebra_vtep_t *zvtep;
	u_int32_t num_vteps = 0;
	u_int32_t num_macs = 0;
	u_int32_t num_neigh = 0;
	json_object *json = NULL;
	json_object *json_vni = NULL;
	json_object *json_ip_str = NULL;
	json_object *json_vtep_list = NULL;

	vty = ctxt[0];
	json = ctxt[1];

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	zvtep = zvni->vteps;
	while (zvtep) {
		num_vteps++;
		zvtep = zvtep->next;
	}

	num_macs = num_valid_macs(zvni);
	num_neigh = hashcount(zvni->neigh_table);
	if (json == NULL)
		vty_out(vty,
			"%-10u %-4s %-21s %-8u %-8u %-15u %-37s\n",
			zvni->vni, "L2",
			zvni->vxlan_if ? zvni->vxlan_if->name : "unknown",
			num_macs, num_neigh, num_vteps,
			vrf_id_to_name(zvni->vrf_id));
	else {
		char vni_str[VNI_STR_LEN];
		snprintf(vni_str, VNI_STR_LEN, "%u", zvni->vni);
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", zvni->vni);
		json_object_string_add(json_vni, "type", "L2");
		json_object_string_add(json_vni, "vxlanIf",
				       zvni->vxlan_if ? zvni->vxlan_if->name
						      : "unknown");
		json_object_int_add(json_vni, "numMacs", num_macs);
		json_object_int_add(json_vni, "numArpNd", num_neigh);
		json_object_int_add(json_vni, "numRemoteVteps", num_vteps);
		json_object_string_add(json_vni, "tenantVrf",
				       vrf_id_to_name(zvni->vrf_id));
		if (num_vteps) {
			json_vtep_list = json_object_new_array();
			for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next) {
				json_ip_str = json_object_new_string(
					inet_ntoa(zvtep->vtep_ip));
				json_object_array_add(json_vtep_list,
						      json_ip_str);
			}
			json_object_object_add(json_vni, "remoteVteps",
					       json_vtep_list);
		}
		json_object_object_add(json, vni_str, json_vni);
	}
}

/*
 * Inform BGP about local MACIP.
 */
static int zvni_macip_send_msg_to_client(vni_t vni,
					 struct ethaddr *macaddr,
					 struct ipaddr *ip, u_char flags,
					 u_int16_t cmd)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	int ipa_len;
	struct zserv *client = NULL;
	struct stream *s = NULL;

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putl(s, vni);
	stream_put(s, macaddr->octet, ETH_ALEN);
	if (ip) {
		ipa_len = 0;
		if (IS_IPADDR_V4(ip))
			ipa_len = IPV4_MAX_BYTELEN;
		else if (IS_IPADDR_V6(ip))
			ipa_len = IPV6_MAX_BYTELEN;

		stream_putl(s, ipa_len); /* IP address length */
		if (ipa_len)
			stream_put(s, &ip->ip.addr, ipa_len); /* IP address */
	} else
		stream_putl(s, 0); /* Just MAC. */

	stream_putc(s, flags); /* sticky mac/gateway mac */


	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Send MACIP %s flags 0x%x MAC %s IP %s L2-VNI %u to %s",
			(cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			flags, prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)), vni,
			zebra_route_string(client->proto));

	if (cmd == ZEBRA_MACIP_ADD)
		client->macipadd_cnt++;
	else
		client->macipdel_cnt++;

	return zebra_server_send_message(client);
}

/*
 * Make hash key for neighbors.
 */
static unsigned int neigh_hash_keymake(void *p)
{
	zebra_neigh_t *n = p;
	struct ipaddr *ip = &n->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32,
		      ZEBRA_NUM_OF(ip->ipaddr_v6.s6_addr32), 0);
}

/*
 * Compare two neighbor hash structures.
 */
static int neigh_cmp(const void *p1, const void *p2)
{
	const zebra_neigh_t *n1 = p1;
	const zebra_neigh_t *n2 = p2;

	if (n1 == NULL && n2 == NULL)
		return 1;

	if (n1 == NULL || n2 == NULL)
		return 0;

	return (memcmp(&n1->ip, &n2->ip, sizeof(struct ipaddr)) == 0);
}

/*
 * Callback to allocate neighbor hash entry.
 */
static void *zvni_neigh_alloc(void *p)
{
	const zebra_neigh_t *tmp_n = p;
	zebra_neigh_t *n;

	n = XCALLOC(MTYPE_NEIGH, sizeof(zebra_neigh_t));
	*n = *tmp_n;

	return ((void *)n);
}

/*
 * Add neighbor entry.
 */
static zebra_neigh_t *zvni_neigh_add(zebra_vni_t *zvni, struct ipaddr *ip,
				     struct ethaddr *mac)
{
	zebra_neigh_t tmp_n;
	zebra_neigh_t *n = NULL;
	zebra_mac_t *zmac = NULL;

	memset(&tmp_n, 0, sizeof(zebra_neigh_t));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = hash_get(zvni->neigh_table, &tmp_n, zvni_neigh_alloc);
	assert(n);

	memcpy(&n->emac, mac, ETH_ALEN);
	n->state = ZEBRA_NEIGH_INACTIVE;

	/* Associate the neigh to mac */
	zmac = zvni_mac_lookup(zvni, mac);
	if (zmac)
		listnode_add_sort(zmac->neigh_list, n);

	return n;
}

/*
 * Delete neighbor entry.
 */
static int zvni_neigh_del(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	zebra_neigh_t *tmp_n;
	zebra_mac_t *zmac = NULL;

	zmac = zvni_mac_lookup(zvni, &n->emac);
	if (zmac)
		listnode_delete(zmac->neigh_list, n);

	/* Free the VNI hash entry and allocated memory. */
	tmp_n = hash_release(zvni->neigh_table, n);
	if (tmp_n)
		XFREE(MTYPE_NEIGH, tmp_n);

	return 0;
}

/*
 * Free neighbor hash entry (callback)
 */
static int zvni_neigh_del_hash_entry(struct hash_backet *backet, void *arg)
{
	struct neigh_walk_ctx *wctx = arg;
	zebra_neigh_t *n = backet->data;

	if (((wctx->flags & DEL_LOCAL_NEIGH) && (n->flags & ZEBRA_NEIGH_LOCAL))
	    || ((wctx->flags & DEL_REMOTE_NEIGH)
		&& (n->flags & ZEBRA_NEIGH_REMOTE))
	    || ((wctx->flags & DEL_REMOTE_NEIGH_FROM_VTEP)
		&& (n->flags & ZEBRA_NEIGH_REMOTE)
		&& IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip))) {
		if (wctx->upd_client && (n->flags & ZEBRA_NEIGH_LOCAL))
			zvni_neigh_send_del_to_client(wctx->zvni->vni, &n->ip,
						      &n->emac, 0);

		if (wctx->uninstall)
			zvni_neigh_uninstall(wctx->zvni, n);

		return zvni_neigh_del(wctx->zvni, n);
	}

	return 0;
}

/*
 * Delete all neighbor entries from specific VTEP for a particular VNI.
 */
static void zvni_neigh_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				     struct in_addr *r_vtep_ip)
{
	struct neigh_walk_ctx wctx;

	if (!zvni->neigh_table)
		return;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.uninstall = uninstall;
	wctx.flags = DEL_REMOTE_NEIGH_FROM_VTEP;
	wctx.r_vtep_ip = *r_vtep_ip;

	hash_iterate(zvni->neigh_table,
		     (void (*)(struct hash_backet *,
			       void *))zvni_neigh_del_hash_entry,
		     &wctx);
}

/*
 * Delete all neighbor entries for this VNI.
 */
static void zvni_neigh_del_all(zebra_vni_t *zvni,
			       int uninstall, int upd_client, u_int32_t flags)
{
	struct neigh_walk_ctx wctx;

	if (!zvni->neigh_table)
		return;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(zvni->neigh_table,
		     (void (*)(struct hash_backet *,
			       void *))zvni_neigh_del_hash_entry,
		     &wctx);
}

/*
 * Look up neighbor hash entry.
 */
static zebra_neigh_t *zvni_neigh_lookup(zebra_vni_t *zvni, struct ipaddr *ip)
{
	zebra_neigh_t tmp;
	zebra_neigh_t *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	n = hash_lookup(zvni->neigh_table, &tmp);

	return n;
}

/* Process all neigh associated to a mac upon local mac add event */
static void zvni_process_neigh_on_local_mac_add(zebra_vni_t *zvni,
						zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			/* MAC is learnt locally, program all inactive neigh
			 * pointing to this mac */
			if (IS_ZEBRA_NEIGH_INACTIVE(n)) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"neigh %s (MAC %s) on L2-VNI %u is now ACTIVE",
						ipaddr2str(&n->ip, buf2,
							   sizeof(buf2)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						zvni->vni);

				ZEBRA_NEIGH_SET_ACTIVE(n);
				zvni_neigh_send_add_to_client(
					zvni->vni, &n->ip, &n->emac, n->flags);
			} else {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"neigh %s (MAC %s) on VNI %u should NOT be ACTIVE",
						ipaddr2str(&n->ip, buf2,
							   sizeof(buf2)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						zvni->vni);
			}
		} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			/* TODO: assume the neigh has moved too ?? */
		}
	}
}

/* Process all neigh associated to a mac upon local mac del event */
static void zvni_process_neigh_on_local_mac_del(zebra_vni_t *zvni,
						zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_NEIGH_ACTIVE(n)) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"neigh %s (MAC %s) on L2-VNI %u is now INACTIVE",
						ipaddr2str(&n->ip, buf2,
							   sizeof(buf2)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						zvni->vni);

				ZEBRA_NEIGH_SET_INACTIVE(n);
				zvni_neigh_send_del_to_client(
					zvni->vni, &n->ip, &n->emac, 0);
			}
		} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_err(
					"local MAC %s getting deleted on VNI %u has remote neigh %s",
					prefix_mac2str(&n->emac, buf,
						       sizeof(buf)),
					zvni->vni,
					ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		}
	}
}

/* process all neigh associated to a mac entry upon remote mac add */
static void zvni_process_neigh_on_remote_mac_add(zebra_vni_t *zvni,
						 zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_NEIGH_ACTIVE(n)) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"neigh %s (MAC %s) on L2-VNI %u is now INACTIVE",
						ipaddr2str(&n->ip, buf2,
							   sizeof(buf2)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						zvni->vni);

				ZEBRA_NEIGH_SET_INACTIVE(n);
				zvni_neigh_send_del_to_client(
					zvni->vni, &n->ip, &n->emac, 0);
			}
		}
	}
}

/* process all neigh associated to mac entry upon remote mac del */
static void zvni_process_neigh_on_remote_mac_del(zebra_vni_t *zvni,
						 zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_err(
					"remote  MAC %s getting deleted on VNI %u has local neigh %s",
					prefix_mac2str(&n->emac, buf,
						       sizeof(buf)),
					zvni->vni,
					ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		}
	}
}

/*
 * Inform BGP about local neighbor addition.
 */
static int zvni_neigh_send_add_to_client(vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr,
					 u_char neigh_flags)
{
	u_char			flags = 0;

	if (CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_DEF_GW))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	return zvni_macip_send_msg_to_client(vni, macaddr, ip, flags,
					     ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local neighbor deletion.
 */
static int zvni_neigh_send_del_to_client(vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr, u_char flags)
{
	return zvni_macip_send_msg_to_client(vni, macaddr, ip, flags,
					     ZEBRA_MACIP_DEL);
}

/*
 * Install remote neighbor into the kernel.
 */
static int zvni_neigh_install(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;

	vlan_if = zvni_map_to_svi(vxl->access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return -1;

	return kernel_add_neigh(vlan_if, &n->ip, &n->emac);
}

/*
 * Uninstall remote neighbor from the kernel.
 */
static int zvni_neigh_uninstall(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p couldn't be uninstalled - no intf",
			 zvni->vni, zvni);
		return -1;
	}

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;
	vlan_if = zvni_map_to_svi(vxl->access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return -1;

	return kernel_del_neigh(vlan_if, &n->ip);
}

/*
 * Install neighbor hash entry - called upon access VLAN change.
 */
static void zvni_install_neigh_hash(struct hash_backet *backet, void *ctxt)
{
	zebra_neigh_t *n;
	struct neigh_walk_ctx *wctx = ctxt;

	n = (zebra_neigh_t *)backet->data;
	if (!n)
		return;

	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		zvni_neigh_install(wctx->zvni, n);
}

/* Get the VRR interface for SVI if any */
struct interface *zebra_get_vrr_intf_for_svi(struct interface *ifp)
{
	struct zebra_vrf *zvrf = NULL;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif = NULL;

	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	FOR_ALL_INTERFACES (zvrf->vrf, tmp_if) {
		zif = tmp_if->info;
		if (!zif)
			continue;

		if (!IS_ZEBRA_IF_MACVLAN(tmp_if))
			continue;

		if (zif->link == ifp)
			return tmp_if;
	}

	return NULL;
}

static int zvni_del_macip_for_intf(struct interface *ifp, zebra_vni_t *zvni)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zvni_gw_macip_del(ifp, zvni, &ip);
	}

	return 0;
}

static int zvni_add_macip_for_intf(struct interface *ifp, zebra_vni_t *zvni)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zvni_gw_macip_add(ifp, zvni, &macaddr, &ip);
	}
	return 0;
}


static int zvni_advertise_subnet(zebra_vni_t *zvni,
				 struct interface *ifp,
				 int advertise)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct prefix p;

		memcpy(&p, c->address, sizeof(struct prefix));

		/* skip link local address */
		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			continue;

		apply_mask(&p);
		if (advertise)
			ip_prefix_send_to_client(ifp->vrf_id, &p,
						     ZEBRA_IP_PREFIX_ROUTE_ADD);
		else
			ip_prefix_send_to_client(ifp->vrf_id, &p,
						 ZEBRA_IP_PREFIX_ROUTE_DEL);
	}
	return 0;
}

/*
 * zvni_gw_macip_add_to_client
 */
static int zvni_gw_macip_add(struct interface *ifp, zebra_vni_t *zvni,
			     struct ethaddr *macaddr, struct ipaddr *ip)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	zebra_neigh_t *n = NULL;
	zebra_mac_t *mac = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;

	vxl = &zif->l2info.vxl;

	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac) {
		mac = zvni_mac_add(zvni, macaddr);
		if (!mac) {
			zlog_err("Failed to add MAC %s intf %s(%u) VID %u",
				 prefix_mac2str(macaddr, buf, sizeof(buf)),
				 ifp->name, ifp->ifindex, vxl->access_vlan);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
	SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	SET_FLAG(mac->flags, ZEBRA_MAC_DEF_GW);
	memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
	mac->fwd_info.local.ifindex = ifp->ifindex;
	mac->fwd_info.local.vid = vxl->access_vlan;

	n = zvni_neigh_lookup(zvni, ip);
	if (!n) {
		n = zvni_neigh_add(zvni, ip, macaddr);
		if (!n) {
			zlog_err(
				"Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
				ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, zvni->vni);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	SET_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW);
	memcpy(&n->emac, macaddr, ETH_ALEN);
	n->ifindex = ifp->ifindex;

	/* Only advertise in BGP if the knob is enabled */
	if (!advertise_gw_macip_enabled(zvni))
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"SVI %s(%u) L2-VNI %u, sending GW MAC %s IP %s add to BGP",
			ifp->name, ifp->ifindex, zvni->vni,
			prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)));

	zvni_neigh_send_add_to_client(zvni->vni, ip, macaddr,
				      n->flags);

	return 0;
}

/*
 * zvni_gw_macip_del_from_client
 */
static int zvni_gw_macip_del(struct interface *ifp, zebra_vni_t *zvni,
			     struct ipaddr *ip)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	zebra_neigh_t *n = NULL;
	zebra_mac_t *mac = NULL;

	/* If the neigh entry is not present nothing to do*/
	n = zvni_neigh_lookup(zvni, ip);
	if (!n)
		return 0;

	/* mac entry should be present */
	mac = zvni_mac_lookup(zvni, &n->emac);
	if (!mac) {
		zlog_err("MAC %s doesnt exists for neigh %s on VNI %u",
			 prefix_mac2str(&n->emac, buf1, sizeof(buf1)),
			 ipaddr2str(ip, buf2, sizeof(buf2)), zvni->vni);
		return -1;
	}

	/* If the entry is not local nothing to do*/
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
		return -1;

	/* only need to delete the entry from bgp if we sent it before */
	if (advertise_gw_macip_enabled(zvni)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%u:SVI %s(%u) VNI %u, sending GW MAC %s IP %s del to BGP",
				   ifp->vrf_id, ifp->name,
				   ifp->ifindex, zvni->vni,
				   prefix_mac2str(&(n->emac),
						  NULL,
						  ETHER_ADDR_STRLEN),
				   ipaddr2str(ip, buf2, sizeof(buf2)));

		/* Remove neighbor from BGP. */
		zvni_neigh_send_del_to_client(zvni->vni, &n->ip, &n->emac,
					      ZEBRA_MACIP_TYPE_GW);
	}

	/* Delete this neighbor entry. */
	zvni_neigh_del(zvni, n);

	/* see if the mac needs to be deleted as well*/
	if (mac)
		zvni_deref_ip2mac(zvni, mac, 0);

	return 0;
}

static void zvni_gw_macip_del_for_vni_hash(struct hash_backet *backet,
					   void *ctxt)
{
	zebra_vni_t *zvni = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp;

	/* Add primary SVI MAC*/
	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	ifp = zvni->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	zl2_info = zif->l2info.vxl;

	vlan_if = zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Del primary MAC-IP */
	zvni_del_macip_for_intf(vlan_if, zvni);

	/* Del VRR MAC-IP - if any*/
	vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
	if (vrr_if)
		zvni_del_macip_for_intf(vrr_if, zvni);

	return;
}

static void zvni_gw_macip_add_for_vni_hash(struct hash_backet *backet,
					   void *ctxt)
{
	zebra_vni_t *zvni = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp = NULL;

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	ifp = zvni->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;
	zl2_info = zif->l2info.vxl;

	vlan_if = zvni_map_to_svi(zl2_info.access_vlan,
				  zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Add primary SVI MAC-IP */
	zvni_add_macip_for_intf(vlan_if, zvni);

	/* Add VRR MAC-IP - if any*/
	vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
	if (vrr_if)
		zvni_add_macip_for_intf(vrr_if, zvni);

	return;
}

/*
 * Make hash key for MAC.
 */
static unsigned int mac_hash_keymake(void *p)
{
	zebra_mac_t *pmac = p;
	const void *pnt = (void *)pmac->macaddr.octet;

	return jhash(pnt, ETH_ALEN, 0xa5a5a55a);
}

/*
 * Compare two MAC addresses.
 */
static int mac_cmp(const void *p1, const void *p2)
{
	const zebra_mac_t *pmac1 = p1;
	const zebra_mac_t *pmac2 = p2;

	if (pmac1 == NULL && pmac2 == NULL)
		return 1;

	if (pmac1 == NULL || pmac2 == NULL)
		return 0;

	return (memcmp(pmac1->macaddr.octet, pmac2->macaddr.octet,
		       ETH_ALEN)
		== 0);
}

/*
 * Callback to allocate MAC hash entry.
 */
static void *zvni_mac_alloc(void *p)
{
	const zebra_mac_t *tmp_mac = p;
	zebra_mac_t *mac;

	mac = XCALLOC(MTYPE_MAC, sizeof(zebra_mac_t));
	*mac = *tmp_mac;

	return ((void *)mac);
}

/*
 * Add MAC entry.
 */
static zebra_mac_t *zvni_mac_add(zebra_vni_t *zvni, struct ethaddr *macaddr)
{
	zebra_mac_t tmp_mac;
	zebra_mac_t *mac = NULL;

	memset(&tmp_mac, 0, sizeof(zebra_mac_t));
	memcpy(&tmp_mac.macaddr, macaddr, ETH_ALEN);
	mac = hash_get(zvni->mac_table, &tmp_mac, zvni_mac_alloc);
	assert(mac);

	mac->neigh_list = list_new();
	mac->neigh_list->cmp = (int (*)(void *, void *))neigh_cmp;

	return mac;
}

/*
 * Delete MAC entry.
 */
static int zvni_mac_del(zebra_vni_t *zvni, zebra_mac_t *mac)
{
	zebra_mac_t *tmp_mac;

	list_delete_and_null(&mac->neigh_list);

	/* Free the VNI hash entry and allocated memory. */
	tmp_mac = hash_release(zvni->mac_table, mac);
	if (tmp_mac)
		XFREE(MTYPE_MAC, tmp_mac);

	return 0;
}

/*
 * Free MAC hash entry (callback)
 */
static int zvni_mac_del_hash_entry(struct hash_backet *backet, void *arg)
{
	struct mac_walk_ctx *wctx = arg;
	zebra_mac_t *mac = backet->data;

	if (((wctx->flags & DEL_LOCAL_MAC) && (mac->flags & ZEBRA_MAC_LOCAL))
	    || ((wctx->flags & DEL_REMOTE_MAC)
		&& (mac->flags & ZEBRA_MAC_REMOTE))
	    || ((wctx->flags & DEL_REMOTE_MAC_FROM_VTEP)
		&& (mac->flags & ZEBRA_MAC_REMOTE)
		&& IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
				  &wctx->r_vtep_ip))) {
		if (wctx->upd_client && (mac->flags & ZEBRA_MAC_LOCAL)) {
			zvni_mac_send_del_to_client(
				wctx->zvni->vni, &mac->macaddr,
				mac->flags);
		}

		if (wctx->uninstall)
			zvni_mac_uninstall(wctx->zvni, mac, 0);

		return zvni_mac_del(wctx->zvni, mac);
	}

	return 0;
}

/*
 * Delete all MAC entries from specific VTEP for a particular VNI.
 */
static void zvni_mac_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				   struct in_addr *r_vtep_ip)
{
	struct mac_walk_ctx wctx;

	if (!zvni->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.uninstall = uninstall;
	wctx.flags = DEL_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = *r_vtep_ip;

	hash_iterate(zvni->mac_table, (void (*)(struct hash_backet *,
						void *))zvni_mac_del_hash_entry,
		     &wctx);
}

/*
 * Delete all MAC entries for this VNI.
 */
static void zvni_mac_del_all(zebra_vni_t *zvni,
			     int uninstall, int upd_client, u_int32_t flags)
{
	struct mac_walk_ctx wctx;

	if (!zvni->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(zvni->mac_table, (void (*)(struct hash_backet *,
						void *))zvni_mac_del_hash_entry,
		     &wctx);
}

/*
 * Look up MAC hash entry.
 */
static zebra_mac_t *zvni_mac_lookup(zebra_vni_t *zvni, struct ethaddr *mac)
{
	zebra_mac_t tmp;
	zebra_mac_t *pmac;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.macaddr, mac, ETH_ALEN);
	pmac = hash_lookup(zvni->mac_table, &tmp);

	return pmac;
}

/*
 * Inform BGP about local MAC addition.
 */
static int zvni_mac_send_add_to_client(vni_t vni,
				       struct ethaddr *macaddr,
				       u_char mac_flags)
{
	u_char	flags = 0;

	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_STICKY))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_DEF_GW))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	return zvni_macip_send_msg_to_client(vni, macaddr, NULL, flags,
					     ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local MAC deletion.
 */
static int zvni_mac_send_del_to_client(vni_t vni,
				       struct ethaddr *macaddr,
				       u_char mac_flags)
{
	u_char	flags = 0;

	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_STICKY))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_DEF_GW))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	return zvni_macip_send_msg_to_client(vni, macaddr, NULL, flags,
					     ZEBRA_MACIP_DEL);
}

/*
 * Map port or (port, VLAN) to a VNI. This is invoked upon getting MAC
 * notifications, to see if they are of interest.
 */
static zebra_vni_t *zvni_map_vlan(struct interface *ifp,
				  struct interface *br_if, vlanid_t vid)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl = NULL;
	u_char bridge_vlan_aware;
	zebra_vni_t *zvni;
	int found = 0;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware || vxl->access_vlan == vid) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	zvni = zvni_lookup(vxl->vni);
	return zvni;
}

/*
 * Map SVI and associated bridge to a VNI. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 */
static zebra_vni_t *zvni_from_svi(struct interface *ifp,
				  struct interface *br_if)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl = NULL;
	u_char bridge_vlan_aware;
	vlanid_t vid = 0;
	zebra_vni_t *zvni;
	int found = 0;

	if (!br_if)
		return NULL;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;
	if (bridge_vlan_aware) {
		struct zebra_l2info_vlan *vl;

		if (!IS_ZEBRA_IF_VLAN(ifp))
			return NULL;

		zif = ifp->info;
		assert(zif);
		vl = &zif->l2info.vl;
		vid = vl->vid;
	}

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware || vxl->access_vlan == vid) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	zvni = zvni_lookup(vxl->vni);
	return zvni;
}

/* Map to SVI on bridge corresponding to specified VLAN. This can be one
 * of two cases:
 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN interface
 * linked to the bridge
 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge inteface
 * itself
 */
static struct interface *zvni_map_to_svi(vlanid_t vid, struct interface *br_if)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vlan *vl;
	u_char bridge_vlan_aware;
	int found = 0;

	/* Defensive check, caller expected to invoke only with valid bridge. */
	if (!br_if)
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;

	/* Check oper status of the SVI. */
	if (!bridge_vlan_aware)
		return if_is_operative(br_if) ? br_if : NULL;

	/* Identify corresponding VLAN interface. */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		/* Check oper status of the SVI. */
		if (!tmp_if || !if_is_operative(tmp_if))
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VLAN
		    || zif->link != br_if)
			continue;
		vl = (struct zebra_l2info_vlan *)&zif->l2info.vl;

		if (vl->vid == vid) {
			found = 1;
			break;
		}
	}

	return found ? tmp_if : NULL;
}

/*
 * Install remote MAC into the kernel.
 */
static int zvni_mac_install(zebra_vni_t *zvni, zebra_mac_t *mac)
{
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	u_char sticky;

	if (!(mac->flags & ZEBRA_MAC_REMOTE))
		return 0;

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;

	sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0;

	return kernel_add_mac(zvni->vxlan_if, vxl->access_vlan, &mac->macaddr,
			      mac->fwd_info.r_vtep_ip, sticky);
}

/*
 * Uninstall remote MAC from the kernel. In the scenario where the MAC
 * moves to remote, we have to uninstall any existing local entry first.
 */
static int zvni_mac_uninstall(zebra_vni_t *zvni, zebra_mac_t *mac, int local)
{
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct in_addr vtep_ip = {.s_addr = 0};
	struct zebra_ns *zns;
	struct interface *ifp;

	if (!local && !(mac->flags & ZEBRA_MAC_REMOTE))
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p couldn't be uninstalled - no intf",
			 zvni->vni, zvni);
		return -1;
	}

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;

	if (local) {
		zns = zebra_ns_lookup(NS_DEFAULT);
		ifp = if_lookup_by_index_per_ns(zns,
						mac->fwd_info.local.ifindex);
		if (!ifp) // unexpected
			return -1;
	} else {
		ifp = zvni->vxlan_if;
		vtep_ip = mac->fwd_info.r_vtep_ip;
	}

	return kernel_del_mac(ifp, vxl->access_vlan, &mac->macaddr, vtep_ip,
			      local);
}

/*
 * Install MAC hash entry - called upon access VLAN change.
 */
static void zvni_install_mac_hash(struct hash_backet *backet, void *ctxt)
{
	zebra_mac_t *mac;
	struct mac_walk_ctx *wctx = ctxt;

	mac = (zebra_mac_t *)backet->data;
	if (!mac)
		return;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		zvni_mac_install(wctx->zvni, mac);
}

/*
 * Decrement neighbor refcount of MAC; uninstall and free it if
 * appropriate.
 */
static void zvni_deref_ip2mac(zebra_vni_t *zvni, zebra_mac_t *mac,
			      int uninstall)
{
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)
	    || !list_isempty(mac->neigh_list))
		return;

	if (uninstall)
		zvni_mac_uninstall(zvni, mac, 0);

	zvni_mac_del(zvni, mac);
}

/*
 * Read and populate local MACs and neighbors corresponding to this VNI.
 */
static void zvni_read_mac_neigh(zebra_vni_t *zvni,
				struct interface *ifp)
{
	struct zebra_ns *zns;
	struct zebra_if *zif;
	struct interface *vlan_if;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vrr_if;

	zif = ifp->info;
	vxl = &zif->l2info.vxl;
	zns = zebra_ns_lookup(NS_DEFAULT);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
			ifp->name, ifp->ifindex, zvni->vni,
			zif->brslave_info.bridge_ifindex);

	macfdb_read_for_bridge(zns, ifp, zif->brslave_info.br_if);
	vlan_if = zvni_map_to_svi(vxl->access_vlan, zif->brslave_info.br_if);
	if (vlan_if) {

		/* Add SVI MAC-IP */
		zvni_add_macip_for_intf(vlan_if, zvni);

		/* Add VRR MAC-IP - if any*/
		vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
		if (vrr_if)
			zvni_add_macip_for_intf(vrr_if, zvni);

		neigh_read_for_vlan(zns, vlan_if);
	}
}

/*
 * Hash function for VNI.
 */
static unsigned int vni_hash_keymake(void *p)
{
	const zebra_vni_t *zvni = p;

	return (jhash_1word(zvni->vni, 0));
}

/*
 * Compare 2 VNI hash entries.
 */
static int vni_hash_cmp(const void *p1, const void *p2)
{
	const zebra_vni_t *zvni1 = p1;
	const zebra_vni_t *zvni2 = p2;

	return (zvni1->vni == zvni2->vni);
}

/*
 * Callback to allocate VNI hash entry.
 */
static void *zvni_alloc(void *p)
{
	const zebra_vni_t *tmp_vni = p;
	zebra_vni_t *zvni;

	zvni = XCALLOC(MTYPE_ZVNI, sizeof(zebra_vni_t));
	zvni->vni = tmp_vni->vni;
	return ((void *)zvni);
}

/*
 * Look up VNI hash entry.
 */
static zebra_vni_t *zvni_lookup(vni_t vni)
{
	struct zebra_vrf *zvrf;
	zebra_vni_t tmp_vni;
	zebra_vni_t *zvni = NULL;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	assert(zvrf);
	memset(&tmp_vni, 0, sizeof(zebra_vni_t));
	tmp_vni.vni = vni;
	zvni = hash_lookup(zvrf->vni_table, &tmp_vni);

	return zvni;
}

/*
 * Add VNI hash entry.
 */
static zebra_vni_t *zvni_add(vni_t vni)
{
	struct zebra_vrf *zvrf;
	zebra_vni_t tmp_zvni;
	zebra_vni_t *zvni = NULL;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	assert(zvrf);
	memset(&tmp_zvni, 0, sizeof(zebra_vni_t));
	tmp_zvni.vni = vni;
	zvni = hash_get(zvrf->vni_table, &tmp_zvni, zvni_alloc);
	assert(zvni);

	/* Create hash table for MAC */
	zvni->mac_table =
		hash_create(mac_hash_keymake, mac_cmp, "Zebra VNI MAC Table");

	/* Create hash table for neighbors */
	zvni->neigh_table = hash_create(neigh_hash_keymake, neigh_cmp,
					"Zebra VNI Neighbor Table");

	return zvni;
}

/*
 * Delete VNI hash entry.
 */
static int zvni_del(zebra_vni_t *zvni)
{
	struct zebra_vrf *zvrf;
	zebra_vni_t *tmp_zvni;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	assert(zvrf);

	zvni->vxlan_if = NULL;

	/* Free the neighbor hash table. */
	hash_free(zvni->neigh_table);
	zvni->neigh_table = NULL;

	/* Free the MAC hash table. */
	hash_free(zvni->mac_table);
	zvni->mac_table = NULL;

	/* Free the VNI hash entry and allocated memory. */
	tmp_zvni = hash_release(zvrf->vni_table, zvni);
	if (tmp_zvni)
		XFREE(MTYPE_ZVNI, tmp_zvni);

	return 0;
}

/*
 * Inform BGP about local VNI addition.
 */
static int zvni_send_add_to_client(zebra_vni_t *zvni)
{
	struct zserv *client;
	struct stream *s;

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VNI_ADD, VRF_DEFAULT);
	stream_putl(s, zvni->vni);
	stream_put_in_addr(s, &zvni->local_vtep_ip);
	stream_put(s, &zvni->vrf_id, sizeof(vrf_id_t)); /* tenant vrf */

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send VNI_ADD %u %s tenant vrf %s to %s",
			   zvni->vni, inet_ntoa(zvni->local_vtep_ip),
			   vrf_id_to_name(zvni->vrf_id),
			   zebra_route_string(client->proto));

	client->vniadd_cnt++;
	return zebra_server_send_message(client);
}

/*
 * Inform BGP about local VNI deletion.
 */
static int zvni_send_del_to_client(vni_t vni)
{
	struct zserv *client;
	struct stream *s;

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VNI_DEL, VRF_DEFAULT);
	stream_putl(s, vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send VNI_DEL %u to %s", vni,
			   zebra_route_string(client->proto));

	client->vnidel_cnt++;
	return zebra_server_send_message(client);
}

/*
 * Build the VNI hash table by going over the VxLAN interfaces. This
 * is called when EVPN (advertise-all-vni) is enabled.
 */
static void zvni_build_hash_table()
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *ifp;

	/* Walk VxLAN interfaces and create VNI hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		vni_t vni;
		zebra_vni_t *zvni = NULL;
		zebra_l3vni_t *zl3vni = NULL;
		struct zebra_if *zif;
		struct zebra_l2info_vxlan *vxl;

		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;
		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;

		vxl = &zif->l2info.vxl;
		vni = vxl->vni;

		/* L3-VNI and L2-VNI are handled seperately */
		zl3vni = zl3vni_lookup(vni);
		if (zl3vni) {

			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("create L3-VNI hash for Intf %s(%u) L3-VNI %u",
					   ifp->name, ifp->ifindex, vni);

			/* associate with vxlan_if */
			zl3vni->local_vtep_ip = vxl->vtep_ip;
			zl3vni->vxlan_if = ifp;

			/*
			 * we need to associate with SVI.
			 * we can associate with svi-if only after association
			 * with vxlan-intf is complete
			 */
			zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

			if (is_l3vni_oper_up(zl3vni))
				zebra_vxlan_process_l3vni_oper_up(zl3vni);

		} else {
			struct interface *vlan_if = NULL;

			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Create L2-VNI hash for intf %s(%u) L2-VNI %u local IP %s",
					ifp->name, ifp->ifindex, vni,
					inet_ntoa(vxl->vtep_ip));

			/* VNI hash entry is not expected to exist. */
			zvni = zvni_lookup(vni);
			if (zvni) {
				zlog_err(
					"VNI hash already present for IF %s(%u) L2-VNI %u",
					ifp->name, ifp->ifindex, vni);
				continue;
			}

			zvni = zvni_add(vni);
			if (!zvni) {
				zlog_err(
					"Failed to add VNI hash, IF %s(%u) L2-VNI %u",
					ifp->name, ifp->ifindex, vni);
				return;
			}

			zvni->local_vtep_ip = vxl->vtep_ip;
			zvni->vxlan_if = ifp;
			vlan_if = zvni_map_to_svi(vxl->access_vlan,
						  zif->brslave_info.br_if);
			if (vlan_if) {
				zvni->vrf_id = vlan_if->vrf_id;
				zl3vni = zl3vni_from_vrf(vlan_if->vrf_id);
				if (zl3vni)
					listnode_add_sort(zl3vni->l2vnis, zvni);
			}


			/* Inform BGP if intf is up and mapped to bridge. */
			if (if_is_operative(ifp) && zif->brslave_info.br_if)
				zvni_send_add_to_client(zvni);
		}
	}
}

/*
 * See if remote VTEP matches with prefix.
 */
static int zvni_vtep_match(struct in_addr *vtep_ip, zebra_vtep_t *zvtep)
{
	return (IPV4_ADDR_SAME(vtep_ip, &zvtep->vtep_ip));
}

/*
 * Locate remote VTEP in VNI hash table.
 */
static zebra_vtep_t *zvni_vtep_find(zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
	zebra_vtep_t *zvtep;

	if (!zvni)
		return NULL;

	for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next) {
		if (zvni_vtep_match(vtep_ip, zvtep))
			break;
	}

	return zvtep;
}

/*
 * Add remote VTEP to VNI hash table.
 */
static zebra_vtep_t *zvni_vtep_add(zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
	zebra_vtep_t *zvtep;

	zvtep = XCALLOC(MTYPE_ZVNI_VTEP, sizeof(zebra_vtep_t));
	if (!zvtep) {
		zlog_err("Failed to alloc VTEP entry, VNI %u", zvni->vni);
		return NULL;
	}

	zvtep->vtep_ip = *vtep_ip;

	if (zvni->vteps)
		zvni->vteps->prev = zvtep;
	zvtep->next = zvni->vteps;
	zvni->vteps = zvtep;

	return zvtep;
}

/*
 * Remove remote VTEP from VNI hash table.
 */
static int zvni_vtep_del(zebra_vni_t *zvni, zebra_vtep_t *zvtep)
{
	if (zvtep->next)
		zvtep->next->prev = zvtep->prev;
	if (zvtep->prev)
		zvtep->prev->next = zvtep->next;
	else
		zvni->vteps = zvtep->next;

	zvtep->prev = zvtep->next = NULL;
	XFREE(MTYPE_ZVNI_VTEP, zvtep);

	return 0;
}

/*
 * Delete all remote VTEPs for this VNI (upon VNI delete). Also
 * uninstall from kernel if asked to.
 */
static int zvni_vtep_del_all(zebra_vni_t *zvni, int uninstall)
{
	zebra_vtep_t *zvtep, *zvtep_next;

	if (!zvni)
		return -1;

	for (zvtep = zvni->vteps; zvtep; zvtep = zvtep_next) {
		zvtep_next = zvtep->next;
		if (uninstall)
			zvni_vtep_uninstall(zvni, &zvtep->vtep_ip);
		zvni_vtep_del(zvni, zvtep);
	}

	return 0;
}

/*
 * Install remote VTEP into the kernel.
 */
static int zvni_vtep_install(zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
	return kernel_add_vtep(zvni->vni, zvni->vxlan_if, vtep_ip);
}

/*
 * Uninstall remote VTEP from the kernel.
 */
static int zvni_vtep_uninstall(zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p couldn't be uninstalled - no intf",
			 zvni->vni, zvni);
		return -1;
	}

	return kernel_del_vtep(zvni->vni, zvni->vxlan_if, vtep_ip);
}

/*
 * Cleanup VNI/VTEP and update kernel
 */
static void zvni_cleanup_all(struct hash_backet *backet, void *arg)
{
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;
	struct zebra_vrf *zvrf = (struct zebra_vrf *)arg;

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	/* remove from l3-vni list */
	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (zl3vni)
		listnode_delete(zl3vni->l2vnis, zvni);

	/* Free up all neighbors and MACs, if any. */
	zvni_neigh_del_all(zvni, 1, 0, DEL_ALL_NEIGH);
	zvni_mac_del_all(zvni, 1, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zvni_vtep_del_all(zvni, 1);

	/* Delete the hash entry. */
	zvni_del(zvni);
}

/* cleanup L3VNI */
static void zl3vni_cleanup_all(struct hash_backet *backet,
			       void *args)
{
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = (zebra_l3vni_t *)backet->data;
	if (!zl3vni)
		return;

	zebra_vxlan_process_l3vni_oper_down(zl3vni);
}

static int is_host_present_in_host_list(struct list *list,
					struct prefix *host)
{
	struct listnode *node = NULL;
	struct prefix *p = NULL;

	for (ALL_LIST_ELEMENTS_RO(list, node, p)) {
		if (prefix_same(p, host))
			return 1;
	}
	return 0;
}

static void host_list_add_host(struct list *list,
			       struct prefix *host)
{
	struct prefix *p = NULL;

	p = XCALLOC(MTYPE_HOST_PREFIX, sizeof(struct prefix));
	memcpy(p, host, sizeof(struct prefix));

	listnode_add_sort(list, p);
}

static void host_list_delete_host(struct list *list,
				  struct prefix *host)
{
	struct listnode *node = NULL, *nnode = NULL, *node_to_del = NULL;
	struct prefix *p = NULL;

	for (ALL_LIST_ELEMENTS(list, node, nnode, p)) {
		if (prefix_same(p, host)) {
			XFREE(MTYPE_HOST_PREFIX, p);
			node_to_del = node;
		}
	}

	if (node_to_del)
		list_delete_node(list, node_to_del);
}

/*
 * Look up MAC hash entry.
 */
static zebra_mac_t *zl3vni_rmac_lookup(zebra_l3vni_t *zl3vni,
				       struct ethaddr *rmac)
{
	zebra_mac_t tmp;
	zebra_mac_t *pmac;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.macaddr, rmac, ETH_ALEN);
	pmac = hash_lookup(zl3vni->rmac_table, &tmp);

	return pmac;
}

/*
 * Callback to allocate RMAC hash entry.
 */
static void *zl3vni_rmac_alloc(void *p)
{
	const zebra_mac_t *tmp_rmac = p;
	zebra_mac_t *zrmac;

	zrmac = XCALLOC(MTYPE_MAC, sizeof(zebra_mac_t));
	*zrmac = *tmp_rmac;

	return ((void *)zrmac);
}

/*
 * Add RMAC entry to l3-vni
 */
static zebra_mac_t *zl3vni_rmac_add(zebra_l3vni_t *zl3vni,
				    struct ethaddr *rmac)
{
	zebra_mac_t tmp_rmac;
	zebra_mac_t *zrmac = NULL;

	memset(&tmp_rmac, 0, sizeof(zebra_mac_t));
	memcpy(&tmp_rmac.macaddr, rmac, ETH_ALEN);
	zrmac = hash_get(zl3vni->rmac_table, &tmp_rmac, zl3vni_rmac_alloc);
	assert(zrmac);

	zrmac->host_list = list_new();
	zrmac->host_list->cmp = (int (*)(void *, void *))prefix_cmp;

	SET_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE);
	SET_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC);

	return zrmac;
}

/*
 * Delete MAC entry.
 */
static int zl3vni_rmac_del(zebra_l3vni_t *zl3vni,
			   zebra_mac_t *zrmac)
{
	zebra_mac_t *tmp_rmac;

	if (zrmac->host_list)
		list_delete_and_null(&zrmac->host_list);
	zrmac->host_list = NULL;

	tmp_rmac = hash_release(zl3vni->rmac_table, zrmac);
	if (tmp_rmac)
		XFREE(MTYPE_MAC, tmp_rmac);

	return 0;
}

/*
 * Install remote RMAC into the kernel.
 */
static int zl3vni_rmac_install(zebra_l3vni_t *zl3vni,
			       zebra_mac_t *zrmac)
{
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;

	if (!(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE)) ||
	    !(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC)))
		return 0;

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return -1;

	vxl = &zif->l2info.vxl;

	return kernel_add_mac(zl3vni->vxlan_if, vxl->access_vlan,
			      &zrmac->macaddr,
			      zrmac->fwd_info.r_vtep_ip, 0);
}

/*
 * Uninstall remote RMAC from the kernel.
 */
static int zl3vni_rmac_uninstall(zebra_l3vni_t *zl3vni,
			         zebra_mac_t *zrmac)
{
	char buf[ETHER_ADDR_STRLEN];
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;

	if (!(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE)) ||
	    !(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC)))
		return 0;

	if (!zl3vni->vxlan_if) {
		zlog_err(
			 "RMAC %s on L3-VNI %u hash %p couldn't be uninstalled - no vxlan_if",
			 prefix_mac2str(&zrmac->macaddr, buf, sizeof(buf)),
			 zl3vni->vni, zl3vni);
		return -1;
	}

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return -1;

	vxl = &zif->l2info.vxl;

	return kernel_del_mac(zl3vni->vxlan_if, vxl->access_vlan,
			      &zrmac->macaddr, zrmac->fwd_info.r_vtep_ip, 0);
}

/* handle rmac add */
static int zl3vni_remote_rmac_add(zebra_l3vni_t *zl3vni,
				  struct ethaddr *rmac,
				  struct ipaddr *vtep_ip,
				  struct prefix *host_prefix)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	zebra_mac_t *zrmac = NULL;

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac) {

		zrmac = zl3vni_rmac_add(zl3vni, rmac);
		if (!zrmac) {
			zlog_warn(
				"Failed to add RMAC %s L3VNI %u Remote VTEP %s",
				prefix_mac2str(rmac, buf,
					       sizeof(buf)),
				zl3vni->vni, ipaddr2str(vtep_ip, buf1,
							sizeof(buf1)));
			return -1;
		}
		memset(&zrmac->fwd_info, 0, sizeof(zrmac->fwd_info));
		zrmac->fwd_info.r_vtep_ip = vtep_ip->ipaddr_v4;

		/* install rmac in kernel */
		zl3vni_rmac_install(zl3vni, zrmac);
	}

	if (!is_host_present_in_host_list(zrmac->host_list, host_prefix))
		host_list_add_host(zrmac->host_list, host_prefix);
	return 0;
}


/* handle rmac delete */
static int zl3vni_remote_rmac_del(zebra_l3vni_t *zl3vni,
				  struct ethaddr *rmac,
				  struct prefix *host_prefix)
{
	zebra_mac_t *zrmac = NULL;

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac)
		return -1;

	host_list_delete_host(zrmac->host_list, host_prefix);
	if (list_isempty(zrmac->host_list)) {

		/* uninstall from kernel */
		zl3vni_rmac_uninstall(zl3vni, zrmac);

		/* del the rmac entry */
		zl3vni_rmac_del(zl3vni, zrmac);
	}
	return 0;
}

/*
 * Look up nh hash entry on a l3-vni.
 */
static zebra_neigh_t *zl3vni_nh_lookup(zebra_l3vni_t *zl3vni,
				       struct ipaddr *ip)
{
	zebra_neigh_t tmp;
	zebra_neigh_t *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	n = hash_lookup(zl3vni->nh_table, &tmp);

	return n;
}


/*
 * Callback to allocate NH hash entry on L3-VNI.
 */
static void *zl3vni_nh_alloc(void *p)
{
	const zebra_neigh_t *tmp_n = p;
	zebra_neigh_t *n;

	n = XCALLOC(MTYPE_NEIGH, sizeof(zebra_neigh_t));
	*n = *tmp_n;

	return ((void *)n);
}

/*
 * Add neighbor entry.
 */
static zebra_neigh_t *zl3vni_nh_add(zebra_l3vni_t *zl3vni,
				    struct ipaddr *ip,
				    struct ethaddr *mac)
{
	zebra_neigh_t tmp_n;
	zebra_neigh_t *n = NULL;

	memset(&tmp_n, 0, sizeof(zebra_neigh_t));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = hash_get(zl3vni->nh_table, &tmp_n, zl3vni_nh_alloc);
	assert(n);

	n->host_list = list_new();
	n->host_list->cmp = (int (*)(void *, void *))prefix_cmp;

	memcpy(&n->emac, mac, ETH_ALEN);
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE_NH);

	return n;
}

/*
 * Delete neighbor entry.
 */
static int zl3vni_nh_del(zebra_l3vni_t *zl3vni,
			 zebra_neigh_t *n)
{
	zebra_neigh_t *tmp_n;

	if (n->host_list)
		list_delete_and_null(&n->host_list);
	n->host_list = NULL;

	tmp_n = hash_release(zl3vni->nh_table, n);
	if (tmp_n)
		XFREE(MTYPE_NEIGH, tmp_n);

	return 0;
}

/*
 * Install remote nh as neigh into the kernel.
 */
static int zl3vni_nh_install(zebra_l3vni_t *zl3vni,
			     zebra_neigh_t *n)
{
	if (!is_l3vni_oper_up(zl3vni))
		return -1;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE) ||
	    !(n->flags & ZEBRA_NEIGH_REMOTE_NH))
		return 0;

	return kernel_add_neigh(zl3vni->svi_if, &n->ip, &n->emac);
}

/*
 * Uninstall remote nh from the kernel.
 */
static int zl3vni_nh_uninstall(zebra_l3vni_t *zl3vni,
			       zebra_neigh_t *n)
{
	if (!(n->flags & ZEBRA_NEIGH_REMOTE) ||
	    !(n->flags & ZEBRA_NEIGH_REMOTE_NH))
		return 0;

	if (!zl3vni->svi_if || !if_is_operative(zl3vni->svi_if))
		return 0;

	return kernel_del_neigh(zl3vni->svi_if, &n->ip);
}

/* add remote vtep as a neigh entry */
static int zl3vni_remote_nh_add(zebra_l3vni_t *zl3vni,
				struct ipaddr *vtep_ip,
				struct ethaddr *rmac,
				struct prefix *host_prefix)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	zebra_neigh_t *nh = NULL;

	nh = zl3vni_nh_lookup(zl3vni, vtep_ip);
	if (!nh) {
		nh = zl3vni_nh_add(zl3vni, vtep_ip, rmac);
		if (!nh) {

			zlog_warn(
				"Failed to add NH as Neigh (IP %s MAC %s L3-VNI %u)",
				ipaddr2str(vtep_ip, buf1,
					   sizeof(buf1)),
				prefix_mac2str(rmac, buf,
					       sizeof(buf)),
				zl3vni->vni);
			return -1;
		}

		/* install the nh neigh in kernel */
		zl3vni_nh_install(zl3vni, nh);
	}

	if (!is_host_present_in_host_list(nh->host_list, host_prefix))
		host_list_add_host(nh->host_list, host_prefix);

	return 0;
}

/* handle nh neigh delete */
static int zl3vni_remote_nh_del(zebra_l3vni_t *zl3vni,
				struct ipaddr *vtep_ip,
				struct prefix *host_prefix)
{
	zebra_neigh_t *nh = NULL;

	nh = zl3vni_nh_lookup(zl3vni, vtep_ip);
	if (!nh)
		return -1;

	host_list_delete_host(nh->host_list, host_prefix);
	if (list_isempty(nh->host_list)) {

		/* uninstall from kernel */
		zl3vni_nh_uninstall(zl3vni, nh);

		/* delete the nh entry */
		zl3vni_nh_del(zl3vni, nh);
	}

	return 0;
}

/* handle neigh update from kernel - the only thing of interest is to
 * readd stale entries.
 */
static int zl3vni_local_nh_add_update(zebra_l3vni_t *zl3vni,
				      struct ipaddr *ip, u_int16_t state)
{
#ifdef GNU_LINUX
	zebra_neigh_t *n = NULL;

	n = zl3vni_nh_lookup(zl3vni, ip);
	if (!n)
		return 0;

	/* all next hop neigh are remote and installed by frr.
	 * If the kernel has aged this entry, re-install.
	 */
	if (state & NUD_STALE)
		zl3vni_nh_install(zl3vni, n);
#endif
	return 0;
}

/* handle neigh delete from kernel */
static int zl3vni_local_nh_del(zebra_l3vni_t *zl3vni,
			       struct ipaddr *ip)
{
	zebra_neigh_t *n = NULL;

	n = zl3vni_nh_lookup(zl3vni, ip);
	if (!n)
		return 0;

	/* all next hop neigh are remote and installed by frr.
	 * If we get an age out notification for these neigh entries, we have to
	 * install it back
	 */
	zl3vni_nh_install(zl3vni, n);

	return 0;
}

/*
 * Hash function for L3 VNI.
 */
static unsigned int l3vni_hash_keymake(void *p)
{
	const zebra_l3vni_t *zl3vni = p;

	return jhash_1word(zl3vni->vni, 0);
}

/*
 * Compare 2 L3 VNI hash entries.
 */
static int l3vni_hash_cmp(const void *p1, const void *p2)
{
	const zebra_l3vni_t *zl3vni1 = p1;
	const zebra_l3vni_t *zl3vni2 = p2;

	return (zl3vni1->vni == zl3vni2->vni);
}

/*
 * Callback to allocate L3 VNI hash entry.
 */
static void *zl3vni_alloc(void *p)
{
	zebra_l3vni_t *zl3vni = NULL;
	const zebra_l3vni_t *tmp_l3vni = p;

	zl3vni = XCALLOC(MTYPE_ZL3VNI, sizeof(zebra_l3vni_t));
	zl3vni->vni = tmp_l3vni->vni;
	return ((void *)zl3vni);
}

/*
 * Look up L3 VNI hash entry.
 */
static zebra_l3vni_t *zl3vni_lookup(vni_t vni)
{
	struct zebra_ns *zns;
	zebra_l3vni_t tmp_l3vni;
	zebra_l3vni_t *zl3vni = NULL;

	zns = zebra_ns_lookup(NS_DEFAULT);
	assert(zns);
	memset(&tmp_l3vni, 0, sizeof(zebra_l3vni_t));
	tmp_l3vni.vni = vni;
	zl3vni = hash_lookup(zns->l3vni_table, &tmp_l3vni);

	return zl3vni;
}

/*
 * Add L3 VNI hash entry.
 */
static zebra_l3vni_t *zl3vni_add(vni_t vni, vrf_id_t vrf_id)
{
	zebra_l3vni_t tmp_zl3vni;
	struct zebra_ns *zns = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	zns = zebra_ns_lookup(NS_DEFAULT);
	assert(zns);

	memset(&tmp_zl3vni, 0, sizeof(zebra_l3vni_t));
	tmp_zl3vni.vni = vni;

	zl3vni = hash_get(zns->l3vni_table, &tmp_zl3vni, zl3vni_alloc);
	assert(zl3vni);

	zl3vni->vrf_id = vrf_id;
	zl3vni->svi_if = NULL;
	zl3vni->vxlan_if = NULL;
	zl3vni->l2vnis = list_new();
	zl3vni->l2vnis->cmp = (int (*)(void *, void *))vni_hash_cmp;

	/* Create hash table for remote RMAC */
	zl3vni->rmac_table =
		hash_create(mac_hash_keymake, mac_cmp,
			    "Zebra L3-VNI RMAC-Table");

	/* Create hash table for neighbors */
	zl3vni->nh_table = hash_create(neigh_hash_keymake, neigh_cmp,
				     "Zebra L3-VNI next-hop table");

	return zl3vni;
}

/*
 * Delete L3 VNI hash entry.
 */
static int zl3vni_del(zebra_l3vni_t *zl3vni)
{
	struct zebra_ns *zns;
	zebra_l3vni_t *tmp_zl3vni;

	zns = zebra_ns_lookup(NS_DEFAULT);
	assert(zns);

	/* free the list of l2vnis */
	list_delete_and_null(&zl3vni->l2vnis);
	zl3vni->l2vnis = NULL;

	/* Free the rmac table */
	hash_free(zl3vni->rmac_table);
	zl3vni->rmac_table = NULL;

	/* Free the nh table */
	hash_free(zl3vni->nh_table);
	zl3vni->nh_table = NULL;

	/* Free the VNI hash entry and allocated memory. */
	tmp_zl3vni = hash_release(zns->l3vni_table, zl3vni);
	if (tmp_zl3vni)
		XFREE(MTYPE_ZL3VNI, tmp_zl3vni);

	return 0;
}

static struct interface *zl3vni_map_to_vxlan_if(zebra_l3vni_t *zl3vni)
{
	struct zebra_ns *zns = NULL;
	struct route_node *rn = NULL;
	struct interface *ifp = NULL;

	/* loop through all vxlan-interface */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {

		struct zebra_if *zif = NULL;
		struct zebra_l2info_vxlan *vxl = NULL;

		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;

		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;

		vxl = &zif->l2info.vxl;
		if (vxl->vni == zl3vni->vni) {
			zl3vni->local_vtep_ip = vxl->vtep_ip;
			return ifp;
		}
	}

	return NULL;
}

static struct interface *zl3vni_map_to_svi_if(zebra_l3vni_t *zl3vni)
{
	struct zebra_if *zif = NULL; /* zebra_if for vxlan_if */
	struct zebra_l2info_vxlan *vxl = NULL; /* l2 info for vxlan_if */

	if (!zl3vni)
		return NULL;

	if (!zl3vni->vxlan_if)
		return NULL;

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return NULL;

	vxl = &zif->l2info.vxl;

	return zvni_map_to_svi(vxl->access_vlan, zif->brslave_info.br_if);
}

static zebra_l3vni_t *zl3vni_from_vrf(vrf_id_t vrf_id)
{
	struct zebra_vrf *zvrf = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf)
		return NULL;

	return zl3vni_lookup(zvrf->l3vni);
}

/*
 * Map SVI and associated bridge to a VNI. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 */
static zebra_l3vni_t *zl3vni_from_svi(struct interface *ifp,
				      struct interface *br_if)
{
	int found = 0;
	vlanid_t vid = 0;
	u_char bridge_vlan_aware = 0;
	zebra_l3vni_t *zl3vni = NULL;
	struct zebra_ns *zns = NULL;
	struct route_node *rn = NULL;
	struct zebra_if *zif = NULL;
	struct interface *tmp_if = NULL;
	struct zebra_l2info_bridge *br = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;

	if (!br_if)
		return NULL;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;
	if (bridge_vlan_aware) {
		struct zebra_l2info_vlan *vl;

		if (!IS_ZEBRA_IF_VLAN(ifp))
			return NULL;

		zif = ifp->info;
		assert(zif);
		vl = &zif->l2info.vl;
		vid = vl->vid;
	}

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware || vxl->access_vlan == vid) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	zl3vni = zl3vni_lookup(vxl->vni);
	return zl3vni;
}

/*
 * Inform BGP about l3-vni.
 */
static int zl3vni_send_add_to_client(zebra_l3vni_t *zl3vni)
{
	struct stream *s = NULL;
	struct zserv *client = NULL;
	struct ethaddr rmac;
	char buf[ETHER_ADDR_STRLEN];

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	/* get the rmac */
	memset(&rmac, 0, sizeof(struct ethaddr));
	zl3vni_get_rmac(zl3vni, &rmac);

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_L3VNI_ADD,
			    zl3vni_vrf_id(zl3vni));
	stream_putl(s, zl3vni->vni);
	stream_put(s, &rmac, sizeof(struct ethaddr));
	stream_put_in_addr(s, &zl3vni->local_vtep_ip);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send L3_VNI_ADD %u VRF %s RMAC %s local-ip %s to %s",
			   zl3vni->vni, vrf_id_to_name(zl3vni_vrf_id(zl3vni)),
			   prefix_mac2str(&rmac, buf, sizeof(buf)),
			   inet_ntoa(zl3vni->local_vtep_ip),
			   zebra_route_string(client->proto));

	client->l3vniadd_cnt++;
	return zebra_server_send_message(client);
}

/*
 * Inform BGP about local l3-VNI deletion.
 */
static int zl3vni_send_del_to_client(zebra_l3vni_t *zl3vni)
{
	struct stream *s = NULL;
	struct zserv *client = NULL;

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_L3VNI_DEL,
			    zl3vni_vrf_id(zl3vni));
	stream_putl(s, zl3vni->vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send L3_VNI_DEL %u VRF %s to %s",
			   zl3vni->vni,
			   vrf_id_to_name(zl3vni_vrf_id(zl3vni)),
			   zebra_route_string(client->proto));

	client->l3vnidel_cnt++;
	return zebra_server_send_message(client);
}

static void zebra_vxlan_process_l3vni_oper_up(zebra_l3vni_t *zl3vni)
{
	if (!zl3vni)
		return;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("L3-VNI %u is UP - send add to BGP",
			   zl3vni->vni);

	/* send l3vni add to BGP */
	zl3vni_send_add_to_client(zl3vni);
}

static void zebra_vxlan_process_l3vni_oper_down(zebra_l3vni_t *zl3vni)
{
	if (!zl3vni)
		return;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("L3-VNI %u is Down - Send del to BGP",
			   zl3vni->vni);

	/* send l3-vni del to BGP*/
	zl3vni_send_del_to_client(zl3vni);
}

static void zvni_add_to_l3vni_list(struct hash_backet *backet,
				   void *ctxt)
{
	zebra_vni_t *zvni = (zebra_vni_t *) backet->data;
	zebra_l3vni_t *zl3vni = (zebra_l3vni_t *) ctxt;

	if (zvni->vrf_id == zl3vni_vrf_id(zl3vni))
		listnode_add_sort(zl3vni->l2vnis, zvni);
}

/*
 *  handle transition of vni from l2 to l3 and vice versa
 */
static int zebra_vxlan_handle_vni_transition(struct zebra_vrf *zvrf,
					      vni_t vni, int add)
{
	zebra_vni_t *zvni = NULL;

	/* There is a possibility that VNI notification was already received
	 * from kernel and we programmed it as L2-VNI
	 * In such a case we need to delete this L2-VNI first, so
	 * that it can be reprogrammed as L3-VNI in the system. It is also
	 * possible that the vrf-vni mapping is removed from FRR while the vxlan
	 * interface is still present in kernel. In this case to keep it
	 * symmetric, we will delete the l3-vni and reprogram it as l2-vni
	 */
	if (add) {
		/* Locate hash entry */
		zvni = zvni_lookup(vni);
		if (!zvni)
			return 0;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L2-VNI %u - transition to L3-VNI",
				   vni);

		/* Delete VNI from BGP. */
		zvni_send_del_to_client(zvni->vni);

		/* Free up all neighbors and MAC, if any. */
		zvni_neigh_del_all(zvni, 0, 0, DEL_ALL_NEIGH);
		zvni_mac_del_all(zvni, 0, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zvni_vtep_del_all(zvni, 0);

		/* Delete the hash entry. */
		if (zvni_del(zvni)) {
			zlog_err("Failed to del VNI hash %p, VNI %u",
				 zvni, zvni->vni);
			return -1;
		}
	} else {
		/* TODO_MITESH: This needs to be thought through. We don't have
		 * enough information at this point to reprogram the vni as
		 * l2-vni. One way is to store the required info in l3-vni and
		 * used it solely for this purpose
		 */
	}

	return 0;
}

/* delete and uninstall rmac hash entry */
static void zl3vni_del_rmac_hash_entry(struct hash_backet *backet,
				       void *ctx)
{
	zebra_mac_t *zrmac = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	zrmac = (zebra_mac_t *)backet->data;
	zl3vni = (zebra_l3vni_t *)ctx;
	zl3vni_rmac_uninstall(zl3vni, zrmac);
	zl3vni_rmac_del(zl3vni, zrmac);
}

/* delete and uninstall nh hash entry */
static void zl3vni_del_nh_hash_entry(struct hash_backet *backet,
				     void *ctx)
{
	zebra_neigh_t *n = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	n = (zebra_neigh_t *)backet->data;
	zl3vni = (zebra_l3vni_t *)ctx;
	zl3vni_nh_uninstall(zl3vni, n);
	zl3vni_nh_del(zl3vni, n);
}

static int ip_prefix_send_to_client(vrf_id_t vrf_id,
					     struct prefix *p,
					     uint16_t cmd)
{
	struct zserv *client = NULL;
	struct stream *s = NULL;
	char buf[PREFIX_STRLEN];

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, vrf_id);
	stream_put(s, p, sizeof(struct prefix));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			   "Send ip prefix %s %s on vrf %s",
			   prefix2str(p, buf, sizeof(buf)),
			   (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD) ? "ADD" : "DEL",
			   vrf_id_to_name(vrf_id));

	if (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD)
		client->prefixadd_cnt++;
	else
		client->prefixdel_cnt++;

	return zebra_server_send_message(client);
}

/* re-add remote rmac if needed */
static int zebra_vxlan_readd_remote_rmac(zebra_l3vni_t *zl3vni,
				  struct ethaddr *rmac)
{
	char buf[ETHER_ADDR_STRLEN];
	zebra_mac_t *zrmac = NULL;

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del remote RMAC %s L3VNI %u - readd",
			   prefix_mac2str(rmac, buf, sizeof(buf)),
			   zl3vni->vni);

	zl3vni_rmac_install(zl3vni, zrmac);
	return 0;
}

/* Public functions */

/* handle evpn route in vrf table */
void zebra_vxlan_evpn_vrf_route_add(vrf_id_t vrf_id,
				   struct ethaddr *rmac,
				   struct ipaddr *vtep_ip,
				   struct prefix *host_prefix)
{
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return;

	/* add the next hop neighbor */
	zl3vni_remote_nh_add(zl3vni, vtep_ip, rmac, host_prefix);

	/* add the rmac */
	zl3vni_remote_rmac_add(zl3vni, rmac, vtep_ip, host_prefix);
}

/* handle evpn vrf route delete */
void zebra_vxlan_evpn_vrf_route_del(vrf_id_t vrf_id,
				   struct ethaddr *rmac,
				   struct ipaddr *vtep_ip,
				   struct prefix *host_prefix)
{
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni)
		return;

	/* delete the next hop entry */
	zl3vni_remote_nh_del(zl3vni, vtep_ip, host_prefix);

	/* delete the rmac entry */
	zl3vni_remote_rmac_del(zl3vni, rmac, host_prefix);
}

void zebra_vxlan_print_specific_rmac_l3vni(struct vty *vty,
					   vni_t l3vni,
					   struct ethaddr *rmac,
					   u_char use_json)
{
	zebra_l3vni_t *zl3vni = NULL;
	zebra_mac_t *zrmac = NULL;
	json_object *json = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% L3-VNI %u doesnt exist\n",
				l3vni);
		return;
	}

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty,
				"%% Requested RMAC doesnt exist in L3-VNI %u",
				l3vni);
		return;
	}

	zl3vni_print_rmac(zrmac, vty, json);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_rmacs_l3vni(struct vty *vty,
				   vni_t l3vni,
				   u_char use_json)
{
	zebra_l3vni_t *zl3vni;
	u_int32_t num_rmacs;
	struct rmac_walk_ctx wctx;
	json_object *json = NULL;

	if (!is_evpn_enabled())
		return;

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% L3-VNI %u does not exist\n", l3vni);
		return;
	}
	num_rmacs = hashcount(zl3vni->rmac_table);
	if (!num_rmacs)
		return;

	if (use_json)
		json = json_object_new_object();

	memset(&wctx, 0, sizeof(struct rmac_walk_ctx));
	wctx.vty = vty;
	wctx.json = json;
	if (!use_json) {
		vty_out(vty,
			"Number of Remote RMACs known for this VNI: %u\n",
			num_rmacs);
		vty_out(vty, "%-17s %-21s\n", "MAC", "Remote VTEP");
	} else
		json_object_int_add(json, "numRmacs", num_rmacs);

	hash_iterate(zl3vni->rmac_table, zl3vni_print_rmac_hash, &wctx);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_rmacs_all_l3vni(struct vty *vty,
				       u_char use_json)
{
	struct zebra_ns *zns = NULL;
	json_object *json = NULL;
	void *args[2];

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	args[0] = vty;
	args[1] = json;
	hash_iterate(zns->l3vni_table,
		     (void (*)(struct hash_backet *,
			       void *))zl3vni_print_rmac_hash_all_vni,
		     args);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_specific_nh_l3vni(struct vty *vty,
					 vni_t l3vni,
					 struct ipaddr *ip,
					 u_char use_json)
{
	zebra_l3vni_t *zl3vni = NULL;
	zebra_neigh_t *n = NULL;
	json_object *json = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% L3-VNI %u does not exist\n", l3vni);
		return;
	}

	n = zl3vni_nh_lookup(zl3vni, ip);
	if (!n) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty,
				"%% Requested next-hop not present for L3-VNI %u",
				l3vni);
		return;
	}

	zl3vni_print_nh(n, vty, json);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_nh_l3vni(struct vty *vty,
				vni_t l3vni,
				u_char use_json)
{
	u_int32_t num_nh;
	struct nh_walk_ctx wctx;
	json_object *json = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	if (!is_evpn_enabled())
		return;

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% L3-VNI %u does not exist\n", l3vni);
		return;
	}

	num_nh = hashcount(zl3vni->nh_table);
	if (!num_nh)
		return;

	if (use_json)
		json = json_object_new_object();

	wctx.vty = vty;
	wctx.json = json;
	if (!use_json) {
		vty_out(vty,
			"Number of NH Neighbors known for this VNI: %u\n",
			num_nh);
		vty_out(vty, "%-15s %-17s\n", "IP", "RMAC");
	} else
		json_object_int_add(json, "numNextHops", num_nh);

	hash_iterate(zl3vni->nh_table, zl3vni_print_nh_hash, &wctx);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_nh_all_l3vni(struct vty *vty,
				    u_char use_json)
{
	struct zebra_ns *zns = NULL;
	json_object *json = NULL;
	void *args[2];

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns)
		return;

	if (use_json)
		json = json_object_new_object();

	args[0] = vty;
	args[1] = json;
	hash_iterate(zns->l3vni_table,
		     (void (*)(struct hash_backet *,
			       void *))zl3vni_print_nh_hash_all_vni,
		     args);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return;
}

/*
 * Display L3 VNI information (VTY command handler).
 */
void zebra_vxlan_print_l3vni(struct vty *vty, vni_t vni, u_char use_json)
{
	void *args[2];
	json_object *json = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	zl3vni = zl3vni_lookup(vni);
	if (!zl3vni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}

	if (use_json)
		json = json_object_new_object();

	args[0] = vty;
	args[1] = json;
	zl3vni_print(zl3vni, (void *)args);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void zebra_vxlan_print_vrf_vni(struct vty *vty, struct zebra_vrf *zvrf,
			       json_object *json_vrfs)
{
	char buf[ETHER_ADDR_STRLEN];
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return;

	if (!json_vrfs) {
		vty_out(vty, "%-37s %-10u %-20s %-20s %-5s %-18s\n",
			zvrf_name(zvrf),
			zl3vni->vni,
			zl3vni_vxlan_if_name(zl3vni),
			zl3vni_svi_if_name(zl3vni),
			zl3vni_state2str(zl3vni),
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
	} else {
		json_object *json_vrf = NULL;
		json_vrf = json_object_new_object();
		json_object_string_add(json_vrf, "vrf",
				       zvrf_name(zvrf));
		json_object_int_add(json_vrf, "vni", zl3vni->vni);
		json_object_string_add(json_vrf, "vxlanIntf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_string_add(json_vrf, "sviIntf",
				       zl3vni_svi_if_name(zl3vni));
		json_object_string_add(json_vrf, "state",
				       zl3vni_state2str(zl3vni));
		json_object_string_add(json_vrf, "routerMac",
				       zl3vni_rmac2str(zl3vni, buf,
						       sizeof(buf)));
		json_object_array_add(json_vrfs, json_vrf);
	}
}

/*
 * Display Neighbors for a VNI (VTY command handler).
 */
void zebra_vxlan_print_neigh_vni(struct vty *vty, struct zebra_vrf *zvrf,
				 vni_t vni, u_char use_json)
{
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;
	json_object *json = NULL;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_neigh = hashcount(zvni->neigh_table);
	if (!num_neigh)
		return;

	if (use_json)
		json = json_object_new_object();

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json;
	hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

	if (!use_json) {
		vty_out(vty,
			"Number of ARPs (local and remote) known for this VNI: %u\n",
			num_neigh);
		vty_out(vty, "%*s %-6s %-17s %-21s\n", -wctx.addr_width, "IP",
			"Type", "MAC", "Remote VTEP");
	} else
		json_object_int_add(json, "numArpNd", num_neigh);

	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display neighbors across all VNIs (VTY command handler).
 */
void zebra_vxlan_print_neigh_all_vni(struct vty *vty, struct zebra_vrf *zvrf,
				     u_char use_json)
{
	json_object *json = NULL;
	void *args[2];

	if (!is_evpn_enabled())
		return;

	if (use_json)
		json = json_object_new_object();

	args[0] = vty;
	args[1] = json;
	hash_iterate(zvrf->vni_table,
		     (void (*)(struct hash_backet *,
			       void *))zvni_print_neigh_hash_all_vni,
		     args);
	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display specific neighbor for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_neigh_vni(struct vty *vty,
					  struct zebra_vrf *zvrf, vni_t vni,
					  struct ipaddr *ip, u_char use_json)
{
	zebra_vni_t *zvni;
	zebra_neigh_t *n;
	json_object *json = NULL;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	n = zvni_neigh_lookup(zvni, ip);
	if (!n) {
		if (!use_json)
			vty_out(vty,
				"%% Requested neighbor does not exist in VNI %u\n",
				vni);
		return;
	}
	if (use_json)
		json = json_object_new_object();

	zvni_print_neigh(n, vty, json);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display neighbors for a VNI from specific VTEP (VTY command handler).
 * By definition, these are remote neighbors.
 */
void zebra_vxlan_print_neigh_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				      vni_t vni, struct in_addr vtep_ip,
				      u_char use_json)
{
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;
	json_object *json = NULL;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_neigh = hashcount(zvni->neigh_table);
	if (!num_neigh)
		return;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_NEIGH_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json;
	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display MACs for a VNI (VTY command handler).
 */
void zebra_vxlan_print_macs_vni(struct vty *vty, struct zebra_vrf *zvrf,
				vni_t vni, u_char use_json)
{
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx wctx;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = num_valid_macs(zvni);
	if (!num_macs)
		return;

	if (use_json) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.json = json_mac;

	if (!use_json) {
		vty_out(vty,
			"Number of MACs (local and remote) known for this VNI: %u\n",
			num_macs);
		vty_out(vty, "%-17s %-6s %-21s %-5s\n", "MAC", "Type",
			"Intf/Remote VTEP", "VLAN");
	} else
		json_object_int_add(json, "numMacs", num_macs);

	hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);

	if (use_json) {
		json_object_object_add(json, "macs", json_mac);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni(struct vty *vty, struct zebra_vrf *zvrf,
				    u_char use_json)
{
	struct mac_walk_ctx wctx;
	json_object *json = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}
	if (use_json)
		json = json_object_new_object();

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.vty = vty;
	wctx.json = json;
	hash_iterate(zvrf->vni_table, zvni_print_mac_hash_all_vni, &wctx);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni_vtep(struct vty *vty,
					 struct zebra_vrf *zvrf,
					 struct in_addr vtep_ip,
					 u_char use_json)
{
	struct mac_walk_ctx wctx;
	json_object *json = NULL;

	if (!is_evpn_enabled())
		return;

	if (use_json)
		json = json_object_new_object();

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json;
	hash_iterate(zvrf->vni_table, zvni_print_mac_hash_all_vni, &wctx);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display specific MAC for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_mac_vni(struct vty *vty, struct zebra_vrf *zvrf,
					vni_t vni, struct ethaddr *macaddr)
{
	zebra_vni_t *zvni;
	zebra_mac_t *mac;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac) {
		vty_out(vty, "%% Requested MAC does not exist in VNI %u\n",
			vni);
		return;
	}

	zvni_print_mac(mac, vty);
}

/*
 * Display MACs for a VNI from specific VTEP (VTY command handler).
 */
void zebra_vxlan_print_macs_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				     vni_t vni, struct in_addr vtep_ip,
				     u_char use_json)
{
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx wctx;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	if (!is_evpn_enabled())
		return;
	zvni = zvni_lookup(vni);
	if (!zvni) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = num_valid_macs(zvni);
	if (!num_macs)
		return;

	if (use_json) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json_mac;
	hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);

	if (use_json) {
		json_object_int_add(json, "numMacs", wctx.count);
		if (wctx.count)
			json_object_object_add(json, "macs", json_mac);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}


/*
 * Display VNI information (VTY command handler).
 */
void zebra_vxlan_print_vni(struct vty *vty, struct zebra_vrf *zvrf, vni_t vni,
			   u_char use_json)
{
	json_object *json = NULL;
	void *args[2];
	zebra_l3vni_t *zl3vni = NULL;
	zebra_vni_t *zvni = NULL;

	if (!is_evpn_enabled())
		return;

	if (use_json)
		json = json_object_new_object();
	args[0] = vty;
	args[1] = json;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {
		zl3vni_print(zl3vni, (void *)args);
	} else {
		zvni = zvni_lookup(vni);
		if (!zvni) {
			if (use_json)
				vty_out(vty, "{}\n");
			else
				vty_out(vty, "%% VNI %u does not exist\n", vni);
			return;
		}

		zvni_print(zvni, (void *)args);
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/* Display all global details for EVPN */
void zebra_vxlan_print_evpn(struct vty *vty, u_char uj)
{
	int num_l2vnis = 0;
	int num_l3vnis = 0;
	int num_vnis = 0;
	json_object *json = NULL;
	struct zebra_ns *zns = NULL;
	struct zebra_vrf *zvrf = NULL;

	if (!is_evpn_enabled())
		return;

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns)
		return;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return;

	num_l3vnis = hashcount(zns->l3vni_table);
	num_l2vnis = hashcount(zvrf->vni_table);
	num_vnis = num_l2vnis + num_l3vnis;

	if (uj) {
		json = json_object_new_object();
		json_object_string_add(json, "advertiseGatewayMacip",
				       zvrf->advertise_gw_macip ? "Yes" : "No");
		json_object_int_add(json, "numVnis", num_vnis);
		json_object_int_add(json, "numL2Vnis", num_l2vnis);
		json_object_int_add(json, "numL3Vnis", num_l3vnis);
	} else {
		vty_out(vty, "L2 VNIs: %u\n", num_l2vnis);
		vty_out(vty, "L3 VNIs: %u\n", num_l3vnis);
		vty_out(vty, "Advertise gateway mac-ip: %s\n",
			zvrf->advertise_gw_macip ? "Yes" : "No");
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Display VNI hash table (VTY command handler).
 */
void zebra_vxlan_print_vnis(struct vty *vty, struct zebra_vrf *zvrf,
			    u_char use_json)
{
	json_object *json = NULL;
	struct zebra_ns *zns = NULL;
	void *args[2];

	if (!is_evpn_enabled())
		return;

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns)
		return;


	if (use_json)
		json = json_object_new_object();
	else
		vty_out(vty,
			"%-10s %-4s %-21s %-8s %-8s %-15s %-37s\n",
			"VNI", "Type", "VxLAN IF", "# MACs",
			"# ARPs", "# Remote VTEPs", "Tenant VRF");

	args[0] = vty;
	args[1] = json;

	/* Display all L2-VNIs */
	hash_iterate(zvrf->vni_table,
		     (void (*)(struct hash_backet *, void *))zvni_print_hash,
		     args);

	/* Display all L3-VNIs */
	hash_iterate(zns->l3vni_table,
		     (void (*)(struct hash_backet *, void *))zl3vni_print_hash,
		     args);

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

/*
 * Handle neighbor delete (on a VLAN device / L3 interface) from the
 * kernel. This may result in either the neighbor getting deleted from
 * our database or being re-added to the kernel (if it is a valid
 * remote neighbor).
 */
int zebra_vxlan_local_neigh_del(struct interface *ifp,
				struct interface *link_if, struct ipaddr *ip)
{
	char buf[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];
	zebra_neigh_t *n = NULL;
	zebra_vni_t *zvni = NULL;
	zebra_mac_t *zmac = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* check if this is a remote neigh entry corresponding to remote
	 * next-hop
	 */
	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni)
		return zl3vni_local_nh_del(zl3vni, ip);

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zvni = zvni_from_svi(ifp, link_if);
	if (!zvni)
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err(
			"VNI %u hash %p doesn't have intf upon local neighbor DEL",
			zvni->vni, zvni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del neighbor %s intf %s(%u) -> L2-VNI %u",
			   ipaddr2str(ip, buf, sizeof(buf)),
			   ifp->name, ifp->ifindex, zvni->vni);

	/* If entry doesn't exist, nothing to do. */
	n = zvni_neigh_lookup(zvni, ip);
	if (!n)
		return 0;

	zmac = zvni_mac_lookup(zvni, &n->emac);
	if (!zmac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_err(
				"Trying to del a neigh %s without a mac %s on VNI %u",
				ipaddr2str(ip, buf, sizeof(buf)),
				prefix_mac2str(&n->emac, buf2, sizeof(buf2)),
				zvni->vni);

		return 0;
	}

	/* If it is a remote entry, the kernel has aged this out or someone has
	 * deleted it, it needs to be re-installed as Quagga is the owner.
	 */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		zvni_neigh_install(zvni, n);
		return 0;
	}

	/* Remove neighbor from BGP. */
	if (IS_ZEBRA_NEIGH_ACTIVE(n))
		zvni_neigh_send_del_to_client(zvni->vni, &n->ip, &n->emac,
					      0);

	/* Delete this neighbor entry. */
	zvni_neigh_del(zvni, n);

	/* see if the AUTO mac needs to be deleted */
	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_AUTO)
	    && !listcount(zmac->neigh_list))
		zvni_mac_del(zvni, zmac);

	return 0;
}

/*
 * Handle neighbor add or update (on a VLAN device / L3 interface)
 * from the kernel.
 */
int zebra_vxlan_local_neigh_add_update(struct interface *ifp,
				       struct interface *link_if,
				       struct ipaddr *ip,
				       struct ethaddr *macaddr, u_int16_t state,
				       u_char ext_learned)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	zebra_vni_t *zvni = NULL;
	zebra_neigh_t *n = NULL;
	zebra_mac_t *zmac = NULL, *old_zmac = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* check if this is a remote neigh entry corresponding to remote
	 * next-hop
	 */
	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni)
		return zl3vni_local_nh_add_update(zl3vni, ip, state);

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zvni = zvni_from_svi(ifp, link_if);
	if (!zvni)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add/Update neighbor %s MAC %s intf %s(%u) state 0x%x %s-> L2-VNI %u",
			ipaddr2str(ip, buf2, sizeof(buf2)),
			prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			ifp->ifindex, state, ext_learned ? "ext-learned " : "",
			zvni->vni);

	/* create a dummy MAC if the MAC is not already present */
	zmac = zvni_mac_lookup(zvni, macaddr);
	if (!zmac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"AUTO MAC %s created for neigh %s on VNI %u",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ipaddr2str(ip, buf2, sizeof(buf2)), zvni->vni);

		zmac = zvni_mac_add(zvni, macaddr);
		if (!zmac) {
			zlog_warn("Failed to add MAC %s VNI %u",
				  prefix_mac2str(macaddr, buf, sizeof(buf)),
				  zvni->vni);
			return -1;
		}

		memset(&zmac->fwd_info, 0, sizeof(zmac->fwd_info));
		memset(&zmac->flags, 0, sizeof(u_int32_t));
		SET_FLAG(zmac->flags, ZEBRA_MAC_AUTO);
	}

	/* If same entry already exists, it might be a change or it might be a
	 * move from remote to local.
	 */
	n = zvni_neigh_lookup(zvni, ip);
	if (n) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (memcmp(n->emac.octet, macaddr->octet,
				   ETH_ALEN)
			    == 0) {
				/* Update any params and return - client doesn't
				 * care about a purely local change.
				 */
				n->ifindex = ifp->ifindex;
				return 0;
			}

			/* If the MAC has changed,
			 * need to issue a delete first
			 * as this means a different MACIP route.
			 * Also, need to do some unlinking/relinking.
			 */
			zvni_neigh_send_del_to_client(zvni->vni, &n->ip,
						      &n->emac, 0);
			old_zmac = zvni_mac_lookup(zvni, &n->emac);
			if (old_zmac) {
				listnode_delete(old_zmac->neigh_list, n);
				zvni_deref_ip2mac(zvni, old_zmac, 0);
			}

			/* Set "local" forwarding info. */
			SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
			n->ifindex = ifp->ifindex;
			memcpy(&n->emac, macaddr, ETH_ALEN);

			/* Link to new MAC */
			listnode_add_sort(zmac->neigh_list, n);
		} else if (ext_learned)
		/* The neighbor is remote and that is the notification we got.
		   */
		{
			/* TODO: Evaluate if we need to do anything here. */
			return 0;
		} else
		/* Neighbor has moved from remote to local. */
		{
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
			n->r_vtep_ip.s_addr = 0;
			SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
			n->ifindex = ifp->ifindex;
		}
	} else {
		n = zvni_neigh_add(zvni, ip, macaddr);
		if (!n) {
			zlog_err(
				"Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
				ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, zvni->vni);
			return -1;
		}
		/* Set "local" forwarding info. */
		SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
		n->ifindex = ifp->ifindex;
	}

	/* Before we program this in BGP, we need to check if MAC is locally
	 * learnt as well */
	if (!CHECK_FLAG(zmac->flags, ZEBRA_MAC_LOCAL)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Skipping neigh %s add to client as MAC %s is not local on VNI %u",
				ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				zvni->vni);

		return 0;
	}

	/* Inform BGP. */
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("neigh %s (MAC %s) is now ACTIVE on L2-VNI %u",
			   ipaddr2str(ip, buf2, sizeof(buf2)),
			   prefix_mac2str(macaddr, buf, sizeof(buf)),
			   zvni->vni);
	ZEBRA_NEIGH_SET_ACTIVE(n);

	return zvni_neigh_send_add_to_client(zvni->vni, ip, macaddr, n->flags);
}


/*
 * Handle message from client to delete a remote MACIP for a VNI.
 */
int zebra_vxlan_remote_macip_del(struct zserv *client, u_short length,
				 struct zebra_vrf *zvrf)
{
	struct stream *s;
	vni_t vni;
	struct ethaddr macaddr;
	struct ipaddr ip;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;
	zebra_mac_t *mac;
	zebra_neigh_t *n;
	u_short l = 0, ipa_len;
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;

	memset(&macaddr, 0, sizeof(struct ethaddr));
	memset(&ip, 0, sizeof(struct ipaddr));
	memset(&vtep_ip, 0, sizeof(struct in_addr));

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote MACIP and process. */
		/* Message contains VNI, followed by MAC followed by IP (if any)
		 * followed by remote VTEP IP.
		 */
		mac = NULL;
		n = NULL;
		memset(&ip, 0, sizeof(ip));
		STREAM_GETL(s, vni);
		STREAM_GET(&macaddr.octet, s, ETH_ALEN);
		STREAM_GETL(s, ipa_len);
		if (ipa_len) {
			ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4
								    : IPADDR_V6;
			STREAM_GET(&ip.ip.addr, s, ipa_len);
		}
		l += 4 + ETH_ALEN + 4 + ipa_len;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Recv MACIP Del MAC %s IP %s VNI %u Remote VTEP %s from %s",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni,
				inet_ntoa(vtep_ip),
				zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Failed to locate VNI hash upon remote MACIP DEL, "
					"VNI %u",
					vni);
			continue;
		}
		ifp = zvni->vxlan_if;
		if (!ifp) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote MACIP DEL",
				vni, zvni);
			continue;
		}
		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			continue;

		/* The remote VTEP specified is normally expected to exist, but
		 * it is
		 * possible that the peer may delete the VTEP before deleting
		 * any MACs
		 * referring to the VTEP, in which case the handler (see
		 * remote_vtep_del)
		 * would have already deleted the MACs.
		 */
		if (!zvni_vtep_find(zvni, &vtep_ip))
			continue;

		mac = zvni_mac_lookup(zvni, &macaddr);
		if (ipa_len)
			n = zvni_neigh_lookup(zvni, &ip);

		if (n && !mac) {
			zlog_err(
				"Failed to locate MAC %s for neigh %s VNI %u",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni);
			continue;
		}

		/* If the remote mac or neighbor doesn't exist there is nothing
		 * more
		 * to do. Otherwise, uninstall the entry and then remove it.
		 */
		if (!mac && !n)
			continue;

		/* Ignore the delete if this mac is a gateway mac-ip */
		if (mac && CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL) &&
		    CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW)) {
			zlog_err("%u: Ignore Del for  MAC %s neigh %s on VNI %u as it is configured as a default gateway",
				 zvrf_id(zvrf),
				 prefix_mac2str(&macaddr, buf, sizeof(buf)),
				 ipaddr2str(&ip, buf1, sizeof(buf1)),
				 vni);
			continue;
		}

		/* Uninstall remote neighbor or MAC. */
		if (n) {
			/* When the MAC changes for an IP, it is possible the
			 * client may
			 * update the new MAC before trying to delete the "old"
			 * neighbor
			 * (as these are two different MACIP routes). Do the
			 * delete only
			 * if the MAC matches.
			 */
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)
			    && (memcmp(n->emac.octet, macaddr.octet,
				       ETH_ALEN)
				== 0)) {
				zvni_neigh_uninstall(zvni, n);
				zvni_neigh_del(zvni, n);
				zvni_deref_ip2mac(zvni, mac, 1);
			}
		} else {
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
				zvni_process_neigh_on_remote_mac_del(zvni,
								     mac);

				if (list_isempty(mac->neigh_list)) {
					zvni_mac_uninstall(zvni, mac, 0);
					zvni_mac_del(zvni, mac);
				} else
					SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			}
		}
	}

stream_failure:
	return 0;
}

/*
 * Handle message from client to add a remote MACIP for a VNI. This
 * could be just the add of a MAC address or the add of a neighbor
 * (IP+MAC).
 */
int zebra_vxlan_remote_macip_add(struct zserv *client, u_short length,
				 struct zebra_vrf *zvrf)
{
	struct stream *s;
	vni_t vni;
	struct ethaddr macaddr;
	struct ipaddr ip;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;
	zebra_vtep_t *zvtep;
	zebra_mac_t *mac, *old_mac;
	zebra_neigh_t *n;
	u_short l = 0, ipa_len;
	int update_mac = 0, update_neigh = 0;
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	u_char sticky = 0;
	u_char flags = 0;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;

	memset(&macaddr, 0, sizeof(struct ethaddr));
	memset(&ip, 0, sizeof(struct ipaddr));
	memset(&vtep_ip, 0, sizeof(struct in_addr));

	if (!EVPN_ENABLED(zvrf)) {
		zlog_warn("%s: EVPN Not turned on yet we have received a remote_macip add zapi callback",
			  __PRETTY_FUNCTION__);
		return -1;
	}

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote MACIP and process. */
		/* Message contains VNI, followed by MAC followed by IP (if any)
		 * followed by remote VTEP IP.
		 */
		update_mac = update_neigh = 0;
		mac = NULL;
		n = NULL;
		memset(&ip, 0, sizeof(ip));
		STREAM_GETL(s, vni);
		STREAM_GET(&macaddr.octet, s, ETH_ALEN);
		STREAM_GETL(s, ipa_len);
		if (ipa_len) {
			ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4
								    : IPADDR_V6;
			STREAM_GET(&ip.ip.addr, s, ipa_len);
		}
		l += 4 + ETH_ALEN + 4 + ipa_len;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		l += IPV4_MAX_BYTELEN;

		/* Get flags - sticky mac and/or gateway mac */
		flags = stream_getc(s);
		sticky = CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
		l++;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Recv MACIP Add MAC %s IP %s VNI %u Remote VTEP %s with flags 0x%x from %s",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni,
				inet_ntoa(vtep_ip), flags,
				zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash upon remote MACIP ADD, VNI %u",
				vni);
			continue;
		}
		ifp = zvni->vxlan_if;
		if (!ifp) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote MACIP add",
				vni, zvni);
			continue;
		}
		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			continue;

		/* The remote VTEP specified should normally exist, but it is
		 * possible
		 * that when peering comes up, peer may advertise MACIP routes
		 * before
		 * advertising type-3 routes.
		 */
		zvtep = zvni_vtep_find(zvni, &vtep_ip);
		if (!zvtep) {
			if (zvni_vtep_add(zvni, &vtep_ip) == NULL) {
				zlog_err(
					"Failed to add remote VTEP, VNI %u zvni %p",
					vni, zvni);
				continue;
			}

			zvni_vtep_install(zvni, &vtep_ip);
		}

		mac = zvni_mac_lookup(zvni, &macaddr);

		/* Ignore the update if the mac is already present
		   as a gateway mac */
		if (mac && CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW) &&
		    CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW)) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%u:Ignore MAC %s IP %s on VNI %u as MAC is already configured as gateway mac", 
					   zvrf_id(zvrf),
					   prefix_mac2str(&macaddr,
							  buf, sizeof(buf)),
					   ipaddr2str(&ip, buf1,
						      sizeof(buf1)), vni);
			continue;
		}

		/* check if the remote MAC is unknown or has a change.
		 * If so, that needs to be updated first. Note that client could
		 * install MAC and MACIP separately or just install the latter.
		 */
		if (!mac || !CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
		    || (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0)
			       != sticky
		    || !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &vtep_ip))
			update_mac = 1;

		if (update_mac) {
			if (!mac) {
				mac = zvni_mac_add(zvni, &macaddr);
				if (!mac) {
					zlog_warn(
						"Failed to add MAC %s VNI %u Remote VTEP %s",
						prefix_mac2str(&macaddr, buf,
							       sizeof(buf)),
						vni, inet_ntoa(vtep_ip));
					return -1;
				}

				/* Is this MAC created for a MACIP? */
				if (ipa_len)
					SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			}

			/* Set "auto" and "remote" forwarding info. */
			UNSET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
			memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
			SET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
			mac->fwd_info.r_vtep_ip = vtep_ip;

			if (sticky)
				SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
			else
				UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);

			zvni_process_neigh_on_remote_mac_add(zvni, mac);

			/* Install the entry. */
			zvni_mac_install(zvni, mac);
		}

		/* If there is no IP, continue - after clearing AUTO flag of
		 * MAC. */
		if (!ipa_len) {
			UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			continue;
		}

		/* Check if the remote neighbor itself is unknown or has a
		 * change.
		 * If so, create or update and then install the entry.
		 */
		n = zvni_neigh_lookup(zvni, &ip);
		if (!n || !CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)
		    || (memcmp(&n->emac, &macaddr, sizeof(macaddr)) != 0)
		    || !IPV4_ADDR_SAME(&n->r_vtep_ip, &vtep_ip))
			update_neigh = 1;

		if (update_neigh) {
			if (!n) {
				n = zvni_neigh_add(zvni, &ip, &macaddr);
				if (!n) {
					zlog_warn(
						"Failed to add Neigh %s MAC %s VNI %u Remote VTEP %s",
						ipaddr2str(&ip, buf1,
							   sizeof(buf1)),
						prefix_mac2str(&macaddr, buf,
							       sizeof(buf)),
						vni, inet_ntoa(vtep_ip));
					return -1;
				}

			} else if (memcmp(&n->emac, &macaddr, sizeof(macaddr))
				   != 0) {
				/* MAC change, update neigh list for old and new
				 * mac */
				old_mac = zvni_mac_lookup(zvni, &n->emac);
				if (old_mac) {
					listnode_delete(old_mac->neigh_list, n);
					zvni_deref_ip2mac(zvni, old_mac, 1);
				}
				listnode_add_sort(mac->neigh_list, n);
				memcpy(&n->emac, &macaddr, ETH_ALEN);
			}

			/* Set "remote" forwarding info. */
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
			/* TODO: Handle MAC change. */
			n->r_vtep_ip = vtep_ip;
			SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);

			/* Install the entry. */
			zvni_neigh_install(zvni, n);
		}
	}

stream_failure:
	return 0;
}

/*
 * Handle notification of MAC add/update over VxLAN. If the kernel is notifying
 * us, this must involve a multihoming scenario. Treat this as implicit delete
 * of any prior local MAC.
 */
int zebra_vxlan_check_del_local_mac(struct interface *ifp,
				    struct interface *br_if,
				    struct ethaddr *macaddr, vlanid_t vid)
{
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;
	zebra_vni_t *zvni;
	zebra_mac_t *mac;
	char buf[ETHER_ADDR_STRLEN];

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(vni);
	if (!zvni)
		return 0;

	/* If entry doesn't exist, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac)
		return 0;

	/* Is it a local entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add/update remote MAC %s intf %s(%u) VNI %u - del local",
			prefix_mac2str(macaddr, buf, sizeof(buf)),
			ifp->name, ifp->ifindex, vni);

	/* Remove MAC from BGP. */
	zvni_mac_send_del_to_client(zvni->vni, macaddr, mac->flags);

	/*
	 * If there are no neigh associated with the mac delete the mac
	 * else mark it as AUTO for forward reference
	 */
	if (!listcount(mac->neigh_list)) {
		zvni_mac_del(zvni, mac);
	} else {
		UNSET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	}

	return 0;
}

/*
 * Handle remote MAC delete by kernel; readd the remote MAC if we have it.
 * This can happen because the remote MAC entries are also added as "dynamic",
 * so the kernel can ageout the entry.
 */
int zebra_vxlan_check_readd_remote_mac(struct interface *ifp,
				       struct interface *br_if,
				       struct ethaddr *macaddr, vlanid_t vid)
{
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	vni_t vni;
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;
	zebra_mac_t *mac = NULL;
	char buf[ETHER_ADDR_STRLEN];

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	/* check if this is a remote RMAC and readd simillar to remote macs */
	zl3vni = zl3vni_lookup(vni);
	if (zl3vni)
		return zebra_vxlan_readd_remote_rmac(zl3vni, macaddr);

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(vni);
	if (!zvni)
		return 0;

	/* If entry doesn't exist, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac)
		return 0;

	/* Is it a remote entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del remote MAC %s intf %s(%u) VNI %u - readd",
			   prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			   ifp->ifindex, vni);

	zvni_mac_install(zvni, mac);
	return 0;
}

/*
 * Handle local MAC delete (on a port or VLAN corresponding to this VNI).
 */
int zebra_vxlan_local_mac_del(struct interface *ifp, struct interface *br_if,
			      struct ethaddr *macaddr, vlanid_t vid)
{
	zebra_vni_t *zvni;
	zebra_mac_t *mac;
	char buf[ETHER_ADDR_STRLEN];

	/* We are interested in MACs only on ports or (port, VLAN) that
	 * map to a VNI.
	 */
	zvni = zvni_map_vlan(ifp, br_if, vid);
	if (!zvni)
		return 0;
	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p doesn't have intf upon local MAC DEL",
			 zvni->vni, zvni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del MAC %s intf %s(%u) VID %u -> VNI %u",
			   prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			   ifp->ifindex, vid, zvni->vni);

	/* If entry doesn't exist, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac)
		return 0;

	/* Is it a local entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return 0;

	/* Remove MAC from BGP. */
	zvni_mac_send_del_to_client(zvni->vni, macaddr, mac->flags);

	/* Update all the neigh entries associated with this mac */
	zvni_process_neigh_on_local_mac_del(zvni, mac);

	/*
	 * If there are no neigh associated with the mac delete the mac
	 * else mark it as AUTO for forward reference
	 */
	if (!listcount(mac->neigh_list)) {
		zvni_mac_del(zvni, mac);
	} else {
		UNSET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	}

	return 0;
}

/*
 * Handle local MAC add (on a port or VLAN corresponding to this VNI).
 */
int zebra_vxlan_local_mac_add_update(struct interface *ifp,
				     struct interface *br_if,
				     struct ethaddr *macaddr, vlanid_t vid,
				     u_char sticky)
{
	zebra_vni_t *zvni;
	zebra_mac_t *mac;
	char buf[ETHER_ADDR_STRLEN];
	int add = 1;
	u_char mac_sticky;

	/* We are interested in MACs only on ports or (port, VLAN) that
	 * map to a VNI.
	 */
	zvni = zvni_map_vlan(ifp, br_if, vid);
	if (!zvni) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Add/Update %sMAC %s intf %s(%u) VID %u, could not find VNI",
				sticky ? "sticky " : "",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, vid);
		return 0;
	}

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p doesn't have intf upon local MAC ADD",
			 zvni->vni, zvni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add/Update %sMAC %s intf %s(%u) VID %u -> VNI %u",
			sticky ? "sticky " : "",
			prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			ifp->ifindex, vid, zvni->vni);

	/* If same entry already exists, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (mac) {
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			mac_sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)
					     ? 1
					     : 0;


			/*
			 * return if nothing has changed.
			 * inform bgp if sticky flag has changed
			 * update locally and do not inform bgp if local
			 * parameters like interface has changed
			 */
			if (mac_sticky == sticky
			    && mac->fwd_info.local.ifindex == ifp->ifindex
			    && mac->fwd_info.local.vid == vid) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"Add/Update %sMAC %s intf %s(%u) VID %u -> VNI %u, "
						"entry exists and has not changed ",
						sticky ? "sticky " : "",
						prefix_mac2str(macaddr, buf,
							       sizeof(buf)),
						ifp->name, ifp->ifindex, vid,
						zvni->vni);
				return 0;
			} else if (mac_sticky != sticky) {
				add = 1;
			} else {
				add = 0; /* This is an update of local
					    interface. */
			}
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
			/*
			 * If we have already learned the MAC as a remote sticky
			 * MAC,
			 * this is a operator error and we must log a warning
			 */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)) {
				zlog_warn(
					"MAC %s is already learnt as a remote sticky mac behind VTEP %s VNI %d",
					prefix_mac2str(macaddr, buf,
						       sizeof(buf)),
					inet_ntoa(mac->fwd_info.r_vtep_ip),
					zvni->vni);
				return 0;
			}
		}
	}

	if (!mac) {
		mac = zvni_mac_add(zvni, macaddr);
		if (!mac) {
			zlog_err("Failed to add MAC %s intf %s(%u) VID %u",
				 prefix_mac2str(macaddr, buf, sizeof(buf)),
				 ifp->name, ifp->ifindex, vid);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
	memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
	mac->fwd_info.local.ifindex = ifp->ifindex;
	mac->fwd_info.local.vid = vid;

	if (sticky)
		SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
	else
		UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);

	/* Inform BGP if required. */
	if (add) {
		zvni_process_neigh_on_local_mac_add(zvni, mac);
		return zvni_mac_send_add_to_client(zvni->vni, macaddr,
						   mac->flags);
	}

	return 0;
}

/*
 * Handle message from client to delete a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_del(struct zserv *client, u_short length,
				struct zebra_vrf *zvrf)
{
	struct stream *s;
	u_short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;
	zebra_vtep_t *zvtep;
	struct interface *ifp;
	struct zebra_if *zif;

	if (!is_evpn_enabled()) {
		zlog_warn("%s: EVPN is not enabled yet we have received a vtep del command",
			  __PRETTY_FUNCTION__);
		return -1;
	}

	if (zvrf_id(zvrf) != VRF_DEFAULT) {
		zlog_err("Recv MACIP DEL for non-default VRF %u",
			 zvrf_id(zvrf));
		return -1;
	}

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote VTEP and process. */
		STREAM_GETL(s, vni);
		l += 4;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Recv VTEP_DEL %s VNI %u from %s",
				   inet_ntoa(vtep_ip), vni,
				   zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Failed to locate VNI hash upon remote VTEP DEL, "
					"VNI %u",
					vni);
			continue;
		}

		ifp = zvni->vxlan_if;
		if (!ifp) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote VTEP DEL",
				zvni->vni, zvni);
			continue;
		}
		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			continue;

		/* If the remote VTEP does not exist, there's nothing more to
		 * do.
		 * Otherwise, uninstall any remote MACs pointing to this VTEP
		 * and
		 * then, the VTEP entry itself and remove it.
		 */
		zvtep = zvni_vtep_find(zvni, &vtep_ip);
		if (!zvtep)
			continue;

		zvni_neigh_del_from_vtep(zvni, 1, &vtep_ip);
		zvni_mac_del_from_vtep(zvni, 1, &vtep_ip);
		zvni_vtep_uninstall(zvni, &vtep_ip);
		zvni_vtep_del(zvni, zvtep);
	}

stream_failure:
	return 0;
}

/*
 * Handle message from client to add a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_add(struct zserv *client, u_short length,
				struct zebra_vrf *zvrf)
{
	struct stream *s;
	u_short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;
	struct interface *ifp;
	struct zebra_if *zif;

	if (!is_evpn_enabled()) {
		zlog_warn("%s: EVPN not enabled yet we received a vtep_add zapi call",
			  __PRETTY_FUNCTION__);
		return -1;
	}

	if (zvrf_id(zvrf) != VRF_DEFAULT) {
		zlog_err("Recv MACIP ADD for non-default VRF %u",
			 zvrf_id(zvrf));
		return -1;
	}

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote VTEP and process. */
		STREAM_GETL(s, vni);
		l += 4;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Recv VTEP_ADD %s VNI %u from %s",
				   inet_ntoa(vtep_ip), vni,
				   zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash upon remote VTEP ADD, VNI %u",
				vni);
			continue;
		}

		ifp = zvni->vxlan_if;
		if (!ifp) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote VTEP ADD",
				zvni->vni, zvni);
			continue;
		}

		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			continue;

		/* If the remote VTEP already exists,
		   there's nothing more to do. */
		if (zvni_vtep_find(zvni, &vtep_ip))
			continue;

		if (zvni_vtep_add(zvni, &vtep_ip) == NULL) {
			zlog_err(
				"Failed to add remote VTEP, VNI %u zvni %p",
				vni, zvni);
			continue;
		}

		zvni_vtep_install(zvni, &vtep_ip);
	}

stream_failure:
	return 0;
}

/*
 * Add/Del gateway macip to evpn
 * g/w can be:
 *  1. SVI interface on a vlan aware bridge
 *  2. SVI interface on a vlan unaware bridge
 *  3. vrr interface (MACVLAN) associated to a SVI
 * We advertise macip routes for an interface if it is associated to VxLan vlan
 */
int zebra_vxlan_add_del_gw_macip(struct interface *ifp, struct prefix *p,
				 int add)
{
	struct ipaddr ip;
	struct ethaddr macaddr;
	zebra_vni_t *zvni = NULL;

	memset(&ip, 0, sizeof(struct ipaddr));
	memset(&macaddr, 0, sizeof(struct ethaddr));

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		struct interface *svi_if =
			NULL; /* SVI corresponding to the MACVLAN */
		struct zebra_if *ifp_zif =
			NULL; /* Zebra daemon specific info for MACVLAN */
		struct zebra_if *svi_if_zif =
			NULL; /* Zebra daemon specific info for SVI*/

		ifp_zif = ifp->info;
		if (!ifp_zif)
			return -1;

		/*
		 * for a MACVLAN interface the link represents the svi_if
		 */
		svi_if = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
						   ifp_zif->link_ifindex);
		if (!svi_if) {
			zlog_err("MACVLAN %s(%u) without link information",
				 ifp->name, ifp->ifindex);
			return -1;
		}

		if (IS_ZEBRA_IF_VLAN(svi_if)) {
			/*
			 * If it is a vlan aware bridge then the link gives the
			 * bridge information
			 */
			struct interface *svi_if_link = NULL;

			svi_if_zif = svi_if->info;
			if (svi_if_zif) {
				svi_if_link = if_lookup_by_index_per_ns(
					zebra_ns_lookup(NS_DEFAULT),
					svi_if_zif->link_ifindex);
				zvni = zvni_from_svi(svi_if, svi_if_link);
			}
		} else if (IS_ZEBRA_IF_BRIDGE(svi_if)) {
			/*
			 * If it is a vlan unaware bridge then svi is the bridge
			 * itself
			 */
			zvni = zvni_from_svi(svi_if, svi_if);
		}
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_if *svi_if_zif =
			NULL; /* Zebra daemon specific info for SVI */
		struct interface *svi_if_link =
			NULL; /* link info for the SVI = bridge info */

		svi_if_zif = ifp->info;
		svi_if_link = if_lookup_by_index_per_ns(
			zebra_ns_lookup(NS_DEFAULT), svi_if_zif->link_ifindex);
		if (svi_if_zif && svi_if_link)
			zvni = zvni_from_svi(ifp, svi_if_link);
	} else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		zvni = zvni_from_svi(ifp, ifp);
	}

	if (!zvni)
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p doesn't have intf upon MACVLAN up",
			 zvni->vni, zvni);
		return -1;
	}


	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	if (p->family == AF_INET) {
		ip.ipa_type = IPADDR_V4;
		memcpy(&(ip.ipaddr_v4), &(p->u.prefix4),
		       sizeof(struct in_addr));
	} else if (p->family == AF_INET6) {
		ip.ipa_type = IPADDR_V6;
		memcpy(&(ip.ipaddr_v6), &(p->u.prefix6),
		       sizeof(struct in6_addr));
	}


	if (add)
		zvni_gw_macip_add(ifp, zvni, &macaddr, &ip);
	else
		zvni_gw_macip_del(ifp, zvni, &ip);

	return 0;
}

/*
 * Handle SVI interface going down.
 * SVI can be associated to either L3-VNI or L2-VNI.
 * For L2-VNI: At this point, this is a NOP since
 *	the kernel deletes the neighbor entries on this SVI (if any).
 *      We only need to update the vrf corresponding to zvni.
 * For L3-VNI: L3-VNI is operationally down, update mac-ip routes and delete
 *	from bgp
 */
int zebra_vxlan_svi_down(struct interface *ifp, struct interface *link_if)
{
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni) {

		/* process l3-vni down */
		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* remove association with svi-if */
		zl3vni->svi_if = NULL;
	} else {
		zebra_vni_t *zvni = NULL;

		/* since we dont have svi corresponding to zvni, we associate it
		 * to default vrf. Note: the corresponding neigh entries on the
		 * SVI would have already been deleted */
		zvni = zvni_from_svi(ifp, link_if);
		if (zvni) {
			zvni->vrf_id = VRF_DEFAULT;

			/* update the tenant vrf in BGP */
			zvni_send_add_to_client(zvni);
		}
	}
	return 0;
}

/*
 * Handle SVI interface coming up.
 * SVI can be associated to L3-VNI (l3vni vxlan interface) or L2-VNI (l2-vni
 * vxlan intf).
 * For L2-VNI: we need to install any remote neighbors entried (used for
 * apr-suppression)
 * For L3-VNI: SVI will be used to get the rmac to be used with L3-VNI
 */
int zebra_vxlan_svi_up(struct interface *ifp, struct interface *link_if)
{
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni) {

		/* associate with svi */
		zl3vni->svi_if = ifp;

		/* process oper-up */
		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {

		/* process SVI up for l2-vni */
		struct neigh_walk_ctx n_wctx;

		zvni = zvni_from_svi(ifp, link_if);
		if (!zvni)
			return 0;

		if (!zvni->vxlan_if) {
			zlog_err("VNI %u hash %p doesn't have intf upon SVI up",
				 zvni->vni, zvni);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("SVI %s(%u) VNI %u VRF %s is UP, installing neighbors",
				   ifp->name, ifp->ifindex, zvni->vni,
				   vrf_id_to_name(ifp->vrf_id));

		/* update the vrf information for l2-vni and inform bgp */
		zvni->vrf_id = ifp->vrf_id;
		zvni_send_add_to_client(zvni);

		/* Install any remote neighbors for this VNI. */
		memset(&n_wctx, 0, sizeof(struct neigh_walk_ctx));
		n_wctx.zvni = zvni;
		hash_iterate(zvni->neigh_table,
			     zvni_install_neigh_hash,
			     &n_wctx);
	}

	return 0;
}

/*
 * Handle VxLAN interface down
 */
int zebra_vxlan_if_down(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_l3vni_t *zl3vni = NULL;
	zebra_vni_t *zvni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {
		/* process-if-down for l3-vni */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L3-VNI %u is DOWN",
				   ifp->name, ifp->ifindex, vni);

		zebra_vxlan_process_l3vni_oper_down(zl3vni);
	} else {
		/* process if-down for l2-vni */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L2-VNI %u is DOWN",
				   ifp->name, ifp->ifindex, vni);

		/* Locate hash entry; it is expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash at DOWN, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		assert(zvni->vxlan_if == ifp);

		/* Delete this VNI from BGP. */
		zvni_send_del_to_client(zvni->vni);

		/* Free up all neighbors and MACs, if any. */
		zvni_neigh_del_all(zvni, 1, 0, DEL_ALL_NEIGH);
		zvni_mac_del_all(zvni, 1, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zvni_vtep_del_all(zvni, 1);
	}
	return 0;
}

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int zebra_vxlan_if_up(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L3-VNI %u is UP",
				   ifp->name, ifp->ifindex, vni);

		/* we need to associate with SVI, if any, we can associate with
		 * svi-if only after association with vxlan-intf is complete
		 */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {
		/* Handle L2-VNI add */
		struct interface *vlan_if = NULL;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L2-VNI %u is UP",
				   ifp->name, ifp->ifindex, vni);

		/* Locate hash entry; it is expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash at UP, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		assert(zvni->vxlan_if == ifp);
		vlan_if = zvni_map_to_svi(vxl->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if) {
			zvni->vrf_id = vlan_if->vrf_id;
			zl3vni = zl3vni_from_vrf(vlan_if->vrf_id);
			if (zl3vni)
				listnode_add_sort(zl3vni->l2vnis, zvni);
		}

		/* If part of a bridge, inform BGP about this VNI. */
		/* Also, read and populate local MACs and neighbors. */
		if (zif->brslave_info.br_if) {
			zvni_send_add_to_client(zvni);
			zvni_read_mac_neigh(zvni, ifp);
		}
	}

	return 0;
}

/*
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int zebra_vxlan_if_del(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L3-VNI %u intf %s(%u)",
				   vni, ifp->name, ifp->ifindex);

		/* process oper-down for l3-vni */
		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* remove the association with vxlan_if */
		memset(&zl3vni->local_vtep_ip, 0, sizeof(struct in_addr));
		zl3vni->vxlan_if = NULL;
	} else {

		/* process if-del for l2-vni*/
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L2-VNI %u intf %s(%u)",
				   vni, ifp->name, ifp->ifindex);

		/* Locate hash entry; it is expected to exist. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash at del, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return 0;
		}

		/* remove from l3-vni list */
		zl3vni = zl3vni_from_vrf(zvni->vrf_id);
		if (zl3vni)
			listnode_delete(zl3vni->l2vnis, zvni);

		/* Delete VNI from BGP. */
		zvni_send_del_to_client(zvni->vni);

		/* Free up all neighbors and MAC, if any. */
		zvni_neigh_del_all(zvni, 0, 0, DEL_ALL_NEIGH);
		zvni_mac_del_all(zvni, 0, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zvni_vtep_del_all(zvni, 0);

		/* Delete the hash entry. */
		if (zvni_del(zvni)) {
			zlog_err("Failed to del VNI hash %p, IF %s(%u) VNI %u",
				 zvni, ifp->name, ifp->ifindex, zvni->vni);
			return -1;
		}
	}
	return 0;
}

/*
 * Handle VxLAN interface update - change to tunnel IP, master or VLAN.
 */
int zebra_vxlan_if_update(struct interface *ifp, u_int16_t chgflags)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Update L3-VNI %u intf %s(%u) VLAN %u local IP %s master %u chg 0x%x",
				vni, ifp->name, ifp->ifindex,
				vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
				zif->brslave_info.bridge_ifindex, chgflags);

		/* Removed from bridge? Cleanup and return */
		if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		    && (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
			zebra_vxlan_process_l3vni_oper_down(zl3vni);
			return 0;
		}

		/* access-vlan change - process oper down, associate with new
		 * svi_if and then process oper up again
		 */
		if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
			if (if_is_operative(ifp)) {
				zebra_vxlan_process_l3vni_oper_down(zl3vni);
				zl3vni->svi_if = NULL;
				zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);
				if (is_l3vni_oper_up(zl3vni))
					zebra_vxlan_process_l3vni_oper_up(
									zl3vni);
			}
		}

		/* if we have a valid new master, process l3-vni oper up */
		if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE) {
			if (is_l3vni_oper_up(zl3vni))
				zebra_vxlan_process_l3vni_oper_up(zl3vni);
		}
	} else {

		/* Update VNI hash. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zlog_err(
				"Failed to find L2-VNI hash on update, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Update L2-VNI %u intf %s(%u) VLAN %u local IP %s master %u chg 0x%x",
				vni, ifp->name, ifp->ifindex,
				vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
				zif->brslave_info.bridge_ifindex, chgflags);

		/* Removed from bridge? Cleanup and return */
		if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		    && (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
			/* Delete from client, remove all remote VTEPs */
			/* Also, free up all MACs and neighbors. */
			zvni_send_del_to_client(zvni->vni);
			zvni_neigh_del_all(zvni, 1, 0, DEL_ALL_NEIGH);
			zvni_mac_del_all(zvni, 1, 0, DEL_ALL_MAC);
			zvni_vtep_del_all(zvni, 1);
			return 0;
		}

		/* Handle other changes. */
		if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
			/* Remove all existing local neigh and MACs for this VNI
			 * (including from BGP)
			 */
			zvni_neigh_del_all(zvni, 0, 1, DEL_LOCAL_MAC);
			zvni_mac_del_all(zvni, 0, 1, DEL_LOCAL_MAC);
		}

		zvni->local_vtep_ip = vxl->vtep_ip;
		zvni->vxlan_if = ifp;

		/* Take further actions needed.
		 * Note that if we are here, there is a change of interest.
		 */
		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		/* Inform BGP, if there is a change of interest. */
		if (chgflags
		    & (ZEBRA_VXLIF_MASTER_CHANGE | ZEBRA_VXLIF_LOCAL_IP_CHANGE))
			zvni_send_add_to_client(zvni);

		/* If there is a valid new master or a VLAN mapping change,
		 * read and populate local MACs and neighbors.
		 * Also, reinstall any remote MACs and neighbors
		 * for this VNI (based on new VLAN).
		 */
		if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
			zvni_read_mac_neigh(zvni, ifp);
		else if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
			struct mac_walk_ctx m_wctx;
			struct neigh_walk_ctx n_wctx;

			zvni_read_mac_neigh(zvni, ifp);

			memset(&m_wctx, 0, sizeof(struct mac_walk_ctx));
			m_wctx.zvni = zvni;
			hash_iterate(zvni->mac_table,
				     zvni_install_mac_hash,
				     &m_wctx);

			memset(&n_wctx, 0, sizeof(struct neigh_walk_ctx));
			n_wctx.zvni = zvni;
			hash_iterate(zvni->neigh_table, zvni_install_neigh_hash,
				     &n_wctx);
		}
	}

	return 0;
}

/*
 * Handle VxLAN interface add.
 */
int zebra_vxlan_if_add(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_vni_t *zvni = NULL;
	zebra_l3vni_t *zl3vni = NULL;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		/* process if-add for l3-vni*/
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Add L3-VNI %u intf %s(%u) VLAN %u local IP %s master %u",
				vni, ifp->name, ifp->ifindex,
				vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
				zif->brslave_info.bridge_ifindex);

		/* associate with vxlan_if */
		zl3vni->local_vtep_ip = vxl->vtep_ip;
		zl3vni->vxlan_if = ifp;

		/* Associate with SVI, if any. We can associate with svi-if only
		 * after association with vxlan_if is complete */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {

		/* process if-add for l2-vni */
		struct interface *vlan_if = NULL;

		/* Create or update VNI hash. */
		zvni = zvni_lookup(vni);
		if (!zvni) {
			zvni = zvni_add(vni);
			if (!zvni) {
				zlog_err(
					"Failed to add VNI hash, IF %s(%u) VNI %u",
					ifp->name, ifp->ifindex, vni);
				return -1;
			}
		}

		zvni->local_vtep_ip = vxl->vtep_ip;
		zvni->vxlan_if = ifp;
		vlan_if = zvni_map_to_svi(vxl->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if) {
			zvni->vrf_id = vlan_if->vrf_id;
			zl3vni = zl3vni_from_vrf(vlan_if->vrf_id);
			if (zl3vni)
				listnode_add_sort(zl3vni->l2vnis, zvni);
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Add L2-VNI %u VRF %s intf %s(%u) VLAN %u local IP %s master %u",
				vni,
				vlan_if ? vrf_id_to_name(vlan_if->vrf_id) :
					"Default",
				ifp->name, ifp->ifindex,
				vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
				zif->brslave_info.bridge_ifindex);

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		/* Inform BGP */
		zvni_send_add_to_client(zvni);

		/* Read and populate local MACs and neighbors */
		zvni_read_mac_neigh(zvni, ifp);
	}

	return 0;
}

int zebra_vxlan_process_vrf_vni_cmd(struct zebra_vrf *zvrf,
				    vni_t vni,
				    char *err, int err_str_sz,
				    int add)
{
	zebra_l3vni_t *zl3vni = NULL;
	struct zebra_vrf *zvrf_default = NULL;

	zvrf_default = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	if (!zvrf_default)
		return -1;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("vrf %s vni %u %s",
			   zvrf_name(zvrf),
			   vni,
			   add ? "ADD" : "DEL");

	if (add) {

		zebra_vxlan_handle_vni_transition(zvrf, vni, add);

		/* check if the vni is already present under zvrf */
		if (zvrf->l3vni) {
			snprintf(err, err_str_sz,
				 "VNI is already configured under the vrf");
			return -1;
		}

		/* check if this VNI is already present in the system */
		zl3vni = zl3vni_lookup(vni);
		if (zl3vni) {
			snprintf(err, err_str_sz,
				 "VNI is already configured as L3-VNI");
			return -1;
		}

		/* add the L3-VNI to the global table */
		zl3vni = zl3vni_add(vni, zvrf_id(zvrf));
		if (!zl3vni) {
			snprintf(err, err_str_sz,
				 "Could not add L3-VNI");
			return -1;
		}

		/* associate the vrf with vni */
		zvrf->l3vni = vni;

		/* associate with vxlan-intf;
		 * we need to associate with the vxlan-intf first
		 */
		zl3vni->vxlan_if = zl3vni_map_to_vxlan_if(zl3vni);

		/* associate with corresponding SVI interface, we can associate
		 * with svi-if only after vxlan interface association is
		 * complete
		 */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		/* formulate l2vni list */
		hash_iterate(zvrf_default->vni_table,
			     zvni_add_to_l3vni_list, zl3vni);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);

	} else {
		zl3vni = zl3vni_lookup(vni);
		if (!zl3vni) {
			snprintf(err, err_str_sz, "VNI doesn't exist");
			return -1;
		}

		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* delete and uninstall all rmacs */
		hash_iterate(zl3vni->rmac_table,
			     zl3vni_del_rmac_hash_entry,
			     zl3vni);

		/* delete and uninstall all next-hops */
		hash_iterate(zl3vni->nh_table,
			     zl3vni_del_nh_hash_entry,
			     zl3vni);

		zvrf->l3vni = 0;
		zl3vni_del(zl3vni);

		zebra_vxlan_handle_vni_transition(zvrf, vni, add);
	}
	return 0;
}

int zebra_vxlan_vrf_enable(struct zebra_vrf *zvrf)
{
	zebra_l3vni_t *zl3vni = NULL;

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return 0;

	zl3vni->vrf_id = zvrf_id(zvrf);
	if (is_l3vni_oper_up(zl3vni))
		zebra_vxlan_process_l3vni_oper_up(zl3vni);
	return 0;
}

int zebra_vxlan_vrf_disable(struct zebra_vrf *zvrf)
{
	zebra_l3vni_t *zl3vni = NULL;

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return 0;

	zl3vni->vrf_id = VRF_UNKNOWN;
	zebra_vxlan_process_l3vni_oper_down(zl3vni);
	return 0;
}

int zebra_vxlan_vrf_delete(struct zebra_vrf *zvrf)
{
	zebra_l3vni_t *zl3vni = NULL;
	vni_t vni;

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return 0;

	vni = zl3vni->vni;
	zl3vni_del(zl3vni);
	zebra_vxlan_handle_vni_transition(zvrf, vni, 0);

	return 0;
}

/*
 * Handle message from client to enable/disable advertisement of g/w macip
 * routes
 */
int zebra_vxlan_advertise_subnet(struct zserv *client, u_short length,
				 struct zebra_vrf *zvrf)
{
	struct stream *s;
	int advertise;
	vni_t vni = 0;
	zebra_vni_t *zvni = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;

	if (zvrf_id(zvrf) != VRF_DEFAULT) {
		zlog_err("EVPN GW-MACIP Adv for non-default VRF %u",
			 zvrf_id(zvrf));
		return -1;
	}

	s = client->ibuf;
	advertise = stream_getc(s);
	vni = stream_get3(s);

	zvni = zvni_lookup(vni);
	if (!zvni)
		return 0;

	if (zvni->advertise_subnet == advertise)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"EVPN subnet Adv %s on VNI %d , currently %s",
			advertise ? "enabled" : "disabled", vni,
			zvni->advertise_subnet ? "enabled" : "disabled");


	zvni->advertise_subnet = advertise;

	ifp = zvni->vxlan_if;
	if (!ifp)
		return 0;

	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return 0;

	zl2_info = zif->l2info.vxl;

	vlan_if = zvni_map_to_svi(zl2_info.access_vlan,
				  zif->brslave_info.br_if);
	if (!vlan_if)
		return 0;

	if (zvni->advertise_subnet)
		zvni_advertise_subnet(zvni, vlan_if, 1);
	else
		zvni_advertise_subnet(zvni, vlan_if, 0);

	return 0;
}

/*
 * Handle message from client to enable/disable advertisement of g/w macip
 * routes
 */
int zebra_vxlan_advertise_gw_macip(struct zserv *client, u_short length,
				   struct zebra_vrf *zvrf)
{
	struct stream *s;
	int advertise;
	vni_t vni = 0;
	zebra_vni_t *zvni = NULL;
	struct interface *ifp = NULL;

	if (zvrf_id(zvrf) != VRF_DEFAULT) {
		zlog_err("EVPN GW-MACIP Adv for non-default VRF %u",
			 zvrf_id(zvrf));
		return -1;
	}

	s = client->ibuf;
	STREAM_GETC(s, advertise);
	STREAM_GET(&vni, s, 3);

	if (!vni) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("EVPN gateway macip Adv %s, currently %s",
				   advertise ? "enabled" : "disabled",
				   advertise_gw_macip_enabled(NULL)
					   ? "enabled"
					   : "disabled");

		if (zvrf->advertise_gw_macip == advertise)
			return 0;

		zvrf->advertise_gw_macip = advertise;

		if (advertise_gw_macip_enabled(zvni))
			hash_iterate(zvrf->vni_table,
				     zvni_gw_macip_add_for_vni_hash, NULL);
		else
			hash_iterate(zvrf->vni_table,
				     zvni_gw_macip_del_for_vni_hash, NULL);

	} else {
		struct zebra_if *zif = NULL;
		struct zebra_l2info_vxlan zl2_info;
		struct interface *vlan_if = NULL;
		struct interface *vrr_if = NULL;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"EVPN gateway macip Adv %s on VNI %d , currently %s",
				advertise ? "enabled" : "disabled", vni,
				advertise_gw_macip_enabled(zvni)
					? "enabled"
					: "disabled");

		zvni = zvni_lookup(vni);
		if (!zvni)
			return 0;

		if (zvni->advertise_gw_macip == advertise)
			return 0;

		zvni->advertise_gw_macip = advertise;

		ifp = zvni->vxlan_if;
		if (!ifp)
			return 0;

		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		zl2_info = zif->l2info.vxl;

		vlan_if = zvni_map_to_svi(zl2_info.access_vlan,
					  zif->brslave_info.br_if);
		if (!vlan_if)
			return 0;

		if (advertise_gw_macip_enabled(zvni)) {
			/* Add primary SVI MAC-IP */
			zvni_add_macip_for_intf(vlan_if, zvni);

			/* Add VRR MAC-IP - if any*/
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zvni_add_macip_for_intf(vrr_if, zvni);
		} else {
			/* Del primary MAC-IP */
			zvni_del_macip_for_intf(vlan_if, zvni);

			/* Del VRR MAC-IP - if any*/
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zvni_del_macip_for_intf(vrr_if, zvni);
		}
	}

stream_failure:
	return 0;
}


/*
 * Handle message from client to learn (or stop learning) about VNIs and MACs.
 * When enabled, the VNI hash table will be built and MAC FDB table read;
 * when disabled, the entries should be deleted and remote VTEPs and MACs
 * uninstalled from the kernel.
 */
int zebra_vxlan_advertise_all_vni(struct zserv *client,
				  u_short length, struct zebra_vrf *zvrf)
{
	struct stream *s = NULL;
	int advertise = 0;
	struct zebra_ns *zns = NULL;

	if (zvrf_id(zvrf) != VRF_DEFAULT) {
		zlog_err("EVPN VNI Adv for non-default VRF %u",
			 zvrf_id(zvrf));
		return -1;
	}

	s = client->ibuf;
	STREAM_GETC(s, advertise);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("EVPN VNI Adv %s, currently %s",
			   advertise ? "enabled" : "disabled",
			   is_evpn_enabled() ? "enabled" : "disabled");

	if (zvrf->advertise_all_vni == advertise)
		return 0;

	zvrf->advertise_all_vni = advertise;
	if (is_evpn_enabled()) {
		/* Build VNI hash table and inform BGP. */
		zvni_build_hash_table();

		/* Add all SVI (L3 GW) MACs to BGP*/
		hash_iterate(zvrf->vni_table, zvni_gw_macip_add_for_vni_hash,
			     NULL);

		/* Read the MAC FDB */
		macfdb_read(zvrf->zns);

		/* Read neighbors */
		neigh_read(zvrf->zns);
	} else {
		/* Cleanup VTEPs for all VNIs - uninstall from
		 * kernel and free entries.
		 */
		hash_iterate(zvrf->vni_table, zvni_cleanup_all, zvrf);

		/* cleanup all l3vnis */
		zns = zebra_ns_lookup(NS_DEFAULT);
		if (!zns)
			return -1;

		hash_iterate(zns->l3vni_table, zl3vni_cleanup_all, NULL);
	}

stream_failure:
	return 0;
}

/*
 * Allocate VNI hash table for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_vxlan_init_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	zvrf->vni_table = hash_create(vni_hash_keymake, vni_hash_cmp,
				      "Zebra VRF VNI Table");
}

/* Cleanup VNI info, but don't free the table. */
void zebra_vxlan_cleanup_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	hash_iterate(zvrf->vni_table, zvni_cleanup_all, zvrf);
}

/* Close all VNI handling */
void zebra_vxlan_close_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	hash_iterate(zvrf->vni_table, zvni_cleanup_all, zvrf);
	hash_free(zvrf->vni_table);
}

/* init the l3vni table */
void zebra_vxlan_ns_init(struct zebra_ns *zns)
{
	zns->l3vni_table = hash_create(l3vni_hash_keymake, l3vni_hash_cmp,
				       "Zebra VRF L3 VNI table");
}

/* free l3vni table */
void zebra_vxlan_ns_disable(struct zebra_ns *zns)
{
	hash_free(zns->l3vni_table);
}

/* get the l3vni svi ifindex */
ifindex_t get_l3vni_svi_ifindex(vrf_id_t vrf_id)
{
	zebra_l3vni_t *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return 0;

	return zl3vni->svi_if->ifindex;
}
