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
#include "lib/json.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZVNI, "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI_VTEP, "VNI remote VTEP");
DEFINE_MTYPE_STATIC(ZEBRA, MAC, "VNI MAC");
DEFINE_MTYPE_STATIC(ZEBRA, NEIGH, "VNI Neighbor");

/* definitions */


/* static function declarations */
static void zvni_print_neigh(zebra_neigh_t *n, void *ctxt, json_object *json);
static void zvni_print_neigh_hash(struct hash_backet *backet, void *ctxt);
static void zvni_print_neigh_hash_all_vni(struct hash_backet *backet,
					  void **args);
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
static zebra_vni_t *zvni_map_svi(struct interface *ifp,
				 struct interface *br_if);
static struct interface *zvni_map_to_svi(vlanid_t vid,
					 struct interface *br_if);

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

	if (json == NULL)
		vty_out(vty, "VNI: %u\n", zvni->vni);
	else
		json_object_int_add(json, "vni", zvni->vni);

	if (!zvni->vxlan_if) { // unexpected
		if (json == NULL)
			vty_out(vty, " VxLAN interface: unknown\n");
		return;
	}
	num_macs = num_valid_macs(zvni);
	num_neigh = hashcount(zvni->neigh_table);
	if (json == NULL)
		vty_out(vty, " VxLAN interface: %s ifIndex: %u VTEP IP: %s\n",
			zvni->vxlan_if->name, zvni->vxlan_if->ifindex,
			inet_ntoa(zvni->local_vtep_ip));
	else {
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
		vty_out(vty, "%-10u %-21s %-15s %-8u %-8u %-15u\n", zvni->vni,
			zvni->vxlan_if ? zvni->vxlan_if->name : "unknown",
			inet_ntoa(zvni->local_vtep_ip), num_macs, num_neigh,
			num_vteps);
	else {
		char vni_str[VNI_STR_LEN];
		snprintf(vni_str, VNI_STR_LEN, "%u", zvni->vni);
		json_vni = json_object_new_object();
		json_object_string_add(json_vni, "vxlanIf",
				       zvni->vxlan_if ? zvni->vxlan_if->name
						      : "unknown");
		json_object_string_add(json_vni, "vtepIp",
				       inet_ntoa(zvni->local_vtep_ip));
		json_object_int_add(json_vni, "numMacs", num_macs);
		json_object_int_add(json_vni, "numArpNd", num_neigh);
		json_object_int_add(json_vni, "numRemoteVteps", num_vteps);
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
	struct zserv *client;
	struct stream *s;
	int ipa_len;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	client = zebra_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, cmd, VRF_DEFAULT);
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
			"Send MACIP %s flags 0x%x MAC %s IP %s VNI %u to %s",
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
						"neigh %s (MAC %s) on VNI %u is now ACTIVE",
						ipaddr2str(&n->ip, buf2,
							   sizeof(buf2)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						zvni->vni);

				ZEBRA_NEIGH_SET_ACTIVE(n);
				zvni_neigh_send_add_to_client(
					zvni->vni, &n->ip, &n->emac, 0);
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
						"neigh %s (MAC %s) on VNI %u is now INACTIVE",
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
						"neigh %s (MAC %s) on VNI %u INACTIVE",
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
					 struct ethaddr *macaddr, u_char flags)
{
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

/*
 * zvni_gw_macip_add_to_client
 */
static int zvni_gw_macip_add(struct interface *ifp, zebra_vni_t *zvni,
			     struct ethaddr *macaddr, struct ipaddr *ip)
{
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	zebra_neigh_t *n = NULL;
	zebra_mac_t *mac = NULL;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

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
	memcpy(&n->emac, macaddr, ETH_ALEN);
	n->ifindex = ifp->ifindex;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"SVI %s(%u) VNI %u, sending GW MAC %s IP %s add to BGP",
			ifp->name, ifp->ifindex, zvni->vni,
			prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)));

	zvni_neigh_send_add_to_client(zvni->vni, ip, macaddr,
				      ZEBRA_MAC_TYPE_GW);

	return 0;
}

/*
 * zvni_gw_macip_del_from_client
 */
static int zvni_gw_macip_del(struct interface *ifp, zebra_vni_t *zvni,
			     struct ipaddr *ip)
{
	zebra_neigh_t *n = NULL;
	zebra_mac_t *mac = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

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

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"SVI %s(%u) VNI %u, sending GW MAC %s IP %s del to BGP",
			ifp->name, ifp->ifindex, zvni->vni,
			prefix_mac2str(&(n->emac), buf1, sizeof(buf1)),
			ipaddr2str(ip, buf2, sizeof(buf2)));

	/* Remove neighbor from BGP. */
	zvni_neigh_send_del_to_client(zvni->vni, &n->ip, &n->emac,
				      ZEBRA_MAC_TYPE_GW);

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

	if (!advertise_gw_macip_enabled(zvni))
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
	u_char sticky = 0;

	if (((wctx->flags & DEL_LOCAL_MAC) && (mac->flags & ZEBRA_MAC_LOCAL))
	    || ((wctx->flags & DEL_REMOTE_MAC)
		&& (mac->flags & ZEBRA_MAC_REMOTE))
	    || ((wctx->flags & DEL_REMOTE_MAC_FROM_VTEP)
		&& (mac->flags & ZEBRA_MAC_REMOTE)
		&& IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
				  &wctx->r_vtep_ip))) {
		if (wctx->upd_client && (mac->flags & ZEBRA_MAC_LOCAL)) {
			sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1
									  : 0;
			zvni_mac_send_del_to_client(
				wctx->zvni->vni, &mac->macaddr,
				(sticky ? ZEBRA_MAC_TYPE_STICKY : 0));
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
				       struct ethaddr *macaddr, u_char flags)
{
	return zvni_macip_send_msg_to_client(vni, macaddr, NULL, flags,
					     ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local MAC deletion.
 */
static int zvni_mac_send_del_to_client(vni_t vni,
				       struct ethaddr *macaddr, u_char flags)
{
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
static zebra_vni_t *zvni_map_svi(struct interface *ifp, struct interface *br_if)
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

		if (advertise_gw_macip_enabled(zvni)) {
			/* Add SVI MAC-IP */
			zvni_add_macip_for_intf(vlan_if, zvni);

			/* Add VRR MAC-IP - if any*/
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zvni_add_macip_for_intf(vrr_if, zvni);
		}

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

	zserv_create_header(s, ZEBRA_VNI_ADD, VRF_DEFAULT);
	stream_putl(s, zvni->vni);
	stream_put_in_addr(s, &zvni->local_vtep_ip);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send VNI_ADD %u %s to %s",
			   zvni->vni, inet_ntoa(zvni->local_vtep_ip),
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

	zserv_create_header(s, ZEBRA_VNI_DEL, VRF_DEFAULT);
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
		struct zebra_if *zif;
		struct zebra_l2info_vxlan *vxl;
		zebra_vni_t *zvni;
		vni_t vni;

		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;
		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		vxl = &zif->l2info.vxl;

		vni = vxl->vni;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Create VNI hash for intf %s(%u) VNI %u local IP %s",
				ifp->name, ifp->ifindex, vni,
				inet_ntoa(vxl->vtep_ip));

		/* VNI hash entry is not expected to exist. */
		zvni = zvni_lookup(vni);
		if (zvni) {
			zlog_err(
				"VNI hash already present for IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			continue;
		}

		zvni = zvni_add(vni);
		if (!zvni) {
			zlog_err(
				"Failed to add VNI hash, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return;
		}

		zvni->local_vtep_ip = vxl->vtep_ip;
		zvni->vxlan_if = ifp;

		/* Inform BGP if interface is up and mapped to bridge. */
		if (if_is_operative(ifp) && zif->brslave_info.br_if)
			zvni_send_add_to_client(zvni);
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
static void zvni_cleanup_all(struct hash_backet *backet, void *zvrf)
{
	zebra_vni_t *zvni;

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	/* Free up all neighbors and MACs, if any. */
	zvni_neigh_del_all(zvni, 1, 0, DEL_ALL_NEIGH);
	zvni_mac_del_all(zvni, 1, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zvni_vtep_del_all(zvni, 1);

	/* Delete the hash entry. */
	zvni_del(zvni);
}


/* Public functions */

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
	zebra_vni_t *zvni;
	json_object *json = NULL;
	void *args[2];

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
	if (use_json)
		json = json_object_new_object();
	args[0] = vty;
	args[1] = json;
	zvni_print(zvni, (void *)args);
	if (use_json) {
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
	u_int32_t num_vnis;
	json_object *json = NULL;
	void *args[2];

	if (!is_evpn_enabled())
		return;
	num_vnis = hashcount(zvrf->vni_table);
	if (!num_vnis) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}
	if (use_json) {
		json = json_object_new_object();
		json_object_string_add(json, "advertiseGatewayMacip",
				       zvrf->advertise_gw_macip ? "Yes" : "No");
		json_object_int_add(json, "numVnis", num_vnis);
	} else {
		vty_out(vty, "Advertise gateway mac-ip: %s\n",
			zvrf->advertise_gw_macip ? "Yes" : "No");
		vty_out(vty, "Number of VNIs: %u\n", num_vnis);
		vty_out(vty, "%-10s %-21s %-15s %-8s %-8s %-15s\n", "VNI",
			"VxLAN IF", "VTEP IP", "# MACs", "# ARPs",
			"# Remote VTEPs");
	}
	args[0] = vty;
	args[1] = json;

	hash_iterate(zvrf->vni_table,
		     (void (*)(struct hash_backet *, void *))zvni_print_hash,
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
	zebra_vni_t *zvni;
	zebra_neigh_t *n;
	char buf[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];
	zebra_mac_t *zmac;

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zvni = zvni_map_svi(ifp, link_if);
	if (!zvni)
		return 0;
	if (!zvni->vxlan_if) {
		zlog_err(
			"VNI %u hash %p doesn't have intf upon local neighbor DEL",
			zvni->vni, zvni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del neighbor %s intf %s(%u) -> VNI %u",
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
	zebra_vni_t *zvni;
	zebra_neigh_t *n;
	zebra_mac_t *zmac, *old_zmac;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zvni = zvni_map_svi(ifp, link_if);
	if (!zvni)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add/Update neighbor %s MAC %s intf %s(%u) state 0x%x "
			"%s-> VNI %u",
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
		zlog_debug("neigh %s (MAC %s) is now ACTIVE on VNI %u",
			   ipaddr2str(ip, buf2, sizeof(buf2)),
			   prefix_mac2str(macaddr, buf, sizeof(buf)),
			   zvni->vni);

	ZEBRA_NEIGH_SET_ACTIVE(n);
	return zvni_neigh_send_add_to_client(zvni->vni, ip, macaddr, 0);
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
	u_char sticky;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;

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

		/* Get 'sticky' flag. */
		STREAM_GETC(s, sticky);
		l++;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Recv MACIP Add %sMAC %s IP %s VNI %u Remote VTEP %s from %s",
				sticky ? "sticky " : "",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni,
				inet_ntoa(vtep_ip),
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

		/* First, check if the remote MAC is unknown or has a change. If
		 * so,
		 * that needs to be updated first. Note that client could
		 * install
		 * MAC and MACIP separately or just install the latter.
		 */
		mac = zvni_mac_lookup(zvni, &macaddr);
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
	u_char sticky;

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
	sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0;
	zvni_mac_send_del_to_client(zvni->vni, macaddr,
				    (sticky ? ZEBRA_MAC_TYPE_STICKY : 0));

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
	u_char sticky;

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
	sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0;
	zvni_mac_send_del_to_client(zvni->vni, macaddr,
				    (sticky ? ZEBRA_MAC_TYPE_STICKY : 0));

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
						   sticky);
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
				zvni = zvni_map_svi(svi_if, svi_if_link);
			}
		} else if (IS_ZEBRA_IF_BRIDGE(svi_if)) {
			/*
			 * If it is a vlan unaware bridge then svi is the bridge
			 * itself
			 */
			zvni = zvni_map_svi(svi_if, svi_if);
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
			zvni = zvni_map_svi(ifp, svi_if_link);
	} else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		zvni = zvni_map_svi(ifp, ifp);
	}

	if (!zvni)
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p doesn't have intf upon MACVLAN up",
			 zvni->vni, zvni);
		return -1;
	}


	/* check if we are advertising gw macip routes */
	if (!advertise_gw_macip_enabled(zvni))
		return 0;

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
 * Handle SVI interface going down. At this point, this is a NOP since
 * the kernel deletes the neighbor entries on this SVI (if any).
 */
int zebra_vxlan_svi_down(struct interface *ifp, struct interface *link_if)
{
	return 0;
}

/*
 * Handle SVI interface coming up. This may or may not be of interest,
 * but if this is a SVI on a VxLAN bridge, we need to install any remote
 * neighbor entries (which will be used for EVPN ARP suppression).
 */
int zebra_vxlan_svi_up(struct interface *ifp, struct interface *link_if)
{
	zebra_vni_t *zvni;
	struct neigh_walk_ctx n_wctx;

	zvni = zvni_map_svi(ifp, link_if);
	if (!zvni)
		return 0;

	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p doesn't have intf upon SVI up",
			 zvni->vni, zvni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("SVI %s(%u) VNI %u is UP, installing neighbors",
			   ifp->name, ifp->ifindex, zvni->vni);

	/* Install any remote neighbors for this VNI. */
	memset(&n_wctx, 0, sizeof(struct neigh_walk_ctx));
	n_wctx.zvni = zvni;
	hash_iterate(zvni->neigh_table, zvni_install_neigh_hash, &n_wctx);

	return 0;
}

/*
 * Handle VxLAN interface down - update BGP if required, and do
 * internal cleanup.
 */
int zebra_vxlan_if_down(struct interface *ifp)
{
	struct zebra_if *zif;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Intf %s(%u) VNI %u is DOWN",
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

	return 0;
}

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int zebra_vxlan_if_up(struct interface *ifp)
{
	struct zebra_if *zif;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Intf %s(%u) VNI %u is UP",
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

	/* If part of a bridge, inform BGP about this VNI. */
	/* Also, read and populate local MACs and neighbors. */
	if (zif->brslave_info.br_if) {
		zvni_send_add_to_client(zvni);
		zvni_read_mac_neigh(zvni, ifp);
	}

	return 0;
}

/*
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int zebra_vxlan_if_del(struct interface *ifp)
{
	struct zebra_if *zif;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del VNI %u intf %s(%u)",
			   vni, ifp->name, ifp->ifindex);

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(vni);
	if (!zvni) {
		zlog_err(
			"Failed to locate VNI hash at del, IF %s(%u) VNI %u",
			ifp->name, ifp->ifindex, vni);
		return 0;
	}

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

	return 0;
}

/*
 * Handle VxLAN interface update - change to tunnel IP, master or VLAN.
 */
int zebra_vxlan_if_update(struct interface *ifp, u_int16_t chgflags)
{
	struct zebra_if *zif;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	/* Update VNI hash. */
	zvni = zvni_lookup(vni);
	if (!zvni) {
		zlog_err(
			"Failed to find VNI hash on update, IF %s(%u) VNI %u",
			ifp->name, ifp->ifindex, vni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Update VNI %u intf %s(%u) VLAN %u local IP %s "
			"master %u chg 0x%x",
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
		/* Remove all existing local neighbors and MACs for this VNI
		 * (including from BGP)
		 */
		zvni_neigh_del_all(zvni, 0, 1, DEL_LOCAL_MAC);
		zvni_mac_del_all(zvni, 0, 1, DEL_LOCAL_MAC);
	}

	zvni->local_vtep_ip = vxl->vtep_ip;
	zvni->vxlan_if = ifp;

	/* Take further actions needed. Note that if we are here, there is a
	 * change of interest.
	 */
	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return 0;

	/* Inform BGP, if there is a change of interest. */
	if (chgflags
	    & (ZEBRA_VXLIF_MASTER_CHANGE | ZEBRA_VXLIF_LOCAL_IP_CHANGE))
		zvni_send_add_to_client(zvni);

	/* If there is a valid new master or a VLAN mapping change, read and
	 * populate local MACs and neighbors. Also, reinstall any remote MACs
	 * and neighbors for this VNI (based on new VLAN).
	 */
	if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		zvni_read_mac_neigh(zvni, ifp);
	else if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
		struct mac_walk_ctx m_wctx;
		struct neigh_walk_ctx n_wctx;

		zvni_read_mac_neigh(zvni, ifp);

		memset(&m_wctx, 0, sizeof(struct mac_walk_ctx));
		m_wctx.zvni = zvni;
		hash_iterate(zvni->mac_table, zvni_install_mac_hash, &m_wctx);

		memset(&n_wctx, 0, sizeof(struct neigh_walk_ctx));
		n_wctx.zvni = zvni;
		hash_iterate(zvni->neigh_table, zvni_install_neigh_hash,
			     &n_wctx);
	}

	return 0;
}

/*
 * Handle VxLAN interface add.
 */
int zebra_vxlan_if_add(struct interface *ifp)
{
	struct zebra_if *zif;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add VNI %u intf %s(%u) VLAN %u local IP %s master %u",
			vni, ifp->name, ifp->ifindex,
			vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
			zif->brslave_info.bridge_ifindex);

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

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return 0;

	/* Inform BGP */
	zvni_send_add_to_client(zvni);

	/* Read and populate local MACs and neighbors */
	zvni_read_mac_neigh(zvni, ifp);

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
	struct stream *s;
	int advertise;

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

/* Close all VNI handling */
void zebra_vxlan_close_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	hash_iterate(zvrf->vni_table, zvni_cleanup_all, zvrf);
	hash_free(zvrf->vni_table);
}
