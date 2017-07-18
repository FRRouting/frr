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

DEFINE_MTYPE_STATIC(ZEBRA, ZVNI, "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI_VTEP, "VNI remote VTEP");
DEFINE_MTYPE_STATIC(ZEBRA, MAC, "VNI MAC");
DEFINE_MTYPE_STATIC(ZEBRA, NEIGH, "VNI Neighbor");

/* definitions */


/* static function declarations */
static void zvni_print_neigh(zebra_neigh_t *n, void *ctxt);
static void zvni_print_neigh_hash(struct hash_backet *backet, void *ctxt);
static void zvni_print_neigh_hash_all_vni(struct hash_backet *backet,
					  void *ctxt);
static void zvni_print_mac(zebra_mac_t *mac, void *ctxt);
static void zvni_print_mac_hash(struct hash_backet *backet, void *ctxt);
static void zvni_print_mac_hash_all_vni(struct hash_backet *backet, void *ctxt);
static void zvni_print(zebra_vni_t *zvni, void *ctxt);
static void zvni_print_hash(struct hash_backet *backet, void *ctxt);

static int zvni_macip_send_msg_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ethaddr *macaddr,
					 struct ipaddr *ip, u_char sticky,
					 u_int16_t cmd);
static unsigned int neigh_hash_keymake(void *p);
static int neigh_cmp(const void *p1, const void *p2);
static void *zvni_neigh_alloc(void *p);
static zebra_neigh_t *zvni_neigh_add(zebra_vni_t *zvni, struct ipaddr *ip);
static int zvni_neigh_del(zebra_vni_t *zvni, zebra_neigh_t *n);
static int zvni_neigh_del_hash_entry(struct hash_backet *backet, void *arg);
static void zvni_neigh_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				     struct in_addr *r_vtep_ip);
static void zvni_neigh_del_all(struct zebra_vrf *zvrf, zebra_vni_t *zvni,
			       int uninstall, int upd_client, u_int32_t flags);
static zebra_neigh_t *zvni_neigh_lookup(zebra_vni_t *zvni, struct ipaddr *ip);
static int zvni_neigh_send_add_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr);
static int zvni_neigh_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr);
static int zvni_neigh_install(zebra_vni_t *zvni, zebra_neigh_t *n);
static int zvni_neigh_uninstall(zebra_vni_t *zvni, zebra_neigh_t *n);
static zebra_vni_t *zvni_map_svi(struct interface *ifp,
				 struct interface *br_if);
static struct interface *zvni_map_to_svi(struct zebra_vrf *zvrf, vlanid_t vid,
					 struct interface *br_if);

static unsigned int mac_hash_keymake(void *p);
static int mac_cmp(const void *p1, const void *p2);
static void *zvni_mac_alloc(void *p);
static zebra_mac_t *zvni_mac_add(zebra_vni_t *zvni, struct ethaddr *macaddr);
static int zvni_mac_del(zebra_vni_t *zvni, zebra_mac_t *mac);
static int zvni_mac_del_hash_entry(struct hash_backet *backet, void *arg);
static void zvni_mac_del_from_vtep(zebra_vni_t *zvni, int uninstall,
				   struct in_addr *r_vtep_ip);
static void zvni_mac_del_all(struct zebra_vrf *zvrf, zebra_vni_t *zvni,
			     int uninstall, int upd_client, u_int32_t flags);
static zebra_mac_t *zvni_mac_lookup(zebra_vni_t *zvni, struct ethaddr *macaddr);
static int zvni_mac_send_add_to_client(struct zebra_vrf *zvrf, vni_t vni,
				       struct ethaddr *macaddr, u_char sticky);
static int zvni_mac_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni,
				       struct ethaddr *macaddr, u_char sticky);
static zebra_vni_t *zvni_map_vlan(struct interface *ifp,
				  struct interface *br_if, vlanid_t vid);
static int zvni_mac_install(zebra_vni_t *zvni, zebra_mac_t *mac);
static int zvni_mac_uninstall(zebra_vni_t *zvni, zebra_mac_t *mac, int local);
static void zvni_install_mac_hash(struct hash_backet *backet, void *ctxt);

static unsigned int vni_hash_keymake(void *p);
static int vni_hash_cmp(const void *p1, const void *p2);
static void *zvni_alloc(void *p);
static zebra_vni_t *zvni_lookup(struct zebra_vrf *zvrf, vni_t vni);
static zebra_vni_t *zvni_add(struct zebra_vrf *zvrf, vni_t vni);
static int zvni_del(struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int zvni_send_add_to_client(struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int zvni_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni);
static void zvni_build_hash_table(struct zebra_vrf *zvrf);
static int zvni_vtep_match(struct in_addr *vtep_ip, zebra_vtep_t *zvtep);
static zebra_vtep_t *zvni_vtep_find(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static zebra_vtep_t *zvni_vtep_add(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int zvni_vtep_del(zebra_vni_t *zvni, zebra_vtep_t *zvtep);
static int zvni_vtep_del_all(zebra_vni_t *zvni, int uninstall);
static int zvni_vtep_install(zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int zvni_vtep_uninstall(zebra_vni_t *zvni, struct in_addr *vtep_ip);


/* Private functions */

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
static void zvni_print_neigh(zebra_neigh_t *n, void *ctxt)
{
	struct vty *vty;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	ipaddr2str(&n->ip, buf2, sizeof(buf2)), vty = (struct vty *)ctxt;
	vty_out(vty, "IP: %s\n", ipaddr2str(&n->ip, buf2, sizeof(buf2)));
	vty_out(vty, " MAC: %s", prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		vty_out(vty, " Remote VTEP: %s", inet_ntoa(n->r_vtep_ip));
	vty_out(vty, "\n");
}

/*
 * Print neighbor hash entry - called for display of all neighbors.
 */
static void zvni_print_neigh_hash(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	zebra_neigh_t *n;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;

	vty = wctx->vty;
	n = (zebra_neigh_t *)backet->data;
	if (!n)
		return;

	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)
	    && !(wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)) {
		vty_out(vty, "%*s %-6s %-17s\n", -wctx->addr_width, buf2,
			"local", buf1);
		wctx->count++;
	} else {
		if (wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP) {
			if (IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip)) {
				if (wctx->count == 0)
					vty_out(vty, "%*s %-6s %-17s %-21s\n",
						-wctx->addr_width, "Neighbor",
						"Type", "MAC", "Remote VTEP");
				vty_out(vty, "%*s %-6s %-17s %-21s\n",
					-wctx->addr_width, buf2, "remote", buf1,
					inet_ntoa(n->r_vtep_ip));
				wctx->count++;
			}
		} else {
			vty_out(vty, "%*s %-6s %-17s %-21s\n",
				-wctx->addr_width, buf2, "remote", buf1,
				inet_ntoa(n->r_vtep_ip));
			wctx->count++;
		}
	}
}

/*
 * Print neighbors for all VNI.
 */
static void zvni_print_neigh_hash_all_vni(struct hash_backet *backet,
					  void *ctxt)
{
	struct vty *vty;
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;

	vty = (struct vty *)ctxt;
	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	num_neigh = hashcount(zvni->neigh_table);
	vty_out(vty, "\nVNI %u #ARP (IPv4 and IPv6, local and remote) %u\n\n",
		zvni->vni, num_neigh);
	if (!num_neigh)
		return;

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.addr_width = 15;
	hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

	vty_out(vty, "%*s %-6s %-17s %-21s\n", -wctx.addr_width, "IP", "Type",
		"MAC", "Remote VTEP");
	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Print a specific MAC entry.
 */
static void zvni_print_mac(zebra_mac_t *mac, void *ctxt)
{
	struct vty *vty;
	char buf1[20];

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
	} else {
		vty_out(vty, " Remote VTEP: %s",
			inet_ntoa(mac->fwd_info.r_vtep_ip));
	}
	vty_out(vty, " ARP ref: %u", mac->neigh_refcnt);
	vty_out(vty, "\n");
}

/*
 * Print MAC hash entry - called for display of all MACs.
 */
static void zvni_print_mac_hash(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	zebra_mac_t *mac;
	char buf1[20];
	struct mac_walk_ctx *wctx = ctxt;

	vty = wctx->vty;
	mac = (zebra_mac_t *)backet->data;
	if (!mac)
		return;

	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));
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
		vty_out(vty, "%-17s %-6s %-21s", buf1, "local", ifp->name);
		if (vid)
			vty_out(vty, " %-5u", vid);
		vty_out(vty, "\n");
		wctx->count++;
	} else {
		if (wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP) {
			if (IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
					   &wctx->r_vtep_ip)) {
				if (wctx->count == 0) {
					vty_out(vty, "\nVNI %u",
						wctx->zvni->vni);
					vty_out(vty, "%-17s %-6s %-21s %-5s",
						"MAC", "Type",
						"Intf/Remote VTEP", "VLAN");
				}
				vty_out(vty, "%-17s %-6s %-21s", buf1, "remote",
					inet_ntoa(mac->fwd_info.r_vtep_ip));
				wctx->count++;
			}
		} else {
			vty_out(vty, "%-17s %-6s %-21s", buf1, "remote",
				inet_ntoa(mac->fwd_info.r_vtep_ip));
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
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx *wctx = ctxt;

	vty = (struct vty *)wctx->vty;

	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;
	wctx->zvni = zvni;

	/*We are iterating over a new VNI, set the count to 0*/
	wctx->count = 0;

	num_macs = hashcount(zvni->mac_table);
	if (!num_macs)
		return;
	if (!CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP)) {
		vty_out(vty, "\nVNI %u #MACs (local and remote) %u\n\n",
			zvni->vni, num_macs);
		vty_out(vty, "%-17s %-6s %-21s %-5s\n", "MAC", "Type",
			"Intf/Remote VTEP", "VLAN");
	}

	hash_iterate(zvni->mac_table, zvni_print_mac_hash, wctx);
}

/*
 * Print a specific VNI entry.
 */
static void zvni_print(zebra_vni_t *zvni, void *ctxt)
{
	struct vty *vty;
	zebra_vtep_t *zvtep;
	u_int32_t num_macs;
	u_int32_t num_neigh;

	vty = (struct vty *)ctxt;

	vty_out(vty, "VNI: %u\n", zvni->vni);
	if (!zvni->vxlan_if) { // unexpected
		vty_out(vty, " VxLAN interface: unknown\n");
		return;
	}
	vty_out(vty, " VxLAN interface: %s ifIndex: %u VTEP IP: %s\n",
		zvni->vxlan_if->name, zvni->vxlan_if->ifindex,
		inet_ntoa(zvni->local_vtep_ip));

	if (!zvni->vteps) {
		vty_out(vty, " No remote VTEPs known for this VNI\n");
	} else {
		vty_out(vty, " Remote VTEPs for this VNI:\n");
		for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next)
			vty_out(vty, "  %s\n", inet_ntoa(zvtep->vtep_ip));
	}
	num_macs = hashcount(zvni->mac_table);
	vty_out(vty,
		" Number of MACs (local and remote) known for this VNI: %u\n",
		num_macs);
	num_neigh = hashcount(zvni->neigh_table);
	vty_out(vty,
		" Number of ARPs (IPv4 and IPv6, local and remote) "
		"known for this VNI: %u",
		num_neigh);
}

/*
 * Print a VNI hash entry - called for display of all VNIs.
 */
static void zvni_print_hash(struct hash_backet *backet, void *ctxt)
{
	struct vty *vty;
	zebra_vni_t *zvni;
	zebra_vtep_t *zvtep;
	u_int32_t num_vteps = 0;
	u_int32_t num_macs = 0;
	u_int32_t num_neigh = 0;

	vty = (struct vty *)ctxt;
	zvni = (zebra_vni_t *)backet->data;
	if (!zvni)
		return;

	zvtep = zvni->vteps;
	while (zvtep) {
		num_vteps++;
		zvtep = zvtep->next;
	}

	num_macs = hashcount(zvni->mac_table);
	num_neigh = hashcount(zvni->neigh_table);
	vty_out(vty, "%-10u %-21s %-15s %-8u %-8u %-15u\n", zvni->vni,
		zvni->vxlan_if ? zvni->vxlan_if->name : "unknown",
		inet_ntoa(zvni->local_vtep_ip), num_macs, num_neigh, num_vteps);
}

/*
 * Inform BGP about local MACIP.
 */
static int zvni_macip_send_msg_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ethaddr *macaddr,
					 struct ipaddr *ip, u_char sticky,
					 u_int16_t cmd)
{
	struct zserv *client;
	struct stream *s;
	int ipa_len;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	client = zebra_find_client(ZEBRA_ROUTE_BGP);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, cmd, zvrf_id(zvrf));
	stream_putl(s, vni);
	stream_put(s, macaddr->octet, ETHER_ADDR_LEN);
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

	stream_putc(s, sticky); /* Sticky MAC? */

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Send MACIP %s %sMAC %s IP %s VNI %u to %s",
			   zvrf_id(zvrf),
			   (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			   sticky ? "sticky " : "",
			   prefix_mac2str(macaddr, buf, sizeof(buf)),
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
static zebra_neigh_t *zvni_neigh_add(zebra_vni_t *zvni, struct ipaddr *ip)
{
	zebra_neigh_t tmp_n;
	zebra_neigh_t *n = NULL;

	memset(&tmp_n, 0, sizeof(zebra_neigh_t));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = hash_get(zvni->neigh_table, &tmp_n, zvni_neigh_alloc);
	assert(n);

	return n;
}

/*
 * Delete neighbor entry.
 */
static int zvni_neigh_del(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	zebra_neigh_t *tmp_n;

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
			zvni_neigh_send_del_to_client(
				wctx->zvrf, wctx->zvni->vni, &n->ip, &n->emac);

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
static void zvni_neigh_del_all(struct zebra_vrf *zvrf, zebra_vni_t *zvni,
			       int uninstall, int upd_client, u_int32_t flags)
{
	struct neigh_walk_ctx wctx;

	if (!zvni->neigh_table)
		return;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.zvrf = zvrf;
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

/*
 * Inform BGP about local neighbor addition.
 */
static int zvni_neigh_send_add_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr)
{
	return zvni_macip_send_msg_to_client(zvrf, vni, macaddr, ip, 0,
					     ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local neighbor deletion.
 */
static int zvni_neigh_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni,
					 struct ipaddr *ip,
					 struct ethaddr *macaddr)
{
	return zvni_macip_send_msg_to_client(zvrf, vni, macaddr, ip, 0,
					     ZEBRA_MACIP_DEL);
}

/*
 * Install remote neighbor into the kernel.
 */
static int zvni_neigh_install(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	struct zebra_vrf *zvrf;
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);
	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;

	vlan_if = zvni_map_to_svi(zvrf, vxl->access_vlan,
				  zif->brslave_info.br_if);
	if (!vlan_if)
		return -1;

	return kernel_add_neigh(vlan_if, &n->ip, &n->emac);
}

/*
 * Uninstall remote neighbor from the kernel.
 */
static int zvni_neigh_uninstall(zebra_vni_t *zvni, zebra_neigh_t *n)
{
	struct zebra_vrf *zvrf;
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);
	if (!zvni->vxlan_if) {
		zlog_err("VNI %u hash %p couldn't be uninstalled - no intf",
			 zvni->vni, zvni);
		return -1;
	}

	zif = zvni->vxlan_if->info;
	if (!zif)
		return -1;
	vxl = &zif->l2info.vxl;
	vlan_if = zvni_map_to_svi(zvrf, vxl->access_vlan,
				  zif->brslave_info.br_if);
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

/*
 * Make hash key for MAC.
 */
static unsigned int mac_hash_keymake(void *p)
{
	zebra_mac_t *pmac = p;
	char *pnt = (char *)pmac->macaddr.octet;
	unsigned int key = 0;
	int c = 0;

	key += pnt[c];
	key += pnt[c + 1];
	key += pnt[c + 2];
	key += pnt[c + 3];
	key += pnt[c + 4];
	key += pnt[c + 5];

	return (key);
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
		       ETHER_ADDR_LEN)
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
	memcpy(&tmp_mac.macaddr, macaddr, ETHER_ADDR_LEN);
	mac = hash_get(zvni->mac_table, &tmp_mac, zvni_mac_alloc);
	assert(mac);

	return mac;
}

/*
 * Delete MAC entry.
 */
static int zvni_mac_del(zebra_vni_t *zvni, zebra_mac_t *mac)
{
	zebra_mac_t *tmp_mac;

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
			zvni_mac_send_del_to_client(wctx->zvrf, wctx->zvni->vni,
						    &mac->macaddr, sticky);
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

	hash_iterate(
		zvni->mac_table,
		(void (*)(struct hash_backet *, void *))zvni_mac_del_hash_entry,
		&wctx);
}

/*
 * Delete all MAC entries for this VNI.
 */
static void zvni_mac_del_all(struct zebra_vrf *zvrf, zebra_vni_t *zvni,
			     int uninstall, int upd_client, u_int32_t flags)
{
	struct mac_walk_ctx wctx;

	if (!zvni->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.zvrf = zvrf;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(
		zvni->mac_table,
		(void (*)(struct hash_backet *, void *))zvni_mac_del_hash_entry,
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
	memcpy(&tmp.macaddr, mac, ETHER_ADDR_LEN);
	pmac = hash_lookup(zvni->mac_table, &tmp);

	return pmac;
}

/*
 * Inform BGP about local MAC addition.
 */
static int zvni_mac_send_add_to_client(struct zebra_vrf *zvrf, vni_t vni,
				       struct ethaddr *macaddr, u_char sticky)
{
	return zvni_macip_send_msg_to_client(zvrf, vni, macaddr, NULL, sticky,
					     ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local MAC deletion.
 */
static int zvni_mac_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni,
				       struct ethaddr *macaddr, u_char sticky)
{
	return zvni_macip_send_msg_to_client(zvrf, vni, macaddr, NULL, sticky,
					     ZEBRA_MACIP_DEL);
}

/*
 * Map port or (port, VLAN) to a VNI. This is invoked upon getting MAC
 * notifications, to see if there are of interest.
 * TODO: Need to make this as a hash table.
 */
static zebra_vni_t *zvni_map_vlan(struct interface *ifp,
				  struct interface *br_if, vlanid_t vid)
{
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct interface *tmp_if;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl;
	u_char bridge_vlan_aware;
	zebra_vni_t *zvni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(zvrf_id(zvrf)), node, tmp_if)) {
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware)
			break;

		if (vxl->access_vlan == vid)
			break;
	}

	if (!tmp_if)
		return NULL;

	zvni = zvni_lookup(zvrf, vxl->vni);
	return zvni;
}

/*
 * Map SVI and associated bridge to a VNI. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 * TODO: Need to make this as a hash table.
 */
static zebra_vni_t *zvni_map_svi(struct interface *ifp, struct interface *br_if)
{
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct interface *tmp_if;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl;
	u_char bridge_vlan_aware;
	vlanid_t vid = 0;
	zebra_vni_t *zvni;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

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
	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(zvrf_id(zvrf)), node, tmp_if)) {
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware)
			break;

		if (vxl->access_vlan == vid)
			break;
	}

	if (!tmp_if)
		return NULL;

	zvni = zvni_lookup(zvrf, vxl->vni);
	return zvni;
}

/* Map to SVI on bridge corresponding to specified VLAN. This can be one
 * of two cases:
 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN interface
 * linked to the bridge
 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge inteface
 * itself
 */
static struct interface *zvni_map_to_svi(struct zebra_vrf *zvrf, vlanid_t vid,
					 struct interface *br_if)
{
	struct listnode *node;
	struct interface *tmp_if;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vlan *vl;
	u_char bridge_vlan_aware;

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
	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(zvrf_id(zvrf)), node, tmp_if)) {
		/* Check oper status of the SVI. */
		if (!if_is_operative(tmp_if))
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VLAN
		    || zif->link != br_if)
			continue;
		vl = (struct zebra_l2info_vlan *)&zif->l2info.vl;

		if (vl->vid == vid)
			break;
	}

	return tmp_if;
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
	if (mac->neigh_refcnt)
		mac->neigh_refcnt--;

	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO) || mac->neigh_refcnt > 0)
		return;

	if (uninstall)
		zvni_mac_uninstall(zvni, mac, 0);

	zvni_mac_del(zvni, mac);
}

/*
 * Read and populate local MACs and neighbors corresponding to this VNI.
 */
static void zvni_read_mac_neigh(struct zebra_vrf *zvrf, zebra_vni_t *zvni,
				struct interface *ifp)
{
	struct zebra_if *zif;
	struct interface *vlan_if;
	struct zebra_l2info_vxlan *vxl;

	zif = ifp->info;
	vxl = &zif->l2info.vxl;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
			ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni,
			zif->brslave_info.bridge_ifindex);

	macfdb_read_for_bridge(zvrf->zns, ifp, zif->brslave_info.br_if);
	vlan_if = zvni_map_to_svi(zvrf, vxl->access_vlan,
				  zif->brslave_info.br_if);
	if (vlan_if)
		neigh_read_for_vlan(zvrf->zns, vlan_if);
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
static zebra_vni_t *zvni_lookup(struct zebra_vrf *zvrf, vni_t vni)
{
	zebra_vni_t tmp_vni;
	zebra_vni_t *zvni = NULL;

	memset(&tmp_vni, 0, sizeof(zebra_vni_t));
	tmp_vni.vni = vni;
	zvni = hash_lookup(zvrf->vni_table, &tmp_vni);

	return zvni;
}

/*
 * Add VNI hash entry.
 */
static zebra_vni_t *zvni_add(struct zebra_vrf *zvrf, vni_t vni)
{
	zebra_vni_t tmp_zvni;
	zebra_vni_t *zvni = NULL;

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
static int zvni_del(struct zebra_vrf *zvrf, zebra_vni_t *zvni)
{
	zebra_vni_t *tmp_zvni;

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
static int zvni_send_add_to_client(struct zebra_vrf *zvrf, zebra_vni_t *zvni)
{
	struct zserv *client;
	struct stream *s;

	client = zebra_find_client(ZEBRA_ROUTE_BGP);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_VNI_ADD, zvrf_id(zvrf));
	stream_putl(s, zvni->vni);
	stream_put_in_addr(s, &zvni->local_vtep_ip);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Send VNI_ADD %u %s to %s", zvrf_id(zvrf),
			   zvni->vni, inet_ntoa(zvni->local_vtep_ip),
			   zebra_route_string(client->proto));

	client->vniadd_cnt++;
	return zebra_server_send_message(client);
}

/*
 * Inform BGP about local VNI deletion.
 */
static int zvni_send_del_to_client(struct zebra_vrf *zvrf, vni_t vni)
{
	struct zserv *client;
	struct stream *s;

	client = zebra_find_client(ZEBRA_ROUTE_BGP);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_VNI_DEL, zvrf_id(zvrf));
	stream_putl(s, vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Send VNI_DEL %u to %s", zvrf_id(zvrf), vni,
			   zebra_route_string(client->proto));

	client->vnidel_cnt++;
	return zebra_server_send_message(client);
}

/*
 * Build the VNI hash table by going over the VxLAN interfaces. This
 * is called when EVPN (advertise-all-vni) is enabled.
 */
static void zvni_build_hash_table(struct zebra_vrf *zvrf)
{
	struct listnode *node;
	struct interface *ifp;

	/* Walk VxLAN interfaces and create VNI hash. */
	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(zvrf_id(zvrf)), node, ifp)) {
		struct zebra_if *zif;
		struct zebra_l2info_vxlan *vxl;
		zebra_vni_t *zvni;
		vni_t vni;

		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		vxl = &zif->l2info.vxl;

		vni = vxl->vni;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%u:Create VNI hash for intf %s(%u) VNI %u local IP %s",
				zvrf_id(zvrf), ifp->name, ifp->ifindex, vni,
				inet_ntoa(vxl->vtep_ip));

		/* VNI hash entry is not expected to exist. */
		zvni = zvni_lookup(zvrf, vni);
		if (zvni) {
			zlog_err(
				"VNI hash already present for VRF %d IF %s(%u) VNI %u",
				zvrf_id(zvrf), ifp->name, ifp->ifindex, vni);
			continue;
		}

		zvni = zvni_add(zvrf, vni);
		if (!zvni) {
			zlog_err(
				"Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
				zvrf_id(zvrf), ifp->name, ifp->ifindex, vni);
			return;
		}

		zvni->local_vtep_ip = vxl->vtep_ip;
		zvni->vxlan_if = ifp;

		/* Inform BGP if interface is up and mapped to bridge. */
		if (if_is_operative(ifp) && zif->brslave_info.br_if)
			zvni_send_add_to_client(zvrf, zvni);
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
	zvni_neigh_del_all(zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
	zvni_mac_del_all(zvrf, zvni, 1, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zvni_vtep_del_all(zvni, 1);

	/* Delete the hash entry. */
	zvni_del(zvrf, zvni);
}


/* Public functions */

/*
 * Display Neighbors for a VNI (VTY command handler).
 */
void zebra_vxlan_print_neigh_vni(struct vty *vty, struct zebra_vrf *zvrf,
				 vni_t vni)
{
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_neigh = hashcount(zvni->neigh_table);
	if (!num_neigh)
		return;

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.addr_width = 15;
	hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

	vty_out(vty,
		"Number of ARPs (local and remote) known for this VNI: %u\n",
		num_neigh);
	vty_out(vty, "%*s %-6s %-17s %-21s\n", -wctx.addr_width, "IP", "Type",
		"MAC", "Remote VTEP");

	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Display neighbors across all VNIs (VTY command handler).
 */
void zebra_vxlan_print_neigh_all_vni(struct vty *vty, struct zebra_vrf *zvrf)
{
	if (!EVPN_ENABLED(zvrf))
		return;
	hash_iterate(zvrf->vni_table, zvni_print_neigh_hash_all_vni, vty);
}

/*
 * Display specific neighbor for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_neigh_vni(struct vty *vty,
					  struct zebra_vrf *zvrf, vni_t vni,
					  struct ipaddr *ip)
{
	zebra_vni_t *zvni;
	zebra_neigh_t *n;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist", vni);
		return;
	}
	n = zvni_neigh_lookup(zvni, ip);
	if (!n) {
		vty_out(vty, "%% Requested neighbor does not exist in VNI %u\n",
			vni);
		return;
	}

	zvni_print_neigh(n, vty);
}

/*
 * Display neighbors for a VNI from specific VTEP (VTY command handler).
 * By definition, these are remote neighbors.
 */
void zebra_vxlan_print_neigh_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				      vni_t vni, struct in_addr vtep_ip)
{
	zebra_vni_t *zvni;
	u_int32_t num_neigh;
	struct neigh_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
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

	hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Display MACs for a VNI (VTY command handler).
 */
void zebra_vxlan_print_macs_vni(struct vty *vty, struct zebra_vrf *zvrf,
				vni_t vni)
{
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = hashcount(zvni->mac_table);
	if (!num_macs)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;

	vty_out(vty,
		"Number of MACs (local and remote) known for this VNI: %u\n",
		num_macs);
	vty_out(vty, "%-17s %-6s %-21s %-5s\n", "MAC", "Type",
		"Intf/Remote VTEP", "VLAN");

	hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni(struct vty *vty, struct zebra_vrf *zvrf)
{
	struct mac_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.vty = vty;
	hash_iterate(zvrf->vni_table, zvni_print_mac_hash_all_vni, &wctx);
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni_vtep(struct vty *vty,
					 struct zebra_vrf *zvrf,
					 struct in_addr vtep_ip)
{
	struct mac_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	hash_iterate(zvrf->vni_table, zvni_print_mac_hash_all_vni, &wctx);
}

/*
 * Display specific MAC for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_mac_vni(struct vty *vty, struct zebra_vrf *zvrf,
					vni_t vni, struct ethaddr *macaddr)
{
	zebra_vni_t *zvni;
	zebra_mac_t *mac;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
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
				     vni_t vni, struct in_addr vtep_ip)
{
	zebra_vni_t *zvni;
	u_int32_t num_macs;
	struct mac_walk_ctx wctx;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = hashcount(zvni->mac_table);
	if (!num_macs)
		return;
	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zvni = zvni;
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);
}


/*
 * Display VNI information (VTY command handler).
 */
void zebra_vxlan_print_vni(struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
	zebra_vni_t *zvni;

	if (!EVPN_ENABLED(zvrf))
		return;
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	zvni_print(zvni, (void *)vty);
}

/*
 * Display VNI hash table (VTY command handler).
 */
void zebra_vxlan_print_vnis(struct vty *vty, struct zebra_vrf *zvrf)
{
	u_int32_t num_vnis;

	if (!EVPN_ENABLED(zvrf))
		return;
	num_vnis = hashcount(zvrf->vni_table);
	if (!num_vnis)
		return;
	vty_out(vty, "Number of VNIs: %u\n", num_vnis);
	vty_out(vty, "%-10s %-21s %-15s %-8s %-8s %-15s\n", "VNI", "VxLAN IF",
		"VTEP IP", "# MACs", "# ARPs", "# Remote VTEPs");
	hash_iterate(zvrf->vni_table, zvni_print_hash, vty);
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
	struct zebra_vrf *zvrf;
	char buf[INET6_ADDRSTRLEN];

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
		zlog_debug("%u:Del neighbor %s intf %s(%u) -> VNI %u",
			   ifp->vrf_id, ipaddr2str(ip, buf, sizeof(buf)),
			   ifp->name, ifp->ifindex, zvni->vni);

	/* If entry doesn't exist, nothing to do. */
	n = zvni_neigh_lookup(zvni, ip);
	if (!n)
		return 0;

	/* If it is a remote entry, the kernel has aged this out or someone has
	 * deleted it, it needs to be re-installed as Quagga is the owner.
	 */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		zvni_neigh_install(zvni, n);
		return 0;
	}

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);

	/* Remove neighbor from BGP. */
	zvni_neigh_send_del_to_client(zvrf, zvni->vni, &n->ip, &n->emac);

	/* Delete this neighbor entry. */
	zvni_neigh_del(zvni, n);

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
	struct zebra_vrf *zvrf;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	int send_upd = 1, send_del = 0;

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zvni = zvni_map_svi(ifp, link_if);
	if (!zvni)
		return 0;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:Add/Update neighbor %s MAC %s intf %s(%u) state 0x%x "
			"%s-> VNI %u",
			ifp->vrf_id, ipaddr2str(ip, buf2, sizeof(buf2)),
			prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			ifp->ifindex, state, ext_learned ? "ext-learned " : "",
			zvni->vni);

	/* If same entry already exists, it might be a change or it might be a
	 * move from remote to local.
	 */
	n = zvni_neigh_lookup(zvni, ip);
	if (n) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (memcmp(n->emac.octet, macaddr->octet,
				   ETHER_ADDR_LEN)
			    == 0) {
				if (n->ifindex == ifp->ifindex)
					/* we're not interested in whatever has
					 * changed. */
					return 0;
				/* client doesn't care about a purely local
				 * change. */
				send_upd = 0;
			} else
				/* If the MAC has changed, issue a delete first
				 * as this means a
				 * different MACIP route.
				 */
				send_del = 1;
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
		}
	} else {
		n = zvni_neigh_add(zvni, ip);
		if (!n) {
			zlog_err(
				"%u:Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
				ifp->vrf_id, ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, zvni->vni);
			return -1;
		}
	}

	/* Issue delete for older info, if needed. */
	if (send_del)
		zvni_neigh_send_del_to_client(zvrf, zvni->vni, &n->ip,
					      &n->emac);

	/* Set "local" forwarding info. */
	SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	memcpy(&n->emac, macaddr, ETHER_ADDR_LEN);
	n->ifindex = ifp->ifindex;

	/* Inform BGP if required. */
	if (send_upd)
		return zvni_neigh_send_add_to_client(zvrf, zvni->vni, ip,
						     macaddr);

	return 0;
}

/*
 * Handle message from client to delete a remote MACIP for a VNI.
 */
int zebra_vxlan_remote_macip_del(struct zserv *client, int sock, u_short length,
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

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote MACIP and process. */
		/* Message contains VNI, followed by MAC followed by IP (if any)
		 * followed by remote VTEP IP.
		 */
		mac = NULL;
		n = NULL;
		memset(&ip, 0, sizeof(ip));
		vni = (vni_t)stream_getl(s);
		stream_get(&macaddr.octet, s, ETHER_ADDR_LEN);
		ipa_len = stream_getl(s);
		if (ipa_len) {
			ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4
								    : IPADDR_V6;
			stream_get(&ip.ip.addr, s, ipa_len);
		}
		l += 4 + ETHER_ADDR_LEN + 4 + ipa_len;
		vtep_ip.s_addr = stream_get_ipv4(s);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%u:Recv MACIP Del MAC %s IP %s VNI %u Remote VTEP %s from %s",
				zvrf_id(zvrf),
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni,
				inet_ntoa(vtep_ip),
				zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(zvrf, vni);
		if (!zvni) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Failed to locate VNI hash upon remote MACIP DEL, "
					"VRF %d VNI %u",
					zvrf_id(zvrf), vni);
			continue;
		}
		if (!zvni->vxlan_if) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote MACIP DEL",
				vni, zvni);
			continue;
		}

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

		/* If the local VxLAN interface is not up (should be a transient
		 * event),  there's nothing more to do.
		 */
		if (!if_is_operative(zvni->vxlan_if))
			continue;

		mac = zvni_mac_lookup(zvni, &macaddr);
		if (ipa_len)
			n = zvni_neigh_lookup(zvni, &ip);

		if (n && !mac) {
			zlog_err(
				"failed to locate MAC %s for neigh %s in VRF %u VNI %u",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)),
				zvrf_id(zvrf), vni);
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
				       ETHER_ADDR_LEN)
				== 0)) {
				zvni_neigh_uninstall(zvni, n);
				zvni_neigh_del(zvni, n);
				zvni_deref_ip2mac(zvni, mac, 1);
			}
		} else {
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
				if (!mac->neigh_refcnt) {
					zvni_mac_uninstall(zvni, mac, 0);
					zvni_mac_del(zvni, mac);
				} else
					SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			}
		}
	}

	return 0;
}

/*
 * Handle message from client to add a remote MACIP for a VNI. This
 * could be just the add of a MAC address or the add of a neighbor
 * (IP+MAC).
 */
int zebra_vxlan_remote_macip_add(struct zserv *client, int sock, u_short length,
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

	assert(EVPN_ENABLED(zvrf));

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
		vni = (vni_t)stream_getl(s);
		stream_get(&macaddr.octet, s, ETHER_ADDR_LEN);
		ipa_len = stream_getl(s);
		if (ipa_len) {
			ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4
								    : IPADDR_V6;
			stream_get(&ip.ip.addr, s, ipa_len);
		}
		l += 4 + ETHER_ADDR_LEN + 4 + ipa_len;
		vtep_ip.s_addr = stream_get_ipv4(s);
		l += IPV4_MAX_BYTELEN;

		/* Get 'sticky' flag. */
		sticky = stream_getc(s);
		l++;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%u:Recv MACIP Add %sMAC %s IP %s VNI %u Remote VTEP %s from %s",
				zvrf_id(zvrf), sticky ? "sticky " : "",
				prefix_mac2str(&macaddr, buf, sizeof(buf)),
				ipaddr2str(&ip, buf1, sizeof(buf1)), vni,
				inet_ntoa(vtep_ip),
				zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(zvrf, vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash upon remote MACIP ADD, VRF %d VNI %u",
				zvrf_id(zvrf), vni);
			continue;
		}
		if (!zvni->vxlan_if) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote MACIP add",
				vni, zvni);
			continue;
		}
		/* If the local VxLAN interface is not up (should be a transient
		 * event),  there's nothing more to do.
		 */
		if (!if_is_operative(zvni->vxlan_if))
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
					"Failed to add remote VTEP, VRF %d VNI %u zvni %p",
					zvrf_id(zvrf), vni, zvni);
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
						"%u:Failed to add MAC %s VNI %u Remote VTEP %s",
						zvrf_id(zvrf),
						prefix_mac2str(&macaddr, buf,
							       sizeof(buf)),
						vni, inet_ntoa(vtep_ip));
					return -1;
				}

				/* Is this MAC created for a MACIP? */
				if (ipa_len)
					SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
				/* Moving from local to remote, issue delete. */
				zvni_mac_uninstall(zvni, mac, 1);
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
				n = zvni_neigh_add(zvni, &ip);
				if (!n) {
					zlog_warn(
						"%u:Failed to add Neigh %s MAC %s VNI %u Remote VTEP %s",
						zvrf_id(zvrf),
						ipaddr2str(&ip, buf1,
							   sizeof(buf1)),
						prefix_mac2str(&macaddr, buf,
							       sizeof(buf)),
						vni, inet_ntoa(vtep_ip));
					return -1;
				}

				/* New neighbor referring to this MAC. */
				mac->neigh_refcnt++;
			} else if (memcmp(&n->emac, &macaddr, sizeof(macaddr))
				   != 0) {
				/* MAC change, update ref counts for old and new
				 * MAC. */
				old_mac = zvni_mac_lookup(zvni, &n->emac);
				if (old_mac)
					zvni_deref_ip2mac(zvni, old_mac, 1);
				mac->neigh_refcnt++;
			}

			/* Set "remote" forwarding info. */
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
			/* TODO: Handle MAC change. */
			memcpy(&n->emac, &macaddr, ETHER_ADDR_LEN);
			n->r_vtep_ip = vtep_ip;
			SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);

			/* Install the entry. */
			zvni_neigh_install(zvni, n);
		}
	}

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
	struct zebra_vrf *zvrf;
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

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing to do. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(zvrf, vni);
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
			"%u:Add/update remote MAC %s intf %s(%u) VNI %u - del local",
			ifp->vrf_id, prefix_mac2str(macaddr, buf, sizeof(buf)),
			ifp->name, ifp->ifindex, vni);

	/* Remove MAC from BGP. */
	sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0;
	zvni_mac_send_del_to_client(zvrf, zvni->vni, macaddr, sticky);

	/* Delete this MAC entry. */
	zvni_mac_del(zvni, mac);

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
	struct zebra_vrf *zvrf;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;
	zebra_vni_t *zvni;
	zebra_mac_t *mac;
	char buf[ETHER_ADDR_STRLEN];

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing to do. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(zvrf, vni);
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
		zlog_debug("%u:Del remote MAC %s intf %s(%u) VNI %u - readd",
			   ifp->vrf_id,
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
	struct zebra_vrf *zvrf;
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
		zlog_debug("%u:Del MAC %s intf %s(%u) VID %u -> VNI %u",
			   ifp->vrf_id,
			   prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			   ifp->ifindex, vid, zvni->vni);

	/* If entry doesn't exist, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (!mac)
		return 0;

	/* Is it a local entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return 0;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);

	/* Remove MAC from BGP. */
	sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? 1 : 0;
	zvni_mac_send_del_to_client(zvrf, zvni->vni, macaddr, sticky);

	/* Delete this MAC entry. */
	zvni_mac_del(zvni, mac);

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
	struct zebra_vrf *zvrf;
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
				"%u:Add/Update %sMAC %s intf %s(%u) VID %u, could not find VNI",
				ifp->vrf_id, sticky ? "sticky " : "",
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
			"%u:Add/Update %sMAC %s intf %s(%u) VID %u -> VNI %u",
			ifp->vrf_id, sticky ? "sticky " : "",
			prefix_mac2str(macaddr, buf, sizeof(buf)), ifp->name,
			ifp->ifindex, vid, zvni->vni);

	/* If same entry already exists, nothing to do. */
	mac = zvni_mac_lookup(zvni, macaddr);
	if (mac) {
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			mac_sticky = CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)
					     ? 1
					     : 0;

			if (mac_sticky == sticky
			    && mac->fwd_info.local.ifindex == ifp->ifindex
			    && mac->fwd_info.local.vid == vid) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"%u:Add/Update %sMAC %s intf %s(%u) VID %u -> VNI %u, "
						"entry exists and has not changed ",
						ifp->vrf_id,
						sticky ? "sticky " : "",
						prefix_mac2str(macaddr, buf,
							       sizeof(buf)),
						ifp->name, ifp->ifindex, vid,
						zvni->vni);
				return 0;
			}

			add = 0; /* This is an update of local interface. */
		}
	}

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
	assert(zvrf);

	if (!mac) {
		mac = zvni_mac_add(zvni, macaddr);
		if (!mac) {
			zlog_err("%u:Failed to add MAC %s intf %s(%u) VID %u",
				 ifp->vrf_id,
				 prefix_mac2str(macaddr, buf, sizeof(buf)),
				 ifp->name, ifp->ifindex, vid);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
	memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
	SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
	mac->fwd_info.local.ifindex = ifp->ifindex;
	mac->fwd_info.local.vid = vid;

	if (sticky)
		SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
	else
		UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);

	/* Inform BGP if required. */
	if (add)
		return zvni_mac_send_add_to_client(zvrf, zvni->vni, macaddr,
						   sticky);

	return 0;
}

/*
 * Handle message from client to delete a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_del(struct zserv *client, int sock, u_short length,
				struct zebra_vrf *zvrf)
{
	struct stream *s;
	u_short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;
	zebra_vtep_t *zvtep;

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote VTEP and process. */
		vni = (vni_t)stream_getl(s);
		l += 4;
		vtep_ip.s_addr = stream_get_ipv4(s);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%u:Recv VTEP_DEL %s VNI %u from %s",
				   zvrf_id(zvrf), inet_ntoa(vtep_ip), vni,
				   zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(zvrf, vni);
		if (!zvni) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Failed to locate VNI hash upon remote VTEP DEL, "
					"VRF %d VNI %u",
					zvrf_id(zvrf), vni);
			continue;
		}

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

	return 0;
}

/*
 * Handle message from client to add a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_add(struct zserv *client, int sock, u_short length,
				struct zebra_vrf *zvrf)
{
	struct stream *s;
	u_short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;
	zebra_vni_t *zvni;

	assert(EVPN_ENABLED(zvrf));

	s = client->ibuf;

	while (l < length) {
		/* Obtain each remote VTEP and process. */
		vni = (vni_t)stream_getl(s);
		l += 4;
		vtep_ip.s_addr = stream_get_ipv4(s);
		l += IPV4_MAX_BYTELEN;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%u:Recv VTEP_ADD %s VNI %u from %s",
				   zvrf_id(zvrf), inet_ntoa(vtep_ip), vni,
				   zebra_route_string(client->proto));

		/* Locate VNI hash entry - expected to exist. */
		zvni = zvni_lookup(zvrf, vni);
		if (!zvni) {
			zlog_err(
				"Failed to locate VNI hash upon remote VTEP ADD, VRF %d VNI %u",
				zvrf_id(zvrf), vni);
			continue;
		}
		if (!zvni->vxlan_if) {
			zlog_err(
				"VNI %u hash %p doesn't have intf upon remote VTEP ADD",
				zvni->vni, zvni);
			continue;
		}


		/* If the remote VTEP already exists, or the local VxLAN
		 * interface is
		 * not up (should be a transient event),  there's nothing more
		 * to do.
		 * Otherwise, add and install the entry.
		 */
		if (zvni_vtep_find(zvni, &vtep_ip))
			continue;

		if (!if_is_operative(zvni->vxlan_if))
			continue;

		if (zvni_vtep_add(zvni, &vtep_ip) == NULL) {
			zlog_err(
				"Failed to add remote VTEP, VRF %d VNI %u zvni %p",
				zvrf_id(zvrf), vni, zvni);
			continue;
		}

		zvni_vtep_install(zvni, &vtep_ip);
	}

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
		zlog_debug("%u:SVI %s(%u) VNI %u is UP, installing neighbors",
			   ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni);

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
	struct zebra_vrf *zvrf;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing further to be done. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Intf %s(%u) VNI %u is DOWN", ifp->vrf_id,
			   ifp->name, ifp->ifindex, vni);

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		zlog_err(
			"Failed to locate VNI hash at DOWN, VRF %d IF %s(%u) VNI %u",
			ifp->vrf_id, ifp->name, ifp->ifindex, vni);
		return -1;
	}

	assert(zvni->vxlan_if == ifp);

	/* Delete this VNI from BGP. */
	zvni_send_del_to_client(zvrf, zvni->vni);

	/* Free up all neighbors and MACs, if any. */
	zvni_neigh_del_all(zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
	zvni_mac_del_all(zvrf, zvni, 1, 0, DEL_ALL_MAC);

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
	struct zebra_vrf *zvrf;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing further to be done. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Intf %s(%u) VNI %u is UP", ifp->vrf_id,
			   ifp->name, ifp->ifindex, vni);

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		zlog_err(
			"Failed to locate VNI hash at UP, VRF %d IF %s(%u) VNI %u",
			ifp->vrf_id, ifp->name, ifp->ifindex, vni);
		return -1;
	}

	assert(zvni->vxlan_if == ifp);

	/* If part of a bridge, inform BGP about this VNI. */
	/* Also, read and populate local MACs and neighbors. */
	if (zif->brslave_info.br_if) {
		zvni_send_add_to_client(zvrf, zvni);
		zvni_read_mac_neigh(zvrf, zvni, ifp);
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
	struct zebra_vrf *zvrf;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing further to be done. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:Del VNI %u intf %s(%u)", ifp->vrf_id, vni,
			   ifp->name, ifp->ifindex);

	/* Locate hash entry; it is expected to exist. */
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		zlog_err(
			"Failed to locate VNI hash at del, VRF %d IF %s(%u) VNI %u",
			ifp->vrf_id, ifp->name, ifp->ifindex, vni);
		return 0;
	}

	/* Delete VNI from BGP. */
	zvni_send_del_to_client(zvrf, zvni->vni);

	/* Free up all neighbors and MAC, if any. */
	zvni_neigh_del_all(zvrf, zvni, 0, 0, DEL_ALL_NEIGH);
	zvni_mac_del_all(zvrf, zvni, 0, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zvni_vtep_del_all(zvni, 0);

	/* Delete the hash entry. */
	if (zvni_del(zvrf, zvni)) {
		zlog_err("Failed to del VNI hash %p, VRF %d IF %s(%u) VNI %u",
			 zvni, ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni);
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
	struct zebra_vrf *zvrf;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing further to be done. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	/* Update VNI hash. */
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		zlog_err(
			"Failed to find VNI hash on update, VRF %d IF %s(%u) VNI %u",
			ifp->vrf_id, ifp->name, ifp->ifindex, vni);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:Update VNI %u intf %s(%u) VLAN %u local IP %s "
			"master %u chg 0x%x",
			ifp->vrf_id, vni, ifp->name, ifp->ifindex,
			vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
			zif->brslave_info.bridge_ifindex, chgflags);

	/* Removed from bridge? */
	if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
	    && (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
		/* Delete from client, remove all remote VTEPs */
		/* Also, free up all MACs and neighbors. */
		zvni_send_del_to_client(zvrf, zvni->vni);
		zvni_neigh_del_all(zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
		zvni_mac_del_all(zvrf, zvni, 1, 0, DEL_ALL_MAC);
		zvni_vtep_del_all(zvni, 1);
	} else if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
		/* Remove all existing local neighbors and MACs for this VNI
		 * (including from BGP)
		 */
		zvni_neigh_del_all(zvrf, zvni, 0, 1, DEL_LOCAL_MAC);
		zvni_mac_del_all(zvrf, zvni, 0, 1, DEL_LOCAL_MAC);
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
		zvni_send_add_to_client(zvrf, zvni);

	/* If there is a valid new master or a VLAN mapping change, read and
	 * populate local MACs and neighbors. Also, reinstall any remote MACs
	 * and neighbors for this VNI (based on new VLAN).
	 */
	if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		zvni_read_mac_neigh(zvrf, zvni, ifp);
	else if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
		struct mac_walk_ctx m_wctx;
		struct neigh_walk_ctx n_wctx;

		zvni_read_mac_neigh(zvrf, zvni, ifp);

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
	struct zebra_vrf *zvrf;
	zebra_vni_t *zvni;
	struct zebra_l2info_vxlan *vxl;
	vni_t vni;

	/* Locate VRF corresponding to interface. */
	zvrf = vrf_info_lookup(ifp->vrf_id);
	assert(zvrf);

	/* If EVPN is not enabled, nothing further to be done. */
	if (!EVPN_ENABLED(zvrf))
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vxl->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:Add VNI %u intf %s(%u) VLAN %u local IP %s master %u",
			ifp->vrf_id, vni, ifp->name, ifp->ifindex,
			vxl->access_vlan, inet_ntoa(vxl->vtep_ip),
			zif->brslave_info.bridge_ifindex);

	/* Create or update VNI hash. */
	zvni = zvni_lookup(zvrf, vni);
	if (!zvni) {
		zvni = zvni_add(zvrf, vni);
		if (!zvni) {
			zlog_err(
				"Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
				ifp->vrf_id, ifp->name, ifp->ifindex, vni);
			return -1;
		}
	}

	zvni->local_vtep_ip = vxl->vtep_ip;
	zvni->vxlan_if = ifp;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return 0;

	/* Inform BGP */
	zvni_send_add_to_client(zvrf, zvni);

	/* Read and populate local MACs and neighbors */
	zvni_read_mac_neigh(zvrf, zvni, ifp);

	return 0;
}

/*
 * Handle message from client to learn (or stop learning) about VNIs and MACs.
 * When enabled, the VNI hash table will be built and MAC FDB table read;
 * when disabled, the entries should be deleted and remote VTEPs and MACs
 * uninstalled from the kernel.
 */
int zebra_vxlan_advertise_all_vni(struct zserv *client, int sock,
				  u_short length, struct zebra_vrf *zvrf)
{
	struct stream *s;
	int advertise;

	s = client->ibuf;
	advertise = stream_getc(s);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%u:EVPN VNI Adv %s, currently %s", zvrf_id(zvrf),
			   advertise ? "enabled" : "disabled",
			   EVPN_ENABLED(zvrf) ? "enabled" : "disabled");

	if (zvrf->advertise_all_vni == advertise)
		return 0;

	zvrf->advertise_all_vni = advertise;
	if (EVPN_ENABLED(zvrf)) {
		/* Build VNI hash table and inform BGP. */
		zvni_build_hash_table(zvrf);

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
	hash_iterate(zvrf->vni_table, zvni_cleanup_all, zvrf);
}
