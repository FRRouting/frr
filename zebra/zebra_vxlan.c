// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

#include <zebra.h>

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
#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif
#include "lib/printfrr.h"

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_vxlan.h"
#include "zebra/zebra_router.h"

DEFINE_MTYPE_STATIC(ZEBRA, HOST_PREFIX, "host prefix");
DEFINE_MTYPE_STATIC(ZEBRA, ZL3VNI, "L3 VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, L3VNI_MAC, "EVPN L3VNI MAC");
DEFINE_MTYPE_STATIC(ZEBRA, L3NEIGH, "EVPN Neighbor");
DEFINE_MTYPE_STATIC(ZEBRA, ZVXLAN_SG, "zebra VxLAN multicast group");
DEFINE_MTYPE_STATIC(ZEBRA, EVPN_VTEP, "zebra VxLAN VTEP IP");

DEFINE_HOOK(zebra_rmac_update,
	    (struct zebra_mac * rmac, struct zebra_l3vni *zl3vni, bool delete,
	     const char *reason),
	    (rmac, zl3vni, delete, reason));

/* config knobs */
static bool accept_bgp_seq = true;

/* Single VXlan Device Global Neigh Table */
struct hash *svd_nh_table;

/* static function declarations */
static void zevpn_print_neigh_hash_all_evpn(struct hash_bucket *bucket,
					    void **args);
static void zl3vni_print_nh(struct zebra_neigh *n, struct vty *vty,
			    json_object *json);
static void zl3vni_print_rmac(struct zebra_mac *zrmac, struct vty *vty,
			      json_object *json);
static void zevpn_print_mac_hash_all_evpn(struct hash_bucket *bucket, void *ctxt);

/* l3-vni next-hop neigh related APIs */
static struct zebra_neigh *zl3vni_nh_lookup(struct zebra_l3vni *zl3vni,
					    const struct ipaddr *ip);
static void *zl3vni_nh_alloc(void *p);
static struct zebra_neigh *zl3vni_nh_add(struct zebra_l3vni *zl3vni,
					 const struct ipaddr *vtep_ip,
					 const struct ethaddr *rmac);
static int zl3vni_nh_del(struct zebra_l3vni *zl3vni, struct zebra_neigh *n);
static int zl3vni_nh_install(struct zebra_l3vni *zl3vni, struct zebra_neigh *n);
static int zl3vni_nh_uninstall(struct zebra_l3vni *zl3vni,
			       struct zebra_neigh *n);
static struct zebra_neigh *svd_nh_add(const struct ipaddr *vtep_ip,
				      const struct ethaddr *rmac);
static void svd_nh_del(struct zebra_neigh *n);
static int svd_nh_install(struct zebra_l3vni *zl3vni, struct zebra_neigh *n);
static int svd_nh_uninstall(struct zebra_l3vni *zl3vni, struct zebra_neigh *n);

/* l3-vni rmac related APIs */
static void zl3vni_print_rmac_hash(struct hash_bucket *, void *);
static struct zebra_mac *zl3vni_rmac_lookup(struct zebra_l3vni *zl3vni,
					    const struct ethaddr *rmac);
static void *zl3vni_rmac_alloc(void *p);
static struct zebra_mac *zl3vni_rmac_add(struct zebra_l3vni *zl3vni,
					 const struct ethaddr *rmac);
static int zl3vni_rmac_del(struct zebra_l3vni *zl3vni, struct zebra_mac *zrmac);
static int zl3vni_rmac_install(struct zebra_l3vni *zl3vni,
			       struct zebra_mac *zrmac);
static int zl3vni_rmac_uninstall(struct zebra_l3vni *zl3vni,
				 struct zebra_mac *zrmac);

/* l3-vni related APIs*/
static void *zl3vni_alloc(void *p);
static struct zebra_l3vni *zl3vni_add(vni_t vni, vrf_id_t vrf_id);
static int zl3vni_del(struct zebra_l3vni *zl3vni);

static void zevpn_build_hash_table(void);
static unsigned int zebra_vxlan_sg_hash_key_make(const void *p);
static bool zebra_vxlan_sg_hash_eq(const void *p1, const void *p2);
static void zebra_vxlan_sg_do_deref(struct zebra_vrf *zvrf,
		struct in_addr sip, struct in_addr mcast_grp);
static struct zebra_vxlan_sg *zebra_vxlan_sg_do_ref(struct zebra_vrf *vrf,
						    struct in_addr sip,
						    struct in_addr mcast_grp);
static void zebra_vxlan_cleanup_sg_table(struct zebra_vrf *zvrf);

bool zebra_evpn_do_dup_addr_detect(struct zebra_vrf *zvrf)
{
	return zvrf->dup_addr_detect && zebra_evpn_mh_do_dup_addr_detect();
}

/* Private functions */
static int host_rb_entry_compare(const struct host_rb_entry *hle1,
				 const struct host_rb_entry *hle2)
{
	if (hle1->p.family < hle2->p.family)
		return -1;

	if (hle1->p.family > hle2->p.family)
		return 1;

	if (hle1->p.prefixlen < hle2->p.prefixlen)
		return -1;

	if (hle1->p.prefixlen > hle2->p.prefixlen)
		return 1;

	if (hle1->p.family == AF_INET) {
		if (hle1->p.u.prefix4.s_addr < hle2->p.u.prefix4.s_addr)
			return -1;

		if (hle1->p.u.prefix4.s_addr > hle2->p.u.prefix4.s_addr)
			return 1;

		return 0;
	} else if (hle1->p.family == AF_INET6) {
		return memcmp(&hle1->p.u.prefix6, &hle2->p.u.prefix6,
			      IPV6_MAX_BYTELEN);
	} else if (hle1->p.family == AF_EVPN) {
		uint8_t family1;
		uint8_t family2;

		/* two (v4/v6) dummy prefixes of route_type BGP_EVPN_AD_ROUTE
		 * are used for all nexthops associated with a non-zero ESI
		 */
		family1 = is_evpn_prefix_ipaddr_v4(
				  (const struct prefix_evpn *)&hle1->p)
				  ? AF_INET
				  : AF_INET6;
		family2 = is_evpn_prefix_ipaddr_v4(
				  (const struct prefix_evpn *)&hle2->p)
				  ? AF_INET
				  : AF_INET6;


		if (family1 < family2)
			return -1;

		if (family1 > family2)
			return 1;

		return 0;
	} else {
		zlog_debug("%s: Unexpected family type: %d", __func__,
			   hle1->p.family);
		return 0;
	}
}
RB_GENERATE(host_rb_tree_entry, host_rb_entry, hl_entry, host_rb_entry_compare);

static uint32_t rb_host_count(struct host_rb_tree_entry *hrbe)
{
	struct host_rb_entry *hle;
	uint32_t count = 0;

	RB_FOREACH (hle, host_rb_tree_entry, hrbe)
		count++;

	return count;
}

static int l3vni_rmac_nh_list_cmp(void *p1, void *p2)
{
	const struct ipaddr *vtep_ip1 = p1;
	const struct ipaddr *vtep_ip2 = p2;

	return ipaddr_cmp(vtep_ip1, vtep_ip2);
}

static void l3vni_rmac_nh_free(struct ipaddr *vtep_ip)
{
	XFREE(MTYPE_EVPN_VTEP, vtep_ip);
}

static void l3vni_rmac_nh_list_nh_delete(struct zebra_l3vni *zl3vni,
					 struct zebra_mac *zrmac,
					 struct ipaddr *vtep_ip)
{
	struct listnode *node = NULL, *nnode = NULL;
	struct ipaddr *vtep = NULL;

	for (ALL_LIST_ELEMENTS(zrmac->nh_list, node, nnode, vtep)) {
		if (ipaddr_cmp(vtep, vtep_ip) == 0)
			break;
	}

	if (node) {
		l3vni_rmac_nh_free(vtep);
		list_delete_node(zrmac->nh_list, node);
	}
}

/*
 * Print neighbors for all EVPN.
 */
static void zevpn_print_neigh_hash_all_evpn(struct hash_bucket *bucket,
					  void **args)
{
	struct vty *vty;
	json_object *json = NULL, *json_evpn = NULL;
	struct zebra_evpn *zevpn;
	uint32_t num_neigh;
	struct neigh_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];
	uint32_t print_dup;

	vty = (struct vty *)args[0];
	json = (json_object *)args[1];
	print_dup = (uint32_t)(uintptr_t)args[2];

	zevpn = (struct zebra_evpn *)bucket->data;

	num_neigh = hashcount(zevpn->neigh_table);

	if (print_dup)
		num_neigh = num_dup_detected_neighs(zevpn);

	if (json == NULL) {
		vty_out(vty,
			"\nVNI %u #ARP (IPv4 and IPv6, local and remote) %u\n\n",
			zevpn->vni, num_neigh);
	} else {
		json_evpn = json_object_new_object();
		json_object_int_add(json_evpn, "numArpNd", num_neigh);
		snprintf(vni_str, VNI_STR_LEN, "%u", zevpn->vni);
	}

	if (!num_neigh) {
		if (json)
			json_object_object_add(json, vni_str, json_evpn);
		return;
	}

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json_evpn;
	hash_iterate(zevpn->neigh_table, zebra_evpn_find_neigh_addr_width,
		     &wctx);

	if (json == NULL)
		zebra_evpn_print_neigh_hdr(vty, &wctx);

	if (print_dup)
		hash_iterate(zevpn->neigh_table,
			     zebra_evpn_print_dad_neigh_hash, &wctx);
	else
		hash_iterate(zevpn->neigh_table, zebra_evpn_print_neigh_hash,
			     &wctx);

	if (json)
		json_object_object_add(json, vni_str, json_evpn);
}

/*
 * Print neighbors for all EVPNs in detail.
 */
static void zevpn_print_neigh_hash_all_evpn_detail(struct hash_bucket *bucket,
						 void **args)
{
	struct vty *vty;
	json_object *json = NULL, *json_evpn = NULL;
	struct zebra_evpn *zevpn;
	uint32_t num_neigh;
	struct neigh_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];
	uint32_t print_dup;

	vty = (struct vty *)args[0];
	json = (json_object *)args[1];
	print_dup = (uint32_t)(uintptr_t)args[2];

	zevpn = (struct zebra_evpn *)bucket->data;
	if (!zevpn) {
		if (json)
			vty_json_empty(vty, json);
		return;
	}
	num_neigh = hashcount(zevpn->neigh_table);

	if (print_dup && num_dup_detected_neighs(zevpn) == 0)
		return;

	if (json == NULL) {
		vty_out(vty,
			"\nVNI %u #ARP (IPv4 and IPv6, local and remote) %u\n\n",
			zevpn->vni, num_neigh);
	} else {
		json_evpn = json_object_new_object();
		json_object_int_add(json_evpn, "numArpNd", num_neigh);
		snprintf(vni_str, VNI_STR_LEN, "%u", zevpn->vni);
	}
	if (!num_neigh) {
		if (json)
			json_object_object_add(json, vni_str, json_evpn);
		return;
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json_evpn;

	if (print_dup)
		hash_iterate(zevpn->neigh_table,
			     zebra_evpn_print_dad_neigh_hash_detail, &wctx);
	else
		hash_iterate(zevpn->neigh_table,
			     zebra_evpn_print_neigh_hash_detail, &wctx);

	if (json)
		json_object_object_add(json, vni_str, json_evpn);
}

/* print a specific next hop for an l3vni */
static void zl3vni_print_nh(struct zebra_neigh *n, struct vty *vty,
			    json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	json_object *json_hosts = NULL;
	struct host_rb_entry *hle;

	if (!json) {
		vty_out(vty, "Ip: %s\n",
			ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		vty_out(vty, "  RMAC: %s\n",
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
		if (n->refcnt)
			/* SVD neigh */
			vty_out(vty, "  Refcount: %u\n", n->refcnt);
		else {
			vty_out(vty, "  Refcount: %d\n",
				rb_host_count(&n->host_rb));
			vty_out(vty, "  Prefixes:\n");
			RB_FOREACH (hle, host_rb_tree_entry, &n->host_rb)
				vty_out(vty, "    %pFX\n", &hle->p);
		}
	} else {
		json_hosts = json_object_new_array();
		json_object_string_add(
			json, "ip", ipaddr2str(&(n->ip), buf2, sizeof(buf2)));
		json_object_string_add(
			json, "routerMac",
			prefix_mac2str(&n->emac, buf2, sizeof(buf2)));
		if (n->refcnt)
			/* SVD neigh */
			json_object_int_add(json, "refCount", n->refcnt);
		else {
			json_object_int_add(json, "refCount",
					    rb_host_count(&n->host_rb));
			RB_FOREACH (hle, host_rb_tree_entry, &n->host_rb)
				json_object_array_add(
					json_hosts,
					json_object_new_string(prefix2str(
						&hle->p, buf2, sizeof(buf2))));
			json_object_object_add(json, "prefixList", json_hosts);
		}
	}
}

/* Print a specific RMAC entry */
static void zl3vni_print_rmac(struct zebra_mac *zrmac, struct vty *vty,
			      json_object *json)
{
	struct listnode *node = NULL;
	struct ipaddr *vtep = NULL;
	json_object *json_nhs = NULL;

	if (!json) {
		vty_out(vty, "MAC: %pEA\n", &zrmac->macaddr);
		vty_out(vty, " Remote VTEP: %pI4\n",
			&zrmac->fwd_info.r_vtep_ip);
	} else {
		json_nhs = json_object_new_array();
		json_object_string_addf(json, "routerMac", "%pEA",
					&zrmac->macaddr);
		json_object_string_addf(json, "vtepIp", "%pI4",
					&zrmac->fwd_info.r_vtep_ip);
		for (ALL_LIST_ELEMENTS_RO(zrmac->nh_list, node, vtep)) {
			json_object_array_add(json_nhs, json_object_new_stringf(
								"%pIA", vtep));
		}
		json_object_object_add(json, "nexthops", json_nhs);
	}
}

/*
 * Print MACs for all EVPNs.
 */
static void zevpn_print_mac_hash_all_evpn(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json = NULL, *json_evpn = NULL;
	json_object *json_mac = NULL;
	struct zebra_evpn *zevpn;
	uint32_t num_macs;
	struct mac_walk_ctx *wctx = ctxt;
	char vni_str[VNI_STR_LEN];

	vty = wctx->vty;
	json = wctx->json;

	zevpn = (struct zebra_evpn *)bucket->data;
	wctx->zevpn = zevpn;

	/*We are iterating over a new VNI, set the count to 0*/
	wctx->count = 0;

	num_macs = num_valid_macs(zevpn);
	if (!num_macs)
		return;

	if (wctx->print_dup)
		num_macs = num_dup_detected_macs(zevpn);

	if (json) {
		json_evpn = json_object_new_object();
		json_mac = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zevpn->vni);
	}

	if (!CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP)) {
		if (json == NULL) {
			vty_out(vty, "\nVNI %u #MACs (local and remote) %u\n\n",
				zevpn->vni, num_macs);
			vty_out(vty,
				"Flags: N=sync-neighs, I=local-inactive, P=peer-active, X=peer-proxy\n");
			vty_out(vty, "%-17s %-6s %-5s %-30s %-5s %s\n", "MAC",
				"Type", "Flags", "Intf/Remote ES/VTEP",
				"VLAN", "Seq #'s");
		} else
			json_object_int_add(json_evpn, "numMacs", num_macs);
	}

	if (!num_macs) {
		if (json) {
			json_object_int_add(json_evpn, "numMacs", num_macs);
			json_object_object_add(json, vni_str, json_evpn);
		}
		return;
	}

	/* assign per-evpn to wctx->json object to fill macs
	 * under the evpn. Re-assign primary json object to fill
	 * next evpn information.
	 */
	wctx->json = json_mac;
	if (wctx->print_dup)
		hash_iterate(zevpn->mac_table, zebra_evpn_print_dad_mac_hash,
			     wctx);
	else
		hash_iterate(zevpn->mac_table, zebra_evpn_print_mac_hash, wctx);
	wctx->json = json;
	if (json) {
		if (wctx->count)
			json_object_object_add(json_evpn, "macs", json_mac);
		json_object_object_add(json, vni_str, json_evpn);
	}
}

/*
 * Print MACs in detail for all EVPNs.
 */
static void zevpn_print_mac_hash_all_evpn_detail(struct hash_bucket *bucket,
					       void *ctxt)
{
	struct vty *vty;
	json_object *json = NULL, *json_evpn = NULL;
	json_object *json_mac = NULL;
	struct zebra_evpn *zevpn;
	uint32_t num_macs;
	struct mac_walk_ctx *wctx = ctxt;
	char vni_str[VNI_STR_LEN];

	vty = wctx->vty;
	json = wctx->json;

	zevpn = (struct zebra_evpn *)bucket->data;
	if (!zevpn) {
		if (json)
			vty_json_empty(vty, json);
		return;
	}
	wctx->zevpn = zevpn;

	/*We are iterating over a new EVPN, set the count to 0*/
	wctx->count = 0;

	num_macs = num_valid_macs(zevpn);
	if (!num_macs)
		return;

	if (wctx->print_dup && (num_dup_detected_macs(zevpn) == 0))
		return;

	if (json) {
		json_evpn = json_object_new_object();
		json_mac = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zevpn->vni);
	}

	if (!CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP)) {
		if (json == NULL) {
			vty_out(vty, "\nVNI %u #MACs (local and remote) %u\n\n",
				zevpn->vni, num_macs);
		} else
			json_object_int_add(json_evpn, "numMacs", num_macs);
	}
	/* assign per-evpn to wctx->json object to fill macs
	 * under the evpn. Re-assign primary json object to fill
	 * next evpn information.
	 */
	wctx->json = json_mac;
	if (wctx->print_dup)
		hash_iterate(zevpn->mac_table,
			     zebra_evpn_print_dad_mac_hash_detail, wctx);
	else
		hash_iterate(zevpn->mac_table, zebra_evpn_print_mac_hash_detail,
			     wctx);
	wctx->json = json;
	if (json) {
		if (wctx->count)
			json_object_object_add(json_evpn, "macs", json_mac);
		json_object_object_add(json, vni_str, json_evpn);
	}
}

static void zl3vni_print_nh_hash(struct hash_bucket *bucket, void *ctx)
{
	struct nh_walk_ctx *wctx = NULL;
	struct vty *vty = NULL;
	struct json_object *json_evpn = NULL;
	struct json_object *json_nh = NULL;
	struct zebra_neigh *n = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];

	wctx = (struct nh_walk_ctx *)ctx;
	vty = wctx->vty;
	json_evpn = wctx->json;
	if (json_evpn)
		json_nh = json_object_new_object();
	n = (struct zebra_neigh *)bucket->data;

	if (!json_evpn) {
		vty_out(vty, "%-15s %-17s\n",
			ipaddr2str(&(n->ip), buf2, sizeof(buf2)),
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
	} else {
		json_object_string_add(json_nh, "nexthopIp",
				       ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		json_object_string_add(
			json_nh, "routerMac",
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
		json_object_object_add(json_evpn,
				       ipaddr2str(&(n->ip), buf2, sizeof(buf2)),
				       json_nh);
	}
}

static void zl3vni_print_nh_all_table(struct hash *nh_table, vni_t vni,
				      struct vty *vty, json_object *json)
{
	uint32_t num_nh = 0;
	struct nh_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];
	json_object *json_evpn = NULL;
	bool is_svd = false;
	const char *svd_str = "Global SVD Table";

	if (vni == 0)
		is_svd = true;

	num_nh = hashcount(nh_table);

	if (!num_nh)
		return;

	if (json) {
		json_evpn = json_object_new_object();

		snprintf(vni_str, VNI_STR_LEN, "%u", vni);
	}

	if (json == NULL) {
		if (is_svd)
			vty_out(vty, "\n%s #Next-Hops %u\n\n", svd_str, num_nh);
		else
			vty_out(vty, "\nVNI %u #Next-Hops %u\n\n", vni, num_nh);

		vty_out(vty, "%-15s %-17s\n", "IP", "RMAC");
	} else
		json_object_int_add(json_evpn, "numNextHops", num_nh);

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_evpn;
	hash_iterate(nh_table, zl3vni_print_nh_hash, &wctx);
	if (json)
		json_object_object_add(json, vni_str, json_evpn);
}

static void zl3vni_print_nh_hash_all_vni(struct hash_bucket *bucket,
					 void **args)
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	zl3vni = (struct zebra_l3vni *)bucket->data;

	zl3vni_print_nh_all_table(zl3vni->nh_table, zl3vni->vni, vty, json);
}

static void zl3vni_print_rmac_hash_all_vni(struct hash_bucket *bucket,
					   void **args)
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	json_object *json_evpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	uint32_t num_rmacs;
	struct rmac_walk_ctx wctx;
	char vni_str[VNI_STR_LEN];

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	zl3vni = (struct zebra_l3vni *)bucket->data;

	num_rmacs = hashcount(zl3vni->rmac_table);
	if (!num_rmacs)
		return;

	if (json) {
		json_evpn = json_object_new_object();
		snprintf(vni_str, VNI_STR_LEN, "%u", zl3vni->vni);
	}

	if (json == NULL) {
		vty_out(vty, "\nVNI %u #RMACs %u\n\n", zl3vni->vni, num_rmacs);
		vty_out(vty, "%-17s %-21s\n", "RMAC", "Remote VTEP");
	} else
		json_object_int_add(json_evpn, "numRmacs", num_rmacs);

	/* assign per-vni to wctx->json object to fill macs
	 * under the vni. Re-assign primary json object to fill
	 * next vni information.
	 */
	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json_evpn;
	hash_iterate(zl3vni->rmac_table, zl3vni_print_rmac_hash, &wctx);
	if (json)
		json_object_object_add(json, vni_str, json_evpn);
}

static void zl3vni_print_rmac_hash(struct hash_bucket *bucket, void *ctx)
{
	struct zebra_mac *zrmac = NULL;
	struct rmac_walk_ctx *wctx = NULL;
	struct vty *vty = NULL;
	struct json_object *json = NULL;
	struct json_object *json_rmac = NULL;
	char buf[PREFIX_STRLEN];

	wctx = (struct rmac_walk_ctx *)ctx;
	vty = wctx->vty;
	json = wctx->json;
	if (json)
		json_rmac = json_object_new_object();
	zrmac = (struct zebra_mac *)bucket->data;

	if (!json) {
		vty_out(vty, "%-17s %-21pI4\n",
			prefix_mac2str(&zrmac->macaddr, buf, sizeof(buf)),
			&zrmac->fwd_info.r_vtep_ip);
	} else {
		json_object_string_add(
			json_rmac, "routerMac",
			prefix_mac2str(&zrmac->macaddr, buf, sizeof(buf)));
		json_object_string_addf(json_rmac, "vtepIp", "%pI4",
					&zrmac->fwd_info.r_vtep_ip);
		json_object_object_add(
			json, prefix_mac2str(&zrmac->macaddr, buf, sizeof(buf)),
			json_rmac);
	}
}

/* print a specific L3 VNI entry */
static void zl3vni_print(struct zebra_l3vni *zl3vni, void **ctx)
{
	char buf[PREFIX_STRLEN];
	struct vty *vty = NULL;
	json_object *json = NULL;
	struct zebra_evpn *zevpn = NULL;
	json_object *json_evpn_list = NULL;
	struct listnode *node = NULL, *nnode = NULL;

	vty = ctx[0];
	json = ctx[1];

	if (!json) {
		vty_out(vty, "VNI: %u\n", zl3vni->vni);
		vty_out(vty, "  Type: %s\n", "L3");
		vty_out(vty, "  Tenant VRF: %s\n", zl3vni_vrf_name(zl3vni));
		vty_out(vty, "  Vlan: %u\n", zl3vni->vid);
		vty_out(vty, "  Bridge: %s\n",
			zl3vni->bridge_if ? zl3vni->bridge_if->name : "-");
		vty_out(vty, "  Local Vtep Ip: %pI4\n",
			&zl3vni->local_vtep_ip);
		vty_out(vty, "  Vxlan-Intf: %s\n",
			zl3vni_vxlan_if_name(zl3vni));
		vty_out(vty, "  SVI-If: %s\n", zl3vni_svi_if_name(zl3vni));
		vty_out(vty, "  State: %s\n", zl3vni_state2str(zl3vni));
		vty_out(vty, "  VNI Filter: %s\n",
			CHECK_FLAG(zl3vni->filter, PREFIX_ROUTES_ONLY)
				? "prefix-routes-only"
				: "none");
		vty_out(vty, "  System MAC: %s\n",
			zl3vni_sysmac2str(zl3vni, buf, sizeof(buf)));
		vty_out(vty, "  Router MAC: %s\n",
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
		vty_out(vty, "  L2 VNIs: ");
		for (ALL_LIST_ELEMENTS(zl3vni->l2vnis, node, nnode, zevpn))
			vty_out(vty, "%u ", zevpn->vni);
		vty_out(vty, "\n");
	} else {
		json_evpn_list = json_object_new_array();
		json_object_int_add(json, "vni", zl3vni->vni);
		json_object_string_add(json, "type", "L3");
#if CONFDATE > 20240210
CPP_NOTICE("Drop `vrf` from JSON outputs")
#endif
		json_object_string_add(json, "vrf", zl3vni_vrf_name(zl3vni));
		json_object_string_add(json, "tenantVrf",
				       zl3vni_vrf_name(zl3vni));
		json_object_string_addf(json, "localVtepIp", "%pI4",
					&zl3vni->local_vtep_ip);
		json_object_string_add(json, "vxlanIntf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_string_add(json, "sviIntf",
				       zl3vni_svi_if_name(zl3vni));
		json_object_string_add(json, "state", zl3vni_state2str(zl3vni));
		json_object_string_add(
			json, "sysMac",
			zl3vni_sysmac2str(zl3vni, buf, sizeof(buf)));
		json_object_string_add(
			json, "routerMac",
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
		json_object_string_add(
			json, "vniFilter",
			CHECK_FLAG(zl3vni->filter, PREFIX_ROUTES_ONLY)
				? "prefix-routes-only"
				: "none");
		for (ALL_LIST_ELEMENTS(zl3vni->l2vnis, node, nnode, zevpn)) {
			json_object_array_add(json_evpn_list,
					      json_object_new_int(zevpn->vni));
		}
		json_object_object_add(json, "l2Vnis", json_evpn_list);
	}
}

/* print a L3 VNI hash entry */
static void zl3vni_print_hash(struct hash_bucket *bucket, void *ctx[])
{
	struct vty *vty = NULL;
	json_object *json = NULL;
	json_object *json_evpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	vty = (struct vty *)ctx[0];
	json = (json_object *)ctx[1];

	zl3vni = (struct zebra_l3vni *)bucket->data;

	if (!json) {
		vty_out(vty, "%-10u %-4s %-21s %-8lu %-8lu %-15s %-37s\n",
			zl3vni->vni, "L3", zl3vni_vxlan_if_name(zl3vni),
			hashcount(zl3vni->rmac_table),
			hashcount(zl3vni->nh_table), "n/a",
			zl3vni_vrf_name(zl3vni));
	} else {
		char vni_str[VNI_STR_LEN];

		snprintf(vni_str, VNI_STR_LEN, "%u", zl3vni->vni);
		json_evpn = json_object_new_object();
		json_object_int_add(json_evpn, "vni", zl3vni->vni);
		json_object_string_add(json_evpn, "vxlanIf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_int_add(json_evpn, "numMacs",
				    hashcount(zl3vni->rmac_table));
		json_object_int_add(json_evpn, "numArpNd",
				    hashcount(zl3vni->nh_table));
		json_object_string_add(json_evpn, "numRemoteVteps", "n/a");
		json_object_string_add(json_evpn, "type", "L3");
		json_object_string_add(json_evpn, "tenantVrf",
				       zl3vni_vrf_name(zl3vni));
		json_object_object_add(json, vni_str, json_evpn);
	}
}

/* print a L3 VNI hash entry in detail*/
static void zl3vni_print_hash_detail(struct hash_bucket *bucket, void *data)
{
	struct vty *vty = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	json_object *json_array = NULL;
	bool use_json = false;
	struct zebra_evpn_show *zes = data;

	vty = zes->vty;
	json_array = zes->json;
	use_json = zes->use_json;

	zl3vni = (struct zebra_l3vni *)bucket->data;

	zebra_vxlan_print_vni(vty, zes->zvrf, zl3vni->vni,
		use_json, json_array);

	if (!use_json)
		vty_out(vty, "\n");
}

static int zvni_map_to_svi_ns(struct ns *ns,
			      void *_in_param,
			      void **_p_ifp)
{
	struct zebra_ns *zns = ns->info;
	struct route_node *rn;
	struct zebra_from_svi_param *in_param =
		(struct zebra_from_svi_param *)_in_param;
	struct zebra_l2info_vlan *vl;
	struct interface *tmp_if = NULL;
	struct interface **p_ifp = (struct interface **)_p_ifp;
	struct zebra_if *zif;

	assert(in_param && p_ifp);

	/* TODO: Optimize with a hash. */
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		/* Check oper status of the SVI. */
		if (!tmp_if || !if_is_operative(tmp_if))
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VLAN
		    || zif->link != in_param->br_if)
			continue;
		vl = (struct zebra_l2info_vlan *)&zif->l2info.vl;

		if (vl->vid == in_param->vid) {
			*p_ifp = tmp_if;
			route_unlock_node(rn);
			return NS_WALK_STOP;
		}
	}
	return NS_WALK_CONTINUE;
}

/* Map to SVI on bridge corresponding to specified VLAN. This can be one
 * of two cases:
 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN interface
 * linked to the bridge
 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge interface
 * itself
 */
struct interface *zvni_map_to_svi(vlanid_t vid, struct interface *br_if)
{
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_from_svi_param in_param;
	struct interface **p_ifp;
	/* Defensive check, caller expected to invoke only with valid bridge. */
	if (!br_if)
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	in_param.bridge_vlan_aware = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif);
	/* Check oper status of the SVI. */
	if (!in_param.bridge_vlan_aware)
		return if_is_operative(br_if) ? br_if : NULL;

	in_param.vid = vid;
	in_param.br_if = br_if;
	in_param.zif = NULL;
	p_ifp = &tmp_if;
	/* Identify corresponding VLAN interface. */
	ns_walk_func(zvni_map_to_svi_ns, (void *)&in_param,
		     (void **)p_ifp);
	return tmp_if;
}

int zebra_evpn_vxlan_del(struct zebra_evpn *zevpn)
{
	zevpn->vid = 0;
	zevpn_vxlan_if_set(zevpn, zevpn->vxlan_if, false /* set */);
	zevpn_bridge_if_set(zevpn, zevpn->bridge_if, false /* set */);

	/* Remove references to the BUM mcast grp */
	zebra_vxlan_sg_deref(zevpn->local_vtep_ip, zevpn->mcast_grp);

	return zebra_evpn_del(zevpn);
}

static int zevpn_build_vni_hash_table(struct zebra_if *zif,
				      struct zebra_vxlan_vni *vnip, void *arg)
{
	vni_t vni;
	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;
	struct interface *ifp;
	struct zebra_l2info_vxlan *vxl;
	struct interface *br_if;

	ifp = zif->ifp;
	vxl = &zif->l2info.vxl;
	vni = vnip->vni;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Build vni table for vni %u for Intf %s", vni,
			   ifp->name);

	/* L3-VNI and L2-VNI are handled seperately */
	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"create L3-VNI hash for Intf %s(%u) L3-VNI %u",
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

		/* Associate l3vni to mac-vlan and extract VRR MAC */
		zl3vni->mac_vlan_if = zl3vni_map_to_mac_vlan_if(zl3vni);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"create l3vni %u svi_if %s mac_vlan_if %s", vni,
				zl3vni->svi_if ? zl3vni->svi_if->name : "NIL",
				zl3vni->mac_vlan_if ? zl3vni->mac_vlan_if->name
						    : "NIL");

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);

	} else {
		struct interface *vlan_if = NULL;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Create L2-VNI hash for intf %s(%u) L2-VNI %u local IP %pI4",
				ifp->name, ifp->ifindex, vni, &vxl->vtep_ip);

		/*
		 * EVPN hash entry is expected to exist, if the BGP process is
		 * killed
		 */
		zevpn = zebra_evpn_lookup(vni);
		if (zevpn) {
			zlog_debug(
				"EVPN hash already present for IF %s(%u) L2-VNI %u",
				ifp->name, ifp->ifindex, vni);

			/*
			 * Inform BGP if intf is up and mapped to
			 * bridge.
			 */
			if (if_is_operative(ifp) && zif->brslave_info.br_if)
				zebra_evpn_send_add_to_client(zevpn);

			/* Send Local MAC-entries to client */
			zebra_evpn_send_mac_list_to_client(zevpn);

			/* Send Loval Neighbor entries to client */
			zebra_evpn_send_neigh_to_client(zevpn);
		} else {
			zevpn = zebra_evpn_add(vni);
			if (!zevpn) {
				zlog_debug(
					"Failed to add EVPN hash, IF %s(%u) L2-VNI %u",
					ifp->name, ifp->ifindex, vni);
				return 0;
			}

			if (zevpn->local_vtep_ip.s_addr !=
				    vxl->vtep_ip.s_addr ||
			    zevpn->mcast_grp.s_addr != vnip->mcast_grp.s_addr) {
				zebra_vxlan_sg_deref(zevpn->local_vtep_ip,
						     zevpn->mcast_grp);
				zebra_vxlan_sg_ref(vxl->vtep_ip,
						   vnip->mcast_grp);
				zevpn->local_vtep_ip = vxl->vtep_ip;
				zevpn->mcast_grp = vnip->mcast_grp;
				/* on local vtep-ip check if ES
				 * orig-ip needs to be updated
				 */
				zebra_evpn_es_set_base_evpn(zevpn);
			}
			zevpn_vxlan_if_set(zevpn, ifp, true /* set */);
			br_if = zif->brslave_info.br_if;
			zevpn_bridge_if_set(zevpn, br_if, true /* set */);
			vlan_if = zvni_map_to_svi(vnip->access_vlan, br_if);
			if (vlan_if) {
				zevpn->vid = vnip->access_vlan;
				zevpn->svi_if = vlan_if;
				zevpn->vrf_id = vlan_if->vrf->vrf_id;
				zl3vni = zl3vni_from_vrf(vlan_if->vrf->vrf_id);
				if (zl3vni)
					listnode_add_sort(zl3vni->l2vnis,
							  zevpn);
			}

			/*
			 * Inform BGP if intf is up and mapped to
			 * bridge.
			 */
			if (if_is_operative(ifp) && zif->brslave_info.br_if)
				zebra_evpn_send_add_to_client(zevpn);
		}
	}

	return 0;
}

static int zevpn_build_hash_table_zns(struct ns *ns,
				     void *param_in __attribute__((unused)),
				     void **param_out __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;
	struct route_node *rn;
	struct interface *ifp;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();

	/* Walk VxLAN interfaces and create EVPN hash. */
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		struct zebra_if *zif;
		struct zebra_l2info_vxlan *vxl;

		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;
		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;

		vxl = &zif->l2info.vxl;
		/* link of VXLAN interface should be in zebra_evpn_vrf */
		if (zvrf->zns->ns_id != vxl->link_nsid) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Intf %s(%u) link not in same "
					"namespace than BGP EVPN core instance ",
					ifp->name, ifp->ifindex);
			continue;
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Building vni table for %s-if %s",
				   IS_ZEBRA_VXLAN_IF_VNI(zif) ? "vni" : "svd",
				   ifp->name);

		zebra_vxlan_if_vni_iterate(zif, zevpn_build_vni_hash_table,
					   NULL);
	}
	return NS_WALK_CONTINUE;
}

/*
 * Build the VNI hash table by going over the VxLAN interfaces. This
 * is called when EVPN (advertise-all-vni) is enabled.
 */

static void zevpn_build_hash_table(void)
{
	ns_walk_func(zevpn_build_hash_table_zns, NULL, NULL);
}

/*
 * Cleanup EVPN/VTEP and update kernel
 */
static void zebra_evpn_vxlan_cleanup_all(struct hash_bucket *bucket, void *arg)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	zevpn = (struct zebra_evpn *)bucket->data;

	/* remove l2vni from l2vni's tenant-vrf l3-vni list */
	zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
	if (zl3vni)
		listnode_delete(zl3vni->l2vnis, zevpn);

	zebra_evpn_cleanup_all(bucket, arg);
}

/* cleanup L3VNI */
static void zl3vni_cleanup_all(struct hash_bucket *bucket, void *args)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = (struct zebra_l3vni *)bucket->data;

	zebra_vxlan_process_l3vni_oper_down(zl3vni);
}

static void rb_find_or_add_host(struct host_rb_tree_entry *hrbe,
				const struct prefix *host)
{
	struct host_rb_entry lookup;
	struct host_rb_entry *hle;

	memset(&lookup, 0, sizeof(lookup));
	memcpy(&lookup.p, host, sizeof(*host));

	hle = RB_FIND(host_rb_tree_entry, hrbe, &lookup);
	if (hle)
		return;

	hle = XCALLOC(MTYPE_HOST_PREFIX, sizeof(struct host_rb_entry));
	memcpy(hle, &lookup, sizeof(lookup));

	RB_INSERT(host_rb_tree_entry, hrbe, hle);
}

static void rb_delete_host(struct host_rb_tree_entry *hrbe, struct prefix *host)
{
	struct host_rb_entry lookup;
	struct host_rb_entry *hle;

	memset(&lookup, 0, sizeof(lookup));
	memcpy(&lookup.p, host, sizeof(*host));

	hle = RB_FIND(host_rb_tree_entry, hrbe, &lookup);
	if (hle) {
		RB_REMOVE(host_rb_tree_entry, hrbe, hle);
		XFREE(MTYPE_HOST_PREFIX, hle);
	}

	return;
}

/*
 * Look up MAC hash entry.
 */
static struct zebra_mac *zl3vni_rmac_lookup(struct zebra_l3vni *zl3vni,
					    const struct ethaddr *rmac)
{
	struct zebra_mac tmp;
	struct zebra_mac *pmac;

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
	const struct zebra_mac *tmp_rmac = p;
	struct zebra_mac *zrmac;

	zrmac = XCALLOC(MTYPE_L3VNI_MAC, sizeof(struct zebra_mac));
	*zrmac = *tmp_rmac;

	return ((void *)zrmac);
}

/*
 * Add RMAC entry to l3-vni
 */
static struct zebra_mac *zl3vni_rmac_add(struct zebra_l3vni *zl3vni,
					 const struct ethaddr *rmac)
{
	struct zebra_mac tmp_rmac;
	struct zebra_mac *zrmac = NULL;

	memset(&tmp_rmac, 0, sizeof(tmp_rmac));
	memcpy(&tmp_rmac.macaddr, rmac, ETH_ALEN);
	zrmac = hash_get(zl3vni->rmac_table, &tmp_rmac, zl3vni_rmac_alloc);
	zrmac->nh_list = list_new();
	zrmac->nh_list->cmp = (int (*)(void *, void *))l3vni_rmac_nh_list_cmp;
	zrmac->nh_list->del = (void (*)(void *))l3vni_rmac_nh_free;

	SET_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE);
	SET_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC);

	return zrmac;
}

/*
 * Delete MAC entry.
 */
static int zl3vni_rmac_del(struct zebra_l3vni *zl3vni, struct zebra_mac *zrmac)
{
	struct zebra_mac *tmp_rmac;

	/* free the list of nh list*/
	list_delete(&zrmac->nh_list);

	tmp_rmac = hash_release(zl3vni->rmac_table, zrmac);
	XFREE(MTYPE_L3VNI_MAC, tmp_rmac);

	return 0;
}

/*
 * Install remote RMAC into the forwarding plane.
 */
static int zl3vni_rmac_install(struct zebra_l3vni *zl3vni,
			       struct zebra_mac *zrmac)
{
	const struct zebra_if *zif = NULL, *br_zif = NULL;
	const struct zebra_vxlan_vni *vni;
	const struct interface *br_ifp;
	enum zebra_dplane_result res;
	vlanid_t vid;

	if (!(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE))
	    || !(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC)))
		return 0;

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return -1;

	br_ifp = zif->brslave_info.br_if;
	if (br_ifp == NULL)
		return -1;

	vni = zebra_vxlan_if_vni_find(zif, zl3vni->vni);

	br_zif = (const struct zebra_if *)br_ifp->info;

	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		vid = vni->access_vlan;
	else
		vid = 0;

	res = dplane_rem_mac_add(zl3vni->vxlan_if, br_ifp, vid, &zrmac->macaddr,
				 vni->vni, zrmac->fwd_info.r_vtep_ip, 0, 0,
				 false /*was_static*/);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/*
 * Uninstall remote RMAC from the forwarding plane.
 */
static int zl3vni_rmac_uninstall(struct zebra_l3vni *zl3vni,
				 struct zebra_mac *zrmac)
{
	const struct zebra_if *zif = NULL, *br_zif;
	const struct zebra_vxlan_vni *vni;
	const struct interface *br_ifp;
	vlanid_t vid;
	enum zebra_dplane_result res;

	if (!(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE))
	    || !(CHECK_FLAG(zrmac->flags, ZEBRA_MAC_REMOTE_RMAC)))
		return 0;

	if (!zl3vni->vxlan_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"RMAC %pEA on L3-VNI %u hash %p couldn't be uninstalled - no vxlan_if",
				&zrmac->macaddr, zl3vni->vni, zl3vni);
		return -1;
	}

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return -1;

	br_ifp = zif->brslave_info.br_if;
	if (br_ifp == NULL)
		return -1;

	vni = zebra_vxlan_if_vni_find(zif, zl3vni->vni);

	br_zif = (const struct zebra_if *)br_ifp->info;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		vid = vni->access_vlan;
	else
		vid = 0;

	res = dplane_rem_mac_del(zl3vni->vxlan_if, br_ifp, vid, &zrmac->macaddr,
				 vni->vni, zrmac->fwd_info.r_vtep_ip);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/* handle rmac add */
static int zl3vni_remote_rmac_add(struct zebra_l3vni *zl3vni,
				  const struct ethaddr *rmac,
				  const struct ipaddr *vtep_ip)
{
	struct zebra_mac *zrmac = NULL;
	struct ipaddr *vtep = NULL;

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac) {

		 /* Create the RMAC entry, or update its vtep, if necessary. */
		zrmac = zl3vni_rmac_add(zl3vni, rmac);
		if (!zrmac) {
			zlog_debug(
				"Failed to add RMAC %pEA L3VNI %u Remote VTEP %pIA",
				rmac, zl3vni->vni, vtep_ip);
			return -1;
		}
		memset(&zrmac->fwd_info, 0, sizeof(zrmac->fwd_info));
		zrmac->fwd_info.r_vtep_ip = vtep_ip->ipaddr_v4;

		vtep = XCALLOC(MTYPE_EVPN_VTEP, sizeof(struct ipaddr));
		memcpy(vtep, vtep_ip, sizeof(struct ipaddr));
		if (!listnode_add_sort_nodup(zrmac->nh_list, (void *)vtep))
			XFREE(MTYPE_EVPN_VTEP, vtep);

		/* Send RMAC for FPM processing */
		hook_call(zebra_rmac_update, zrmac, zl3vni, false,
			  "new RMAC added");

		/* install rmac in kernel */
		zl3vni_rmac_install(zl3vni, zrmac);
	} else if (!IPV4_ADDR_SAME(&zrmac->fwd_info.r_vtep_ip,
				   &vtep_ip->ipaddr_v4)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"L3VNI %u Remote VTEP change(%pI4 -> %pIA) for RMAC %pEA",
				zl3vni->vni, &zrmac->fwd_info.r_vtep_ip,
				vtep_ip, rmac);

		zrmac->fwd_info.r_vtep_ip = vtep_ip->ipaddr_v4;

		vtep = XCALLOC(MTYPE_EVPN_VTEP, sizeof(struct ipaddr));
		memcpy(vtep, vtep_ip, sizeof(struct ipaddr));
		if (!listnode_add_sort_nodup(zrmac->nh_list, (void *)vtep))
			XFREE(MTYPE_EVPN_VTEP, vtep);

		/* install rmac in kernel */
		zl3vni_rmac_install(zl3vni, zrmac);
	}

	return 0;
}


/* handle rmac delete */
static void zl3vni_remote_rmac_del(struct zebra_l3vni *zl3vni,
				   struct zebra_mac *zrmac,
				   struct ipaddr *vtep_ip)
{
	struct ipaddr ipv4_vtep;

	if (!zl3vni_nh_lookup(zl3vni, vtep_ip)) {
		memset(&ipv4_vtep, 0, sizeof(ipv4_vtep));
		ipv4_vtep.ipa_type = IPADDR_V4;
		if (vtep_ip->ipa_type == IPADDR_V6)
			ipv4_mapped_ipv6_to_ipv4(&vtep_ip->ipaddr_v6,
						 &ipv4_vtep.ipaddr_v4);
		else
			memcpy(&(ipv4_vtep.ipaddr_v4), &vtep_ip->ipaddr_v4,
			       sizeof(struct in_addr));

		/* remove nh from rmac's list */
		l3vni_rmac_nh_list_nh_delete(zl3vni, zrmac, &ipv4_vtep);
		/* delete nh is same as current selected, fall back to
		 * one present in the list
		 */
		if (IPV4_ADDR_SAME(&zrmac->fwd_info.r_vtep_ip,
				   &ipv4_vtep.ipaddr_v4) &&
		    listcount(zrmac->nh_list)) {
			struct ipaddr *vtep;

			vtep = listgetdata(listhead(zrmac->nh_list));
			zrmac->fwd_info.r_vtep_ip = vtep->ipaddr_v4;
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"L3VNI %u Remote VTEP nh change(%pIA -> %pI4) for RMAC %pEA",
					zl3vni->vni, &ipv4_vtep,
					&zrmac->fwd_info.r_vtep_ip,
					&zrmac->macaddr);

			/* install rmac in kernel */
			zl3vni_rmac_install(zl3vni, zrmac);
		}

		if (!listcount(zrmac->nh_list)) {
			/* uninstall from kernel */
			zl3vni_rmac_uninstall(zl3vni, zrmac);

			/* Send RMAC for FPM processing */
			hook_call(zebra_rmac_update, zrmac, zl3vni, true,
				  "RMAC deleted");

			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"L3VNI %u RMAC %pEA vtep_ip %pIA delete",
					zl3vni->vni, &zrmac->macaddr, vtep_ip);

			/* del the rmac entry */
			zl3vni_rmac_del(zl3vni, zrmac);
		}
	}
}

/*
 * Common code for look up of nh hash entry.
 */
static struct zebra_neigh *_nh_lookup(struct zebra_l3vni *zl3vni,
				      const struct ipaddr *ip)
{
	struct zebra_neigh tmp;
	struct zebra_neigh *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));

	if (zl3vni)
		n = hash_lookup(zl3vni->nh_table, &tmp);
	else
		n = hash_lookup(svd_nh_table, &tmp);

	return n;
}

/*
 * Look up nh hash entry on a l3-vni.
 */
static struct zebra_neigh *zl3vni_nh_lookup(struct zebra_l3vni *zl3vni,
					    const struct ipaddr *ip)
{
	return _nh_lookup(zl3vni, ip);
}

/*
 * Look up nh hash entry on a SVD.
 */
static struct zebra_neigh *svd_nh_lookup(const struct ipaddr *ip)
{
	return _nh_lookup(NULL, ip);
}

/*
 * Callback to allocate NH hash entry on L3-VNI.
 */
static void *zl3vni_nh_alloc(void *p)
{
	const struct zebra_neigh *tmp_n = p;
	struct zebra_neigh *n;

	n = XCALLOC(MTYPE_L3NEIGH, sizeof(struct zebra_neigh));
	*n = *tmp_n;

	return ((void *)n);
}

/*
 * Common code for neigh add.
 */
static struct zebra_neigh *_nh_add(struct zebra_l3vni *zl3vni,
				   const struct ipaddr *ip,
				   const struct ethaddr *mac)
{
	struct zebra_neigh tmp_n;
	struct zebra_neigh *n = NULL;

	memset(&tmp_n, 0, sizeof(tmp_n));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));

	if (zl3vni)
		n = hash_get(zl3vni->nh_table, &tmp_n, zl3vni_nh_alloc);
	else
		n = hash_get(svd_nh_table, &tmp_n, zl3vni_nh_alloc);

	assert(n);

	RB_INIT(host_rb_tree_entry, &n->host_rb);

	memcpy(&n->emac, mac, ETH_ALEN);
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE_NH);

	return n;
}

/*
 * Add neighbor entry.
 */
static struct zebra_neigh *zl3vni_nh_add(struct zebra_l3vni *zl3vni,
					 const struct ipaddr *ip,
					 const struct ethaddr *mac)
{
	return _nh_add(zl3vni, ip, mac);
}

/*
 * Delete neighbor entry.
 */
static int zl3vni_nh_del(struct zebra_l3vni *zl3vni, struct zebra_neigh *n)
{
	struct zebra_neigh *tmp_n;
	struct host_rb_entry *hle;

	while (!RB_EMPTY(host_rb_tree_entry, &n->host_rb)) {
		hle = RB_ROOT(host_rb_tree_entry, &n->host_rb);

		RB_REMOVE(host_rb_tree_entry, &n->host_rb, hle);
		XFREE(MTYPE_HOST_PREFIX, hle);
	}

	tmp_n = hash_release(zl3vni->nh_table, n);
	XFREE(MTYPE_L3NEIGH, tmp_n);

	return 0;
}

/*
 * Add Single VXlan Device neighbor entry.
 */
static struct zebra_neigh *svd_nh_add(const struct ipaddr *ip,
				      const struct ethaddr *mac)
{
	return _nh_add(NULL, ip, mac);
}

/*
 * Del Single VXlan Device neighbor entry.
 */
static void svd_nh_del(struct zebra_neigh *n)
{
	if (n->refcnt > 0)
		return;

	hash_release(svd_nh_table, n);
	XFREE(MTYPE_L3NEIGH, n);
}

static void svd_nh_del_terminate(void *ptr)
{
	struct zebra_neigh *n = ptr;

	n->refcnt = 0;
	svd_nh_del(n);
}


/*
 * Common code to install remote nh as neigh into the kernel.
 */
static int _nh_install(struct zebra_l3vni *zl3vni, struct interface *ifp,
		       struct zebra_neigh *n)
{
	uint8_t flags;
	int ret = 0;

	if (zl3vni && !is_l3vni_oper_up(zl3vni))
		return -1;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE)
	    || !(n->flags & ZEBRA_NEIGH_REMOTE_NH))
		return 0;

	flags = DPLANE_NTF_EXT_LEARNED;
	if (n->flags & ZEBRA_NEIGH_ROUTER_FLAG)
		flags |= DPLANE_NTF_ROUTER;

	dplane_rem_neigh_add(ifp, &n->ip, &n->emac, flags,
			     false /*was_static*/);

	return ret;
}

/*
 * Common code to uninstall remote nh from the kernel.
 */
static int _nh_uninstall(struct interface *ifp, struct zebra_neigh *n)
{
	if (!(n->flags & ZEBRA_NEIGH_REMOTE)
	    || !(n->flags & ZEBRA_NEIGH_REMOTE_NH))
		return 0;

	if (!ifp || !if_is_operative(ifp))
		return 0;

	dplane_rem_neigh_delete(ifp, &n->ip);

	return 0;
}

/*
 * Install remote nh as neigh into the kernel.
 */
static int zl3vni_nh_install(struct zebra_l3vni *zl3vni, struct zebra_neigh *n)
{
	return _nh_install(zl3vni, zl3vni->svi_if, n);
}

/*
 * Uninstall remote nh from the kernel.
 */
static int zl3vni_nh_uninstall(struct zebra_l3vni *zl3vni,
			       struct zebra_neigh *n)
{
	return _nh_uninstall(zl3vni->svi_if, n);
}

/*
 * Install SVD remote nh as neigh into the kernel.
 */
static int svd_nh_install(struct zebra_l3vni *zl3vni, struct zebra_neigh *n)
{
	return _nh_install(zl3vni, zl3vni->vxlan_if, n);
}

/*
 * Uninstall SVD remote nh from the kernel.
 */
static int svd_nh_uninstall(struct zebra_l3vni *zl3vni, struct zebra_neigh *n)
{
	return _nh_uninstall(zl3vni->vxlan_if, n);
}

/* Add remote vtep as a neigh entry */
static int zl3vni_remote_nh_add(struct zebra_l3vni *zl3vni,
				const struct ipaddr *vtep_ip,
				const struct ethaddr *rmac,
				const struct prefix *host_prefix)
{
	struct zebra_neigh *nh = NULL;

	/* Create the next hop entry, or update its mac, if necessary. */
	nh = zl3vni_nh_lookup(zl3vni, vtep_ip);
	if (!nh) {
		nh = zl3vni_nh_add(zl3vni, vtep_ip, rmac);
		if (!nh) {
			zlog_debug(
				"Failed to add NH %pIA as Neigh (RMAC %pEA L3-VNI %u prefix %pFX)",
				vtep_ip, rmac, zl3vni->vni, host_prefix);
			return -1;
		}

		/* install the nh neigh in kernel */
		zl3vni_nh_install(zl3vni, nh);
	} else if (memcmp(&nh->emac, rmac, ETH_ALEN) != 0) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"L3VNI %u RMAC change(%pEA --> %pEA) for nexthop %pIA, prefix %pFX",
				zl3vni->vni, &nh->emac, rmac, vtep_ip,
				host_prefix);

		memcpy(&nh->emac, rmac, ETH_ALEN);
		/* install (update) the nh neigh in kernel */
		zl3vni_nh_install(zl3vni, nh);
	}

	rb_find_or_add_host(&nh->host_rb, host_prefix);

	return 0;
}

/* Del remote vtep as a neigh entry */
static void zl3vni_remote_nh_del(struct zebra_l3vni *zl3vni,
				 struct zebra_neigh *nh,
				 struct prefix *host_prefix)
{
	rb_delete_host(&nh->host_rb, host_prefix);

	if (RB_EMPTY(host_rb_tree_entry, &nh->host_rb)) {
		/* uninstall from kernel */
		zl3vni_nh_uninstall(zl3vni, nh);

		/* delete the nh entry */
		zl3vni_nh_del(zl3vni, nh);
	}
}

/* Add remote vtep as a SVD neigh entry */
static int svd_remote_nh_add(struct zebra_l3vni *zl3vni,
			     const struct ipaddr *vtep_ip,
			     const struct ethaddr *rmac,
			     const struct prefix *host_prefix)
{
	struct zebra_neigh *nh = NULL;

	/* SVD backed VNI check */
	if (!IS_ZL3VNI_SVD_BACKED(zl3vni))
		return 0;

	/* Create the SVD next hop entry, or update its mac, if necessary. */
	nh = svd_nh_lookup(vtep_ip);
	if (!nh) {
		nh = svd_nh_add(vtep_ip, rmac);
		if (!nh) {
			zlog_debug(
				"Failed to add NH %pIA as SVD Neigh (RMAC %pEA prefix %pFX)",
				vtep_ip, rmac, host_prefix);
			return -1;
		}

	} else if (memcmp(&nh->emac, rmac, ETH_ALEN) != 0) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("SVD RMAC change(%pEA --> %pEA) for nexthop %pIA, prefix %pFX refcnt %u",
				   &nh->emac, rmac, vtep_ip, host_prefix,
				   nh->refcnt);

		memcpy(&nh->emac, rmac, ETH_ALEN);
		/* install (update) the nh neigh in kernel */
		svd_nh_install(zl3vni, nh);

		/* Don't increment refcnt change */
		return 0;
	}

	nh->refcnt++;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("SVD NH ADD refcnt (%u) for nexthop %pIA",
			   nh->refcnt, vtep_ip);

	/*
	 * Install the nh neigh in kernel if this is the first time we
	 * have seen it.
	 */
	if (nh->refcnt == 1)
		svd_nh_install(zl3vni, nh);

	return 0;
}

/* Del remote vtep as a SVD neigh entry */
static int svd_remote_nh_del(struct zebra_l3vni *zl3vni,
			     const struct ipaddr *vtep_ip)
{
	struct zebra_neigh *nh;

	/* SVD backed VNI check */
	if (!IS_ZL3VNI_SVD_BACKED(zl3vni))
		return 0;

	nh = svd_nh_lookup(vtep_ip);
	if (!nh) {
		zlog_debug("Failed to del NH %pIA as SVD Neigh", vtep_ip);

		return -1;
	}

	nh->refcnt--;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("SVD NH Del refcnt (%u) for nexthop %pIA",
			   nh->refcnt, vtep_ip);

	/* Last refcnt on NH, remove it completely. */
	if (nh->refcnt == 0) {
		svd_nh_uninstall(zl3vni, nh);
		svd_nh_del(nh);
	}

	return 0;
}

/* handle neigh update from kernel - the only thing of interest is to
 * readd stale entries.
 */
static int zl3vni_local_nh_add_update(struct zebra_l3vni *zl3vni,
				      struct ipaddr *ip, uint16_t state)
{
#ifdef GNU_LINUX
	struct zebra_neigh *n = NULL;

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
static int zl3vni_local_nh_del(struct zebra_l3vni *zl3vni, struct ipaddr *ip)
{
	struct zebra_neigh *n = NULL;

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
static unsigned int l3vni_hash_keymake(const void *p)
{
	const struct zebra_l3vni *zl3vni = p;

	return jhash_1word(zl3vni->vni, 0);
}

/*
 * Compare 2 L3 VNI hash entries.
 */
static bool l3vni_hash_cmp(const void *p1, const void *p2)
{
	const struct zebra_l3vni *zl3vni1 = p1;
	const struct zebra_l3vni *zl3vni2 = p2;

	return (zl3vni1->vni == zl3vni2->vni);
}

/*
 * Callback to allocate L3 VNI hash entry.
 */
static void *zl3vni_alloc(void *p)
{
	struct zebra_l3vni *zl3vni = NULL;
	const struct zebra_l3vni *tmp_l3vni = p;

	zl3vni = XCALLOC(MTYPE_ZL3VNI, sizeof(struct zebra_l3vni));
	zl3vni->vni = tmp_l3vni->vni;
	return ((void *)zl3vni);
}

/*
 * Look up L3 VNI hash entry.
 */
struct zebra_l3vni *zl3vni_lookup(vni_t vni)
{
	struct zebra_l3vni tmp_l3vni;
	struct zebra_l3vni *zl3vni = NULL;

	memset(&tmp_l3vni, 0, sizeof(tmp_l3vni));
	tmp_l3vni.vni = vni;
	zl3vni = hash_lookup(zrouter.l3vni_table, &tmp_l3vni);

	return zl3vni;
}

/*
 * Add L3 VNI hash entry.
 */
static struct zebra_l3vni *zl3vni_add(vni_t vni, vrf_id_t vrf_id)
{
	struct zebra_l3vni tmp_zl3vni;
	struct zebra_l3vni *zl3vni = NULL;

	memset(&tmp_zl3vni, 0, sizeof(tmp_zl3vni));
	tmp_zl3vni.vni = vni;

	zl3vni = hash_get(zrouter.l3vni_table, &tmp_zl3vni, zl3vni_alloc);

	zl3vni->vrf_id = vrf_id;
	zl3vni->svi_if = NULL;
	zl3vni->vxlan_if = NULL;
	zl3vni->l2vnis = list_new();
	zl3vni->l2vnis->cmp = zebra_evpn_list_cmp;

	/* Create hash table for remote RMAC */
	zl3vni->rmac_table = zebra_mac_db_create("Zebra L3-VNI RMAC-Table");

	/* Create hash table for neighbors */
	zl3vni->nh_table = zebra_neigh_db_create("Zebra L3-VNI next-hop table");

	return zl3vni;
}

/*
 * Delete L3 VNI hash entry.
 */
static int zl3vni_del(struct zebra_l3vni *zl3vni)
{
	struct zebra_l3vni *tmp_zl3vni;

	/* free the list of l2vnis */
	list_delete(&zl3vni->l2vnis);
	zl3vni->l2vnis = NULL;

	/* Free the rmac table */
	hash_free(zl3vni->rmac_table);
	zl3vni->rmac_table = NULL;

	/* Free the nh table */
	hash_free(zl3vni->nh_table);
	zl3vni->nh_table = NULL;

	/* Free the VNI hash entry and allocated memory. */
	tmp_zl3vni = hash_release(zrouter.l3vni_table, zl3vni);
	XFREE(MTYPE_ZL3VNI, tmp_zl3vni);

	return 0;
}

static int zl3vni_map_to_vxlan_if_ns(struct ns *ns,
				     void *_zl3vni,
				     void **_pifp)
{
	struct zebra_ns *zns = ns->info;
	struct zebra_l3vni *zl3vni = (struct zebra_l3vni *)_zl3vni;
	struct route_node *rn = NULL;
	struct interface *ifp = NULL;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();

	assert(_pifp);

	/* loop through all vxlan-interface */
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {

		struct zebra_if *zif = NULL;
		struct zebra_l2info_vxlan *vxl;
		struct zebra_vxlan_vni *vni = NULL;

		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;

		zif = ifp->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;

		vxl = &zif->l2info.vxl;
		vni = zebra_vxlan_if_vni_find(zif, zl3vni->vni);
		if (!vni || vni->vni != zl3vni->vni)
			continue;

		/* link of VXLAN interface should be in zebra_evpn_vrf */
		if (zvrf->zns->ns_id != vxl->link_nsid) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Intf %s(%u) VNI %u, link not in same "
					"namespace than BGP EVPN core instance ",
					ifp->name, ifp->ifindex, vni->vni);
			continue;
		}


		zl3vni->local_vtep_ip = zif->l2info.vxl.vtep_ip;
		*_pifp = (void *)ifp;
		route_unlock_node(rn);
		return NS_WALK_STOP;
	}

	return NS_WALK_CONTINUE;
}

struct interface *zl3vni_map_to_vxlan_if(struct zebra_l3vni *zl3vni)
{
	struct interface **p_ifp;
	struct interface *ifp = NULL;

	p_ifp = &ifp;

	ns_walk_func(zl3vni_map_to_vxlan_if_ns,
		     (void *)zl3vni, (void **)p_ifp);
	return ifp;
}

struct interface *zl3vni_map_to_svi_if(struct zebra_l3vni *zl3vni)
{
	struct zebra_if *zif = NULL;	   /* zebra_if for vxlan_if */
	struct zebra_vxlan_vni *vni = NULL; /* vni info in vxlan_if */

	if (!zl3vni)
		return NULL;

	if (!zl3vni->vxlan_if)
		return NULL;

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return NULL;

	vni = zebra_vxlan_if_vni_find(zif, zl3vni->vni);
	if (!vni)
		return NULL;

	return zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
}

struct interface *zl3vni_map_to_mac_vlan_if(struct zebra_l3vni *zl3vni)
{
	struct zebra_if *zif = NULL;	   /* zebra_if for vxlan_if */

	if (!zl3vni)
		return NULL;

	if (!zl3vni->vxlan_if)
		return NULL;

	zif = zl3vni->vxlan_if->info;
	if (!zif)
		return NULL;

	return zebra_evpn_map_to_macvlan(zif->brslave_info.br_if,
					 zl3vni->svi_if);
}


struct zebra_l3vni *zl3vni_from_vrf(vrf_id_t vrf_id)
{
	struct zebra_vrf *zvrf = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf)
		return NULL;

	return zl3vni_lookup(zvrf->l3vni);
}

static int zl3vni_from_svi_ns(struct ns *ns, void *_in_param, void **_p_zl3vni)
{
	int found = 0;
	vni_t vni_id = 0;
	struct zebra_ns *zns = ns->info;
	struct zebra_l3vni **p_zl3vni = (struct zebra_l3vni **)_p_zl3vni;
	struct zebra_from_svi_param *in_param =
		(struct zebra_from_svi_param *)_in_param;
	struct route_node *rn = NULL;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_if *br_zif = NULL;

	assert(in_param && p_zl3vni);

	br_zif = in_param->br_if->info;
	assert(br_zif);

	if (in_param->bridge_vlan_aware) {
		vni_id = zebra_l2_bridge_if_vni_find(br_zif, in_param->vid);
		if (vni_id)
			found = 1;
	} else {
		/* loop through all vxlan-interface */
		for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
			tmp_if = (struct interface *)rn->info;
			if (!tmp_if)
				continue;
			zif = tmp_if->info;
			if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
				continue;
			if (!if_is_operative(tmp_if))
				continue;

			if (zif->brslave_info.br_if != in_param->br_if)
				continue;

			vni_id = zebra_vxlan_if_access_vlan_vni_find(
				zif, in_param->br_if);
			if (vni_id) {
				found = 1;
				route_unlock_node(rn);
				break;
			}
		}
	}

	if (!found)
		return NS_WALK_CONTINUE;

	*p_zl3vni = zl3vni_lookup(vni_id);
	return NS_WALK_STOP;
}

/*
 * Map SVI and associated bridge to a VNI. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 */
static struct zebra_l3vni *zl3vni_from_svi(struct interface *ifp,
					   struct interface *br_if)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_from_svi_param in_param = {};
	struct zebra_l3vni **p_zl3vni;

	if (!br_if)
		return NULL;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;
	in_param.br_if = br_if;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	in_param.bridge_vlan_aware = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif);
	if (in_param.bridge_vlan_aware) {
		struct zebra_l2info_vlan *vl;

		if (!IS_ZEBRA_IF_VLAN(ifp))
			return NULL;

		zif = ifp->info;
		assert(zif);
		vl = &zif->l2info.vl;
		in_param.vid = vl->vid;
	}

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */

	p_zl3vni = &zl3vni;

	ns_walk_func(zl3vni_from_svi_ns, (void *)&in_param, (void **)p_zl3vni);
	return zl3vni;
}

vni_t vni_id_from_svi(struct interface *ifp, struct interface *br_if)
{
	vni_t vni = 0;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	/* Check if an L3VNI belongs to this SVI interface.
	 * If not, check if an L2VNI belongs to this SVI interface.
	 */
	zl3vni = zl3vni_from_svi(ifp, br_if);
	if (zl3vni)
		vni = zl3vni->vni;
	else {
		zevpn = zebra_evpn_from_svi(ifp, br_if);
		if (zevpn)
			vni = zevpn->vni;
	}

	return vni;
}

static inline void zl3vni_get_vrr_rmac(struct zebra_l3vni *zl3vni,
				       struct ethaddr *rmac)
{
	if (!zl3vni)
		return;

	if (!is_l3vni_oper_up(zl3vni))
		return;

	if (zl3vni->mac_vlan_if && if_is_operative(zl3vni->mac_vlan_if))
		memcpy(rmac->octet, zl3vni->mac_vlan_if->hw_addr, ETH_ALEN);
}

/*
 * Inform BGP about l3-vni.
 */
static int zl3vni_send_add_to_client(struct zebra_l3vni *zl3vni)
{
	struct stream *s = NULL;
	struct zserv *client = NULL;
	struct ethaddr svi_rmac, vrr_rmac = {.octet = {0} };
	struct zebra_vrf *zvrf;
	bool is_anycast_mac = true;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	zvrf = zebra_vrf_lookup_by_id(zl3vni->vrf_id);
	assert(zvrf);

	/* get the svi and vrr rmac values */
	memset(&svi_rmac, 0, sizeof(svi_rmac));
	zl3vni_get_svi_rmac(zl3vni, &svi_rmac);
	zl3vni_get_vrr_rmac(zl3vni, &vrr_rmac);

	/* In absence of vrr mac use svi mac as anycast MAC value */
	if (is_zero_mac(&vrr_rmac)) {
		memcpy(&vrr_rmac, &svi_rmac, ETH_ALEN);
		is_anycast_mac = false;
	}

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	/* The message is used for both vni add and/or update like
	 * vrr mac is added for l3vni SVI.
	 */
	zclient_create_header(s, ZEBRA_L3VNI_ADD, zl3vni_vrf_id(zl3vni));
	stream_putl(s, zl3vni->vni);
	stream_put(s, &svi_rmac, sizeof(struct ethaddr));
	stream_put_in_addr(s, &zl3vni->local_vtep_ip);
	stream_put(s, &zl3vni->filter, sizeof(int));
	stream_putl(s, zl3vni->svi_if->ifindex);
	stream_put(s, &vrr_rmac, sizeof(struct ethaddr));
	stream_putl(s, is_anycast_mac);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send L3VNI ADD %u VRF %s RMAC %pEA VRR %pEA local-ip %pI4 filter %s to %s",
			   zl3vni->vni, vrf_id_to_name(zl3vni_vrf_id(zl3vni)),
			   &svi_rmac, &vrr_rmac, &zl3vni->local_vtep_ip,
			   CHECK_FLAG(zl3vni->filter, PREFIX_ROUTES_ONLY)
				   ? "prefix-routes-only"
				   : "none",
			   zebra_route_string(client->proto));

	client->l3vniadd_cnt++;
	return zserv_send_message(client, s);
}

/*
 * Inform BGP about local l3-VNI deletion.
 */
static int zl3vni_send_del_to_client(struct zebra_l3vni *zl3vni)
{
	struct stream *s = NULL;
	struct zserv *client = NULL;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_L3VNI_DEL, zl3vni_vrf_id(zl3vni));
	stream_putl(s, zl3vni->vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send L3VNI DEL %u VRF %s to %s", zl3vni->vni,
			   vrf_id_to_name(zl3vni_vrf_id(zl3vni)),
			   zebra_route_string(client->proto));

	client->l3vnidel_cnt++;
	return zserv_send_message(client, s);
}

void zebra_vxlan_process_l3vni_oper_up(struct zebra_l3vni *zl3vni)
{
	if (!zl3vni)
		return;

	/* send l3vni add to BGP */
	zl3vni_send_add_to_client(zl3vni);
}

void zebra_vxlan_process_l3vni_oper_down(struct zebra_l3vni *zl3vni)
{
	if (!zl3vni)
		return;

	/* send l3-vni del to BGP*/
	zl3vni_send_del_to_client(zl3vni);
}

static void zevpn_add_to_l3vni_list(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_evpn *zevpn = (struct zebra_evpn *)bucket->data;
	struct zebra_l3vni *zl3vni = (struct zebra_l3vni *)ctxt;

	if (zevpn->vrf_id == zl3vni_vrf_id(zl3vni))
		listnode_add_sort(zl3vni->l2vnis, zevpn);
}

/*
 * Handle transition of vni from l2 to l3 and vice versa.
 * This function handles only the L2VNI add/delete part of
 * the above transition.
 * L3VNI add/delete is handled by the calling functions.
 */
static int zebra_vxlan_handle_vni_transition(struct zebra_vrf *zvrf, vni_t vni,
					     int add)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

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
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn)
			return 0;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L2-VNI %u - transition to L3-VNI", vni);

		/* Delete EVPN from BGP. */
		zebra_evpn_send_del_to_client(zevpn);

		zebra_evpn_neigh_del_all(zevpn, 0, 0, DEL_ALL_NEIGH);
		zebra_evpn_mac_del_all(zevpn, 0, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zebra_evpn_vtep_del_all(zevpn, 1);

		zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
		if (zl3vni)
			listnode_delete(zl3vni->l2vnis, zevpn);

		/* Delete the hash entry. */
		if (zebra_evpn_vxlan_del(zevpn)) {
			flog_err(EC_ZEBRA_VNI_DEL_FAILED,
				 "Failed to del EVPN hash %p, VNI %u", zevpn,
				 zevpn->vni);
			return -1;
		}
	} else {
		struct zebra_ns *zns;
		struct route_node *rn;
		struct interface *ifp;
		struct zebra_if *zif;
		struct zebra_vxlan_vni *vnip;
		struct zebra_l2info_vxlan *vxl;
		struct interface *vlan_if;
		bool found = false;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Adding L2-VNI %u - transition from L3-VNI",
				   vni);

		/* Find VxLAN interface for this VNI. */
		zns = zebra_ns_lookup(NS_DEFAULT);
		for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
			ifp = (struct interface *)rn->info;
			if (!ifp)
				continue;
			zif = ifp->info;
			if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
				continue;

			vxl = &zif->l2info.vxl;
			vnip = zebra_vxlan_if_vni_find(zif, vni);
			if (vnip) {
				found = true;
				route_unlock_node(rn);
				break;
			}
		}

		if (!found) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_err(
					"Adding L2-VNI - Failed to find VxLAN interface for VNI %u",
					vni);
			return -1;
		}

		/* Create VNI hash entry for L2VNI */
		zevpn = zebra_evpn_lookup(vni);
		if (zevpn)
			return 0;

		zevpn = zebra_evpn_add(vni);

		/* Find bridge interface for the VNI */
		vlan_if = zvni_map_to_svi(vnip->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if) {
			zevpn->vrf_id = vlan_if->vrf->vrf_id;
			zl3vni = zl3vni_from_vrf(vlan_if->vrf->vrf_id);
			if (zl3vni)
				listnode_add_sort_nodup(zl3vni->l2vnis, zevpn);
		}

		zevpn->vxlan_if = ifp;
		zevpn->local_vtep_ip = vxl->vtep_ip;

		/* Inform BGP if the VNI is up and mapped to a bridge. */
		if (if_is_operative(ifp) && zif->brslave_info.br_if) {
			zebra_evpn_send_add_to_client(zevpn);
			zebra_evpn_read_mac_neigh(zevpn, ifp);
		}
	}

	return 0;
}

/* delete and uninstall rmac hash entry */
static void zl3vni_del_rmac_hash_entry(struct hash_bucket *bucket, void *ctx)
{
	struct zebra_mac *zrmac = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	zrmac = (struct zebra_mac *)bucket->data;
	zl3vni = (struct zebra_l3vni *)ctx;
	zl3vni_rmac_uninstall(zl3vni, zrmac);

	/* Send RMAC for FPM processing */
	hook_call(zebra_rmac_update, zrmac, zl3vni, true, "RMAC deleted");

	zl3vni_rmac_del(zl3vni, zrmac);
}

/* delete and uninstall nh hash entry */
static void zl3vni_del_nh_hash_entry(struct hash_bucket *bucket, void *ctx)
{
	struct zebra_neigh *n = NULL, *svd_nh = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	n = (struct zebra_neigh *)bucket->data;
	zl3vni = (struct zebra_l3vni *)ctx;

	/* remove SVD based remote nexthop neigh entry */
	svd_nh = svd_nh_lookup(&n->ip);
	if (svd_nh) {
		svd_nh->refcnt--;
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s L3VNI %u remove svd nh %pIA refcnt %u",
				   __func__, zl3vni->vni, &n->ip,
				   svd_nh->refcnt);
		if (svd_nh->refcnt == 0) {
			svd_nh_uninstall(zl3vni, svd_nh);
			svd_nh_del(svd_nh);
		}
	}

	zl3vni_nh_uninstall(zl3vni, n);
	zl3vni_nh_del(zl3vni, n);
}

/* re-add remote rmac if needed */
static int zebra_vxlan_readd_remote_rmac(struct zebra_l3vni *zl3vni,
					 struct ethaddr *rmac)
{
	struct zebra_mac *zrmac = NULL;

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del remote RMAC %pEA L3VNI %u - readd",
			   rmac, zl3vni->vni);

	zl3vni_rmac_install(zl3vni, zrmac);
	return 0;
}

/* Public functions */

int is_l3vni_for_prefix_routes_only(vni_t vni)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_lookup(vni);
	if (!zl3vni)
		return 0;

	return CHECK_FLAG(zl3vni->filter, PREFIX_ROUTES_ONLY) ? 1 : 0;
}

/* handle evpn route in vrf table */
void zebra_vxlan_evpn_vrf_route_add(vrf_id_t vrf_id, const struct ethaddr *rmac,
				    const struct ipaddr *vtep_ip,
				    const struct prefix *host_prefix)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct ipaddr ipv4_vtep;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return;

	/*
	 * add the next hop neighbor -
	 * neigh to be installed is the ipv6 nexthop neigh
	 */
	zl3vni_remote_nh_add(zl3vni, vtep_ip, rmac, host_prefix);

	/* Add SVD next hop neighbor */
	svd_remote_nh_add(zl3vni, vtep_ip, rmac, host_prefix);

	/*
	 * if the remote vtep is a ipv4 mapped ipv6 address convert it to ipv4
	 * address. Rmac is programmed against the ipv4 vtep because we only
	 * support ipv4 tunnels in the h/w right now
	 */
	memset(&ipv4_vtep, 0, sizeof(ipv4_vtep));
	ipv4_vtep.ipa_type = IPADDR_V4;
	if (vtep_ip->ipa_type == IPADDR_V6)
		ipv4_mapped_ipv6_to_ipv4(&vtep_ip->ipaddr_v6,
					 &(ipv4_vtep.ipaddr_v4));
	else
		memcpy(&(ipv4_vtep.ipaddr_v4), &vtep_ip->ipaddr_v4,
		       sizeof(struct in_addr));

	/*
	 * add the rmac - remote rmac to be installed is against the ipv4
	 * nexthop address
	 */
	zl3vni_remote_rmac_add(zl3vni, rmac, &ipv4_vtep);
}

/* handle evpn vrf route delete */
void zebra_vxlan_evpn_vrf_route_del(vrf_id_t vrf_id,
				    struct ipaddr *vtep_ip,
				    struct prefix *host_prefix)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_neigh *nh = NULL;
	struct zebra_mac *zrmac = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni)
		return;

	/* find the next hop entry and rmac entry */
	nh = zl3vni_nh_lookup(zl3vni, vtep_ip);
	if (!nh)
		return;
	zrmac = zl3vni_rmac_lookup(zl3vni, &nh->emac);

	/* delete the next hop entry */
	zl3vni_remote_nh_del(zl3vni, nh, host_prefix);

	/* Delete SVD next hop entry */
	svd_remote_nh_del(zl3vni, vtep_ip);

	/* delete the rmac entry */
	if (zrmac)
		zl3vni_remote_rmac_del(zl3vni, zrmac, vtep_ip);
}

void zebra_vxlan_print_specific_rmac_l3vni(struct vty *vty, vni_t l3vni,
					   struct ethaddr *rmac, bool use_json)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_mac *zrmac = NULL;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% L3-VNI %u doesn't exist\n", l3vni);
		return;
	}

	zrmac = zl3vni_rmac_lookup(zl3vni, rmac);
	if (!zrmac) {
		if (use_json)
			vty_json(vty, json);
		else
			vty_out(vty,
				"%% Requested RMAC doesn't exist in L3-VNI %u\n",
				l3vni);
		return;
	}

	zl3vni_print_rmac(zrmac, vty, json);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_print_rmacs_l3vni(struct vty *vty, vni_t l3vni, bool use_json)
{
	struct zebra_l3vni *zl3vni;
	uint32_t num_rmacs;
	struct rmac_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% L3-VNI %u does not exist\n", l3vni);
		return;
	}
	num_rmacs = hashcount(zl3vni->rmac_table);
	if (!num_rmacs)
		return;

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	if (!use_json) {
		vty_out(vty, "Number of Remote RMACs known for this VNI: %u\n",
			num_rmacs);
		vty_out(vty, "%-17s %-21s\n", "MAC", "Remote VTEP");
	} else
		json_object_int_add(json, "numRmacs", num_rmacs);

	hash_iterate(zl3vni->rmac_table, zl3vni_print_rmac_hash, &wctx);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_print_rmacs_all_l3vni(struct vty *vty, bool use_json)
{
	json_object *json = NULL;
	void *args[2];

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	args[0] = vty;
	args[1] = json;
	hash_iterate(zrouter.l3vni_table,
		     (void (*)(struct hash_bucket *,
			       void *))zl3vni_print_rmac_hash_all_vni,
		     args);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_print_specific_nh_l3vni(struct vty *vty, vni_t l3vni,
					 struct ipaddr *ip, bool use_json)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_neigh *n = NULL;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	/* If vni=0 passed, assume svd lookup */
	if (!l3vni)
		n = svd_nh_lookup(ip);
	else {
		zl3vni = zl3vni_lookup(l3vni);
		if (!zl3vni) {
			if (use_json)
				vty_json(vty, json);
			else
				vty_out(vty, "%% L3-VNI %u does not exist\n",
					l3vni);
			return;
		}

		n = zl3vni_nh_lookup(zl3vni, ip);
	}

	if (!n) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty,
				"%% Requested next-hop not present for L3-VNI %u\n",
				l3vni);
		return;
	}

	zl3vni_print_nh(n, vty, json);

	if (use_json)
		vty_json(vty, json);
}

static void l3vni_print_nh_table(struct hash *nh_table, struct vty *vty,
				 bool use_json)
{
	uint32_t num_nh;
	struct nh_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	num_nh = hashcount(nh_table);
	if (!num_nh) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	wctx.vty = vty;
	wctx.json = json;
	if (!use_json) {
		vty_out(vty, "Number of NH Neighbors known for this VNI: %u\n",
			num_nh);
		vty_out(vty, "%-15s %-17s\n", "IP", "RMAC");
	} else
		json_object_int_add(json, "numNextHops", num_nh);

	hash_iterate(nh_table, zl3vni_print_nh_hash, &wctx);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_print_nh_l3vni(struct vty *vty, vni_t l3vni, bool use_json)
{
	struct zebra_l3vni *zl3vni = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni) {
		if (use_json)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% L3-VNI %u does not exist\n", l3vni);
		return;
	}

	l3vni_print_nh_table(zl3vni->nh_table, vty, use_json);
}

void zebra_vxlan_print_nh_svd(struct vty *vty, bool use_json)
{
	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	l3vni_print_nh_table(svd_nh_table, vty, use_json);
}

void zebra_vxlan_print_nh_all_l3vni(struct vty *vty, bool use_json)
{
	json_object *json = NULL;
	void *args[2];

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	args[0] = vty;
	args[1] = json;
	hash_iterate(zrouter.l3vni_table,
		     (void (*)(struct hash_bucket *,
			       void *))zl3vni_print_nh_hash_all_vni,
		     args);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display L3 VNI information (VTY command handler).
 */
void zebra_vxlan_print_l3vni(struct vty *vty, vni_t vni, bool use_json)
{
	void *args[2];
	json_object *json = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zl3vni = zl3vni_lookup(vni);
	if (!zl3vni) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}

	args[0] = vty;
	args[1] = json;
	zl3vni_print(zl3vni, (void *)args);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_print_vrf_vni(struct vty *vty, struct zebra_vrf *zvrf,
			       json_object *json_vrfs)
{
	char buf[ETHER_ADDR_STRLEN];
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return;

	if (!json_vrfs) {
		vty_out(vty, "%-37s %-10u %-20s %-20s %-5s %-18s\n",
			zvrf_name(zvrf), zl3vni->vni,
			zl3vni_vxlan_if_name(zl3vni),
			zl3vni_svi_if_name(zl3vni), zl3vni_state2str(zl3vni),
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
	} else {
		json_object *json_vrf = NULL;

		json_vrf = json_object_new_object();
		json_object_string_add(json_vrf, "vrf", zvrf_name(zvrf));
		json_object_int_add(json_vrf, "vni", zl3vni->vni);
		json_object_string_add(json_vrf, "vxlanIntf",
				       zl3vni_vxlan_if_name(zl3vni));
		json_object_string_add(json_vrf, "sviIntf",
				       zl3vni_svi_if_name(zl3vni));
		json_object_string_add(json_vrf, "state",
				       zl3vni_state2str(zl3vni));
		json_object_string_add(
			json_vrf, "routerMac",
			zl3vni_rmac2str(zl3vni, buf, sizeof(buf)));
		json_object_array_add(json_vrfs, json_vrf);
	}
}

/*
 * Display Neighbors for a VNI (VTY command handler).
 */
void zebra_vxlan_print_neigh_vni(struct vty *vty, struct zebra_vrf *zvrf,
				 vni_t vni, bool use_json)
{
	struct zebra_evpn *zevpn;
	uint32_t num_neigh;
	struct neigh_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_neigh = hashcount(zevpn->neigh_table);
	if (!num_neigh)
		return;

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json;
	hash_iterate(zevpn->neigh_table, zebra_evpn_find_neigh_addr_width,
		     &wctx);

	if (!use_json) {
		vty_out(vty,
			"Number of ARPs (local and remote) known for this VNI: %u\n",
			num_neigh);
		zebra_evpn_print_neigh_hdr(vty, &wctx);
	} else
		json_object_int_add(json, "numArpNd", num_neigh);

	hash_iterate(zevpn->neigh_table, zebra_evpn_print_neigh_hash, &wctx);
	if (use_json)
		vty_json(vty, json);
}

/*
 * Display neighbors across all VNIs (VTY command handler).
 */
void zebra_vxlan_print_neigh_all_vni(struct vty *vty, struct zebra_vrf *zvrf,
				     bool print_dup, bool use_json)
{
	json_object *json = NULL;
	void *args[3];

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	args[0] = vty;
	args[1] = json;
	args[2] = (void *)(ptrdiff_t)print_dup;

	hash_iterate(zvrf->evpn_table,
		     (void (*)(struct hash_bucket *,
			       void *))zevpn_print_neigh_hash_all_evpn,
		     args);
	if (use_json)
		vty_json(vty, json);
}

/*
 * Display neighbors across all VNIs in detail(VTY command handler).
 */
void zebra_vxlan_print_neigh_all_vni_detail(struct vty *vty,
					    struct zebra_vrf *zvrf,
					    bool print_dup, bool use_json)
{
	json_object *json = NULL;
	void *args[3];

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	args[0] = vty;
	args[1] = json;
	args[2] = (void *)(ptrdiff_t)print_dup;

	hash_iterate(zvrf->evpn_table,
		     (void (*)(struct hash_bucket *,
			       void *))zevpn_print_neigh_hash_all_evpn_detail,
		     args);
	if (use_json)
		vty_json(vty, json);
}

/*
 * Display specific neighbor for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_neigh_vni(struct vty *vty,
					  struct zebra_vrf *zvrf, vni_t vni,
					  struct ipaddr *ip, bool use_json)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		if (!use_json)
			vty_out(vty,
				"%% Requested neighbor does not exist in VNI %u\n",
				vni);
		return;
	}

	zebra_evpn_print_neigh(n, vty, json);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display neighbors for a VNI from specific VTEP (VTY command handler).
 * By definition, these are remote neighbors.
 */
void zebra_vxlan_print_neigh_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				      vni_t vni, struct in_addr vtep_ip,
				      bool use_json)
{
	struct zebra_evpn *zevpn;
	uint32_t num_neigh;
	struct neigh_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_neigh = hashcount(zevpn->neigh_table);
	if (!num_neigh)
		return;

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.flags = SHOW_REMOTE_NEIGH_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json;
	hash_iterate(zevpn->neigh_table, zebra_evpn_find_neigh_addr_width,
		     &wctx);
	hash_iterate(zevpn->neigh_table, zebra_evpn_print_neigh_hash, &wctx);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display Duplicate detected Neighbors for a VNI
 * (VTY command handler).
 */
void zebra_vxlan_print_neigh_vni_dad(struct vty *vty,
				     struct zebra_vrf *zvrf,
				     vni_t vni,
				     bool use_json)
{
	struct zebra_evpn *zevpn;
	uint32_t num_neigh;
	struct neigh_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}

	num_neigh = hashcount(zevpn->neigh_table);
	if (!num_neigh)
		return;

	num_neigh = num_dup_detected_neighs(zevpn);
	if (!num_neigh)
		return;

	/* Since we have IPv6 addresses to deal with which can vary widely in
	 * size, we try to be a bit more elegant in display by first computing
	 * the maximum width.
	 */
	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.addr_width = 15;
	wctx.json = json;
	hash_iterate(zevpn->neigh_table, zebra_evpn_find_neigh_addr_width,
		     &wctx);

	if (!use_json) {
		vty_out(vty,
			"Number of ARPs (local and remote) known for this VNI: %u\n",
			num_neigh);
		vty_out(vty, "%*s %-6s %-8s %-17s %-30s\n",
			-wctx.addr_width, "IP", "Type",
			"State", "MAC", "Remote ES/VTEP");
	} else
		json_object_int_add(json, "numArpNd", num_neigh);

	hash_iterate(zevpn->neigh_table, zebra_evpn_print_dad_neigh_hash,
		     &wctx);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display MACs for a VNI (VTY command handler).
 */
void zebra_vxlan_print_macs_vni(struct vty *vty, struct zebra_vrf *zvrf,
				vni_t vni, bool use_json, bool detail)
{
	struct zebra_evpn *zevpn;
	uint32_t num_macs;
	struct mac_walk_ctx wctx;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = num_valid_macs(zevpn);
	if (!num_macs) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	if (use_json) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.json = json_mac;

	if (!use_json) {
		if (detail) {
			vty_out(vty, "\nVNI %u #MACs (local and remote) %u\n\n",
				zevpn->vni, num_macs);
		} else {
			vty_out(vty,
				"Number of MACs (local and remote) known for this VNI: %u\n",
				num_macs);
			vty_out(vty,
				"Flags: N=sync-neighs, I=local-inactive, P=peer-active, X=peer-proxy\n");
			vty_out(vty, "%-17s %-6s %-5s %-30s %-5s %s\n", "MAC",
				"Type", "Flags", "Intf/Remote ES/VTEP", "VLAN",
				"Seq #'s");
		}
	} else
		json_object_int_add(json, "numMacs", num_macs);

	if (detail)
		hash_iterate(zevpn->mac_table, zebra_evpn_print_mac_hash_detail,
			     &wctx);
	else
		hash_iterate(zevpn->mac_table, zebra_evpn_print_mac_hash,
			     &wctx);

	if (use_json) {
		json_object_object_add(json, "macs", json_mac);
		/*
		 * This is an extremely expensive operation at scale
		 * and non-pretty reduces memory footprint significantly.
		 */
		vty_json_no_pretty(vty, json);
	}
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni(struct vty *vty, struct zebra_vrf *zvrf,
				    bool print_dup, bool use_json)
{
	struct mac_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	wctx.print_dup = print_dup;
	hash_iterate(zvrf->evpn_table, zevpn_print_mac_hash_all_evpn, &wctx);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display MACs in detail for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni_detail(struct vty *vty,
					   struct zebra_vrf *zvrf,
					   bool print_dup, bool use_json)
{
	struct mac_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.json = json;
	wctx.print_dup = print_dup;
	hash_iterate(zvrf->evpn_table, zevpn_print_mac_hash_all_evpn_detail,
		     &wctx);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void zebra_vxlan_print_macs_all_vni_vtep(struct vty *vty,
					 struct zebra_vrf *zvrf,
					 struct in_addr vtep_ip, bool use_json)
{
	struct mac_walk_ctx wctx;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json;
	hash_iterate(zvrf->evpn_table, zevpn_print_mac_hash_all_evpn, &wctx);

	if (use_json)
		vty_json(vty, json);
}

/*
 * Display specific MAC for a VNI, if present (VTY command handler).
 */
void zebra_vxlan_print_specific_mac_vni(struct vty *vty, struct zebra_vrf *zvrf,
					vni_t vni, struct ethaddr *macaddr,
					bool use_json)
{
	struct zebra_evpn *zevpn;
	struct zebra_mac *mac;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json(vty, json);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		if (use_json)
			vty_json(vty, json);
		else
			vty_out(vty,
				"%% Requested MAC does not exist in VNI %u\n",
				vni);
		return;
	}

	zebra_evpn_print_mac(mac, vty, json);

	if (use_json)
		vty_json(vty, json);
}

/* Print Duplicate MACs per VNI */
void zebra_vxlan_print_macs_vni_dad(struct vty *vty,
				    struct zebra_vrf *zvrf,
				    vni_t vni, bool use_json)
{
	struct zebra_evpn *zevpn;
	struct mac_walk_ctx wctx;
	uint32_t num_macs;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}

	num_macs = num_valid_macs(zevpn);
	if (!num_macs) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	num_macs = num_dup_detected_macs(zevpn);
	if (!num_macs) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	if (use_json) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.json = json_mac;

	if (!use_json) {
		vty_out(vty,
		"Number of MACs (local and remote) known for this VNI: %u\n",
			num_macs);
		vty_out(vty, "%-17s %-6s %-5s %-30s %-5s\n", "MAC", "Type",
			"Flags", "Intf/Remote ES/VTEP", "VLAN");
	} else
		json_object_int_add(json, "numMacs", num_macs);

	hash_iterate(zevpn->mac_table, zebra_evpn_print_dad_mac_hash, &wctx);

	if (use_json) {
		json_object_object_add(json, "macs", json_mac);
		vty_json(vty, json);
	}

}

int zebra_vxlan_clear_dup_detect_vni_mac(struct zebra_vrf *zvrf, vni_t vni,
					 struct ethaddr *macaddr, char *errmsg,
					 size_t errmsg_len)
{
	struct zebra_evpn *zevpn;
	struct zebra_mac *mac;
	struct listnode *node = NULL;
	struct zebra_neigh *nbr = NULL;

	if (!is_evpn_enabled())
		return 0;

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		snprintfrr(errmsg, errmsg_len, "VNI %u does not exist", vni);
		return -1;
	}

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		snprintf(errmsg, errmsg_len,
			 "Requested MAC does not exist in VNI %u\n", vni);
		return -1;
	}

	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)) {
		snprintfrr(errmsg, errmsg_len,
			   "Requested MAC is not duplicate detected\n");
		return -1;
	}

	/* Remove all IPs as duplicate associcated with this MAC */
	for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, nbr)) {
		/* For local neigh mark inactive so MACIP update is generated
		 * to BGP. This is a scenario where MAC update received
		 * and detected as duplicate which marked neigh as duplicate.
		 * Later local neigh update did not get a chance to relay
		 * to BGP. Similarly remote macip update, neigh needs to be
		 * installed locally.
		 */
		if (zvrf->dad_freeze &&
		    CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
			if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL))
				ZEBRA_NEIGH_SET_INACTIVE(nbr);
			else if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE))
				zebra_evpn_rem_neigh_install(
					zevpn, nbr, false /*was_static*/);
		}

		UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
		nbr->dad_count = 0;
		nbr->detect_start_time.tv_sec = 0;
		nbr->dad_dup_detect_time = 0;
	}

	UNSET_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE);
	mac->dad_count = 0;
	mac->detect_start_time.tv_sec = 0;
	mac->detect_start_time.tv_usec = 0;
	mac->dad_dup_detect_time = 0;
	EVENT_OFF(mac->dad_mac_auto_recovery_timer);

	/* warn-only action return */
	if (!zvrf->dad_freeze)
		return 0;

	/* Local: Notify Peer VTEPs, Remote: Install the entry */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		/* Inform to BGP */
		if (zebra_evpn_mac_send_add_to_client(zevpn->vni, &mac->macaddr,
						      mac->flags, mac->loc_seq,
						      mac->es))
			return 0;

		/* Process all neighbors associated with this MAC. */
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac, 0,
							     0 /*es_change*/);

	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);

		/* Install the entry. */
		zebra_evpn_rem_mac_install(zevpn, mac, false /* was_static */);
	}

	return 0;
}

int zebra_vxlan_clear_dup_detect_vni_ip(struct zebra_vrf *zvrf, vni_t vni,
					struct ipaddr *ip, char *errmsg,
					size_t errmsg_len)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *nbr;
	struct zebra_mac *mac;
	char buf[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];

	if (!is_evpn_enabled())
		return 0;

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		snprintfrr(errmsg, errmsg_len, "VNI %u does not exist\n", vni);
		return -1;
	}

	nbr = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!nbr) {
		snprintfrr(errmsg, errmsg_len,
			   "Requested host IP does not exist in VNI %u\n", vni);
		return -1;
	}

	ipaddr2str(&nbr->ip, buf, sizeof(buf));

	if (!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
		snprintfrr(errmsg, errmsg_len,
			   "Requested host IP %s is not duplicate detected\n",
			   buf);
		return -1;
	}

	mac = zebra_evpn_mac_lookup(zevpn, &nbr->emac);

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)) {
		snprintfrr(
			errmsg, errmsg_len,
			"Requested IP's associated MAC %s is still in duplicate state\n",
			prefix_mac2str(&nbr->emac, buf2, sizeof(buf2)));
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: clear neigh %s in dup state, flags 0x%x seq %u",
			   __func__, buf, nbr->flags, nbr->loc_seq);

	UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
	nbr->dad_count = 0;
	nbr->detect_start_time.tv_sec = 0;
	nbr->detect_start_time.tv_usec = 0;
	nbr->dad_dup_detect_time = 0;
	EVENT_OFF(nbr->dad_ip_auto_recovery_timer);

	if (!!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL)) {
		zebra_evpn_neigh_send_add_to_client(zevpn->vni, ip, &nbr->emac,
						    nbr->mac, nbr->flags,
						    nbr->loc_seq);
	} else if (!!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE)) {
		zebra_evpn_rem_neigh_install(zevpn, nbr, false /*was_static*/);
	}

	return 0;
}

static void zevpn_clear_dup_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct mac_walk_ctx *wctx = ctxt;
	struct zebra_mac *mac;
	struct zebra_evpn *zevpn;
	struct listnode *node = NULL;
	struct zebra_neigh *nbr = NULL;

	mac = (struct zebra_mac *)bucket->data;
	if (!mac)
		return;

	zevpn = wctx->zevpn;

	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
		return;

	UNSET_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE);
	mac->dad_count = 0;
	mac->detect_start_time.tv_sec = 0;
	mac->detect_start_time.tv_usec = 0;
	mac->dad_dup_detect_time = 0;
	EVENT_OFF(mac->dad_mac_auto_recovery_timer);

	/* Remove all IPs as duplicate associcated with this MAC */
	for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, nbr)) {
		if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL)
		    && nbr->dad_count)
			ZEBRA_NEIGH_SET_INACTIVE(nbr);

		UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
		nbr->dad_count = 0;
		nbr->detect_start_time.tv_sec = 0;
		nbr->dad_dup_detect_time = 0;
	}

	/* Local: Notify Peer VTEPs, Remote: Install the entry */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		/* Inform to BGP */
		if (zebra_evpn_mac_send_add_to_client(zevpn->vni, &mac->macaddr,
						      mac->flags, mac->loc_seq,
						      mac->es))
			return;

		/* Process all neighbors associated with this MAC. */
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac, 0,
							     0 /*es_change*/);

	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);

		/* Install the entry. */
		zebra_evpn_rem_mac_install(zevpn, mac, false /* was_static */);
	}
}

static void zevpn_clear_dup_detect_hash_vni_all(struct hash_bucket *bucket,
					    void **args)
{
	struct zebra_evpn *zevpn;
	struct zebra_vrf *zvrf;
	struct mac_walk_ctx m_wctx;
	struct neigh_walk_ctx n_wctx;

	zevpn = (struct zebra_evpn *)bucket->data;
	if (!zevpn)
		return;

	zvrf = (struct zebra_vrf *)args[0];

	if (hashcount(zevpn->neigh_table)) {
		memset(&n_wctx, 0, sizeof(n_wctx));
		n_wctx.zevpn = zevpn;
		n_wctx.zvrf = zvrf;
		hash_iterate(zevpn->neigh_table,
			     zebra_evpn_clear_dup_neigh_hash, &n_wctx);
	}

	if (num_valid_macs(zevpn)) {
		memset(&m_wctx, 0, sizeof(m_wctx));
		m_wctx.zevpn = zevpn;
		m_wctx.zvrf = zvrf;
		hash_iterate(zevpn->mac_table, zevpn_clear_dup_mac_hash, &m_wctx);
	}

}

int zebra_vxlan_clear_dup_detect_vni_all(struct zebra_vrf *zvrf)
{
	void *args[1];

	if (!is_evpn_enabled())
		return 0;

	args[0] = zvrf;

	hash_iterate(zvrf->evpn_table,
		     (void (*)(struct hash_bucket *, void *))
		     zevpn_clear_dup_detect_hash_vni_all, args);

	return 0;
}

int zebra_vxlan_clear_dup_detect_vni(struct zebra_vrf *zvrf, vni_t vni)
{
	struct zebra_evpn *zevpn;
	struct mac_walk_ctx m_wctx;
	struct neigh_walk_ctx n_wctx;

	if (!is_evpn_enabled())
		return 0;

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		zlog_warn("VNI %u does not exist", vni);
		return CMD_WARNING;
	}

	if (hashcount(zevpn->neigh_table)) {
		memset(&n_wctx, 0, sizeof(n_wctx));
		n_wctx.zevpn = zevpn;
		n_wctx.zvrf = zvrf;
		hash_iterate(zevpn->neigh_table,
			     zebra_evpn_clear_dup_neigh_hash, &n_wctx);
	}

	if (num_valid_macs(zevpn)) {
		memset(&m_wctx, 0, sizeof(m_wctx));
		m_wctx.zevpn = zevpn;
		m_wctx.zvrf = zvrf;
		hash_iterate(zevpn->mac_table, zevpn_clear_dup_mac_hash, &m_wctx);
	}

	return 0;
}

/*
 * Display MACs for a VNI from specific VTEP (VTY command handler).
 */
void zebra_vxlan_print_macs_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				     vni_t vni, struct in_addr vtep_ip,
				     bool use_json)
{
	struct zebra_evpn *zevpn;
	uint32_t num_macs;
	struct mac_walk_ctx wctx;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (use_json)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% VNI %u does not exist\n", vni);
		return;
	}
	num_macs = num_valid_macs(zevpn);
	if (!num_macs) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	if (use_json) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.vty = vty;
	wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
	wctx.r_vtep_ip = vtep_ip;
	wctx.json = json_mac;
	hash_iterate(zevpn->mac_table, zebra_evpn_print_mac_hash, &wctx);

	if (use_json) {
		json_object_int_add(json, "numMacs", wctx.count);
		if (wctx.count)
			json_object_object_add(json, "macs", json_mac);
		vty_json(vty, json);
	}
}


/*
 * Display VNI information (VTY command handler).
 *
 * use_json flag indicates that output should be in JSON format.
 * json_array is non NULL when JSON output needs to be aggregated (by the
 * caller) and then printed, otherwise, JSON evpn vni info is printed
 * right away.
 */
void zebra_vxlan_print_vni(struct vty *vty, struct zebra_vrf *zvrf, vni_t vni,
			   bool use_json, json_object *json_array)
{
	json_object *json = NULL;
	void *args[2];
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_evpn *zevpn = NULL;

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	args[0] = vty;
	args[1] = json;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {
		zl3vni_print(zl3vni, (void *)args);
	} else {
		zevpn = zebra_evpn_lookup(vni);
		if (zevpn)
			zebra_evpn_print(zevpn, (void *)args);
		else if (!json)
			vty_out(vty, "%% VNI %u does not exist\n", vni);
	}

	if (use_json) {
		/*
		 * Each "json" object contains info about 1 VNI.
		 * When "json_array" is non-null, we aggreggate the json output
		 * into json_array and print it as a JSON array.
		 */
		if (json_array)
			json_object_array_add(json_array, json);
		else
			vty_json(vty, json);
	}
}

/* Display all global details for EVPN */
void zebra_vxlan_print_evpn(struct vty *vty, bool uj)
{
	int num_l2vnis = 0;
	int num_l3vnis = 0;
	int num_vnis = 0;
	json_object *json = NULL;
	struct zebra_vrf *zvrf = NULL;

	if (uj)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	zvrf = zebra_vrf_get_evpn();

	num_l3vnis = hashcount(zrouter.l3vni_table);
	num_l2vnis = hashcount(zvrf->evpn_table);
	num_vnis = num_l2vnis + num_l3vnis;

	if (uj) {
		json_object_string_add(json, "advertiseGatewayMacip",
				       zvrf->advertise_gw_macip ? "Yes" : "No");
		json_object_string_add(json, "advertiseSviMacip",
				       zvrf->advertise_svi_macip ? "Yes"
								 : "No");
		json_object_string_add(json, "advertiseSviMac",
				       zebra_evpn_mh_do_adv_svi_mac() ? "Yes"
								      : "No");
		json_object_int_add(json, "numVnis", num_vnis);
		json_object_int_add(json, "numL2Vnis", num_l2vnis);
		json_object_int_add(json, "numL3Vnis", num_l3vnis);
		if (zebra_evpn_do_dup_addr_detect(zvrf))
			json_object_boolean_true_add(json,
						"isDuplicateAddrDetection");
		else
			json_object_boolean_false_add(json,
						"isDuplicateAddrDetection");
		json_object_int_add(json, "maxMoves", zvrf->dad_max_moves);
		json_object_int_add(json, "detectionTime", zvrf->dad_time);
		json_object_int_add(json, "detectionFreezeTime",
				    zvrf->dad_freeze_time);
		json_object_boolean_add(json, "isDetectionFreeze",
					zvrf->dad_freeze);
		zebra_evpn_mh_json(json);
	} else {
		vty_out(vty, "L2 VNIs: %u\n", num_l2vnis);
		vty_out(vty, "L3 VNIs: %u\n", num_l3vnis);
		vty_out(vty, "Advertise gateway mac-ip: %s\n",
			zvrf->advertise_gw_macip ? "Yes" : "No");
		vty_out(vty, "Advertise svi mac-ip: %s\n",
			zvrf->advertise_svi_macip ? "Yes" : "No");
		vty_out(vty, "Advertise svi mac: %s\n",
			zebra_evpn_mh_do_adv_svi_mac() ? "Yes" : "No");
		vty_out(vty, "Duplicate address detection: %s\n",
			zebra_evpn_do_dup_addr_detect(zvrf) ? "Enable"
							    : "Disable");
		vty_out(vty, "  Detection max-moves %u, time %d\n",
			zvrf->dad_max_moves, zvrf->dad_time);
		if (zvrf->dad_freeze) {
			if (zvrf->dad_freeze_time)
				vty_out(vty, "  Detection freeze %u\n",
					zvrf->dad_freeze_time);
			else
				vty_out(vty, "  Detection freeze %s\n",
					"permanent");
		}
		zebra_evpn_mh_print(vty);
	}

	if (uj)
		vty_json(vty, json);
}

/*
 * Display VNI hash table (VTY command handler).
 */
void zebra_vxlan_print_vnis(struct vty *vty, struct zebra_vrf *zvrf,
			    bool use_json)
{
	json_object *json = NULL;
	void *args[2];

	if (use_json)
		json = json_object_new_object();

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, json);
		return;
	}

	if (!use_json)
		vty_out(vty, "%-10s %-4s %-21s %-8s %-8s %-15s %-37s\n", "VNI",
			"Type", "VxLAN IF", "# MACs", "# ARPs",
			"# Remote VTEPs", "Tenant VRF");

	args[0] = vty;
	args[1] = json;

	/* Display all L2-VNIs */
	hash_iterate(
		zvrf->evpn_table,
		(void (*)(struct hash_bucket *, void *))zebra_evpn_print_hash,
		args);

	/* Display all L3-VNIs */
	hash_iterate(zrouter.l3vni_table,
		     (void (*)(struct hash_bucket *, void *))zl3vni_print_hash,
		     args);

	if (use_json)
		vty_json(vty, json);
}

void zebra_vxlan_dup_addr_detection(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	int time = 0;
	uint32_t max_moves = 0;
	uint32_t freeze_time = 0;
	bool dup_addr_detect = false;
	bool freeze = false;
	bool old_addr_detect;

	s = msg;
	STREAM_GETL(s, dup_addr_detect);
	STREAM_GETL(s, time);
	STREAM_GETL(s, max_moves);
	STREAM_GETL(s, freeze);
	STREAM_GETL(s, freeze_time);

	old_addr_detect = zebra_evpn_do_dup_addr_detect(zvrf);
	zvrf->dup_addr_detect = dup_addr_detect;
	dup_addr_detect = zebra_evpn_do_dup_addr_detect(zvrf);

	/* DAD previous state was enabled, and new state is disable,
	 * clear all duplicate detected addresses.
	 */
	if (old_addr_detect && !dup_addr_detect)
		zebra_vxlan_clear_dup_detect_vni_all(zvrf);

	zvrf->dad_time = time;
	zvrf->dad_max_moves = max_moves;
	zvrf->dad_freeze = freeze;
	zvrf->dad_freeze_time = freeze_time;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"VRF %s duplicate detect %s max_moves %u timeout %u freeze %s freeze_time %u",
			vrf_id_to_name(zvrf->vrf->vrf_id),
			dup_addr_detect ? "enable" : "disable",
			zvrf->dad_max_moves, zvrf->dad_time,
			zvrf->dad_freeze ? "enable" : "disable",
			zvrf->dad_freeze_time);

stream_failure:
	return;
}

/*
 * Display VNI hash table in detail(VTY command handler).
 */
void zebra_vxlan_print_vnis_detail(struct vty *vty, struct zebra_vrf *zvrf,
				   bool use_json)
{
	json_object *json_array = NULL;
	struct zebra_ns *zns = NULL;
	struct zebra_evpn_show zes;

	if (!is_evpn_enabled()) {
		if (use_json)
			vty_json_empty(vty, NULL);
		return;
	}

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns)
		return;

	if (use_json)
		json_array = json_object_new_array();

	zes.vty = vty;
	zes.json = json_array;
	zes.zvrf = zvrf;
	zes.use_json = use_json;

	/* Display all L2-VNIs */
	hash_iterate(zvrf->evpn_table,
		     (void (*)(struct hash_bucket *,
			       void *))zebra_evpn_print_hash_detail,
		     &zes);

	/* Display all L3-VNIs */
	hash_iterate(zrouter.l3vni_table,
		     (void (*)(struct hash_bucket *,
			       void *))zl3vni_print_hash_detail,
		     &zes);

	/*
	 * This is an extremely expensive operation at scale
	 * and non-pretty reduces memory footprint significantly.
	 */
	if (use_json)
		vty_json_no_pretty(vty, json_array);
}

/*
 * Handle neighbor delete notification from the kernel (on a VLAN device
 * / L3 interface). This may result in either the neighbor getting deleted
 * from our database or being re-added to the kernel (if it is a valid
 * remote neighbor).
 */
int zebra_vxlan_handle_kernel_neigh_del(struct interface *ifp,
					struct interface *link_if,
					struct ipaddr *ip)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	/* check if this is a remote neigh entry corresponding to remote
	 * next-hop
	 */
	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni)
		return zl3vni_local_nh_del(zl3vni, ip);

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zevpn = zebra_evpn_from_svi(ifp, link_if);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: Del neighbor %pIA EVPN is not present for interface %s",
				__func__, ip, ifp->name);
		return 0;
	}

	if (!zevpn->vxlan_if) {
		zlog_debug(
			"VNI %u hash %p doesn't have intf upon local neighbor DEL",
			zevpn->vni, zevpn);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Del neighbor %pIA intf %s(%u) -> L2-VNI %u",
			   ip, ifp->name, ifp->ifindex, zevpn->vni);

	return zebra_evpn_neigh_del_ip(zevpn, ip);
}

/*
 * Handle neighbor add or update notification from the kernel (on a VLAN
 * device / L3 interface). This is typically for a local neighbor but can
 * also be for a remote neighbor (e.g., ageout notification). It could
 * also be a "move" scenario.
 */
int zebra_vxlan_handle_kernel_neigh_update(struct interface *ifp,
					   struct interface *link_if,
					   struct ipaddr *ip,
					   struct ethaddr *macaddr,
					   uint16_t state,
					   bool is_ext,
					   bool is_router,
					   bool local_inactive, bool dp_static)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

	/* check if this is a remote neigh entry corresponding to remote
	 * next-hop
	 */
	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni)
		return zl3vni_local_nh_add_update(zl3vni, ip, state);

	/* We are only interested in neighbors on an SVI that resides on top
	 * of a VxLAN bridge.
	 */
	zevpn = zebra_evpn_from_svi(ifp, link_if);
	if (!zevpn)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug(
			"Add/Update neighbor %pIA MAC %pEA intf %s(%u) state 0x%x %s%s%s%s-> L2-VNI %u",
			ip, macaddr, ifp->name,
			ifp->ifindex, state, is_ext ? "ext-learned " : "",
			is_router ? "router " : "",
			local_inactive ? "local_inactive " : "",
			dp_static ? "peer_sync " : "", zevpn->vni);

	/* Is this about a local neighbor or a remote one? */
	if (!is_ext)
		return zebra_evpn_local_neigh_update(zevpn, ifp, ip, macaddr,
						     is_router, local_inactive,
						     dp_static);

	return zebra_evpn_remote_neigh_update(zevpn, ifp, ip, macaddr, state);
}

static int32_t
zebra_vxlan_remote_macip_helper(bool add, struct stream *s, vni_t *vni,
				struct ethaddr *macaddr, uint16_t *ipa_len,
				struct ipaddr *ip, struct in_addr *vtep_ip,
				uint8_t *flags, uint32_t *seq, esi_t *esi)
{
	uint16_t l = 0;

	/*
	 * Obtain each remote MACIP and process.
	 * Message contains VNI, followed by MAC followed by IP (if any)
	 * followed by remote VTEP IP.
	 */
	memset(ip, 0, sizeof(*ip));
	STREAM_GETL(s, *vni);
	STREAM_GET(macaddr->octet, s, ETH_ALEN);
	STREAM_GETW(s, *ipa_len);

	if (*ipa_len) {
		if (*ipa_len == IPV4_MAX_BYTELEN)
			ip->ipa_type = IPADDR_V4;
		else if (*ipa_len == IPV6_MAX_BYTELEN)
			ip->ipa_type = IPADDR_V6;
		else {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"ipa_len *must* be %d or %d bytes in length not %d",
					IPV4_MAX_BYTELEN, IPV6_MAX_BYTELEN,
					*ipa_len);
			goto stream_failure;
		}

		STREAM_GET(&ip->ip.addr, s, *ipa_len);
	}
	l += 4 + ETH_ALEN + 4 + *ipa_len;
	STREAM_GET(&vtep_ip->s_addr, s, IPV4_MAX_BYTELEN);
	l += IPV4_MAX_BYTELEN;

	if (add) {
		STREAM_GETC(s, *flags);
		STREAM_GETL(s, *seq);
		l += 5;
		STREAM_GET(esi, s, sizeof(esi_t));
		l += sizeof(esi_t);
	}

	return l;

stream_failure:
	return -1;
}

/*
 * Handle message from client to delete a remote MACIP for a VNI.
 */
void zebra_vxlan_remote_macip_del(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	vni_t vni;
	struct ethaddr macaddr;
	struct ipaddr ip;
	struct in_addr vtep_ip;
	uint16_t l = 0, ipa_len;
	char buf1[INET6_ADDRSTRLEN];

	s = msg;

	while (l < hdr->length) {
		int res_length = zebra_vxlan_remote_macip_helper(
			false, s, &vni, &macaddr, &ipa_len, &ip, &vtep_ip, NULL,
			NULL, NULL);

		if (res_length == -1)
			goto stream_failure;

		l += res_length;
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Recv MACIP DEL VNI %u MAC %pEA%s%s Remote VTEP %pI4 from %s",
				vni, &macaddr,
				ipa_len ? " IP " : "",
				ipa_len ?
				ipaddr2str(&ip, buf1, sizeof(buf1)) : "",
				&vtep_ip, zebra_route_string(client->proto));

		/* Enqueue to workqueue for processing */
		zebra_rib_queue_evpn_rem_macip_del(vni, &macaddr, &ip, vtep_ip);
	}

stream_failure:
	return;
}

/*
 * Handle message from client to add a remote MACIP for a VNI. This
 * could be just the add of a MAC address or the add of a neighbor
 * (IP+MAC).
 */
void zebra_vxlan_remote_macip_add(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	vni_t vni;
	struct ethaddr macaddr;
	struct ipaddr ip;
	struct in_addr vtep_ip;
	uint16_t l = 0, ipa_len;
	uint8_t flags = 0;
	uint32_t seq;
	char buf1[INET6_ADDRSTRLEN];
	esi_t esi;
	char esi_buf[ESI_STR_LEN];

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("EVPN not enabled, ignoring remote MACIP ADD");
		return;
	}

	s = msg;

	while (l < hdr->length) {

		int res_length = zebra_vxlan_remote_macip_helper(
			true, s, &vni, &macaddr, &ipa_len, &ip, &vtep_ip,
			&flags, &seq, &esi);

		if (res_length == -1)
			goto stream_failure;

		l += res_length;
		if (IS_ZEBRA_DEBUG_VXLAN) {
			if (memcmp(&esi, zero_esi, sizeof(esi_t)))
				esi_to_str(&esi, esi_buf, sizeof(esi_buf));
			else
				strlcpy(esi_buf, "-", ESI_STR_LEN);
			zlog_debug(
				"Recv %sMACIP ADD VNI %u MAC %pEA%s%s flags 0x%x seq %u VTEP %pI4 ESI %s from %s",
				(flags & ZEBRA_MACIP_TYPE_SYNC_PATH) ?
				"sync-" : "",
				vni, &macaddr,
				ipa_len ? " IP " : "",
				ipa_len ?
				ipaddr2str(&ip, buf1, sizeof(buf1)) : "",
				flags, seq, &vtep_ip, esi_buf,
				zebra_route_string(client->proto));
		}

		/* Enqueue to workqueue for processing */
		zebra_rib_queue_evpn_rem_macip_add(vni, &macaddr, &ip, flags,
						   seq, vtep_ip, &esi);
	}

stream_failure:
	return;
}

/*
 * Handle remote vtep delete by kernel; re-add the vtep if we have it
 */
int zebra_vxlan_check_readd_vtep(struct interface *ifp, vni_t vni,
				 struct in_addr vtep_ip)
{
	struct zebra_if *zif;
	struct zebra_vrf *zvrf = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_vtep *zvtep = NULL;
	struct zebra_vxlan_vni *vnip;

	zif = ifp->info;
	assert(zif);

	/* If EVPN is not enabled, nothing to do. */
	if (!is_evpn_enabled())
		return 0;

	/* Locate VRF corresponding to interface. */
	zvrf = ifp->vrf->info;
	if (!zvrf)
		return -1;

	vnip = zebra_vxlan_if_vni_find(zif, vni);
	if (!vnip)
		return 0;

	/* Locate hash entry; it is expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn)
		return 0;

	/* If the remote vtep entry doesn't exists nothing to do */
	zvtep = zebra_evpn_vtep_find(zevpn, &vtep_ip);
	if (!zvtep)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Del MAC for remote VTEP %pI4 intf %s(%u) VNI %u - readd",
			&vtep_ip, ifp->name, ifp->ifindex, vni);

	zebra_evpn_vtep_install(zevpn, zvtep);
	return 0;
}

/*
 * Handle notification of MAC add/update over VxLAN. If the kernel is notifying
 * us, this must involve a multihoming scenario. Treat this as implicit delete
 * of any prior local MAC.
 */
static int zebra_vxlan_check_del_local_mac(struct interface *ifp,
					   struct interface *br_if,
					   struct ethaddr *macaddr,
					   vlanid_t vid, vni_t vni)
{
	struct zebra_if *zif;
	struct zebra_evpn *zevpn;
	struct zebra_mac *mac;

	zif = ifp->info;
	assert(zif);

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	/* Locate hash entry; it is expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn)
		return 0;

	/* If entry doesn't exist, nothing to do. */
	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac)
		return 0;

	/* Is it a local entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Add/update remote MAC %pEA intf %s(%u) VNI %u flags 0x%x - del local",
			macaddr, ifp->name, ifp->ifindex, vni, mac->flags);

	/* Remove MAC from BGP. */
	zebra_evpn_mac_send_del_to_client(zevpn->vni, macaddr, mac->flags,
					  false /* force */);

	/*
	 * If there are no neigh associated with the mac delete the mac
	 * else mark it as AUTO for forward reference
	 */
	if (!listcount(mac->neigh_list)) {
		zebra_evpn_mac_del(zevpn, mac);
	} else {
		zebra_evpn_mac_clear_fwd_info(mac);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_ALL_LOCAL_FLAGS);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	}

	return 0;
}

/* MAC notification from the dataplane with a network dest port -
 * 1. This can be a local MAC on a down ES (if fast-failover is not possible
 * 2. Or it can be a remote MAC
 */
int zebra_vxlan_dp_network_mac_add(struct interface *ifp,
				   struct interface *br_if,
				   struct ethaddr *macaddr, vlanid_t vid,
				   vni_t vni, uint32_t nhg_id, bool sticky,
				   bool dp_static)
{
	struct zebra_evpn_es *es;
	struct interface *acc_ifp;

	/* If netlink message is with vid, it will have no nexthop.
	 * So skip it.
	 */
	if (vid) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("dpAdd MAC %pEA VID %u - ignore as no nhid",
				   macaddr, vid);
		return 0;
	}

	/* Get vxlan's vid for netlink message has no it. */
	vid = ((struct zebra_if *)ifp->info)
		      ->l2info.vxl.vni_info.vni.access_vlan;

	/* if remote mac delete the local entry */
	if (!nhg_id || !zebra_evpn_nhg_is_local_es(nhg_id, &es)
	    || !zebra_evpn_es_local_mac_via_network_port(es)) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("dpAdd remote MAC %pEA VID %u", macaddr,
				   vid);
		return zebra_vxlan_check_del_local_mac(ifp, br_if, macaddr, vid,
						       vni);
	}

	/* If local MAC on a down local ES translate the network-mac-add
	 * to a local-active-mac-add
	 */
	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("dpAdd local-nw-MAC %pEA VID %u", macaddr, vid);
	acc_ifp = es->zif->ifp;
	return zebra_vxlan_local_mac_add_update(
		acc_ifp, br_if, macaddr, vid, sticky,
		false /* local_inactive */, dp_static);
}

/*
 * Handle network MAC delete by kernel -
 * 1. readd the remote MAC if we have it
 * 2. local MAC with does ES may also need to be re-installed
 */
int zebra_vxlan_dp_network_mac_del(struct interface *ifp,
				   struct interface *br_if,
				   struct ethaddr *macaddr, vlanid_t vid,
				   vni_t vni)
{
	struct zebra_if *zif = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_mac *mac = NULL;

	zif = ifp->info;
	assert(zif);

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	/* check if this is a remote RMAC and readd simillar to remote macs */
	zl3vni = zl3vni_lookup(vni);
	if (zl3vni)
		return zebra_vxlan_readd_remote_rmac(zl3vni, macaddr);

	/* Locate hash entry; it is expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn)
		return 0;

	/* If entry doesn't exist, nothing to do. */
	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac)
		return 0;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		/* If remote entry simply re-install */
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"dpDel remote MAC %pEA intf %s(%u) VNI %u - readd",
				macaddr, ifp->name, ifp->ifindex, vni);
		zebra_evpn_rem_mac_install(zevpn, mac, false /* was_static */);
	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL) && mac->es
		   && zebra_evpn_es_local_mac_via_network_port(mac->es)) {
		/* If local entry via nw-port call local-del which will
		 * re-install entry in the dataplane is needed
		 */
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("dpDel local-nw-MAC %pEA VNI %u", macaddr,
				   vni);

		zebra_evpn_del_local_mac(zevpn, mac, false);
	}

	return 0;
}

/*
 * Handle local MAC delete (on a port or VLAN corresponding to this VNI).
 */
int zebra_vxlan_local_mac_del(struct interface *ifp, struct interface *br_if,
			      struct ethaddr *macaddr, vlanid_t vid)
{
	struct zebra_evpn *zevpn;
	struct zebra_mac *mac;

	/* We are interested in MACs only on ports or (port, VLAN) that
	 * map to a VNI.
	 */
	zevpn = zebra_evpn_map_vlan(ifp, br_if, vid);
	if (!zevpn)
		return 0;
	if (!zevpn->vxlan_if) {
		zlog_debug(
			"VNI %u hash %p doesn't have intf upon local MAC DEL",
			zevpn->vni, zevpn);
		return -1;
	}

	/* If entry doesn't exist, nothing to do. */
	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac)
		return 0;

	/* Is it a local entry? */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return 0;

	return zebra_evpn_del_local_mac(zevpn, mac, false);
}

/*
 * Handle local MAC add (on a port or VLAN corresponding to this VNI).
 */
int zebra_vxlan_local_mac_add_update(struct interface *ifp,
				     struct interface *br_if,
				     struct ethaddr *macaddr, vlanid_t vid,
					 bool sticky, bool local_inactive,
					 bool dp_static)
{
	struct zebra_evpn *zevpn;
	struct zebra_vrf *zvrf;

	assert(ifp);

	/* We are interested in MACs only on ports or (port, VLAN) that
	 * map to an EVPN.
	 */
	zevpn = zebra_evpn_map_vlan(ifp, br_if, vid);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"        Add/Update %sMAC %pEA intf %s(%u) VID %u, could not find EVPN",
				sticky ? "sticky " : "", macaddr,
				ifp->name, ifp->ifindex, vid);
		return 0;
	}

	if (!zevpn->vxlan_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"        VNI %u hash %p doesn't have intf upon local MAC ADD",
				zevpn->vni, zevpn);
		return -1;
	}

	zvrf = zebra_vrf_get_evpn();
	return zebra_evpn_add_update_local_mac(zvrf, zevpn, ifp, macaddr, vid,
					       sticky, local_inactive,
					       dp_static, NULL);
}

/*
 * Handle message from client to delete a remote VTEP for an EVPN.
 */
void zebra_vxlan_remote_vtep_del_zapi(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	unsigned short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;

	if (!is_evpn_enabled()) {
		zlog_debug(
			"%s: EVPN is not enabled yet we have received a VTEP DEL msg",
			__func__);
		return;
	}

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("Recv VTEP DEL zapi for non-EVPN VRF %u",
			   zvrf_id(zvrf));
		return;
	}

	s = msg;

	while (l < hdr->length) {
		int flood_control __attribute__((unused));

		/* Obtain each remote VTEP and process. */
		STREAM_GETL(s, vni);
		l += 4;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		l += IPV4_MAX_BYTELEN;

		/* Flood control is intentionally ignored right now */
		STREAM_GETL(s, flood_control);
		l += 4;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Recv VTEP DEL %pI4 VNI %u from %s",
				   &vtep_ip, vni,
				   zebra_route_string(client->proto));

		/* Enqueue for processing */
		zebra_rib_queue_evpn_rem_vtep_del(zvrf_id(zvrf), vni, vtep_ip);
	}

stream_failure:
	return;
}

/*
 * Handle message from client to delete a remote VTEP for an EVPN.
 */
void zebra_vxlan_remote_vtep_del(vrf_id_t vrf_id, vni_t vni,
				 struct in_addr vtep_ip)
{
	struct zebra_evpn *zevpn;
	struct zebra_vtep *zvtep;
	struct interface *ifp;
	struct zebra_if *zif;
	struct zebra_vrf *zvrf;

	if (!is_evpn_enabled()) {
		zlog_debug("%s: Can't process vtep del: EVPN is not enabled",
			   __func__);
		return;
	}

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf)
		return;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("Can't process VTEP DEL for non-EVPN VRF %u",
			   zvrf_id(zvrf));
		return;
	}

	/* Locate VNI hash entry - expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Failed to locate VNI hash for remote VTEP DEL, VNI %u",
				vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (!ifp) {
		zlog_debug(
			"VNI %u hash %p doesn't have intf upon remote VTEP DEL",
			zevpn->vni, zevpn);
		return;
	}
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	/* If the remote VTEP does not exist, there's nothing more to
	 * do.
	 * Otherwise, uninstall any remote MACs pointing to this VTEP
	 * and then, the VTEP entry itself and remove it.
	 */
	zvtep = zebra_evpn_vtep_find(zevpn, &vtep_ip);
	if (!zvtep)
		return;

	zebra_evpn_vtep_uninstall(zevpn, &vtep_ip);
	zebra_evpn_vtep_del(zevpn, zvtep);
}

/*
 * Handle message from client to add a remote VTEP for an EVPN.
 */
void zebra_vxlan_remote_vtep_add(vrf_id_t vrf_id, vni_t vni,
				 struct in_addr vtep_ip, int flood_control)
{
	struct zebra_evpn *zevpn;
	struct interface *ifp;
	struct zebra_if *zif;
	struct zebra_vtep *zvtep;
	struct zebra_vrf *zvrf;

	if (!is_evpn_enabled()) {
		zlog_debug("%s: EVPN not enabled: can't process a VTEP ADD",
			   __func__);
		return;
	}

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf)
		return;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("Can't process VTEP ADD for non-EVPN VRF %u",
			   zvrf_id(zvrf));
		return;
	}

	/* Locate VNI hash entry - expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		flog_err(
			EC_ZEBRA_VTEP_ADD_FAILED,
			"Failed to locate EVPN hash upon remote VTEP ADD, VNI %u",
			vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (!ifp) {
		flog_err(
			EC_ZEBRA_VTEP_ADD_FAILED,
			"VNI %u hash %p doesn't have intf upon remote VTEP ADD",
			zevpn->vni, zevpn);
		return;
	}

	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	zvtep = zebra_evpn_vtep_find(zevpn, &vtep_ip);
	if (zvtep) {
		/* If the remote VTEP already exists check if
		 * the flood mode has changed
		 */
		if (zvtep->flood_control != flood_control) {
			if (zvtep->flood_control == VXLAN_FLOOD_DISABLED)
				/* old mode was head-end-replication but
				 * is no longer; get rid of the HER fdb
				 * entry installed before
				 */
				zebra_evpn_vtep_uninstall(zevpn, &vtep_ip);
			zvtep->flood_control = flood_control;
			zebra_evpn_vtep_install(zevpn, zvtep);
		}
	} else {
		zvtep = zebra_evpn_vtep_add(zevpn, &vtep_ip, flood_control);
		if (zvtep)
			zebra_evpn_vtep_install(zevpn, zvtep);
		else
			flog_err(EC_ZEBRA_VTEP_ADD_FAILED,
				 "Failed to add remote VTEP, VNI %u zevpn %p",
				 vni, zevpn);
	}
}

/*
 * Handle message from client to add a remote VTEP for an EVPN.
 */
void zebra_vxlan_remote_vtep_add_zapi(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	unsigned short l = 0;
	vni_t vni;
	struct in_addr vtep_ip;
	int flood_control;

	if (!is_evpn_enabled()) {
		zlog_debug(
			"%s: EVPN not enabled yet we received a VTEP ADD zapi msg",
			__func__);
		return;
	}

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("Recv VTEP ADD zapi for non-EVPN VRF %u",
			   zvrf_id(zvrf));
		return;
	}

	s = msg;

	while (l < hdr->length) {
		/* Obtain each remote VTEP and process. */
		STREAM_GETL(s, vni);
		l += 4;
		STREAM_GET(&vtep_ip.s_addr, s, IPV4_MAX_BYTELEN);
		STREAM_GETL(s, flood_control);
		l += IPV4_MAX_BYTELEN + 4;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Recv VTEP ADD %pI4 VNI %u flood %d from %s",
				   &vtep_ip, vni, flood_control,
				   zebra_route_string(client->proto));

		/* Enqueue for processing */
		zebra_rib_queue_evpn_rem_vtep_add(zvrf_id(zvrf), vni, vtep_ip,
						  flood_control);
	}

stream_failure:
	return;
}

/*
 * Add/Del gateway macip to evpn
 * g/w can be:
 *  1. SVI interface on a vlan aware bridge
 *  2. SVI interface on a vlan unaware bridge
 *  3. vrr interface (MACVLAN) associated to a SVI
 * We advertise macip routes for an interface if it is associated to VxLan vlan
 */
int zebra_vxlan_add_del_gw_macip(struct interface *ifp, const struct prefix *p,
				 int add)
{
	struct ipaddr ip;
	struct ethaddr macaddr;
	struct zebra_evpn *zevpn = NULL;

	memset(&ip, 0, sizeof(ip));
	memset(&macaddr, 0, sizeof(macaddr));

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
			zlog_debug("MACVLAN %s(%u) without link information",
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
				zevpn = zebra_evpn_from_svi(svi_if,
							    svi_if_link);
			}
		} else if (IS_ZEBRA_IF_BRIDGE(svi_if)) {
			/*
			 * If it is a vlan unaware bridge then svi is the bridge
			 * itself
			 */
			zevpn = zebra_evpn_from_svi(svi_if, svi_if);
		}
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_if *svi_if_zif =
			NULL; /* Zebra daemon specific info for SVI */
		struct interface *svi_if_link =
			NULL; /* link info for the SVI = bridge info */

		svi_if_zif = ifp->info;
		if (svi_if_zif) {
			svi_if_link = if_lookup_by_index_per_ns(
				zebra_ns_lookup(NS_DEFAULT),
				svi_if_zif->link_ifindex);
			if (svi_if_link)
				zevpn = zebra_evpn_from_svi(ifp, svi_if_link);
		}
	} else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		zevpn = zebra_evpn_from_svi(ifp, ifp);
	}

	if (!zevpn)
		return 0;

	if (!zevpn->vxlan_if) {
		zlog_debug("VNI %u hash %p doesn't have intf upon MACVLAN up",
			   zevpn->vni, zevpn);
		return -1;
	}

	/* VRR IP is advertised only if gw-macip-adv-enabled */
	if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		if (!advertise_gw_macip_enabled(zevpn))
			return 0;
	} else {
		/* SVI IP is advertised if gw or svi macip-adv-enabled */
		if (!advertise_svi_macip_enabled(zevpn)
		    && !advertise_gw_macip_enabled(zevpn))
			return 0;
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
		zebra_evpn_gw_macip_add(ifp, zevpn, &macaddr, &ip);
	else
		zebra_evpn_gw_macip_del(ifp, zevpn, &ip);

	return 0;
}

/*
 * Handle SVI interface going down.
 * SVI can be associated to either L3-VNI or L2-VNI.
 * For L2-VNI: At this point, this is a NOP since
 *	the kernel deletes the neighbor entries on this SVI (if any).
 *      We only need to update the vrf corresponding to zevpn.
 * For L3-VNI: L3-VNI is operationally down, update mac-ip routes and delete
 *	from bgp
 */
int zebra_vxlan_svi_down(struct interface *ifp, struct interface *link_if)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_from_svi(ifp, link_if);
	if (zl3vni) {

		/* process l3-vni down */
		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* remove association with svi-if */
		zl3vni->svi_if = NULL;
	} else {
		struct zebra_evpn *zevpn = NULL;

		/* Unlink the SVI from the access VLAN */
		zebra_evpn_acc_bd_svi_set(ifp->info, link_if->info, false);

		/* since we dont have svi corresponding to zevpn, we associate it
		 * to default vrf. Note: the corresponding neigh entries on the
		 * SVI would have already been deleted */
		zevpn = zebra_evpn_from_svi(ifp, link_if);

		if (zevpn) {
			/* remove from l3-vni list */
			zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
			if (zl3vni)
				listnode_delete(zl3vni->l2vnis, zevpn);

			zevpn->svi_if = NULL;
			zevpn->vrf_id = VRF_DEFAULT;

			/* update the tenant vrf in BGP */
			if (if_is_operative(zevpn->vxlan_if))
				zebra_evpn_send_add_to_client(zevpn);
		}
	}
	return 0;
}

/*
 * Handle SVI interface coming up.
 * SVI can be associated to L3-VNI (l3vni vxlan interface) or L2-VNI (l2-vni
 * vxlan intf).
 * For L2-VNI: we need to install any remote neighbors entried (used for
 * arp-suppression)
 * For L3-VNI: SVI will be used to get the rmac to be used with L3-VNI
 */
int zebra_vxlan_svi_up(struct interface *ifp, struct interface *link_if)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;

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

		zevpn = zebra_evpn_from_svi(ifp, link_if);
		if (!zevpn)
			return 0;

		if (!zevpn->vxlan_if) {
			zlog_debug(
				"VNI %u hash %p doesn't have intf upon SVI up",
				zevpn->vni, zevpn);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"SVI %s(%u) VNI %u VRF %s is UP, installing neighbors",
				ifp->name, ifp->ifindex, zevpn->vni,
				ifp->vrf->name);

		/* update the vrf information for l2-vni and inform bgp */
		zevpn->svi_if = ifp;
		zevpn->vrf_id = ifp->vrf->vrf_id;

		zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
		if (zl3vni)
			listnode_add_sort_nodup(zl3vni->l2vnis, zevpn);

		if (if_is_operative(zevpn->vxlan_if))
			zebra_evpn_send_add_to_client(zevpn);

		/* Install any remote neighbors for this VNI. */
		memset(&n_wctx, 0, sizeof(n_wctx));
		n_wctx.zevpn = zevpn;
		hash_iterate(zevpn->neigh_table, zebra_evpn_install_neigh_hash,
			     &n_wctx);

		/* Link the SVI from the access VLAN */
		zebra_evpn_acc_bd_svi_set(ifp->info, link_if->info, true);

		/* Update MACIP routes created by advertise-svi-ip */
		if (advertise_svi_macip_enabled(zevpn)) {
			zebra_evpn_del_macip_for_intf(ifp, zevpn);
			zebra_evpn_add_macip_for_intf(ifp, zevpn);
		}
	}

	return 0;
}

/*
 * Handle MAC-VLAN interface going down.
 * L3VNI: When MAC-VLAN interface goes down,
 * find its associated SVI and update type2/type-5 routes
 * with SVI as RMAC
 */
void zebra_vxlan_macvlan_down(struct interface *ifp)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_if *zif, *link_zif;
	struct interface *link_ifp, *link_if;

	zif = ifp->info;
	assert(zif);
	link_ifp = zif->link;
	if (!link_ifp) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"macvlan parent link is not found. Parent index %d ifp %s",
				zif->link_ifindex,
				ifindex2ifname(zif->link_ifindex,
					       ifp->vrf->vrf_id));
		return;
	}
	link_zif = link_ifp->info;
	assert(link_zif);

	link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					    link_zif->link_ifindex);

	zl3vni = zl3vni_from_svi(link_ifp, link_if);
	if (zl3vni) {
		zl3vni->mac_vlan_if = NULL;
		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	}
}

/*
 * Handle MAC-VLAN interface going up.
 * L3VNI: When MAC-VLAN interface comes up,
 * find its associated SVI and update type-2 routes
 * with MAC-VLAN's MAC as RMAC and for type-5 routes
 * use SVI's MAC as RMAC.
 */
void zebra_vxlan_macvlan_up(struct interface *ifp)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_if *zif, *link_zif;
	struct interface *link_ifp, *link_if;

	zif = ifp->info;
	assert(zif);

	if (zif->link_nsid)
		/* the link interface is another namespace */
		return;

	link_ifp = zif->link;
	if (!link_ifp) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"macvlan parent link is not found. Parent index %d ifp %s",
				zif->link_ifindex,
				ifindex2ifname(zif->link_ifindex,
					       ifp->vrf->vrf_id));
		return;
	}
	link_zif = link_ifp->info;
	assert(link_zif);

	link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					    link_zif->link_ifindex);
	zl3vni = zl3vni_from_svi(link_ifp, link_if);
	if (zl3vni) {
		/* associate with macvlan (VRR) interface */
		zl3vni->mac_vlan_if = ifp;

		/* process oper-up */
		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	}
}

void zebra_vxlan_process_vrf_vni_cmd(struct zebra_vrf *zvrf, vni_t vni,
				     int filter, int add)
{
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_vrf *zvrf_evpn = NULL;

	zvrf_evpn = zebra_vrf_get_evpn();

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("vrf %s vni %u %s", zvrf_name(zvrf), vni,
			   add ? "ADD" : "DEL");

	if (add) {
		/* Remove L2VNI if present */
		zebra_vxlan_handle_vni_transition(zvrf, vni, add);

		/* add the L3-VNI to the global table */
		zl3vni = zl3vni_add(vni, zvrf_id(zvrf));

		/* associate the vrf with vni */
		zvrf->l3vni = vni;

		/* set the filter in l3vni to denote if we are using l3vni only
		 * for prefix routes
		 */
		if (filter)
			SET_FLAG(zl3vni->filter, PREFIX_ROUTES_ONLY);

		/* associate with vxlan-intf;
		 * we need to associate with the vxlan-intf first
		 */
		zl3vni->vxlan_if = zl3vni_map_to_vxlan_if(zl3vni);

		/* associate with corresponding SVI interface, we can associate
		 * with svi-if only after vxlan interface association is
		 * complete
		 */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		zl3vni->mac_vlan_if = zl3vni_map_to_mac_vlan_if(zl3vni);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: l3vni %u svi_if %s mac_vlan_if %s",
				__func__, vni,
				zl3vni->svi_if ? zl3vni->svi_if->name : "NIL",
				zl3vni->mac_vlan_if ? zl3vni->mac_vlan_if->name
						    : "NIL");

		/* formulate l2vni list */
		hash_iterate(zvrf_evpn->evpn_table, zevpn_add_to_l3vni_list,
			     zl3vni);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);

	} else {
		zl3vni = zl3vni_lookup(vni);
		assert(zl3vni);

		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* delete and uninstall all rmacs */
		hash_iterate(zl3vni->rmac_table, zl3vni_del_rmac_hash_entry,
			     zl3vni);

		/* delete and uninstall all next-hops */
		hash_iterate(zl3vni->nh_table, zl3vni_del_nh_hash_entry,
			     zl3vni);

		zvrf->l3vni = 0;
		zl3vni_del(zl3vni);

		/* Add L2VNI for this VNI */
		zebra_vxlan_handle_vni_transition(zvrf, vni, add);
	}
}

int zebra_vxlan_vrf_enable(struct zebra_vrf *zvrf)
{
	struct zebra_l3vni *zl3vni = NULL;

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
	struct zebra_l3vni *zl3vni = NULL;

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return 0;

	zebra_vxlan_process_l3vni_oper_down(zl3vni);

	/* delete and uninstall all rmacs */
	hash_iterate(zl3vni->rmac_table, zl3vni_del_rmac_hash_entry, zl3vni);
	/* delete and uninstall all next-hops */
	hash_iterate(zl3vni->nh_table, zl3vni_del_nh_hash_entry, zl3vni);

	zl3vni->vrf_id = VRF_UNKNOWN;

	return 0;
}

int zebra_vxlan_vrf_delete(struct zebra_vrf *zvrf)
{
	struct zebra_l3vni *zl3vni = NULL;
	vni_t vni;

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (!zl3vni)
		return 0;

	vni = zl3vni->vni;
	zl3vni_del(zl3vni);

	if (!zrouter.in_shutdown)
		zebra_vxlan_handle_vni_transition(zvrf, vni, 0);

	return 0;
}

/*
 * Handle message from client to specify the flooding mechanism for
 * BUM packets. The default is to do head-end (ingress) replication
 * and the other supported option is to disable it. This applies to
 * all BUM traffic and disabling it applies to both the transmit and
 * receive direction.
 */
void zebra_vxlan_flood_control(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	enum vxlan_flood_control flood_ctrl;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_err("EVPN flood control for non-EVPN VRF %u",
			 zvrf_id(zvrf));
		return;
	}

	s = msg;
	STREAM_GETC(s, flood_ctrl);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("EVPN flood control %u, currently %u",
			   flood_ctrl, zvrf->vxlan_flood_ctrl);

	if (zvrf->vxlan_flood_ctrl == flood_ctrl)
		return;

	zvrf->vxlan_flood_ctrl = flood_ctrl;

	/* Install or uninstall flood entries corresponding to
	 * remote VTEPs.
	 */
	hash_iterate(zvrf->evpn_table, zebra_evpn_handle_flooding_remote_vteps,
		     zvrf);

stream_failure:
	return;
}

/*
 * Handle message from client to enable/disable advertisement of svi macip
 * routes
 */
void zebra_vxlan_advertise_svi_macip(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	int advertise;
	vni_t vni = 0;
	struct zebra_evpn *zevpn = NULL;
	struct interface *ifp = NULL;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("EVPN SVI-MACIP Adv for non-EVPN VRF %u",
			  zvrf_id(zvrf));
		return;
	}

	s = msg;
	STREAM_GETC(s, advertise);
	STREAM_GETL(s, vni);

	if (!vni) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("EVPN SVI-MACIP Adv %s, currently %s",
				   advertise ? "enabled" : "disabled",
				   advertise_svi_macip_enabled(NULL)
					   ? "enabled"
					   : "disabled");

		if (zvrf->advertise_svi_macip == advertise)
			return;


		if (advertise) {
			zvrf->advertise_svi_macip = advertise;
			hash_iterate(zvrf->evpn_table,
				     zebra_evpn_gw_macip_add_for_evpn_hash,
				     NULL);
		} else {
			hash_iterate(zvrf->evpn_table,
				     zebra_evpn_svi_macip_del_for_evpn_hash,
				     NULL);
			zvrf->advertise_svi_macip = advertise;
		}

	} else {
		struct zebra_if *zif = NULL;
		struct interface *vlan_if = NULL;
		struct zebra_vxlan_vni *zl2_info_vni;
		int old_advertise;

		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn)
			return;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"EVPN SVI macip Adv %s on VNI %d, currently %s",
				advertise ? "enabled" : "disabled", vni,
				advertise_svi_macip_enabled(zevpn)
					? "enabled"
					: "disabled");

		old_advertise = advertise_svi_macip_enabled(zevpn);

		/* Store flag even though SVI is not present.
		 * Once SVI comes up triggers self MAC-IP route add.
		 */
		zevpn->advertise_svi_macip = advertise;
		if (advertise_svi_macip_enabled(zevpn) == old_advertise)
			return;

		ifp = zevpn->vxlan_if;
		if (!ifp)
			return;

		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return;

		zl2_info_vni = zebra_vxlan_if_vni_find(zif, vni);
		if (!zl2_info_vni)
			return;

		vlan_if = zvni_map_to_svi(zl2_info_vni->access_vlan,
					  zif->brslave_info.br_if);
		if (!vlan_if)
			return;

		if (advertise) {
			/* Add primary SVI MAC-IP */
			zebra_evpn_add_macip_for_intf(vlan_if, zevpn);
		} else {
			/* Del primary SVI MAC-IP */
			zebra_evpn_del_macip_for_intf(vlan_if, zevpn);
		}
	}

stream_failure:
	return;
}

/*
 * Handle message from client to enable/disable advertisement of g/w macip
 * routes
 */
void zebra_vxlan_advertise_subnet(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	int advertise;
	vni_t vni = 0;
	struct zebra_evpn *zevpn = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct interface *vlan_if = NULL;
	struct zebra_vxlan_vni *zl2_info_vni = NULL;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("EVPN GW-MACIP Adv for non-EVPN VRF %u",
			  zvrf_id(zvrf));
		return;
	}

	s = msg;
	STREAM_GETC(s, advertise);
	STREAM_GET(&vni, s, 3);

	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn)
		return;

	if (zevpn->advertise_subnet == advertise)
		return;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("EVPN subnet Adv %s on VNI %d, currently %s",
			   advertise ? "enabled" : "disabled", vni,
			   zevpn->advertise_subnet ? "enabled" : "disabled");


	zevpn->advertise_subnet = advertise;

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return;

	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	zl2_info_vni = zebra_vxlan_if_vni_find(zif, vni);
	if (!zl2_info_vni)
		return;

	vlan_if = zvni_map_to_svi(zl2_info_vni->access_vlan,
				  zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	if (zevpn->advertise_subnet)
		zebra_evpn_advertise_subnet(zevpn, vlan_if, 1);
	else
		zebra_evpn_advertise_subnet(zevpn, vlan_if, 0);

stream_failure:
	return;
}

/*
 * Handle message from client to enable/disable advertisement of g/w macip
 * routes
 */
void zebra_vxlan_advertise_gw_macip(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	int advertise;
	vni_t vni = 0;
	struct zebra_evpn *zevpn = NULL;
	struct interface *ifp = NULL;

	if (!EVPN_ENABLED(zvrf)) {
		zlog_debug("EVPN GW-MACIP Adv for non-EVPN VRF %u",
			   zvrf_id(zvrf));
		return;
	}

	s = msg;
	STREAM_GETC(s, advertise);
	STREAM_GETL(s, vni);

	if (!vni) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("EVPN gateway macip Adv %s, currently %s",
				   advertise ? "enabled" : "disabled",
				   advertise_gw_macip_enabled(NULL)
					   ? "enabled"
					   : "disabled");

		if (zvrf->advertise_gw_macip == advertise)
			return;

		zvrf->advertise_gw_macip = advertise;

		if (advertise_gw_macip_enabled(zevpn))
			hash_iterate(zvrf->evpn_table,
				     zebra_evpn_gw_macip_add_for_evpn_hash,
				     NULL);
		else
			hash_iterate(zvrf->evpn_table,
				     zebra_evpn_gw_macip_del_for_evpn_hash,
				     NULL);

	} else {
		struct zebra_if *zif = NULL;
		struct interface *vlan_if = NULL;
		struct interface *vrr_if = NULL;
		struct zebra_vxlan_vni *zl2_info_vni = NULL;
		int old_advertise;

		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn)
			return;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"EVPN gateway macip Adv %s on VNI %d, currently %s",
				advertise ? "enabled" : "disabled", vni,
				advertise_gw_macip_enabled(zevpn) ? "enabled"
								  : "disabled");

		old_advertise = advertise_gw_macip_enabled(zevpn);

		zevpn->advertise_gw_macip = advertise;
		if (advertise_gw_macip_enabled(zevpn) == old_advertise)
			return;

		ifp = zevpn->vxlan_if;
		if (!ifp)
			return;

		zif = ifp->info;

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return;

		zl2_info_vni = zebra_vxlan_if_vni_find(zif, vni);
		if (!zl2_info_vni)
			return;

		vlan_if = zvni_map_to_svi(zl2_info_vni->access_vlan,
					  zif->brslave_info.br_if);
		if (!vlan_if)
			return;

		if (advertise_gw_macip_enabled(zevpn)) {
			/* Add primary SVI MAC-IP */
			zebra_evpn_add_macip_for_intf(vlan_if, zevpn);

			/* Add VRR MAC-IP - if any*/
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zebra_evpn_add_macip_for_intf(vrr_if, zevpn);
		} else {
			/* Del primary MAC-IP */
			zebra_evpn_del_macip_for_intf(vlan_if, zevpn);

			/* Del VRR MAC-IP - if any*/
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zebra_evpn_del_macip_for_intf(vrr_if, zevpn);
		}
	}

stream_failure:
	return;
}

static int macfdb_read_ns(struct ns *ns,
			  void *_in_param __attribute__((unused)),
			  void **out_param __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;

	macfdb_read(zns);
	return NS_WALK_CONTINUE;
}

static int neigh_read_ns(struct ns *ns,
			 void *_in_param __attribute__((unused)),
			 void **out_param __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;

	neigh_read(zns);
	return NS_WALK_CONTINUE;
}

/*
 * Handle message from client to learn (or stop learning) about VNIs and MACs.
 * When enabled, the VNI hash table will be built and MAC FDB table read;
 * when disabled, the entries should be deleted and remote VTEPs and MACs
 * uninstalled from the kernel.
 * This also informs the setting for BUM handling at the time this change
 * occurs; it is relevant only when specifying "learn".
 */
void zebra_vxlan_advertise_all_vni(ZAPI_HANDLER_ARGS)
{
	struct stream *s = NULL;
	int advertise = 0;
	enum vxlan_flood_control flood_ctrl;

	/* Mismatch between EVPN VRF and current VRF (should be prevented by
	 * bgpd's cli) */
	if (is_evpn_enabled() && !EVPN_ENABLED(zvrf))
		return;

	s = msg;
	STREAM_GETC(s, advertise);
	STREAM_GETC(s, flood_ctrl);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("EVPN VRF %s(%u) VNI Adv %s, currently %s, flood control %u",
			   zvrf_name(zvrf), zvrf_id(zvrf),
			   advertise ? "enabled" : "disabled",
			   is_evpn_enabled() ? "enabled" : "disabled",
			   flood_ctrl);

	if (zvrf->advertise_all_vni == advertise)
		return;

	zvrf->advertise_all_vni = advertise;
	if (EVPN_ENABLED(zvrf)) {
		zrouter.evpn_vrf = zvrf;

		/* Note BUM handling */
		zvrf->vxlan_flood_ctrl = flood_ctrl;

		/* Replay all ESs */
		zebra_evpn_es_send_all_to_client(true /* add */);

		/* Build EVPN hash table and inform BGP. */
		zevpn_build_hash_table();

		/* Add all SVI (L3 GW) MACs to BGP*/
		hash_iterate(zvrf->evpn_table,
			     zebra_evpn_gw_macip_add_for_evpn_hash, NULL);

		/* Read the MAC FDB */
		ns_walk_func(macfdb_read_ns, NULL, NULL);

		/* Read neighbors */
		ns_walk_func(neigh_read_ns, NULL, NULL);
	} else {
		/* Cleanup VTEPs for all EVPNs - uninstall from
		 * kernel and free entries.
		 */
		hash_iterate(zvrf->evpn_table, zebra_evpn_vxlan_cleanup_all,
			     zvrf);

		/* Delete all ESs in BGP */
		zebra_evpn_es_send_all_to_client(false /* add */);

		/* cleanup all l3vnis */
		hash_iterate(zrouter.l3vni_table, zl3vni_cleanup_all, NULL);

		/* Mark as "no EVPN VRF" */
		zrouter.evpn_vrf = NULL;
	}

stream_failure:
	return;
}

/*
 * Allocate EVPN hash table for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_vxlan_init_tables(struct zebra_vrf *zvrf)
{
	char buffer[80];

	if (!zvrf)
		return;

	snprintf(buffer, sizeof(buffer), "Zebra VRF EVPN Table: %s",
		 zvrf->vrf->name);
	zvrf->evpn_table = hash_create_size(8, zebra_evpn_hash_keymake,
					    zebra_evpn_hash_cmp, buffer);

	snprintf(buffer, sizeof(buffer), "Zebra VxLAN SG Table: %s",
		 zvrf->vrf->name);
	zvrf->vxlan_sg_table = hash_create_size(8, zebra_vxlan_sg_hash_key_make,
						zebra_vxlan_sg_hash_eq, buffer);
}

/* Cleanup EVPN info, but don't free the table. */
void zebra_vxlan_cleanup_tables(struct zebra_vrf *zvrf)
{
	struct zebra_vrf *evpn_zvrf = zebra_vrf_get_evpn();

	hash_iterate(zvrf->evpn_table, zebra_evpn_vxlan_cleanup_all, zvrf);
	zebra_vxlan_cleanup_sg_table(zvrf);

	if (zvrf == evpn_zvrf)
		zebra_evpn_es_cleanup();
}

/* Close all EVPN handling */
void zebra_vxlan_close_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	hash_iterate(zvrf->evpn_table, zebra_evpn_vxlan_cleanup_all, zvrf);
	hash_free(zvrf->evpn_table);
	if (zvrf->vxlan_sg_table) {
		zebra_vxlan_cleanup_sg_table(zvrf);
		hash_free(zvrf->vxlan_sg_table);
		zvrf->vxlan_sg_table = NULL;
	}
}

/* init the l3vni table */
void zebra_vxlan_init(void)
{
	zrouter.l3vni_table = hash_create(l3vni_hash_keymake, l3vni_hash_cmp,
					  "Zebra VRF L3 VNI table");

	svd_nh_table = zebra_neigh_db_create("Zebra SVD next-hop table");

	zrouter.evpn_vrf = NULL;
	zebra_evpn_mh_init();
}

void zebra_vxlan_terminate(void)
{
	hash_clean_and_free(&svd_nh_table, svd_nh_del_terminate);
}

/* free l3vni table */
void zebra_vxlan_disable(void)
{
	hash_free(zrouter.l3vni_table);
	zebra_evpn_mh_terminate();
}

/* get the l3vni svi ifindex */
ifindex_t get_l3vni_svi_ifindex(vrf_id_t vrf_id)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return 0;

	return zl3vni->svi_if->ifindex;
}

/* get the l3vni vxlan ifindex */
ifindex_t get_l3vni_vxlan_ifindex(vrf_id_t vrf_id)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return 0;

	return zl3vni->vxlan_if->ifindex;
}

/* get the l3vni vni */
vni_t get_l3vni_vni(vrf_id_t vrf_id)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return 0;

	return zl3vni->vni;
}

/* is the vrf l3vni SVD backed? */
bool is_vrf_l3vni_svd_backed(vrf_id_t vrf_id)
{
	struct zebra_l3vni *zl3vni = NULL;

	zl3vni = zl3vni_from_vrf(vrf_id);
	if (!zl3vni || !is_l3vni_oper_up(zl3vni))
		return false;

	return IS_ZL3VNI_SVD_BACKED(zl3vni);
}

/************************** vxlan SG cache management ************************/
/* Inform PIM about the mcast group */
static int zebra_vxlan_sg_send(struct zebra_vrf *zvrf,
		struct prefix_sg *sg,
		char *sg_str, uint16_t cmd)
{
	struct zserv *client = NULL;
	struct stream *s = NULL;

	client = zserv_find_client(ZEBRA_ROUTE_PIM, 0);
	if (!client)
		return 0;

	if (!CHECK_FLAG(zvrf->flags, ZEBRA_PIM_SEND_VXLAN_SG))
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putl(s, IPV4_MAX_BYTELEN);
	stream_put(s, &sg->src.s_addr, IPV4_MAX_BYTELEN);
	stream_put(s, &sg->grp.s_addr, IPV4_MAX_BYTELEN);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Send %s %s to %s",
			(cmd == ZEBRA_VXLAN_SG_ADD) ? "add" : "del", sg_str,
			zebra_route_string(client->proto));

	if (cmd == ZEBRA_VXLAN_SG_ADD)
		client->vxlan_sg_add_cnt++;
	else
		client->vxlan_sg_del_cnt++;

	return zserv_send_message(client, s);
}

static unsigned int zebra_vxlan_sg_hash_key_make(const void *p)
{
	const struct zebra_vxlan_sg *vxlan_sg = p;

	return (jhash_2words(vxlan_sg->sg.src.s_addr,
				vxlan_sg->sg.grp.s_addr, 0));
}

static bool zebra_vxlan_sg_hash_eq(const void *p1, const void *p2)
{
	const struct zebra_vxlan_sg *sg1 = p1;
	const struct zebra_vxlan_sg *sg2 = p2;

	return ((sg1->sg.src.s_addr == sg2->sg.src.s_addr)
		&& (sg1->sg.grp.s_addr == sg2->sg.grp.s_addr));
}

static struct zebra_vxlan_sg *zebra_vxlan_sg_new(struct zebra_vrf *zvrf,
						 struct prefix_sg *sg)
{
	struct zebra_vxlan_sg *vxlan_sg;

	vxlan_sg = XCALLOC(MTYPE_ZVXLAN_SG, sizeof(*vxlan_sg));

	vxlan_sg->zvrf = zvrf;
	vxlan_sg->sg = *sg;
	prefix_sg2str(sg, vxlan_sg->sg_str);

	vxlan_sg = hash_get(zvrf->vxlan_sg_table, vxlan_sg, hash_alloc_intern);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s created", vxlan_sg->sg_str);

	return vxlan_sg;
}

static struct zebra_vxlan_sg *zebra_vxlan_sg_find(struct zebra_vrf *zvrf,
						  struct prefix_sg *sg)
{
	struct zebra_vxlan_sg lookup;

	lookup.sg = *sg;
	return hash_lookup(zvrf->vxlan_sg_table, &lookup);
}

static struct zebra_vxlan_sg *zebra_vxlan_sg_add(struct zebra_vrf *zvrf,
						 struct prefix_sg *sg)
{
	struct zebra_vxlan_sg *vxlan_sg;
	struct zebra_vxlan_sg *parent = NULL;
	struct in_addr sip;

	vxlan_sg = zebra_vxlan_sg_find(zvrf, sg);
	if (vxlan_sg)
		return vxlan_sg;

	/* create a *G entry for every BUM group implicitly -
	 * 1. The SG entry is used by pimd to setup the vxlan-origination-mroute
	 * 2. the XG entry is used by pimd to setup the
	 * vxlan-termination-mroute
	 */
	if (sg->src.s_addr != INADDR_ANY) {
		memset(&sip, 0, sizeof(sip));
		parent = zebra_vxlan_sg_do_ref(zvrf, sip, sg->grp);
		if (!parent)
			return NULL;
	}

	vxlan_sg = zebra_vxlan_sg_new(zvrf, sg);

	zebra_vxlan_sg_send(zvrf, sg, vxlan_sg->sg_str,
			ZEBRA_VXLAN_SG_ADD);

	return vxlan_sg;
}

static void zebra_vxlan_sg_del(struct zebra_vxlan_sg *vxlan_sg)
{
	struct in_addr sip;
	struct zebra_vrf *zvrf;

	zvrf = vrf_info_lookup(VRF_DEFAULT);

	/* On SG entry deletion remove the reference to its parent XG
	 * entry
	 */
	if (vxlan_sg->sg.src.s_addr != INADDR_ANY) {
		memset(&sip, 0, sizeof(sip));
		zebra_vxlan_sg_do_deref(zvrf, sip, vxlan_sg->sg.grp);
	}

	zebra_vxlan_sg_send(zvrf, &vxlan_sg->sg,
			vxlan_sg->sg_str, ZEBRA_VXLAN_SG_DEL);

	hash_release(vxlan_sg->zvrf->vxlan_sg_table, vxlan_sg);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("VXLAN SG %s deleted", vxlan_sg->sg_str);

	XFREE(MTYPE_ZVXLAN_SG, vxlan_sg);
}

static void zebra_vxlan_sg_do_deref(struct zebra_vrf *zvrf,
		struct in_addr sip, struct in_addr mcast_grp)
{
	struct zebra_vxlan_sg *vxlan_sg;
	struct prefix_sg sg;

	sg.family = AF_INET;
	sg.prefixlen = IPV4_MAX_BYTELEN;
	sg.src = sip;
	sg.grp = mcast_grp;
	vxlan_sg = zebra_vxlan_sg_find(zvrf, &sg);
	if (!vxlan_sg)
		return;

	if (vxlan_sg->ref_cnt)
		--vxlan_sg->ref_cnt;

	if (!vxlan_sg->ref_cnt)
		zebra_vxlan_sg_del(vxlan_sg);
}

static struct zebra_vxlan_sg *zebra_vxlan_sg_do_ref(struct zebra_vrf *zvrf,
						    struct in_addr sip,
						    struct in_addr mcast_grp)
{
	struct zebra_vxlan_sg *vxlan_sg;
	struct prefix_sg sg;

	sg.family = AF_INET;
	sg.prefixlen = IPV4_MAX_BYTELEN;
	sg.src = sip;
	sg.grp = mcast_grp;
	vxlan_sg = zebra_vxlan_sg_add(zvrf, &sg);
	if (vxlan_sg)
		++vxlan_sg->ref_cnt;

	return vxlan_sg;
}

void zebra_vxlan_sg_deref(struct in_addr local_vtep_ip,
			  struct in_addr mcast_grp)
{
	struct zebra_vrf *zvrf;

	if (local_vtep_ip.s_addr == INADDR_ANY
	    || mcast_grp.s_addr == INADDR_ANY)
		return;

	zvrf = vrf_info_lookup(VRF_DEFAULT);

	zebra_vxlan_sg_do_deref(zvrf, local_vtep_ip, mcast_grp);
}

void zebra_vxlan_sg_ref(struct in_addr local_vtep_ip, struct in_addr mcast_grp)
{
	struct zebra_vrf *zvrf;

	if (local_vtep_ip.s_addr == INADDR_ANY
	    || mcast_grp.s_addr == INADDR_ANY)
		return;

	zvrf = vrf_info_lookup(VRF_DEFAULT);

	zebra_vxlan_sg_do_ref(zvrf, local_vtep_ip, mcast_grp);
}

static void zebra_vxlan_xg_pre_cleanup(struct hash_bucket *bucket, void *arg)
{
	struct zebra_vxlan_sg *vxlan_sg = (struct zebra_vxlan_sg *)bucket->data;

	/* increment the ref count against (*,G) to prevent them from being
	 * deleted
	 */
	if (vxlan_sg->sg.src.s_addr == INADDR_ANY)
		++vxlan_sg->ref_cnt;
}

static void zebra_vxlan_xg_post_cleanup(struct hash_bucket *bucket, void *arg)
{
	struct zebra_vxlan_sg *vxlan_sg = (struct zebra_vxlan_sg *)bucket->data;

	/* decrement the dummy ref count against (*,G) to delete them */
	if (vxlan_sg->sg.src.s_addr == INADDR_ANY) {
		if (vxlan_sg->ref_cnt)
			--vxlan_sg->ref_cnt;
		if (!vxlan_sg->ref_cnt)
			zebra_vxlan_sg_del(vxlan_sg);
	}
}

static void zebra_vxlan_sg_cleanup(struct hash_bucket *bucket, void *arg)
{
	struct zebra_vxlan_sg *vxlan_sg = (struct zebra_vxlan_sg *)bucket->data;

	zebra_vxlan_sg_del(vxlan_sg);
}

static void zebra_vxlan_cleanup_sg_table(struct zebra_vrf *zvrf)
{
	/* increment the ref count against (*,G) to prevent them from being
	 * deleted
	 */
	hash_iterate(zvrf->vxlan_sg_table, zebra_vxlan_xg_pre_cleanup, NULL);

	hash_iterate(zvrf->vxlan_sg_table, zebra_vxlan_sg_cleanup, NULL);

	/* decrement the dummy ref count against the XG entries */
	hash_iterate(zvrf->vxlan_sg_table, zebra_vxlan_xg_post_cleanup, NULL);
}

static void zebra_vxlan_sg_replay_send(struct hash_bucket *bucket, void *arg)
{
	struct zebra_vxlan_sg *vxlan_sg = (struct zebra_vxlan_sg *)bucket->data;

	zebra_vxlan_sg_send(vxlan_sg->zvrf, &vxlan_sg->sg,
			vxlan_sg->sg_str, ZEBRA_VXLAN_SG_ADD);
}

/* Handle message from client to replay vxlan SG entries */
void zebra_vxlan_sg_replay(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("VxLAN SG updates to PIM, start");

	SET_FLAG(zvrf->flags, ZEBRA_PIM_SEND_VXLAN_SG);

	if (!EVPN_ENABLED(zvrf)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VxLAN SG replay request on unexpected vrf %d",
				   zvrf->vrf->vrf_id);
		return;
	}

	hash_iterate(zvrf->vxlan_sg_table, zebra_vxlan_sg_replay_send, NULL);
}


/* Cleanup EVPN configuration of a specific VRF */
static void zebra_evpn_vrf_cfg_cleanup(struct zebra_vrf *zvrf)
{
	struct zebra_l3vni *zl3vni = NULL;

	zvrf->advertise_all_vni = 0;
	zvrf->advertise_gw_macip = 0;
	zvrf->advertise_svi_macip = 0;
	zvrf->vxlan_flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	hash_iterate(zvrf->evpn_table, zebra_evpn_cfg_cleanup, NULL);

	if (zvrf->l3vni)
		zl3vni = zl3vni_lookup(zvrf->l3vni);
	if (zl3vni) {
		/* delete and uninstall all rmacs */
		hash_iterate(zl3vni->rmac_table, zl3vni_del_rmac_hash_entry,
			     zl3vni);
		/* delete and uninstall all next-hops */
		hash_iterate(zl3vni->nh_table, zl3vni_del_nh_hash_entry,
			     zl3vni);
	}
}

/* Cleanup BGP EVPN configuration upon client disconnect */
static int zebra_evpn_bgp_cfg_clean_up(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (zvrf)
			zebra_evpn_vrf_cfg_cleanup(zvrf);
	}

	return 0;
}

static int zebra_evpn_pim_cfg_clean_up(struct zserv *client)
{
	struct zebra_vrf *zvrf = zebra_vrf_get_evpn();

	if (CHECK_FLAG(zvrf->flags, ZEBRA_PIM_SEND_VXLAN_SG)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VxLAN SG updates to PIM, stop");
		UNSET_FLAG(zvrf->flags, ZEBRA_PIM_SEND_VXLAN_SG);
	}

	return 0;
}

static int zebra_evpn_cfg_clean_up(struct zserv *client)
{
	if (client->proto == ZEBRA_ROUTE_BGP)
		return zebra_evpn_bgp_cfg_clean_up(client);

	if (client->proto == ZEBRA_ROUTE_PIM)
		return zebra_evpn_pim_cfg_clean_up(client);

	return 0;
}

/*
 * Handle results for vxlan dataplane operations.
 */
extern void zebra_vxlan_handle_result(struct zebra_dplane_ctx *ctx)
{
	return;
}

/* Config knob for accepting lower sequence numbers */
void zebra_vxlan_set_accept_bgp_seq(bool set)
{
	accept_bgp_seq = set;
}

bool zebra_vxlan_get_accept_bgp_seq(void)
{
	return accept_bgp_seq;
}

/* Cleanup BGP EVPN configuration upon client disconnect */
extern void zebra_evpn_init(void)
{
	hook_register(zserv_client_close, zebra_evpn_cfg_clean_up);
}
