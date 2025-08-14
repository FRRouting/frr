// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra neighbor table management
 *
 * Copyright (C) 2021 Nvidia
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

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_errors.h"
#include "zebra/interface.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zapi_msg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_INFO, "Zebra neigh table");
DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_ENT, "Zebra neigh entry");

#define ZEBRA_NUD_VALID	      0xDE
#define ZEBRA_NUD_FAILED      0x20
#define ZEBRA_NUD_PERMANENT   0x80
#define ZEBRA_NTF_EXT_LEARNED 0x10

static const char ipv4_ll_buf[16] = "169.254.0.1";
static void zebra_neigh_macfdb_update(struct zebra_dplane_ctx *ctx);
static void zebra_neigh_ipaddr_update(struct zebra_dplane_ctx *ctx);

static int zebra_neigh_rb_cmp(const struct zebra_neigh_ent *n1,
			      const struct zebra_neigh_ent *n2)
{
	if (n1->ifindex < n2->ifindex)
		return -1;

	if (n1->ifindex > n2->ifindex)
		return 1;

	if (n1->ip.ipa_type < n2->ip.ipa_type)
		return -1;

	if (n1->ip.ipa_type > n2->ip.ipa_type)
		return 1;

	if (n1->ip.ipa_type == AF_INET) {
		if (n1->ip.ipaddr_v4.s_addr < n2->ip.ipaddr_v4.s_addr)
			return -1;

		if (n1->ip.ipaddr_v4.s_addr > n2->ip.ipaddr_v4.s_addr)
			return 1;

		return 0;
	}

	return memcmp(&n1->ip.ipaddr_v6, &n2->ip.ipaddr_v6, IPV6_MAX_BYTELEN);
}
RB_GENERATE(zebra_neigh_rb_head, zebra_neigh_ent, rb_node, zebra_neigh_rb_cmp);

static struct zebra_neigh_ent *zebra_neigh_find(ifindex_t ifindex,
						struct ipaddr *ip)
{
	struct zebra_neigh_ent tmp;

	tmp.ifindex = ifindex;
	memcpy(&tmp.ip, ip, sizeof(*ip));
	return RB_FIND(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, &tmp);
}

static struct zebra_neigh_ent *
zebra_neigh_new(ifindex_t ifindex, struct ipaddr *ip, struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	n = XCALLOC(MTYPE_ZNEIGH_ENT, sizeof(struct zebra_neigh_ent));

	memcpy(&n->ip, ip, sizeof(*ip));
	n->ifindex = ifindex;
	if (mac) {
		memcpy(&n->mac, mac, sizeof(*mac));
		SET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);
	}

	/* Add to rb_tree */
	if (RB_INSERT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n)) {
		XFREE(MTYPE_ZNEIGH_ENT, n);
		return NULL;
	}

	/* Initialise the pbr rule list */
	n->pbr_rule_list = list_new();
	listset_app_node_mem(n->pbr_rule_list);

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh new if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	return n;
}

static void zebra_neigh_pbr_rules_update(struct zebra_neigh_ent *n)
{
	struct zebra_pbr_rule *rule;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(n->pbr_rule_list, node, rule))
		dplane_pbr_rule_update(rule, rule);
}

static void zebra_neigh_free(struct zebra_neigh_ent *n)
{
	if (listcount(n->pbr_rule_list)) {
		/* if rules are still using the neigh mark it as inactive and
		 * update the dataplane
		 */
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);
		memset(&n->mac, 0, sizeof(n->mac));
		zebra_neigh_pbr_rules_update(n);
		return;
	}
	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh free if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	/* cleanup resources maintained against the neigh */
	list_delete(&n->pbr_rule_list);

	RB_REMOVE(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n);

	XFREE(MTYPE_ZNEIGH_ENT, n);
}

/* kernel neigh del */
void zebra_neigh_del(struct interface *ifp, struct ipaddr *ip)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh del if %s/%d %pIA", ifp->name,
			   ifp->ifindex, ip);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (!n)
		return;
	zebra_neigh_free(n);
}

/* kernel neigh delete all for a given interface */
void zebra_neigh_del_all(struct interface *ifp)
{
	struct zebra_neigh_ent *n, *next;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh delete all for interface %s/%d",
			   ifp->name, ifp->ifindex);

	RB_FOREACH_SAFE (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, next) {
		if (n->ifindex == ifp->ifindex) {
			/* Free the neighbor directly instead of looking it up again */
			zebra_neigh_free(n);
		}
	}
}

/* kernel neigh add */
void zebra_neigh_add(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh add if %s/%d %pIA %pEA", ifp->name,
			   ifp->ifindex, ip, mac);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (n) {
		if (!memcmp(&n->mac, mac, sizeof(*mac)))
			return;

		memcpy(&n->mac, mac, sizeof(*mac));
		SET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);

		/* update rules linked to the neigh */
		zebra_neigh_pbr_rules_update(n);
	} else {
		zebra_neigh_new(ifp->ifindex, ip, mac);
	}
}

void zebra_neigh_deref(struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n = rule->action.neigh;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh deref if %d %pIA by pbr rule %u",
			   n->ifindex, &n->ip, rule->rule.seq);

	rule->action.neigh = NULL;
	/* remove rule from the list and free if it is inactive */
	list_delete_node(n->pbr_rule_list, &rule->action.neigh_listnode);
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE))
		zebra_neigh_free(n);
}

/* XXX - this needs to work with evpn's neigh read */
static void zebra_neigh_read_on_first_ref(void)
{
	static bool neigh_read_done;

	if (!neigh_read_done) {
		neigh_read(zebra_ns_lookup(NS_DEFAULT));
		neigh_read_done = true;
	}
}

void zebra_neigh_ref(int ifindex, struct ipaddr *ip,
		     struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh ref if %d %pIA by pbr rule %u", ifindex,
			   ip, rule->rule.seq);

	zebra_neigh_read_on_first_ref();
	n = zebra_neigh_find(ifindex, ip);
	if (!n)
		n = zebra_neigh_new(ifindex, ip, NULL);

	/* link the pbr entry to the neigh */
	if (rule->action.neigh == n)
		return;

	if (rule->action.neigh)
		zebra_neigh_deref(rule);

	rule->action.neigh = n;
	listnode_init(&rule->action.neigh_listnode, rule);
	listnode_add(n->pbr_rule_list, &rule->action.neigh_listnode);
}

static void zebra_neigh_show_one(struct vty *vty, struct zebra_neigh_ent *n)
{
	char mac_buf[ETHER_ADDR_STRLEN];
	char ip_buf[INET6_ADDRSTRLEN];
	struct interface *ifp;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					n->ifindex);
	ipaddr2str(&n->ip, ip_buf, sizeof(ip_buf));
	prefix_mac2str(&n->mac, mac_buf, sizeof(mac_buf));
	vty_out(vty, "%-20s %-30s %-18s %u\n", ifp ? ifp->name : "-", ip_buf,
		mac_buf, listcount(n->pbr_rule_list));
}

void zebra_neigh_show(struct vty *vty)
{
	struct zebra_neigh_ent *n;

	vty_out(vty, "%-20s %-30s %-18s %s\n", "Interface", "Neighbor", "MAC",
		"#Rules");
	RB_FOREACH (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree)
		zebra_neigh_show_one(vty, n);
}

void zebra_neigh_init(void)
{
	zneigh_info = XCALLOC(MTYPE_ZNEIGH_INFO, sizeof(*zrouter.neigh_info));
	RB_INIT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree);
}

void zebra_neigh_terminate(void)
{
	struct zebra_neigh_ent *n, *next;

	if (!zrouter.neigh_info)
		return;

	RB_FOREACH_SAFE (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree,
			 next)
		zebra_neigh_free(n);
	XFREE(MTYPE_ZNEIGH_INFO, zneigh_info);
}

/*
 * In the event the kernel deletes ipv4 link-local neighbor entries created for
 * 5549 support, re-install them.
 */
static void zebra_neigh_handle_5549(uint32_t ndm_family, uint32_t ndm_state, struct zebra_if *zif,
				    struct interface *ifp, struct ipaddr *ip, bool handle_failed)
{
	if (ndm_family != AF_INET)
		return;

	if (!zif->v6_2_v4_ll_neigh_entry)
		return;

	struct in_addr ipv4_ll;

	inet_pton(AF_INET, ipv4_ll_buf, &ipv4_ll);

	if (ipv4_ll.s_addr != ip->ip._v4_addr.s_addr)
		return;

	if (handle_failed && ndm_state & ZEBRA_NUD_FAILED) {
		zlog_info("Neighbor Entry for %s has entered a failed state, not reinstalling",
			  ifp->name);
		return;
	}

	if_nbr_ipv6ll_to_ipv4ll_neigh_update(ifp, &zif->v6_2_v4_ll_addr6, true);
}

/* Is vni mcast group */
static bool is_mac_vni_mcast_group(struct ethaddr *mac, vni_t vni, struct in_addr grp_addr)
{
	if (!vni)
		return false;

	if (!is_zero_mac(mac))
		return false;

	if (!IN_MULTICAST(ntohl(grp_addr.s_addr)))
		return false;

	return true;
}

static int zebra_nbr_entry_state_to_zclient(int nbr_state)
{
	/* an exact match is done between
	 * - zebra neighbor state values: NDM_XXX (see in linux/neighbour.h)
	 * - zclient neighbor state values: ZEBRA_NEIGH_STATE_XXX
	 *  (see in lib/zclient.h)
	 */
	return nbr_state;
}

void zebra_neigh_dplane_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_NEIGH_IP_DELETE || op == DPLANE_OP_NEIGH_IP_INSTALL ||
	    op == DPLANE_OP_NEIGH_DISCOVER) {
		zebra_neigh_ipaddr_update(ctx);
	} else if (op == DPLANE_OP_NEIGH_INSTALL || op == DPLANE_OP_NEIGH_DELETE ||
		   op == DPLANE_OP_NEIGH_UPDATE) {
		zebra_neigh_macfdb_update(ctx);
	}
}

static void zebra_neigh_ipaddr_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	struct ipaddr ip;
	ns_id_t ns_id;
	int32_t ndm_ifindex;
	struct interface *ifp;
	struct zebra_if *zif;
	uint16_t ndm_state;
	uint32_t ndm_family;
	int l2_len;
	union sockunion link_layer_ipv4;
	struct interface *link_if;
	struct ethaddr mac;
	bool is_ext;
	bool is_router;
	bool local_inactive;
	bool dp_static;
	int cmd = -1;

	op = dplane_ctx_get_op(ctx);
	ip = *dplane_ctx_neigh_get_ipaddr(ctx);
	ns_id = dplane_ctx_get_ns_id(ctx);
	ndm_ifindex = dplane_ctx_get_ifindex(ctx);

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm_ifindex);
	if (!ifp || !ifp->info)
		return;

	zif = (struct zebra_if *)ifp->info;

	ndm_state = dplane_ctx_neigh_get_ndm_state(ctx);
	ndm_family = dplane_ctx_neigh_get_ndm_family(ctx);

	/* if kernel deletes our rfc5549 neighbor entry, re-install it */
	if (op == DPLANE_OP_NEIGH_IP_DELETE && (ndm_state & ZEBRA_NUD_PERMANENT)) {
		zebra_neigh_handle_5549(ndm_family, ndm_state, zif, ifp, &ip, false);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("    Neighbor Entry received is a 5549 entry, finished");
		return;
	}

	/* if kernel marks our rfc5549 neighbor entry invalid, re-install it */
	if (op == DPLANE_OP_NEIGH_IP_INSTALL && !(ndm_state & ZEBRA_NUD_VALID))
		zebra_neigh_handle_5549(ndm_family, ndm_state, zif, ifp, &ip, true);

	if (op == DPLANE_OP_NEIGH_IP_INSTALL)
		cmd = ZEBRA_NEIGH_ADDED;
	else if (op == DPLANE_OP_NEIGH_IP_DELETE)
		cmd = ZEBRA_NEIGH_REMOVED;
	else if (op == DPLANE_OP_NEIGH_DISCOVER)
		cmd = ZEBRA_NEIGH_GET;
	else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry received is not a Neighbor IP ADD/DELETE/DISCOVER event, ignoring.");
		return;
	}

	l2_len = dplane_ctx_neigh_get_l2_len(ctx);
	link_layer_ipv4 = dplane_ctx_neigh_get_link_layer_ipv4(ctx);

	zsend_neighbor_notify(cmd, ifp, &ip, zebra_nbr_entry_state_to_zclient(ndm_state),
			      &link_layer_ipv4, l2_len);

	if (op == DPLANE_OP_NEIGH_DISCOVER)
		return;

	/* The neighbor is present on an SVI. From this, we locate the
	 * underlying
	 * bridge because we're only interested in neighbors on a VxLAN bridge.
	 * The bridge is located based on the nature of the SVI:
	 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN
	 * interface
	 * and is linked to the bridge
	 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge
	 * interface
	 * itself
	 */
	if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), zif->link_ifindex);
		if (!link_if)
			return;
	} else if (IS_ZEBRA_IF_BRIDGE(ifp))
		link_if = ifp;
	else {
		link_if = NULL;
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry received is not on a VLAN or a BRIDGE, ignoring");
	}

	if (op == DPLANE_OP_NEIGH_IP_INSTALL) {
		mac = *dplane_ctx_neigh_get_mac(ctx);
		is_ext = dplane_ctx_neigh_get_is_ext(ctx);
		is_router = dplane_ctx_neigh_get_is_router(ctx);
		local_inactive = dplane_ctx_neigh_get_local_inactive(ctx);
		dp_static = dplane_ctx_neigh_get_dp_static(ctx);

		/* If the neighbor state is valid for use, process as an add or
		 * update
		 * else process as a delete. Note that the delete handling may
		 * result
		 * in re-adding the neighbor if it is a valid "remote" neighbor.
		 */
		if (ndm_state & ZEBRA_NUD_VALID) {
			/* Add local neighbors to the l3 interface database */
			if (is_ext)
				zebra_neigh_del(ifp, &ip);
			else
				zebra_neigh_add(ifp, &ip, &mac);

			if (link_if)
				zebra_vxlan_handle_kernel_neigh_update(ifp, link_if, &ip, &mac,
								       ndm_state, is_ext, is_router,
								       local_inactive, dp_static);
			return;
		}

		zebra_neigh_del(ifp, &ip);
		if (link_if)
			zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
		return;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s family %s IF %s(%u) vrf %s(%u) IP %pIA", dplane_op2str(op),
			   family2str(ndm_family), ifp->name, ndm_ifindex, ifp->vrf->name,
			   ifp->vrf->vrf_id, &ip);

	/* Process the delete - it may result in re-adding the neighbor if it is
	 * a valid "remote" neighbor.
	 */
	zebra_neigh_del(ifp, &ip);
	if (link_if)
		zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
}

static void zebra_neigh_macfdb_update(struct zebra_dplane_ctx *ctx)
{
	ns_id_t ns_id;
	ifindex_t ndm_ifindex;
	struct interface *ifp;
	bool vni_mcast_grp;
	struct zebra_if *zif;
	struct interface *br_if;
	enum dplane_op_e op;
	ifindex_t vni;
	struct zebra_vxlan_vni *vnip;
	struct ethaddr mac;
	struct in_addr vtep_ip;
	bool sticky;
	bool local_inactive;
	bool dp_static;
	uint32_t vid;
	uint32_t nhg_id;
	int dst_present;
	uint16_t ndm_state;
	uint8_t ndm_flags;

	/* We only process macfdb notifications if EVPN is enabled */
	if (!is_evpn_enabled())
		return;

	ns_id = dplane_ctx_get_ns_id(ctx);
	ndm_ifindex = dplane_ctx_get_ifindex(ctx);

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm_ifindex);
	if (!ifp || !ifp->info)
		return;

	/* The interface should be something we're interested in. */
	if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
		return;

	op = dplane_ctx_get_op(ctx);
	zif = (struct zebra_if *)ifp->info;
	br_if = zif->brslave_info.br_if;

	if (br_if == NULL) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s AF_BRIDGE IF %s(%u) brIF %u - no bridge master",
				   dplane_op2str(op), ifp->name, ndm_ifindex,
				   zif->brslave_info.bridge_ifindex);
		return;
	}

	vni = dplane_ctx_mac_get_vni(ctx);

	/* For per vni device, vni comes from device itself */
	if (IS_ZEBRA_IF_VXLAN(ifp) && IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vnip = zebra_vxlan_if_vni_find(zif, 0);
		vni = vnip->vni;
	}

	mac = *dplane_ctx_mac_get_addr(ctx);
	vtep_ip = *dplane_ctx_mac_get_vtep_ip(ctx);

	/* Check if this is a mcast group update (svd case) */
	vni_mcast_grp = is_mac_vni_mcast_group(&mac, vni, vtep_ip);

	sticky = dplane_ctx_mac_is_sticky(ctx);
	local_inactive = dplane_ctx_mac_get_local_inactive(ctx);
	dp_static = dplane_ctx_mac_get_dp_static(ctx);
	vid = dplane_ctx_mac_get_vlan(ctx);
	nhg_id = dplane_ctx_mac_get_nhg_id(ctx);
	dst_present = dplane_ctx_mac_get_dst_present(ctx);
	ndm_state = dplane_ctx_mac_get_ndm_state(ctx);
	ndm_flags = dplane_ctx_mac_get_ndm_flags(ctx);

	/* If add or update, do accordingly if learnt on a "local" interface; if
	 * the notification is over VxLAN, this has to be related to
	 * multi-homing,
	 * so perform an implicit delete of any local entry (if it exists).
	 */
	if (op == DPLANE_OP_NEIGH_INSTALL) {
		/* Drop "permanent" entries. */
		if (!vni_mcast_grp && (ndm_state & ZEBRA_NUD_PERMANENT)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("        Dropping entry because of ZEBRA_NUD_PERMANENT");
			return;
		}

		if (IS_ZEBRA_IF_VXLAN(ifp)) {
			if (!dst_present)
				return;

			if (vni_mcast_grp) {
				zebra_vxlan_if_vni_mcast_group_add_update(ifp, vni, &vtep_ip);
				return;
			}

			zebra_vxlan_dp_network_mac_add(ifp, br_if, &mac, vid, vni, nhg_id, sticky,
						       !!(ndm_flags & ZEBRA_NTF_EXT_LEARNED));
			return;
		}

		zebra_vxlan_local_mac_add_update(ifp, br_if, &mac, vid, sticky, local_inactive,
						 dp_static);
		return;
	}

	/* This is a delete notification.
	 * Ignore the notification with IP dest as it may just signify that the
	 * MAC has moved from remote to local. The exception is the special
	 * all-zeros MAC that represents the BUM flooding entry; we may have
	 * to readd it. Otherwise,
	 *  1. For a MAC over VxLan, check if it needs to be refreshed(readded)
	 *  2. For a MAC over "local" interface, delete the mac
	 * Note: We will get notifications from both bridge driver and VxLAN
	 * driver.
	 */
	if (nhg_id)
		return;

	if (dst_present) {
		if (vni_mcast_grp) {
			zebra_vxlan_if_vni_mcast_group_del(ifp, vni, &vtep_ip);
			return;
		}

		if (is_zero_mac(&mac) && vni) {
			zebra_vxlan_check_readd_vtep(ifp, vni, vtep_ip);
			return;
		}
		return;
	}

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return;

	zebra_vxlan_local_mac_del(ifp, br_if, &mac, vid);
}
