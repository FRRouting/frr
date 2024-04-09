// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "command.h"
#include "frrevent.h"
#include "prefix.h"
#include "lib/json.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "hash.h"
#include "jhash.h"
#include "nexthop.h"
#include "queue.h"
#include "filter.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_mplsvpn.h"

DEFINE_MTYPE_STATIC(BGPD, MARTIAN_STRING, "BGP Martian Addr Intf String");

int bgp_nexthop_cache_compare(const struct bgp_nexthop_cache *a,
			      const struct bgp_nexthop_cache *b)
{
	if (a->srte_color < b->srte_color)
		return -1;
	if (a->srte_color > b->srte_color)
		return 1;

	if (a->ifindex_ipv6_ll < b->ifindex_ipv6_ll)
		return -1;
	if (a->ifindex_ipv6_ll > b->ifindex_ipv6_ll)
		return 1;

	return prefix_cmp(&a->prefix, &b->prefix);
}

void bnc_nexthop_free(struct bgp_nexthop_cache *bnc)
{
	nexthops_free(bnc->nexthop);
}

struct bgp_nexthop_cache *bnc_new(struct bgp_nexthop_cache_head *tree,
				  struct prefix *prefix, uint32_t srte_color,
				  ifindex_t ifindex)
{
	struct bgp_nexthop_cache *bnc;

	bnc = XCALLOC(MTYPE_BGP_NEXTHOP_CACHE,
		      sizeof(struct bgp_nexthop_cache));
	bnc->prefix = *prefix;
	bnc->ifindex_ipv6_ll = ifindex;
	bnc->srte_color = srte_color;
	bnc->tree = tree;
	LIST_INIT(&(bnc->paths));
	bgp_nexthop_cache_add(tree, bnc);

	return bnc;
}

bool bnc_existing_for_prefix(struct bgp_nexthop_cache *bnc)
{
	struct bgp_nexthop_cache *bnc_tmp;

	frr_each (bgp_nexthop_cache, bnc->tree, bnc_tmp) {
		if (bnc_tmp == bnc)
			continue;
		if (prefix_cmp(&bnc->prefix, &bnc_tmp->prefix) == 0)
			return true;
	}
	return false;
}

void bnc_free(struct bgp_nexthop_cache *bnc)
{
	bnc_nexthop_free(bnc);
	bgp_nexthop_cache_del(bnc->tree, bnc);
	XFREE(MTYPE_BGP_NEXTHOP_CACHE, bnc);
}

struct bgp_nexthop_cache *bnc_find(struct bgp_nexthop_cache_head *tree,
				   struct prefix *prefix, uint32_t srte_color,
				   ifindex_t ifindex)
{
	struct bgp_nexthop_cache bnc = {};

	if (!tree)
		return NULL;

	bnc.prefix = *prefix;
	bnc.srte_color = srte_color;
	bnc.ifindex_ipv6_ll = ifindex;
	return bgp_nexthop_cache_find(tree, &bnc);
}

/* Reset and free all BGP nexthop cache. */
static void bgp_nexthop_cache_reset(struct bgp_nexthop_cache_head *tree)
{
	struct bgp_nexthop_cache *bnc;

	while (bgp_nexthop_cache_count(tree) > 0) {
		bnc = bgp_nexthop_cache_first(tree);

		while (!LIST_EMPTY(&(bnc->paths))) {
			struct bgp_path_info *path = LIST_FIRST(&(bnc->paths));

			bgp_mplsvpn_path_nh_label_unlink(path);
			bgp_mplsvpn_path_nh_label_bind_unlink(path);

			path_nh_map(path, bnc, false);
		}

		bnc_free(bnc);
	}
}

static void *bgp_tip_hash_alloc(void *p)
{
	const struct in_addr *val = (const struct in_addr *)p;
	struct tip_addr *addr;

	addr = XMALLOC(MTYPE_TIP_ADDR, sizeof(struct tip_addr));
	addr->refcnt = 0;
	addr->addr.s_addr = val->s_addr;

	return addr;
}

static void bgp_tip_hash_free(void *addr)
{
	XFREE(MTYPE_TIP_ADDR, addr);
}

static unsigned int bgp_tip_hash_key_make(const void *p)
{
	const struct tip_addr *addr = p;

	return jhash_1word(addr->addr.s_addr, 0);
}

static bool bgp_tip_hash_cmp(const void *p1, const void *p2)
{
	const struct tip_addr *addr1 = p1;
	const struct tip_addr *addr2 = p2;

	return addr1->addr.s_addr == addr2->addr.s_addr;
}

void bgp_tip_hash_init(struct bgp *bgp)
{
	bgp->tip_hash = hash_create(bgp_tip_hash_key_make, bgp_tip_hash_cmp,
				    "BGP TIP hash");
}

void bgp_tip_hash_destroy(struct bgp *bgp)
{
	hash_clean_and_free(&bgp->tip_hash, bgp_tip_hash_free);
}

/* Add/Update Tunnel-IP entry of bgp martian next-hop table.
 *
 * Returns true only if we add a _new_ TIP so the caller knows that an
 * actionable change has occurred. If we find an existing TIP then we
 * only need to update the refcnt, since the collection of known TIPs
 * has not changed.
 */
bool bgp_tip_add(struct bgp *bgp, struct in_addr *tip)
{
	struct tip_addr tmp;
	struct tip_addr *addr;
	bool tip_added = false;

	tmp.addr = *tip;

	addr = hash_lookup(bgp->tip_hash, &tmp);
	if (!addr) {
		addr = hash_get(bgp->tip_hash, &tmp, bgp_tip_hash_alloc);
		tip_added = true;
	}

	addr->refcnt++;

	return tip_added;
}

void bgp_tip_del(struct bgp *bgp, struct in_addr *tip)
{
	struct tip_addr tmp;
	struct tip_addr *addr;

	tmp.addr = *tip;

	addr = hash_lookup(bgp->tip_hash, &tmp);
	/* may have been deleted earlier by bgp_interface_down() */
	if (addr == NULL)
		return;

	addr->refcnt--;

	if (addr->refcnt == 0) {
		hash_release(bgp->tip_hash, addr);
		XFREE(MTYPE_TIP_ADDR, addr);
	}
}

/* BGP own address structure */
struct bgp_addr {
	struct prefix p;
	struct list *ifp_name_list;
};

static void show_address_entry(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct bgp_addr *addr = (struct bgp_addr *)bucket->data;
	char *name;
	struct listnode *node;
	char str[INET6_ADDRSTRLEN] = {0};

	vty_out(vty, "addr: %s, count: %d : ",
		inet_ntop(addr->p.family, &(addr->p.u.prefix),
			  str, INET6_ADDRSTRLEN),
		addr->ifp_name_list->count);

	for (ALL_LIST_ELEMENTS_RO(addr->ifp_name_list, node, name)) {
		vty_out(vty, " %s,", name);
	}

	vty_out(vty, "\n");
}

void bgp_nexthop_show_address_hash(struct vty *vty, struct bgp *bgp)
{
	hash_iterate(bgp->address_hash,
		     (void (*)(struct hash_bucket *, void *))show_address_entry,
		     vty);
}

static void bgp_address_hash_string_del(void *val)
{
	char *data = val;

	XFREE(MTYPE_MARTIAN_STRING, data);
}

static void *bgp_address_hash_alloc(void *p)
{
	struct bgp_addr *copy_addr = p;
	struct bgp_addr *addr = NULL;

	addr = XMALLOC(MTYPE_BGP_ADDR, sizeof(struct bgp_addr));
	prefix_copy(&addr->p, &copy_addr->p);

	addr->ifp_name_list = list_new();
	addr->ifp_name_list->del = bgp_address_hash_string_del;

	return addr;
}

static void bgp_address_hash_free(void *data)
{
	struct bgp_addr *addr = data;

	list_delete(&addr->ifp_name_list);
	XFREE(MTYPE_BGP_ADDR, addr);
}

static unsigned int bgp_address_hash_key_make(const void *p)
{
	const struct bgp_addr *addr = p;

	return prefix_hash_key(&addr->p);
}

static bool bgp_address_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_addr *addr1 = p1;
	const struct bgp_addr *addr2 = p2;

	return prefix_same(&addr1->p, &addr2->p);
}

void bgp_address_init(struct bgp *bgp)
{
	bgp->address_hash =
		hash_create(bgp_address_hash_key_make, bgp_address_hash_cmp,
				"BGP Connected Address Hash");
}

void bgp_address_destroy(struct bgp *bgp)
{
	hash_clean_and_free(&bgp->address_hash, bgp_address_hash_free);
}

static void bgp_address_add(struct bgp *bgp, struct connected *ifc,
			    struct prefix *p)
{
	struct bgp_addr tmp;
	struct bgp_addr *addr;
	struct listnode *node;
	char *name;

	tmp.p = *p;

	if (tmp.p.family == AF_INET)
		tmp.p.prefixlen = IPV4_MAX_BITLEN;
	else if (tmp.p.family == AF_INET6)
		tmp.p.prefixlen = IPV6_MAX_BITLEN;

	addr = hash_get(bgp->address_hash, &tmp, bgp_address_hash_alloc);

	for (ALL_LIST_ELEMENTS_RO(addr->ifp_name_list, node, name)) {
		if (strcmp(ifc->ifp->name, name) == 0)
			break;
	}
	if (!node) {
		name = XSTRDUP(MTYPE_MARTIAN_STRING, ifc->ifp->name);
		listnode_add(addr->ifp_name_list, name);
	}
}

static void bgp_address_del(struct bgp *bgp, struct connected *ifc,
			    struct prefix *p)
{
	struct bgp_addr tmp;
	struct bgp_addr *addr;
	struct listnode *node;
	char *name;

	tmp.p = *p;

	if (tmp.p.family == AF_INET)
		tmp.p.prefixlen = IPV4_MAX_BITLEN;
	else if (tmp.p.family == AF_INET6)
		tmp.p.prefixlen = IPV6_MAX_BITLEN;

	addr = hash_lookup(bgp->address_hash, &tmp);
	/* may have been deleted earlier by bgp_interface_down() */
	if (addr == NULL)
		return;

	for (ALL_LIST_ELEMENTS_RO(addr->ifp_name_list, node, name)) {
		if (strcmp(ifc->ifp->name, name) == 0)
			break;
	}

	if (node) {
		list_delete_node(addr->ifp_name_list, node);
		XFREE(MTYPE_MARTIAN_STRING, name);
	}

	if (addr->ifp_name_list->count == 0) {
		hash_release(bgp->address_hash, addr);
		list_delete(&addr->ifp_name_list);
		XFREE(MTYPE_BGP_ADDR, addr);
	}
}


struct bgp_connected_ref {
	unsigned int refcnt;
};

void bgp_connected_add(struct bgp *bgp, struct connected *ifc)
{
	struct prefix p;
	struct prefix *addr;
	struct bgp_dest *dest;
	struct bgp_connected_ref *bc;
	struct listnode *node, *nnode;
	struct peer *peer;
	struct peer_connection *connection;

	addr = ifc->address;

	p = *(CONNECTED_PREFIX(ifc));
	if (addr->family == AF_INET) {
		apply_mask_ipv4((struct prefix_ipv4 *)&p);

		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;

		bgp_address_add(bgp, ifc, addr);

		dest = bgp_node_get(bgp->connected_table[AFI_IP], &p);
		bc = bgp_dest_get_bgp_connected_ref_info(dest);
		if (bc)
			bc->refcnt++;
		else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			bgp_dest_set_bgp_connected_ref_info(dest, bc);
		}

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->conf_if &&
			    (strcmp(peer->conf_if, ifc->ifp->name) == 0) &&
			    !peer_established(peer->connection) &&
			    !CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY)) {
				connection = peer->connection;
				if (peer_active(peer))
					BGP_EVENT_ADD(connection, BGP_Stop);
				BGP_EVENT_ADD(connection, BGP_Start);
			}
		}
	} else if (addr->family == AF_INET6) {
		apply_mask_ipv6((struct prefix_ipv6 *)&p);

		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			return;

		bgp_address_add(bgp, ifc, addr);

		dest = bgp_node_get(bgp->connected_table[AFI_IP6], &p);

		bc = bgp_dest_get_bgp_connected_ref_info(dest);
		if (bc)
			bc->refcnt++;
		else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			bgp_dest_set_bgp_connected_ref_info(dest, bc);
		}
	}
}

void bgp_connected_delete(struct bgp *bgp, struct connected *ifc)
{
	struct prefix p;
	struct prefix *addr;
	struct bgp_dest *dest = NULL;
	struct bgp_connected_ref *bc;

	addr = ifc->address;

	p = *(CONNECTED_PREFIX(ifc));
	apply_mask(&p);
	if (addr->family == AF_INET) {
		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;

		bgp_address_del(bgp, ifc, addr);

		dest = bgp_node_lookup(bgp->connected_table[AFI_IP], &p);
	} else if (addr->family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			return;

		bgp_address_del(bgp, ifc, addr);

		dest = bgp_node_lookup(bgp->connected_table[AFI_IP6], &p);
	}

	if (!dest)
		return;

	bc = bgp_dest_get_bgp_connected_ref_info(dest);
	bc->refcnt--;
	if (bc->refcnt == 0) {
		XFREE(MTYPE_BGP_CONN, bc);
		bgp_dest_set_bgp_connected_ref_info(dest, NULL);
	}

	dest = bgp_dest_unlock_node(dest);
	assert(dest);
	bgp_dest_unlock_node(dest);
}

static void bgp_connected_cleanup(struct route_table *table,
				  struct route_node *rn)
{
	struct bgp_connected_ref *bc;
	struct bgp_dest *bn = bgp_dest_from_rnode(rn);

	bc = bgp_dest_get_bgp_connected_ref_info(bn);
	if (!bc)
		return;

	XFREE(MTYPE_BGP_CONN, bc);
	bgp_dest_set_bgp_connected_ref_info(bn, NULL);
}

bool bgp_nexthop_self(struct bgp *bgp, afi_t afi, uint8_t type,
		      uint8_t sub_type, struct attr *attr,
		      struct bgp_dest *dest)
{
	uint8_t new_afi = afi == AFI_IP ? AF_INET : AF_INET6;
	struct bgp_addr tmp_addr = {{0}}, *addr = NULL;
	struct tip_addr tmp_tip, *tip = NULL;
	const struct prefix *p = bgp_dest_get_prefix(dest);
	bool is_bgp_static_route =
		((type == ZEBRA_ROUTE_BGP) && (sub_type == BGP_ROUTE_STATIC))
			? true
			: false;

	if (!is_bgp_static_route)
		new_afi = BGP_ATTR_NEXTHOP_AFI_IP6(attr) ? AF_INET6 : AF_INET;

	tmp_addr.p.family = new_afi;
	switch (new_afi) {
	case AF_INET:
		if (is_bgp_static_route) {
			tmp_addr.p.u.prefix4 = p->u.prefix4;
			tmp_addr.p.prefixlen = p->prefixlen;
		} else {
			/* Here we need to find out which nexthop to be used*/
			if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {
				tmp_addr.p.u.prefix4 = attr->nexthop;
				tmp_addr.p.prefixlen = IPV4_MAX_BITLEN;
			} else if ((attr->mp_nexthop_len)
				   && ((attr->mp_nexthop_len
					== BGP_ATTR_NHLEN_IPV4)
				       || (attr->mp_nexthop_len
					   == BGP_ATTR_NHLEN_VPNV4))) {
				tmp_addr.p.u.prefix4 =
					attr->mp_nexthop_global_in;
				tmp_addr.p.prefixlen = IPV4_MAX_BITLEN;
			} else
				return false;
		}
		break;
	case AF_INET6:
		if (is_bgp_static_route) {
			tmp_addr.p.u.prefix6 = p->u.prefix6;
			tmp_addr.p.prefixlen = p->prefixlen;
		} else {
			tmp_addr.p.u.prefix6 = attr->mp_nexthop_global;
			tmp_addr.p.prefixlen = IPV6_MAX_BITLEN;
		}
		break;
	default:
		break;
	}

	addr = hash_lookup(bgp->address_hash, &tmp_addr);
	if (addr)
		return true;

	if (new_afi == AF_INET && hashcount(bgp->tip_hash)) {
		memset(&tmp_tip, 0, sizeof(tmp_tip));
		tmp_tip.addr = attr->nexthop;

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {
			tmp_tip.addr = attr->nexthop;
		} else if ((attr->mp_nexthop_len) &&
			   ((attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4)
			    || (attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV4))) {
			tmp_tip.addr = attr->mp_nexthop_global_in;
		}

		tip = hash_lookup(bgp->tip_hash, &tmp_tip);
		if (tip)
			return true;
	}

	return false;
}

bool bgp_multiaccess_check_v4(struct in_addr nexthop, struct peer *peer)
{
	struct bgp_dest *dest1;
	struct bgp_dest *dest2;
	struct prefix p;
	int ret;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = nexthop;

	dest1 = bgp_node_match(peer->bgp->connected_table[AFI_IP], &p);
	if (!dest1)
		return false;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = peer->connection->su.sin.sin_addr;

	dest2 = bgp_node_match(peer->bgp->connected_table[AFI_IP], &p);
	if (!dest2) {
		bgp_dest_unlock_node(dest1);
		return false;
	}

	ret = (dest1 == dest2);

	bgp_dest_unlock_node(dest1);
	bgp_dest_unlock_node(dest2);

	return ret;
}

bool bgp_multiaccess_check_v6(struct in6_addr nexthop, struct peer *peer)
{
	struct bgp_dest *dest1;
	struct bgp_dest *dest2;
	struct prefix p;
	int ret;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.u.prefix6 = nexthop;

	dest1 = bgp_node_match(peer->bgp->connected_table[AFI_IP6], &p);
	if (!dest1)
		return false;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.u.prefix6 = peer->connection->su.sin6.sin6_addr;

	dest2 = bgp_node_match(peer->bgp->connected_table[AFI_IP6], &p);
	if (!dest2) {
		bgp_dest_unlock_node(dest1);
		return false;
	}

	ret = (dest1 == dest2);

	bgp_dest_unlock_node(dest1);
	bgp_dest_unlock_node(dest2);

	return ret;
}

bool bgp_subgrp_multiaccess_check_v6(struct in6_addr nexthop,
				     struct update_subgroup *subgrp,
				     struct peer *exclude)
{
	struct bgp_dest *dest1 = NULL, *dest2 = NULL;
	struct peer_af *paf = NULL;
	struct prefix p = {0}, np = {0};
	struct bgp *bgp = NULL;

	np.family = AF_INET6;
	np.prefixlen = IPV6_MAX_BITLEN;
	np.u.prefix6 = nexthop;

	p.family = AF_INET;
	p.prefixlen = IPV6_MAX_BITLEN;

	bgp = SUBGRP_INST(subgrp);
	dest1 = bgp_node_match(bgp->connected_table[AFI_IP6], &np);
	if (!dest1)
		return false;

	SUBGRP_FOREACH_PEER (subgrp, paf) {
		/* Skip peer we're told to exclude - e.g., source of route. */
		if (paf->peer == exclude)
			continue;

		p.u.prefix6 = paf->peer->connection->su.sin6.sin6_addr;
		dest2 = bgp_node_match(bgp->connected_table[AFI_IP6], &p);
		if (dest1 == dest2) {
			bgp_dest_unlock_node(dest1);
			bgp_dest_unlock_node(dest2);
			return true;
		}

		if (dest2)
			bgp_dest_unlock_node(dest2);
	}

	bgp_dest_unlock_node(dest1);
	return false;
}

bool bgp_subgrp_multiaccess_check_v4(struct in_addr nexthop,
				     struct update_subgroup *subgrp,
				     struct peer *exclude)
{
	struct bgp_dest *dest1, *dest2;
	struct peer_af *paf;
	struct prefix p, np;
	struct bgp *bgp;

	np.family = AF_INET;
	np.prefixlen = IPV4_MAX_BITLEN;
	np.u.prefix4 = nexthop;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;

	bgp = SUBGRP_INST(subgrp);
	dest1 = bgp_node_match(bgp->connected_table[AFI_IP], &np);
	if (!dest1)
		return false;

	SUBGRP_FOREACH_PEER (subgrp, paf) {
		/* Skip peer we're told to exclude - e.g., source of route. */
		if (paf->peer == exclude)
			continue;

		p.u.prefix4 = paf->peer->connection->su.sin.sin_addr;

		dest2 = bgp_node_match(bgp->connected_table[AFI_IP], &p);
		if (dest1 == dest2) {
			bgp_dest_unlock_node(dest1);
			bgp_dest_unlock_node(dest2);
			return true;
		}

		if (dest2)
			bgp_dest_unlock_node(dest2);
	}

	bgp_dest_unlock_node(dest1);
	return false;
}

static void bgp_show_bgp_path_info_flags(uint32_t flags, json_object *json)
{
	json_object *json_flags = NULL;

	if (!json)
		return;

	json_flags = json_object_new_object();
	json_object_boolean_add(json_flags, "igpChanged",
				CHECK_FLAG(flags, BGP_PATH_IGP_CHANGED));
	json_object_boolean_add(json_flags, "damped",
				CHECK_FLAG(flags, BGP_PATH_DAMPED));
	json_object_boolean_add(json_flags, "history",
				CHECK_FLAG(flags, BGP_PATH_HISTORY));
	json_object_boolean_add(json_flags, "bestpath",
				CHECK_FLAG(flags, BGP_PATH_SELECTED));
	json_object_boolean_add(json_flags, "valid",
				CHECK_FLAG(flags, BGP_PATH_VALID));
	json_object_boolean_add(json_flags, "attrChanged",
				CHECK_FLAG(flags, BGP_PATH_ATTR_CHANGED));
	json_object_boolean_add(json_flags, "deterministicMedCheck",
				CHECK_FLAG(flags, BGP_PATH_DMED_CHECK));
	json_object_boolean_add(json_flags, "deterministicMedSelected",
				CHECK_FLAG(flags, BGP_PATH_DMED_SELECTED));
	json_object_boolean_add(json_flags, "stale",
				CHECK_FLAG(flags, BGP_PATH_STALE));
	json_object_boolean_add(json_flags, "removed",
				CHECK_FLAG(flags, BGP_PATH_REMOVED));
	json_object_boolean_add(json_flags, "counted",
				CHECK_FLAG(flags, BGP_PATH_COUNTED));
	json_object_boolean_add(json_flags, "multipath",
				CHECK_FLAG(flags, BGP_PATH_MULTIPATH));
	json_object_boolean_add(json_flags, "multipathChanged",
				CHECK_FLAG(flags, BGP_PATH_MULTIPATH_CHG));
	json_object_boolean_add(json_flags, "ribAttributeChanged",
				CHECK_FLAG(flags, BGP_PATH_RIB_ATTR_CHG));
	json_object_boolean_add(json_flags, "nexthopSelf",
				CHECK_FLAG(flags, BGP_PATH_ANNC_NH_SELF));
	json_object_boolean_add(json_flags, "linkBandwidthChanged",
				CHECK_FLAG(flags, BGP_PATH_LINK_BW_CHG));
	json_object_boolean_add(json_flags, "acceptOwn",
				CHECK_FLAG(flags, BGP_PATH_ACCEPT_OWN));
	json_object_object_add(json, "flags", json_flags);
}

static void bgp_show_nexthop_paths(struct vty *vty, struct bgp *bgp,
				   struct bgp_nexthop_cache *bnc,
				   json_object *json)
{
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	afi_t afi;
	safi_t safi;
	struct bgp_table *table;
	struct bgp *bgp_path;
	json_object *paths = NULL;
	json_object *json_path = NULL;

	if (json)
		paths = json_object_new_array();
	else
		vty_out(vty, "  Paths:\n");
	LIST_FOREACH (path, &(bnc->paths), nh_thread) {
		dest = path->net;
		assert(dest && bgp_dest_table(dest));
		afi = family2afi(bgp_dest_get_prefix(dest)->family);
		table = bgp_dest_table(dest);
		safi = table->safi;
		bgp_path = table->bgp;


		if (json) {
			json_path = json_object_new_object();
			json_object_string_add(json_path, "afi", afi2str(afi));
			json_object_string_add(json_path, "safi",
					       safi2str(safi));
			json_object_string_addf(json_path, "prefix", "%pBD",
						dest);
			if (dest->pdest)
				json_object_string_addf(
					json_path, "rd",
					BGP_RD_AS_FORMAT(bgp->asnotation),
					(struct prefix_rd *)bgp_dest_get_prefix(
						dest->pdest));
			json_object_string_add(
				json_path, "vrf",
				vrf_id_to_name(bgp_path->vrf_id));
			bgp_show_bgp_path_info_flags(path->flags, json_path);
			json_object_array_add(paths, json_path);
			continue;
		}
		if (dest->pdest) {
			vty_out(vty, "    %d/%d %pBD RD ", afi, safi, dest);
			vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
				(struct prefix_rd *)bgp_dest_get_prefix(
					dest->pdest));
			vty_out(vty, " %s flags 0x%x\n", bgp_path->name_pretty,
				path->flags);
		} else
			vty_out(vty, "    %d/%d %pBD %s flags 0x%x\n",
				afi, safi, dest, bgp_path->name_pretty, path->flags);
	}
	if (json)
		json_object_object_add(json, "paths", paths);
}

static void bgp_show_nexthops_detail(struct vty *vty, struct bgp *bgp,
				     struct bgp_nexthop_cache *bnc,
				     json_object *json)
{
	struct nexthop *nexthop;
	json_object *json_gates = NULL;
	json_object *json_gate = NULL;

	if (json)
		json_gates = json_object_new_array();
	for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next) {
		if (json) {
			json_gate = json_object_new_object();
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV6:
				json_object_string_addf(json_gate, "ip", "%pI6",
							&nexthop->gate.ipv6);
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				json_object_string_addf(json_gate, "ip", "%pI6",
							&nexthop->gate.ipv6);
				json_object_string_add(
					json_gate, "interfaceName",
					ifindex2ifname(
						bnc->ifindex_ipv6_ll
							? bnc->ifindex_ipv6_ll
							: nexthop->ifindex,
						bgp->vrf_id));
				break;
			case NEXTHOP_TYPE_IPV4:
				json_object_string_addf(json_gate, "ip", "%pI4",
							&nexthop->gate.ipv4);
				break;
			case NEXTHOP_TYPE_IFINDEX:
				json_object_string_add(
					json_gate, "interfaceName",
					ifindex2ifname(
						bnc->ifindex_ipv6_ll
							? bnc->ifindex_ipv6_ll
							: nexthop->ifindex,
						bgp->vrf_id));
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				json_object_string_addf(json_gate, "ip", "%pI4",
							&nexthop->gate.ipv4);
				json_object_string_add(
					json_gate, "interfaceName",
					ifindex2ifname(
						bnc->ifindex_ipv6_ll
							? bnc->ifindex_ipv6_ll
							: nexthop->ifindex,
						bgp->vrf_id));
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				json_object_boolean_true_add(json_gate,
							     "unreachable");
				switch (nexthop->bh_type) {
				case BLACKHOLE_REJECT:
					json_object_boolean_true_add(json_gate,
								     "reject");
					break;
				case BLACKHOLE_ADMINPROHIB:
					json_object_boolean_true_add(
						json_gate, "adminProhibited");
					break;
				case BLACKHOLE_NULL:
					json_object_boolean_true_add(
						json_gate, "blackhole");
					break;
				case BLACKHOLE_UNSPEC:
					break;
				}
				break;
			default:
				break;
			}
			json_object_array_add(json_gates, json_gate);
			continue;
		}
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			vty_out(vty, "  gate %pI6", &nexthop->gate.ipv6);
			if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX &&
			    bnc->ifindex_ipv6_ll)
				vty_out(vty, ", if %s\n",
					ifindex2ifname(bnc->ifindex_ipv6_ll,
						       bgp->vrf_id));
			else if (nexthop->ifindex)
				vty_out(vty, ", if %s\n",
					ifindex2ifname(nexthop->ifindex,
						       bgp->vrf_id));
			else
				vty_out(vty, "\n");
			break;
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			vty_out(vty, "  gate %pI4", &nexthop->gate.ipv4);
			if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX &&
			    bnc->ifindex_ipv6_ll)
				vty_out(vty, ", if %s\n",
					ifindex2ifname(bnc->ifindex_ipv6_ll,
						       bgp->vrf_id));
			else if (nexthop->ifindex)
				vty_out(vty, ", if %s\n",
					ifindex2ifname(nexthop->ifindex,
						       bgp->vrf_id));
			else
				vty_out(vty, "\n");
			break;
		case NEXTHOP_TYPE_IFINDEX:
			vty_out(vty, "  if %s\n",
				ifindex2ifname(bnc->ifindex_ipv6_ll
						       ? bnc->ifindex_ipv6_ll
						       : nexthop->ifindex,
					       bgp->vrf_id));
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			vty_out(vty, "  blackhole\n");
			break;
		default:
			vty_out(vty, "  invalid nexthop type %u\n",
				nexthop->type);
		}
	}
	if (json)
		json_object_object_add(json, "nexthops", json_gates);
}

static void bgp_show_nexthop(struct vty *vty, struct bgp *bgp,
			     struct bgp_nexthop_cache *bnc, bool specific,
			     json_object *json)
{
	char buf[PREFIX2STR_BUFFER];
	time_t tbuf;
	char timebuf[32];
	struct peer *peer;
	json_object *json_last_update = NULL;
	json_object *json_nexthop = NULL;

	peer = (struct peer *)bnc->nht_info;

	if (json)
		json_nexthop = json_object_new_object();
	if (bnc->srte_color) {
		if (json)
			json_object_int_add(json_nexthop, "srteColor",
					    bnc->srte_color);
		else
			vty_out(vty, " SR-TE color %u -", bnc->srte_color);
	}
	inet_ntop(bnc->prefix.family, &bnc->prefix.u.prefix, buf, sizeof(buf));
	if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)) {
		if (json) {
			json_object_boolean_true_add(json_nexthop, "valid");
			json_object_boolean_true_add(json_nexthop, "complete");
			json_object_int_add(json_nexthop, "igpMetric",
					    bnc->metric);
			json_object_int_add(json_nexthop, "pathCount",
					    bnc->path_count);
			if (peer)
				json_object_string_add(json_nexthop, "peer",
						       peer->host);
			if (bnc->is_evpn_gwip_nexthop)
				json_object_boolean_true_add(json_nexthop,
							     "isEvpnGatewayIp");
			json_object_string_addf(json, "resolvedPrefix", "%pFX",
						&bnc->resolved_prefix);
		} else {
			vty_out(vty, " %s valid [IGP metric %d], #paths %d",
				buf, bnc->metric, bnc->path_count);
			if (peer)
				vty_out(vty, ", peer %s", peer->host);
			if (bnc->is_evpn_gwip_nexthop)
				vty_out(vty, " EVPN Gateway IP");
			vty_out(vty, "\n  Resolved prefix %pFX",
				&bnc->resolved_prefix);
			vty_out(vty, "\n");
		}
		bgp_show_nexthops_detail(vty, bgp, bnc, json_nexthop);
	} else if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE)) {
		if (json) {
			json_object_boolean_true_add(json_nexthop, "valid");
			json_object_boolean_false_add(json_nexthop, "complete");
			json_object_int_add(json_nexthop, "igpMetric",
					    bnc->metric);
			json_object_int_add(json_nexthop, "pathCount",
					    bnc->path_count);
			if (bnc->is_evpn_gwip_nexthop)
				json_object_boolean_true_add(json_nexthop,
							     "isEvpnGatewayIp");
		} else {
			vty_out(vty,
				" %s overlay index unresolved [IGP metric %d], #paths %d",
				buf, bnc->metric, bnc->path_count);
			if (bnc->is_evpn_gwip_nexthop)
				vty_out(vty, " EVPN Gateway IP");
			vty_out(vty, "\n");
		}
		bgp_show_nexthops_detail(vty, bgp, bnc, json_nexthop);
	} else {
		if (json) {
			json_object_boolean_false_add(json_nexthop, "valid");
			json_object_boolean_false_add(json_nexthop, "complete");
			json_object_int_add(json_nexthop, "pathCount",
					    bnc->path_count);
			if (peer)
				json_object_string_add(json_nexthop, "peer",
						       peer->host);
			if (bnc->is_evpn_gwip_nexthop)
				json_object_boolean_true_add(json_nexthop,
							     "isEvpnGatewayIp");
			if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
				json_object_boolean_false_add(json_nexthop,
							      "isConnected");
			if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
				json_object_boolean_false_add(json_nexthop,
							      "isRegistered");
		} else {
			vty_out(vty, " %s invalid, #paths %d", buf,
				bnc->path_count);
			if (peer)
				vty_out(vty, ", peer %s", peer->host);
			if (bnc->is_evpn_gwip_nexthop)
				vty_out(vty, " EVPN Gateway IP");
			vty_out(vty, "\n");
			if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
				vty_out(vty, "  Must be Connected\n");
			if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
				vty_out(vty, "  Is not Registered\n");
		}
	}
	tbuf = time(NULL) - (monotime(NULL) - bnc->last_update);
	if (json) {
		if (!specific) {
			json_last_update = json_object_new_object();
			json_object_int_add(json_last_update, "epoch", tbuf);
			json_object_string_add(json_last_update, "string",
					       ctime_r(&tbuf, timebuf));
			json_object_object_add(json_nexthop, "lastUpdate",
					       json_last_update);
		} else {
			json_object_int_add(json_nexthop, "lastUpdate", tbuf);
		}
	} else {
		vty_out(vty, "  Last update: %s", ctime_r(&tbuf, timebuf));
	}

	/* show paths dependent on nexthop, if needed. */
	if (specific)
		bgp_show_nexthop_paths(vty, bgp, bnc, json_nexthop);
	if (json)
		json_object_object_add(json, buf, json_nexthop);
}

static void bgp_show_nexthops(struct vty *vty, struct bgp *bgp,
			      bool import_table, json_object *json, afi_t afi,
			      bool detail)
{
	struct bgp_nexthop_cache *bnc;
	struct bgp_nexthop_cache_head(*tree)[AFI_MAX];
	json_object *json_afi = NULL;
	bool found = false;

	if (!json) {
		if (import_table)
			vty_out(vty, "Current BGP import check cache:\n");
		else
			vty_out(vty, "Current BGP nexthop cache:\n");
	}
	if (import_table)
		tree = &bgp->import_check_table;
	else
		tree = &bgp->nexthop_cache_table;

	if (afi == AFI_IP || afi == AFI_IP6) {
		if (json)
			json_afi = json_object_new_object();
		frr_each (bgp_nexthop_cache, &(*tree)[afi], bnc) {
			bgp_show_nexthop(vty, bgp, bnc, detail, json_afi);
			found = true;
		}
		if (found && json)
			json_object_object_add(
				json, (afi == AFI_IP) ? "ipv4" : "ipv6",
				json_afi);
		return;
	}

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (json && (afi == AFI_IP || afi == AFI_IP6))
			json_afi = json_object_new_object();
		frr_each (bgp_nexthop_cache, &(*tree)[afi], bnc)
			bgp_show_nexthop(vty, bgp, bnc, detail, json_afi);
		if (json && (afi == AFI_IP || afi == AFI_IP6))
			json_object_object_add(
				json, (afi == AFI_IP) ? "ipv4" : "ipv6",
				json_afi);
	}
}

static int show_ip_bgp_nexthop_table(struct vty *vty, const char *name,
				     const char *nhopip_str, bool import_table,
				     json_object *json, afi_t afi, bool detail)
{
	struct bgp *bgp;

	if (name && !strmatch(name, VRF_DEFAULT_NAME))
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();
	if (!bgp) {
		if (!json)
			vty_out(vty, "%% No such BGP instance exist\n");
		return CMD_WARNING;
	}

	if (nhopip_str) {
		struct prefix nhop;
		struct bgp_nexthop_cache_head (*tree)[AFI_MAX];
		struct bgp_nexthop_cache *bnc;
		bool found = false;
		json_object *json_afi = NULL;

		if (!str2prefix(nhopip_str, &nhop)) {
			if (!json)
				vty_out(vty, "nexthop address is malformed\n");
			return CMD_WARNING;
		}
		tree = import_table ? &bgp->import_check_table
				    : &bgp->nexthop_cache_table;
		if (json)
			json_afi = json_object_new_object();
		frr_each (bgp_nexthop_cache, &(*tree)[family2afi(nhop.family)],
			  bnc) {
			if (prefix_cmp(&bnc->prefix, &nhop))
				continue;
			bgp_show_nexthop(vty, bgp, bnc, true, json_afi);
			found = true;
		}
		if (json)
			json_object_object_add(
				json,
				(family2afi(nhop.family) == AFI_IP) ? "ipv4"
								    : "ipv6",
				json_afi);
		if (!found && !json)
			vty_out(vty, "nexthop %s does not have entry\n",
				nhopip_str);
	} else
		bgp_show_nexthops(vty, bgp, import_table, json, afi, detail);

	return CMD_SUCCESS;
}

static void bgp_show_all_instances_nexthops_vty(struct vty *vty,
						json_object *json, afi_t afi,
						bool detail)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	const char *inst_name;
	json_object *json_instance = NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		inst_name = (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				    ? VRF_DEFAULT_NAME
				    : bgp->name;
		if (json)
			json_instance = json_object_new_object();
		else
			vty_out(vty, "\nInstance %s:\n", inst_name);

		bgp_show_nexthops(vty, bgp, false, json_instance, afi, detail);

		if (json)
			json_object_object_add(json, inst_name, json_instance);
	}
}

#include "bgpd/bgp_nexthop_clippy.c"

DEFPY (show_ip_bgp_nexthop,
       show_ip_bgp_nexthop_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME$vrf] nexthop [<A.B.C.D|X:X::X:X>$nhop] [<ipv4$afi [A.B.C.D$nhop]|ipv6$afi [X:X::X:X$nhop]>] [detail$detail] [json$uj]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP nexthop table\n"
       "IPv4 nexthop address\n"
       "IPv6 nexthop address\n"
       "BGP nexthop IPv4 table\n"
       "IPv4 nexthop address\n"
       "BGP nexthop IPv6 table\n"
       "IPv6 nexthop address\n"
       "Show detailed information\n"
       JSON_STR)
{
	int rc = 0;
	json_object *json = NULL;
	afi_t afiz = AFI_UNSPEC;

	if (uj)
		json = json_object_new_object();

	if (afi)
		afiz = bgp_vty_afi_from_str(afi);

	rc = show_ip_bgp_nexthop_table(vty, vrf, nhop_str, false, json, afiz,
				       detail);

	if (uj)
		vty_json(vty, json);

	return rc;
}

DEFPY (show_ip_bgp_import_check,
       show_ip_bgp_import_check_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME$vrf] import-check-table [detail$detail] [json$uj]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP import check table\n"
       "Show detailed information\n"
       JSON_STR)
{
	int rc = 0;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	rc = show_ip_bgp_nexthop_table(vty, vrf, NULL, true, json, AFI_UNSPEC,
				       detail);

	if (uj)
		vty_json(vty, json);

	return rc;
}

DEFPY (show_ip_bgp_instance_all_nexthop,
       show_ip_bgp_instance_all_nexthop_cmd,
       "show [ip] bgp <view|vrf> all nexthop [<ipv4|ipv6>$afi] [detail$detail] [json$uj]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "BGP nexthop table\n"
       "BGP IPv4 nexthop table\n"
       "BGP IPv6 nexthop table\n"
       "Show detailed information\n"
       JSON_STR)
{
	json_object *json = NULL;
	afi_t afiz = AFI_UNSPEC;

	if (uj)
		json = json_object_new_object();

	if (afi)
		afiz = bgp_vty_afi_from_str(afi);

	bgp_show_all_instances_nexthops_vty(vty, json, afiz, detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

void bgp_scan_init(struct bgp *bgp)
{
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		bgp_nexthop_cache_init(&bgp->nexthop_cache_table[afi]);
		bgp_nexthop_cache_init(&bgp->import_check_table[afi]);
		bgp->connected_table[afi] = bgp_table_init(bgp, afi,
			SAFI_UNICAST);
	}
}

void bgp_scan_vty_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_nexthop_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_import_check_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_instance_all_nexthop_cmd);
}

void bgp_scan_finish(struct bgp *bgp)
{
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		/* Only the current one needs to be reset. */
		bgp_nexthop_cache_reset(&bgp->nexthop_cache_table[afi]);
		bgp_nexthop_cache_reset(&bgp->import_check_table[afi]);

		bgp->connected_table[afi]->route_table->cleanup =
			bgp_connected_cleanup;
		bgp_table_unlock(bgp->connected_table[afi]);
		bgp->connected_table[afi] = NULL;
	}
}

char *bgp_nexthop_dump_bnc_flags(struct bgp_nexthop_cache *bnc, char *buf,
				 size_t len)
{
	if (bnc->flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(buf, len, "%s%s%s%s%s%s%s",
		   CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) ? "Valid " : "",
		   CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED) ? "Reg " : "",
		   CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED) ? "Conn " : "",
		   CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED) ? "Notify "
								     : "",
		   CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE) ? "Static " : "",
		   CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH)
			   ? "Static Exact "
			   : "",
		   CHECK_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID)
			   ? "Label Valid "
			   : "");

	return buf;
}

char *bgp_nexthop_dump_bnc_change_flags(struct bgp_nexthop_cache *bnc,
					char *buf, size_t len)
{
	if (bnc->flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(buf, len, "%s%s%s",
		   CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED)
			   ? "Changed "
			   : "",
		   CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_METRIC_CHANGED)
			   ? "Metric "
			   : "",
		   CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CONNECTED_CHANGED)
			   ? "Connected "
			   : "");

	return buf;
}
