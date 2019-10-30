/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "thread.h"
#include "prefix.h"
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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_vty.h"

DEFINE_MTYPE_STATIC(BGPD, MARTIAN_STRING, "BGP Martian Address Intf String");

char *bnc_str(struct bgp_nexthop_cache *bnc, char *buf, int size)
{
	prefix2str(&(bnc->node->p), buf, size);
	return buf;
}

void bnc_nexthop_free(struct bgp_nexthop_cache *bnc)
{
	nexthops_free(bnc->nexthop);
}

struct bgp_nexthop_cache *bnc_new(void)
{
	struct bgp_nexthop_cache *bnc;

	bnc = XCALLOC(MTYPE_BGP_NEXTHOP_CACHE,
		      sizeof(struct bgp_nexthop_cache));
	LIST_INIT(&(bnc->paths));
	return bnc;
}

void bnc_free(struct bgp_nexthop_cache *bnc)
{
	bnc_nexthop_free(bnc);
	XFREE(MTYPE_BGP_NEXTHOP_CACHE, bnc);
}

/* Reset and free all BGP nexthop cache. */
static void bgp_nexthop_cache_reset(struct bgp_table *table)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;

	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		bnc = bgp_node_get_bgp_nexthop_info(rn);
		if (!bnc)
			continue;

		while (!LIST_EMPTY(&(bnc->paths))) {
			struct bgp_path_info *path = LIST_FIRST(&(bnc->paths));

			path_nh_map(path, bnc, false);
		}

		bnc_free(bnc);
		bgp_node_set_bgp_nexthop_info(rn, NULL);
		bgp_unlock_node(rn);
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
	if (bgp->tip_hash == NULL)
		return;
	hash_clean(bgp->tip_hash, bgp_tip_hash_free);
	hash_free(bgp->tip_hash);
	bgp->tip_hash = NULL;
}

void bgp_tip_add(struct bgp *bgp, struct in_addr *tip)
{
	struct tip_addr tmp;
	struct tip_addr *addr;

	tmp.addr = *tip;

	addr = hash_get(bgp->tip_hash, &tmp, bgp_tip_hash_alloc);
	if (!addr)
		return;

	addr->refcnt++;
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
	struct prefix *p;
	struct list *ifp_name_list;
};

static void show_address_entry(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct bgp_addr *addr = (struct bgp_addr *)bucket->data;
	char *name;
	struct listnode *node;
	char str[INET6_ADDRSTRLEN] = {0};

	if (addr->p->family == AF_INET) {
		vty_out(vty, "addr: %s, count: %d : ", inet_ntop(AF_INET,
				&(addr->p->u.prefix4),
				str, INET_ADDRSTRLEN),
				addr->ifp_name_list->count);
	} else if (addr->p->family == AF_INET6) {
		vty_out(vty, "addr: %s, count: %d : ", inet_ntop(AF_INET6,
				&(addr->p->u.prefix6),
				str, INET6_ADDRSTRLEN),
				addr->ifp_name_list->count);
	}

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
	addr->p = prefix_new();
	prefix_copy(addr->p, copy_addr->p);

	addr->ifp_name_list = list_new();
	addr->ifp_name_list->del = bgp_address_hash_string_del;

	return addr;
}

static void bgp_address_hash_free(void *data)
{
	struct bgp_addr *addr = data;

	prefix_free(&addr->p);
	list_delete(&addr->ifp_name_list);
	XFREE(MTYPE_BGP_ADDR, addr);
}

static unsigned int bgp_address_hash_key_make(const void *p)
{
	const struct bgp_addr *addr = p;

	return prefix_hash_key((const void *)(addr->p));
}

static bool bgp_address_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_addr *addr1 = p1;
	const struct bgp_addr *addr2 = p2;

	return prefix_same(addr1->p, addr2->p);
}

void bgp_address_init(struct bgp *bgp)
{
	bgp->address_hash =
		hash_create(bgp_address_hash_key_make, bgp_address_hash_cmp,
				"BGP Connected Address Hash");
}

void bgp_address_destroy(struct bgp *bgp)
{
	if (bgp->address_hash == NULL)
		return;
	hash_clean(bgp->address_hash, bgp_address_hash_free);
	hash_free(bgp->address_hash);
	bgp->address_hash = NULL;
}

static void bgp_address_add(struct bgp *bgp, struct connected *ifc,
			    struct prefix *p)
{
	struct bgp_addr tmp;
	struct bgp_addr *addr;
	struct listnode *node;
	char *name;

	tmp.p = p;

	if (tmp.p->family == AF_INET)
		tmp.p->prefixlen = IPV4_MAX_BITLEN;
	else if (tmp.p->family == AF_INET6)
		tmp.p->prefixlen = IPV6_MAX_BITLEN;

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

	tmp.p = p;

	if (tmp.p->family == AF_INET)
		tmp.p->prefixlen = IPV4_MAX_BITLEN;
	else if (tmp.p->family == AF_INET6)
		tmp.p->prefixlen = IPV6_MAX_BITLEN;

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
	struct bgp_node *rn;
	struct bgp_connected_ref *bc;
	struct listnode *node, *nnode;
	struct peer *peer;

	addr = ifc->address;

	p = *(CONNECTED_PREFIX(ifc));
	if (addr->family == AF_INET) {
		apply_mask_ipv4((struct prefix_ipv4 *)&p);

		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;

		bgp_address_add(bgp, ifc, addr);

		rn = bgp_node_get(bgp->connected_table[AFI_IP],
				  (struct prefix *)&p);
		bc = bgp_node_get_bgp_connected_ref_info(rn);
		if (bc)
			bc->refcnt++;
		else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			bgp_node_set_bgp_connected_ref_info(rn, bc);
		}

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->conf_if
			    && (strcmp(peer->conf_if, ifc->ifp->name) == 0)
			    && peer->status != Established
			    && !CHECK_FLAG(peer->flags,
					   PEER_FLAG_IFPEER_V6ONLY)) {
				if (peer_active(peer))
					BGP_EVENT_ADD(peer, BGP_Stop);
				BGP_EVENT_ADD(peer, BGP_Start);
			}
		}
	} else if (addr->family == AF_INET6) {
		apply_mask_ipv6((struct prefix_ipv6 *)&p);

		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			return;

		bgp_address_add(bgp, ifc, addr);

		rn = bgp_node_get(bgp->connected_table[AFI_IP6],
				  (struct prefix *)&p);

		bc = bgp_node_get_bgp_connected_ref_info(rn);
		if (bc)
			bc->refcnt++;
		else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			bgp_node_set_bgp_connected_ref_info(rn, bc);
		}
	}
}

void bgp_connected_delete(struct bgp *bgp, struct connected *ifc)
{
	struct prefix p;
	struct prefix *addr;
	struct bgp_node *rn = NULL;
	struct bgp_connected_ref *bc;

	addr = ifc->address;

	p = *(CONNECTED_PREFIX(ifc));
	apply_mask(&p);
	if (addr->family == AF_INET) {
		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;

		bgp_address_del(bgp, ifc, addr);

		rn = bgp_node_lookup(bgp->connected_table[AFI_IP], &p);
	} else if (addr->family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			return;

		bgp_address_del(bgp, ifc, addr);

		rn = bgp_node_lookup(bgp->connected_table[AFI_IP6],
				     (struct prefix *)&p);
	}

	if (!rn)
		return;

	bc = bgp_node_get_bgp_connected_ref_info(rn);
	bc->refcnt--;
	if (bc->refcnt == 0) {
		XFREE(MTYPE_BGP_CONN, bc);
		bgp_node_set_bgp_connected_ref_info(rn, NULL);
	}
	bgp_unlock_node(rn);
	bgp_unlock_node(rn);
}

static void bgp_connected_cleanup(struct route_table *table,
				  struct route_node *rn)
{
	struct bgp_connected_ref *bc;
	struct bgp_node *bn = bgp_node_from_rnode(rn);

	bc = bgp_node_get_bgp_connected_ref_info(bn);
	if (!bc)
		return;

	bc->refcnt--;
	if (bc->refcnt == 0) {
		XFREE(MTYPE_BGP_CONN, bc);
		bgp_node_set_bgp_connected_ref_info(bn, NULL);
	}
}

int bgp_nexthop_self(struct bgp *bgp, afi_t afi, uint8_t type, uint8_t sub_type,
		struct attr *attr, struct bgp_node *rn)
{
	struct prefix p = {0};
	afi_t new_afi = afi;
	struct bgp_addr tmp_addr = {0}, *addr = NULL;
	struct tip_addr tmp_tip, *tip = NULL;

	bool is_bgp_static_route = ((type == ZEBRA_ROUTE_BGP)
			&& (sub_type == BGP_ROUTE_STATIC))
			? true
			: false;

	if (!is_bgp_static_route)
		new_afi = BGP_ATTR_NEXTHOP_AFI_IP6(attr) ? AFI_IP6 : AFI_IP;

	switch (new_afi) {
	case AFI_IP:
		p.family = AF_INET;
		if (is_bgp_static_route) {
			p.u.prefix4 = rn->p.u.prefix4;
			p.prefixlen = rn->p.prefixlen;
		} else {
			/* Here we need to find out which nexthop to be used*/
			if (attr->flag &
					ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {

				p.u.prefix4 = attr->nexthop;
				p.prefixlen = IPV4_MAX_BITLEN;

			} else if ((attr->mp_nexthop_len) &&
					((attr->mp_nexthop_len ==
					  BGP_ATTR_NHLEN_IPV4) ||
					 (attr->mp_nexthop_len ==
					  BGP_ATTR_NHLEN_VPNV4))) {
				p.u.prefix4 =
					attr->mp_nexthop_global_in;
				p.prefixlen = IPV4_MAX_BITLEN;
			} else
				return 0;
		}
		break;
	case AFI_IP6:
		p.family = AF_INET6;

		if (is_bgp_static_route) {
			p.u.prefix6 = rn->p.u.prefix6;
			p.prefixlen = rn->p.prefixlen;
		} else {
			p.u.prefix6 = attr->mp_nexthop_global;
			p.prefixlen = IPV6_MAX_BITLEN;
		}
		break;
	default:
		break;
	}

	tmp_addr.p = &p;
	addr = hash_lookup(bgp->address_hash, &tmp_addr);
	if (addr)
		return 1;

	if (new_afi == AFI_IP) {
		memset(&tmp_tip, 0, sizeof(struct tip_addr));
		tmp_tip.addr = attr->nexthop;

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {
			tmp_tip.addr = attr->nexthop;
		} else if ((attr->mp_nexthop_len) &&
				((attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4)
				 || (attr->mp_nexthop_len ==
					 BGP_ATTR_NHLEN_VPNV4))) {
			tmp_tip.addr = attr->mp_nexthop_global_in;
		}

		tip = hash_lookup(bgp->tip_hash, &tmp_tip);
		if (tip)
			return 1;
	}

	return 0;
}

int bgp_multiaccess_check_v4(struct in_addr nexthop, struct peer *peer)
{
	struct bgp_node *rn1;
	struct bgp_node *rn2;
	struct prefix p;
	int ret;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = nexthop;

	rn1 = bgp_node_match(peer->bgp->connected_table[AFI_IP], &p);
	if (!rn1)
		return 0;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = peer->su.sin.sin_addr;

	rn2 = bgp_node_match(peer->bgp->connected_table[AFI_IP], &p);
	if (!rn2) {
		bgp_unlock_node(rn1);
		return 0;
	}

	ret = (rn1 == rn2) ? 1 : 0;

	bgp_unlock_node(rn1);
	bgp_unlock_node(rn2);

	return (ret);
}

int bgp_multiaccess_check_v6(struct in6_addr nexthop, struct peer *peer)
{
	struct bgp_node *rn1;
	struct bgp_node *rn2;
	struct prefix p;
	int ret;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.u.prefix6 = nexthop;

	rn1 = bgp_node_match(peer->bgp->connected_table[AFI_IP6], &p);
	if (!rn1)
		return 0;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.u.prefix6 = peer->su.sin6.sin6_addr;

	rn2 = bgp_node_match(peer->bgp->connected_table[AFI_IP6], &p);
	if (!rn2) {
		bgp_unlock_node(rn1);
		return 0;
	}

	ret = (rn1 == rn2) ? 1 : 0;

	bgp_unlock_node(rn1);
	bgp_unlock_node(rn2);

	return ret;
}

int bgp_subgrp_multiaccess_check_v6(struct in6_addr nexthop,
			struct update_subgroup *subgrp)
{
	struct bgp_node *rn1 = NULL, *rn2 = NULL;
	struct peer_af *paf = NULL;
	struct prefix p = {0}, np = {0};
	struct bgp *bgp = NULL;

	np.family = AF_INET6;
	np.prefixlen = IPV6_MAX_BITLEN;
	np.u.prefix6 = nexthop;

	p.family = AF_INET;
	p.prefixlen = IPV6_MAX_BITLEN;

	bgp = SUBGRP_INST(subgrp);
	rn1 = bgp_node_match(bgp->connected_table[AFI_IP6], &np);
	if (!rn1)
		return 0;

	SUBGRP_FOREACH_PEER (subgrp, paf) {

		p.u.prefix6 = paf->peer->su.sin6.sin6_addr;
		rn2 = bgp_node_match(bgp->connected_table[AFI_IP6], &p);
		if (rn1 == rn2) {
			bgp_unlock_node(rn1);
			bgp_unlock_node(rn2);
			return 1;
		}

		if (rn2)
			bgp_unlock_node(rn2);
	}

	bgp_unlock_node(rn1);
	return 0;
}

int bgp_subgrp_multiaccess_check_v4(struct in_addr nexthop,
				    struct update_subgroup *subgrp)
{
	struct bgp_node *rn1, *rn2;
	struct peer_af *paf;
	struct prefix p, np;
	struct bgp *bgp;

	np.family = AF_INET;
	np.prefixlen = IPV4_MAX_BITLEN;
	np.u.prefix4 = nexthop;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;

	bgp = SUBGRP_INST(subgrp);
	rn1 = bgp_node_match(bgp->connected_table[AFI_IP], &np);
	if (!rn1)
		return 0;

	SUBGRP_FOREACH_PEER (subgrp, paf) {
		p.u.prefix4 = paf->peer->su.sin.sin_addr;

		rn2 = bgp_node_match(bgp->connected_table[AFI_IP], &p);
		if (rn1 == rn2) {
			bgp_unlock_node(rn1);
			bgp_unlock_node(rn2);
			return 1;
		}

		if (rn2)
			bgp_unlock_node(rn2);
	}

	bgp_unlock_node(rn1);
	return 0;
}

static void bgp_show_nexthops_detail(struct vty *vty, struct bgp *bgp,
				     struct bgp_nexthop_cache *bnc)
{
	char buf[PREFIX2STR_BUFFER];
	struct nexthop *nexthop;

	for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next)
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV6:
			vty_out(vty, "  gate %s\n",
				inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
					  sizeof(buf)));
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			vty_out(vty, "  gate %s, if %s\n",
				inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
					  sizeof(buf)),
				ifindex2ifname(nexthop->ifindex, bgp->vrf_id));
			break;
		case NEXTHOP_TYPE_IPV4:
			vty_out(vty, "  gate %s\n",
				inet_ntop(AF_INET, &nexthop->gate.ipv4, buf,
					  sizeof(buf)));
			break;
		case NEXTHOP_TYPE_IFINDEX:
			vty_out(vty, "  if %s\n",
				ifindex2ifname(nexthop->ifindex, bgp->vrf_id));
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			vty_out(vty, "  gate %s, if %s\n",
				inet_ntop(AF_INET, &nexthop->gate.ipv4, buf,
					  sizeof(buf)),
				ifindex2ifname(nexthop->ifindex, bgp->vrf_id));
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			vty_out(vty, "  blackhole\n");
			break;
		default:
			vty_out(vty, "  invalid nexthop type %u\n",
				nexthop->type);
		}
}

static void bgp_show_nexthops(struct vty *vty, struct bgp *bgp, int detail,
			     bool import_table)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	char buf[PREFIX2STR_BUFFER];
	time_t tbuf;
	afi_t afi;
	struct bgp_table **table;

	if (import_table)
		vty_out(vty, "Current BGP import check cache:\n");
	else
		vty_out(vty, "Current BGP nexthop cache:\n");
	if (import_table)
		table = bgp->import_check_table;
	else
		table = bgp->nexthop_cache_table;
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (!table || !table[afi])
			continue;
		for (rn = bgp_table_top(table[afi]); rn;
		     rn = bgp_route_next(rn)) {
			struct peer *peer;

			bnc = bgp_node_get_bgp_nexthop_info(rn);
			if (!bnc)
				continue;
			peer = (struct peer *)bnc->nht_info;

			if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)) {
				vty_out(vty,
					" %s valid [IGP metric %d], #paths %d",
					inet_ntop(rn->p.family,
						  &rn->p.u.prefix, buf,
						  sizeof(buf)),
					bnc->metric, bnc->path_count);
				if (peer)
					vty_out(vty, ", peer %s", peer->host);
				vty_out(vty, "\n");

				if (!detail)
					continue;

				bgp_show_nexthops_detail(vty, bgp, bnc);

			} else {
				vty_out(vty, " %s invalid",
					inet_ntop(rn->p.family,
						  &rn->p.u.prefix, buf,
						  sizeof(buf)));
				if (peer)
					vty_out(vty, ", peer %s", peer->host);
				vty_out(vty, "\n");
				if (CHECK_FLAG(bnc->flags,
					       BGP_NEXTHOP_CONNECTED))
					vty_out(vty, "  Must be Connected\n");
				if (!CHECK_FLAG(bnc->flags,
						BGP_NEXTHOP_REGISTERED))
					vty_out(vty, "  Is not Registered\n");
			}
			tbuf = time(NULL) - (bgp_clock() - bnc->last_update);
			vty_out(vty, "  Last update: %s", ctime(&tbuf));
			vty_out(vty, "\n");
		}
	}
}

static int show_ip_bgp_nexthop_table(struct vty *vty, const char *name,
				     int detail, bool import_table)
{
	struct bgp *bgp;

	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "%% No such BGP instance exist\n");
		return CMD_WARNING;
	}

	bgp_show_nexthops(vty, bgp, detail, import_table);

	return CMD_SUCCESS;
}

static void bgp_show_all_instances_nexthops_vty(struct vty *vty)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		vty_out(vty, "\nInstance %s:\n",
			(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? VRF_DEFAULT_NAME
				: bgp->name);
		bgp_show_nexthops(vty, bgp, 0, false);
	}
}

DEFUN (show_ip_bgp_nexthop,
       show_ip_bgp_nexthop_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] nexthop [detail]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP nexthop table\n"
       "Show detailed information\n")
{
	int idx = 0;
	char *vrf = NULL;

	if (argv_find(argv, argc, "view", &idx)
	    || argv_find(argv, argc, "vrf", &idx))
		vrf = argv[++idx]->arg;
	int detail = argv_find(argv, argc, "detail", &idx) ? 1 : 0;

	return show_ip_bgp_nexthop_table(vty, vrf, detail, false);
}

DEFUN (show_ip_bgp_import_check,
       show_ip_bgp_import_check_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] import-check-table [detail]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP import check table\n"
       "Show detailed information\n")
{
	int idx = 0;
	char *vrf = NULL;

	if (argv_find(argv, argc, "view", &idx)
	    || argv_find(argv, argc, "vrf", &idx))
		vrf = argv[++idx]->arg;
	int detail = argv_find(argv, argc, "detail", &idx) ? 1 : 0;
	return show_ip_bgp_nexthop_table(vty, vrf, detail, true);
}

DEFUN (show_ip_bgp_instance_all_nexthop,
       show_ip_bgp_instance_all_nexthop_cmd,
       "show [ip] bgp <view|vrf> all nexthop",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "BGP nexthop table\n")
{
	bgp_show_all_instances_nexthops_vty(vty);
	return CMD_SUCCESS;
}

void bgp_scan_init(struct bgp *bgp)
{
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		bgp->nexthop_cache_table[afi] =
			bgp_table_init(bgp, afi, SAFI_UNICAST);
		bgp->connected_table[afi] = bgp_table_init(bgp, afi,
			SAFI_UNICAST);
		bgp->import_check_table[afi] =
			bgp_table_init(bgp, afi, SAFI_UNICAST);
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
		bgp_nexthop_cache_reset(bgp->nexthop_cache_table[afi]);
		bgp_table_unlock(bgp->nexthop_cache_table[afi]);
		bgp->nexthop_cache_table[afi] = NULL;

		bgp->connected_table[afi]->route_table->cleanup =
			bgp_connected_cleanup;
		bgp_table_unlock(bgp->connected_table[afi]);
		bgp->connected_table[afi] = NULL;

		bgp_table_unlock(bgp->import_check_table[afi]);
		bgp->import_check_table[afi] = NULL;
	}
}
