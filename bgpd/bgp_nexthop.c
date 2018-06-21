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
#include "zebra/rib.h"
#include "zebra/zserv.h" /* For ZEBRA_SERV_PATH. */

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

	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn))
		if ((bnc = rn->info) != NULL) {
			bnc_free(bnc);
			rn->info = NULL;
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

static unsigned int bgp_tip_hash_key_make(void *p)
{
	const struct tip_addr *addr = p;

	return jhash_1word(addr->addr.s_addr, 0);
}

static int bgp_tip_hash_cmp(const void *p1, const void *p2)
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

static void *bgp_address_hash_alloc(void *p)
{
	const struct in_addr *val = (const struct in_addr *)p;
	struct bgp_addr *addr;

	addr = XMALLOC(MTYPE_BGP_ADDR, sizeof(struct bgp_addr));
	addr->refcnt = 0;
	addr->addr.s_addr = val->s_addr;

	return addr;
}

static void bgp_address_hash_free(void *addr)
{
	XFREE(MTYPE_BGP_ADDR, addr);
}

static unsigned int bgp_address_hash_key_make(void *p)
{
	const struct bgp_addr *addr = p;

	return jhash_1word(addr->addr.s_addr, 0);
}

static int bgp_address_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_addr *addr1 = p1;
	const struct bgp_addr *addr2 = p2;

	return addr1->addr.s_addr == addr2->addr.s_addr;
}

void bgp_address_init(struct bgp *bgp)
{
	bgp->address_hash =
		hash_create(bgp_address_hash_key_make, bgp_address_hash_cmp,
			    "BGP Address Hash");
}

void bgp_address_destroy(struct bgp *bgp)
{
	if (bgp->address_hash == NULL)
		return;
	hash_clean(bgp->address_hash, bgp_address_hash_free);
	hash_free(bgp->address_hash);
	bgp->address_hash = NULL;
}

static void bgp_address_add(struct bgp *bgp, struct prefix *p)
{
	struct bgp_addr tmp;
	struct bgp_addr *addr;

	tmp.addr = p->u.prefix4;

	addr = hash_get(bgp->address_hash, &tmp, bgp_address_hash_alloc);
	if (!addr)
		return;

	addr->refcnt++;
}

static void bgp_address_del(struct bgp *bgp, struct prefix *p)
{
	struct bgp_addr tmp;
	struct bgp_addr *addr;

	tmp.addr = p->u.prefix4;

	addr = hash_lookup(bgp->address_hash, &tmp);
	/* may have been deleted earlier by bgp_interface_down() */
	if (addr == NULL)
		return;

	addr->refcnt--;

	if (addr->refcnt == 0) {
		hash_release(bgp->address_hash, addr);
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

		bgp_address_add(bgp, addr);

		rn = bgp_node_get(bgp->connected_table[AFI_IP],
				  (struct prefix *)&p);
		if (rn->info) {
			bc = rn->info;
			bc->refcnt++;
		} else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			rn->info = bc;
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

		rn = bgp_node_get(bgp->connected_table[AFI_IP6],
				  (struct prefix *)&p);
		if (rn->info) {
			bc = rn->info;
			bc->refcnt++;
		} else {
			bc = XCALLOC(MTYPE_BGP_CONN,
				     sizeof(struct bgp_connected_ref));
			bc->refcnt = 1;
			rn->info = bc;
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

		bgp_address_del(bgp, addr);

		rn = bgp_node_lookup(bgp->connected_table[AFI_IP], &p);
	} else if (addr->family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			return;

		rn = bgp_node_lookup(bgp->connected_table[AFI_IP6],
				     (struct prefix *)&p);
	}

	if (!rn)
		return;

	bc = rn->info;
	bc->refcnt--;
	if (bc->refcnt == 0) {
		XFREE(MTYPE_BGP_CONN, bc);
		rn->info = NULL;
	}
	bgp_unlock_node(rn);
	bgp_unlock_node(rn);
}

static void bgp_connected_cleanup(struct route_table *table,
				  struct route_node *rn)
{
	struct bgp_connected_ref *bc;

	bc = rn->info;
	if (!bc)
		return;

	bc->refcnt--;
	if (bc->refcnt == 0) {
		XFREE(MTYPE_BGP_CONN, bc);
		rn->info = NULL;
	}
}

int bgp_nexthop_self(struct bgp *bgp, struct in_addr nh_addr)
{
	struct bgp_addr tmp, *addr;
	struct tip_addr tmp_tip, *tip;

	tmp.addr = nh_addr;

	addr = hash_lookup(bgp->address_hash, &tmp);
	if (addr)
		return 1;

	tmp_tip.addr = nh_addr;
	tip = hash_lookup(bgp->tip_hash, &tmp_tip);
	if (tip)
		return 1;

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

	rn2 = NULL;

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

static void bgp_show_nexthops(struct vty *vty, struct bgp *bgp, int detail)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	char buf[PREFIX2STR_BUFFER];
	time_t tbuf;
	afi_t afi;

	vty_out(vty, "Current BGP nexthop cache:\n");
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (!bgp->nexthop_cache_table[afi])
			continue;

		for (rn = bgp_table_top(bgp->nexthop_cache_table[afi]); rn;
		     rn = bgp_route_next(rn)) {
			if ((bnc = rn->info) != NULL) {
				if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)) {
					vty_out(vty,
						" %s valid [IGP metric %d], #paths %d\n",
						inet_ntop(rn->p.family,
							  &rn->p.u.prefix, buf,
							  sizeof(buf)),
						bnc->metric, bnc->path_count);

					if (!detail)
						continue;

					bgp_show_nexthops_detail(vty, bgp, bnc);

				} else {
					vty_out(vty, " %s invalid\n",
						inet_ntop(rn->p.family,
							  &rn->p.u.prefix, buf,
							  sizeof(buf)));
					if (CHECK_FLAG(bnc->flags,
						       BGP_NEXTHOP_CONNECTED))
						vty_out(vty,
							"  Must be Connected\n");
				}
				tbuf = time(NULL)
				       - (bgp_clock() - bnc->last_update);
				vty_out(vty, "  Last update: %s", ctime(&tbuf));
				vty_out(vty, "\n");
			}
		}
	}
}

static int show_ip_bgp_nexthop_table(struct vty *vty, const char *name,
				     int detail)
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

	bgp_show_nexthops(vty, bgp, detail);

	return CMD_SUCCESS;
}

static void bgp_show_all_instances_nexthops_vty(struct vty *vty)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		vty_out(vty, "\nInstance %s:\n",
			(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? "Default"
				: bgp->name);
		bgp_show_nexthops(vty, bgp, 0);
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
	return show_ip_bgp_nexthop_table(vty, vrf, detail);
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
