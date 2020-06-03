/* BGP attributes management routines.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
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

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vector.h"
#include "stream.h"
#include "log.h"
#include "hash.h"
#include "jhash.h"
#include "queue.h"
#include "table.h"
#include "filter.h"
#include "command.h"
#include "srv6.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_encap_types.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgp_encap_types.h"
#include "bgp_vnc_types.h"
#endif
#include "bgp_evpn.h"
#include "bgp_flowspec_private.h"
#include "bgp_mac.h"

/* Attribute strings for logging. */
static const struct message attr_str[] = {
	{BGP_ATTR_ORIGIN, "ORIGIN"},
	{BGP_ATTR_AS_PATH, "AS_PATH"},
	{BGP_ATTR_NEXT_HOP, "NEXT_HOP"},
	{BGP_ATTR_MULTI_EXIT_DISC, "MULTI_EXIT_DISC"},
	{BGP_ATTR_LOCAL_PREF, "LOCAL_PREF"},
	{BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE"},
	{BGP_ATTR_AGGREGATOR, "AGGREGATOR"},
	{BGP_ATTR_COMMUNITIES, "COMMUNITY"},
	{BGP_ATTR_ORIGINATOR_ID, "ORIGINATOR_ID"},
	{BGP_ATTR_CLUSTER_LIST, "CLUSTER_LIST"},
	{BGP_ATTR_DPA, "DPA"},
	{BGP_ATTR_ADVERTISER, "ADVERTISER"},
	{BGP_ATTR_RCID_PATH, "RCID_PATH"},
	{BGP_ATTR_MP_REACH_NLRI, "MP_REACH_NLRI"},
	{BGP_ATTR_MP_UNREACH_NLRI, "MP_UNREACH_NLRI"},
	{BGP_ATTR_EXT_COMMUNITIES, "EXT_COMMUNITIES"},
	{BGP_ATTR_AS4_PATH, "AS4_PATH"},
	{BGP_ATTR_AS4_AGGREGATOR, "AS4_AGGREGATOR"},
	{BGP_ATTR_AS_PATHLIMIT, "AS_PATHLIMIT"},
	{BGP_ATTR_PMSI_TUNNEL, "PMSI_TUNNEL_ATTRIBUTE"},
	{BGP_ATTR_ENCAP, "ENCAP"},
#ifdef ENABLE_BGP_VNC_ATTR
	{BGP_ATTR_VNC, "VNC"},
#endif
	{BGP_ATTR_LARGE_COMMUNITIES, "LARGE_COMMUNITY"},
	{BGP_ATTR_PREFIX_SID, "PREFIX_SID"},
	{0}};

static const struct message attr_flag_str[] = {
	{BGP_ATTR_FLAG_OPTIONAL, "Optional"},
	{BGP_ATTR_FLAG_TRANS, "Transitive"},
	{BGP_ATTR_FLAG_PARTIAL, "Partial"},
	/* bgp_attr_flags_diagnose() relies on this bit being last in
	   this list */
	{BGP_ATTR_FLAG_EXTLEN, "Extended Length"},
	{0}};

static struct hash *cluster_hash;

static void *cluster_hash_alloc(void *p)
{
	const struct cluster_list *val = (const struct cluster_list *)p;
	struct cluster_list *cluster;

	cluster = XMALLOC(MTYPE_CLUSTER, sizeof(struct cluster_list));
	cluster->length = val->length;

	if (cluster->length) {
		cluster->list = XMALLOC(MTYPE_CLUSTER_VAL, val->length);
		memcpy(cluster->list, val->list, val->length);
	} else
		cluster->list = NULL;

	cluster->refcnt = 0;

	return cluster;
}

/* Cluster list related functions. */
static struct cluster_list *cluster_parse(struct in_addr *pnt, int length)
{
	struct cluster_list tmp = {};
	struct cluster_list *cluster;

	tmp.length = length;
	tmp.list = length == 0 ? NULL : pnt;

	cluster = hash_get(cluster_hash, &tmp, cluster_hash_alloc);
	cluster->refcnt++;
	return cluster;
}

bool cluster_loop_check(struct cluster_list *cluster, struct in_addr originator)
{
	int i;

	for (i = 0; i < cluster->length / 4; i++)
		if (cluster->list[i].s_addr == originator.s_addr)
			return true;
	return false;
}

static unsigned int cluster_hash_key_make(const void *p)
{
	const struct cluster_list *cluster = p;

	return jhash(cluster->list, cluster->length, 0);
}

static bool cluster_hash_cmp(const void *p1, const void *p2)
{
	const struct cluster_list *cluster1 = p1;
	const struct cluster_list *cluster2 = p2;

	if (cluster1->list == cluster2->list)
		return true;

	if (!cluster1->list || !cluster2->list)
		return false;

	if (cluster1->length != cluster2->length)
		return false;

	return (memcmp(cluster1->list, cluster2->list, cluster1->length) == 0);
}

static void cluster_free(struct cluster_list *cluster)
{
	XFREE(MTYPE_CLUSTER_VAL, cluster->list);
	XFREE(MTYPE_CLUSTER, cluster);
}

static struct cluster_list *cluster_intern(struct cluster_list *cluster)
{
	struct cluster_list *find;

	find = hash_get(cluster_hash, cluster, cluster_hash_alloc);
	find->refcnt++;

	return find;
}

static void cluster_unintern(struct cluster_list **cluster)
{
	if ((*cluster)->refcnt)
		(*cluster)->refcnt--;

	if ((*cluster)->refcnt == 0) {
		void *p = hash_release(cluster_hash, *cluster);
		assert(p == *cluster);
		cluster_free(*cluster);
		*cluster = NULL;
	}
}

static void cluster_init(void)
{
	cluster_hash = hash_create(cluster_hash_key_make, cluster_hash_cmp,
				   "BGP Cluster");
}

static void cluster_finish(void)
{
	hash_clean(cluster_hash, (void (*)(void *))cluster_free);
	hash_free(cluster_hash);
	cluster_hash = NULL;
}

static struct hash *encap_hash = NULL;
#ifdef ENABLE_BGP_VNC
static struct hash *vnc_hash = NULL;
#endif
static struct hash *srv6_l3vpn_hash;
static struct hash *srv6_vpn_hash;

struct bgp_attr_encap_subtlv *encap_tlv_dup(struct bgp_attr_encap_subtlv *orig)
{
	struct bgp_attr_encap_subtlv *new;
	struct bgp_attr_encap_subtlv *tail;
	struct bgp_attr_encap_subtlv *p;

	for (p = orig, tail = new = NULL; p; p = p->next) {
		int size = sizeof(struct bgp_attr_encap_subtlv) + p->length;
		if (tail) {
			tail->next = XCALLOC(MTYPE_ENCAP_TLV, size);
			tail = tail->next;
		} else {
			tail = new = XCALLOC(MTYPE_ENCAP_TLV, size);
		}
		assert(tail);
		memcpy(tail, p, size);
		tail->next = NULL;
	}

	return new;
}

static void encap_free(struct bgp_attr_encap_subtlv *p)
{
	struct bgp_attr_encap_subtlv *next;
	while (p) {
		next = p->next;
		p->next = NULL;
		XFREE(MTYPE_ENCAP_TLV, p);
		p = next;
	}
}

void bgp_attr_flush_encap(struct attr *attr)
{
	if (!attr)
		return;

	if (attr->encap_subtlvs) {
		encap_free(attr->encap_subtlvs);
		attr->encap_subtlvs = NULL;
	}
#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs) {
		encap_free(attr->vnc_subtlvs);
		attr->vnc_subtlvs = NULL;
	}
#endif
}

/*
 * Compare encap sub-tlv chains
 *
 *	1 = equivalent
 *	0 = not equivalent
 *
 * This algorithm could be made faster if needed
 */
static bool encap_same(const struct bgp_attr_encap_subtlv *h1,
		       const struct bgp_attr_encap_subtlv *h2)
{
	const struct bgp_attr_encap_subtlv *p;
	const struct bgp_attr_encap_subtlv *q;

	if (h1 == h2)
		return true;
	if (h1 == NULL || h2 == NULL)
		return false;

	for (p = h1; p; p = p->next) {
		for (q = h2; q; q = q->next) {
			if ((p->type == q->type) && (p->length == q->length)
			    && !memcmp(p->value, q->value, p->length)) {

				break;
			}
		}
		if (!q)
			return false;
	}

	for (p = h2; p; p = p->next) {
		for (q = h1; q; q = q->next) {
			if ((p->type == q->type) && (p->length == q->length)
			    && !memcmp(p->value, q->value, p->length)) {

				break;
			}
		}
		if (!q)
			return false;
	}

	return true;
}

static void *encap_hash_alloc(void *p)
{
	/* Encap structure is already allocated.  */
	return p;
}

typedef enum {
	ENCAP_SUBTLV_TYPE,
#ifdef ENABLE_BGP_VNC
	VNC_SUBTLV_TYPE
#endif
} encap_subtlv_type;

static struct bgp_attr_encap_subtlv *
encap_intern(struct bgp_attr_encap_subtlv *encap, encap_subtlv_type type)
{
	struct bgp_attr_encap_subtlv *find;
	struct hash *hash = encap_hash;
#ifdef ENABLE_BGP_VNC
	if (type == VNC_SUBTLV_TYPE)
		hash = vnc_hash;
#endif

	find = hash_get(hash, encap, encap_hash_alloc);
	if (find != encap)
		encap_free(encap);
	find->refcnt++;

	return find;
}

static void encap_unintern(struct bgp_attr_encap_subtlv **encapp,
			   encap_subtlv_type type)
{
	struct bgp_attr_encap_subtlv *encap = *encapp;
	if (encap->refcnt)
		encap->refcnt--;

	if (encap->refcnt == 0) {
		struct hash *hash = encap_hash;
#ifdef ENABLE_BGP_VNC
		if (type == VNC_SUBTLV_TYPE)
			hash = vnc_hash;
#endif
		hash_release(hash, encap);
		encap_free(encap);
		*encapp = NULL;
	}
}

static unsigned int encap_hash_key_make(const void *p)
{
	const struct bgp_attr_encap_subtlv *encap = p;

	return jhash(encap->value, encap->length, 0);
}

static bool encap_hash_cmp(const void *p1, const void *p2)
{
	return encap_same((const struct bgp_attr_encap_subtlv *)p1,
			  (const struct bgp_attr_encap_subtlv *)p2);
}

static void encap_init(void)
{
	encap_hash = hash_create(encap_hash_key_make, encap_hash_cmp,
				 "BGP Encap Hash");
#ifdef ENABLE_BGP_VNC
	vnc_hash = hash_create(encap_hash_key_make, encap_hash_cmp,
			       "BGP VNC Hash");
#endif
}

static void encap_finish(void)
{
	hash_clean(encap_hash, (void (*)(void *))encap_free);
	hash_free(encap_hash);
	encap_hash = NULL;
#ifdef ENABLE_BGP_VNC
	hash_clean(vnc_hash, (void (*)(void *))encap_free);
	hash_free(vnc_hash);
	vnc_hash = NULL;
#endif
}

static bool overlay_index_same(const struct attr *a1, const struct attr *a2)
{
	if (!a1 && a2)
		return false;
	if (!a2 && a1)
		return false;
	if (!a1 && !a2)
		return true;
	return !memcmp(&(a1->evpn_overlay), &(a2->evpn_overlay),
		       sizeof(struct bgp_route_evpn));
}

/* Unknown transit attribute. */
static struct hash *transit_hash;

static void transit_free(struct transit *transit)
{
	XFREE(MTYPE_TRANSIT_VAL, transit->val);
	XFREE(MTYPE_TRANSIT, transit);
}

static void *transit_hash_alloc(void *p)
{
	/* Transit structure is already allocated.  */
	return p;
}

static struct transit *transit_intern(struct transit *transit)
{
	struct transit *find;

	find = hash_get(transit_hash, transit, transit_hash_alloc);
	if (find != transit)
		transit_free(transit);
	find->refcnt++;

	return find;
}

static void transit_unintern(struct transit **transit)
{
	if ((*transit)->refcnt)
		(*transit)->refcnt--;

	if ((*transit)->refcnt == 0) {
		hash_release(transit_hash, *transit);
		transit_free(*transit);
		*transit = NULL;
	}
}

static void *srv6_l3vpn_hash_alloc(void *p)
{
	return p;
}

static void srv6_l3vpn_free(struct bgp_attr_srv6_l3vpn *l3vpn)
{
	XFREE(MTYPE_BGP_SRV6_L3VPN, l3vpn);
}

static struct bgp_attr_srv6_l3vpn *
srv6_l3vpn_intern(struct bgp_attr_srv6_l3vpn *l3vpn)
{
	struct bgp_attr_srv6_l3vpn *find;

	find = hash_get(srv6_l3vpn_hash, l3vpn, srv6_l3vpn_hash_alloc);
	if (find != l3vpn)
		srv6_l3vpn_free(l3vpn);
	find->refcnt++;
	return find;
}

static void srv6_l3vpn_unintern(struct bgp_attr_srv6_l3vpn **l3vpnp)
{
	struct bgp_attr_srv6_l3vpn *l3vpn = *l3vpnp;

	if (l3vpn->refcnt)
		l3vpn->refcnt--;

	if (l3vpn->refcnt == 0) {
		hash_release(srv6_l3vpn_hash, l3vpn);
		srv6_l3vpn_free(l3vpn);
		*l3vpnp = NULL;
	}
}

static void *srv6_vpn_hash_alloc(void *p)
{
	return p;
}

static void srv6_vpn_free(struct bgp_attr_srv6_vpn *vpn)
{
	XFREE(MTYPE_BGP_SRV6_VPN, vpn);
}

static struct bgp_attr_srv6_vpn *srv6_vpn_intern(struct bgp_attr_srv6_vpn *vpn)
{
	struct bgp_attr_srv6_vpn *find;

	find = hash_get(srv6_vpn_hash, vpn, srv6_vpn_hash_alloc);
	if (find != vpn)
		srv6_vpn_free(vpn);
	find->refcnt++;
	return find;
}

static void srv6_vpn_unintern(struct bgp_attr_srv6_vpn **vpnp)
{
	struct bgp_attr_srv6_vpn *vpn = *vpnp;

	if (vpn->refcnt)
		vpn->refcnt--;

	if (vpn->refcnt == 0) {
		hash_release(srv6_vpn_hash, vpn);
		srv6_vpn_free(vpn);
		*vpnp = NULL;
	}
}

static uint32_t srv6_l3vpn_hash_key_make(const void *p)
{
	const struct bgp_attr_srv6_l3vpn *l3vpn = p;
	uint32_t key = 0;

	key = jhash(&l3vpn->sid, 16, key);
	key = jhash_1word(l3vpn->sid_flags, key);
	key = jhash_1word(l3vpn->endpoint_behavior, key);
	return key;
}

static bool srv6_l3vpn_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_attr_srv6_l3vpn *l3vpn1 = p1;
	const struct bgp_attr_srv6_l3vpn *l3vpn2 = p2;

	return sid_same(&l3vpn1->sid, &l3vpn2->sid)
	       && l3vpn1->sid_flags == l3vpn2->sid_flags
	       && l3vpn1->endpoint_behavior == l3vpn2->endpoint_behavior;
}

static bool srv6_l3vpn_same(const struct bgp_attr_srv6_l3vpn *h1,
			    const struct bgp_attr_srv6_l3vpn *h2)
{
	if (h1 == h2)
		return true;
	else if (h1 == NULL || h2 == NULL)
		return false;
	else
		return srv6_l3vpn_hash_cmp((const void *)h1, (const void *)h2);
}

static unsigned int srv6_vpn_hash_key_make(const void *p)
{
	const struct bgp_attr_srv6_vpn *vpn = p;
	uint32_t key = 0;

	key = jhash(&vpn->sid, 16, key);
	key = jhash_1word(vpn->sid_flags, key);
	return key;
}

static bool srv6_vpn_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_attr_srv6_vpn *vpn1 = p1;
	const struct bgp_attr_srv6_vpn *vpn2 = p2;

	return sid_same(&vpn1->sid, &vpn2->sid)
	       && vpn1->sid_flags == vpn2->sid_flags;
}

static bool srv6_vpn_same(const struct bgp_attr_srv6_vpn *h1,
			  const struct bgp_attr_srv6_vpn *h2)
{
	if (h1 == h2)
		return true;
	else if (h1 == NULL || h2 == NULL)
		return false;
	else
		return srv6_vpn_hash_cmp((const void *)h1, (const void *)h2);
}

static void srv6_init(void)
{
	srv6_l3vpn_hash =
		hash_create(srv6_l3vpn_hash_key_make, srv6_l3vpn_hash_cmp,
			    "BGP Prefix-SID SRv6-L3VPN-Service-TLV");
	srv6_vpn_hash = hash_create(srv6_vpn_hash_key_make, srv6_vpn_hash_cmp,
				    "BGP Prefix-SID SRv6-VPN-Service-TLV");
}

static void srv6_finish(void)
{
	hash_clean(srv6_l3vpn_hash, (void (*)(void *))srv6_l3vpn_free);
	hash_free(srv6_l3vpn_hash);
	srv6_l3vpn_hash = NULL;
	hash_clean(srv6_vpn_hash, (void (*)(void *))srv6_vpn_free);
	hash_free(srv6_vpn_hash);
	srv6_vpn_hash = NULL;
}

static unsigned int transit_hash_key_make(const void *p)
{
	const struct transit *transit = p;

	return jhash(transit->val, transit->length, 0);
}

static bool transit_hash_cmp(const void *p1, const void *p2)
{
	const struct transit *transit1 = p1;
	const struct transit *transit2 = p2;

	return (transit1->length == transit2->length
		&& memcmp(transit1->val, transit2->val, transit1->length) == 0);
}

static void transit_init(void)
{
	transit_hash = hash_create(transit_hash_key_make, transit_hash_cmp,
				   "BGP Transit Hash");
}

static void transit_finish(void)
{
	hash_clean(transit_hash, (void (*)(void *))transit_free);
	hash_free(transit_hash);
	transit_hash = NULL;
}

/* Attribute hash routines. */
static struct hash *attrhash;

unsigned long int attr_count(void)
{
	return attrhash->count;
}

unsigned long int attr_unknown_count(void)
{
	return transit_hash->count;
}

unsigned int attrhash_key_make(const void *p)
{
	const struct attr *attr = (struct attr *)p;
	uint32_t key = 0;
#define MIX(val)	key = jhash_1word(val, key)
#define MIX3(a, b, c)	key = jhash_3words((a), (b), (c), key)

	MIX3(attr->origin, attr->nexthop.s_addr, attr->med);
	MIX3(attr->local_pref, attr->aggregator_as,
	     attr->aggregator_addr.s_addr);
	MIX3(attr->weight, attr->mp_nexthop_global_in.s_addr,
	     attr->originator_id.s_addr);
	MIX3(attr->tag, attr->label, attr->label_index);

	if (attr->aspath)
		MIX(aspath_key_make(attr->aspath));
	if (attr->community)
		MIX(community_hash_make(attr->community));

	if (attr->lcommunity)
		MIX(lcommunity_hash_make(attr->lcommunity));
	if (attr->ecommunity)
		MIX(ecommunity_hash_make(attr->ecommunity));
	if (attr->cluster)
		MIX(cluster_hash_key_make(attr->cluster));
	if (attr->transit)
		MIX(transit_hash_key_make(attr->transit));
	if (attr->encap_subtlvs)
		MIX(encap_hash_key_make(attr->encap_subtlvs));
#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs)
		MIX(encap_hash_key_make(attr->vnc_subtlvs));
#endif
	MIX(attr->mp_nexthop_len);
	key = jhash(attr->mp_nexthop_global.s6_addr, IPV6_MAX_BYTELEN, key);
	key = jhash(attr->mp_nexthop_local.s6_addr, IPV6_MAX_BYTELEN, key);
	MIX3(attr->nh_ifindex, attr->nh_lla_ifindex, attr->distance);
	MIX(attr->rmap_table_id);

	return key;
}

bool attrhash_cmp(const void *p1, const void *p2)
{
	const struct attr *attr1 = p1;
	const struct attr *attr2 = p2;

	if (attr1->flag == attr2->flag && attr1->origin == attr2->origin
	    && attr1->nexthop.s_addr == attr2->nexthop.s_addr
	    && attr1->aspath == attr2->aspath
	    && attr1->community == attr2->community && attr1->med == attr2->med
	    && attr1->local_pref == attr2->local_pref
	    && attr1->rmap_change_flags == attr2->rmap_change_flags) {
		if (attr1->aggregator_as == attr2->aggregator_as
		    && attr1->aggregator_addr.s_addr
			       == attr2->aggregator_addr.s_addr
		    && attr1->weight == attr2->weight
		    && attr1->tag == attr2->tag
		    && attr1->label_index == attr2->label_index
		    && attr1->mp_nexthop_len == attr2->mp_nexthop_len
		    && attr1->ecommunity == attr2->ecommunity
		    && attr1->lcommunity == attr2->lcommunity
		    && attr1->cluster == attr2->cluster
		    && attr1->transit == attr2->transit
		    && attr1->rmap_table_id == attr2->rmap_table_id
		    && (attr1->encap_tunneltype == attr2->encap_tunneltype)
		    && encap_same(attr1->encap_subtlvs, attr2->encap_subtlvs)
#ifdef ENABLE_BGP_VNC
		    && encap_same(attr1->vnc_subtlvs, attr2->vnc_subtlvs)
#endif
		    && IPV6_ADDR_SAME(&attr1->mp_nexthop_global,
				      &attr2->mp_nexthop_global)
		    && IPV6_ADDR_SAME(&attr1->mp_nexthop_local,
				      &attr2->mp_nexthop_local)
		    && IPV4_ADDR_SAME(&attr1->mp_nexthop_global_in,
				      &attr2->mp_nexthop_global_in)
		    && IPV4_ADDR_SAME(&attr1->originator_id,
				      &attr2->originator_id)
		    && overlay_index_same(attr1, attr2)
		    && !memcmp(&attr1->esi, &attr2->esi, sizeof(esi_t))
		    && attr1->es_flags == attr2->es_flags
		    && attr1->mm_sync_seqnum == attr2->mm_sync_seqnum
		    && attr1->df_pref == attr2->df_pref
		    && attr1->df_alg == attr2->df_alg
		    && attr1->nh_ifindex == attr2->nh_ifindex
		    && attr1->nh_lla_ifindex == attr2->nh_lla_ifindex
		    && attr1->distance == attr2->distance
		    && srv6_l3vpn_same(attr1->srv6_l3vpn, attr2->srv6_l3vpn)
		    && srv6_vpn_same(attr1->srv6_vpn, attr2->srv6_vpn))
			return true;
	}

	return false;
}

static void attrhash_init(void)
{
	attrhash =
		hash_create(attrhash_key_make, attrhash_cmp, "BGP Attributes");
}

/*
 * special for hash_clean below
 */
static void attr_vfree(void *attr)
{
	XFREE(MTYPE_ATTR, attr);
}

static void attrhash_finish(void)
{
	hash_clean(attrhash, attr_vfree);
	hash_free(attrhash);
	attrhash = NULL;
}

static void attr_show_all_iterator(struct hash_bucket *bucket, struct vty *vty)
{
	struct attr *attr = bucket->data;
	char sid_str[BUFSIZ];

	vty_out(vty, "attr[%ld] nexthop %s\n", attr->refcnt,
		inet_ntoa(attr->nexthop));

	sid_str[0] = '\0';
	if (attr->srv6_l3vpn)
		inet_ntop(AF_INET6, &attr->srv6_l3vpn->sid, sid_str, BUFSIZ);
	else if (attr->srv6_vpn)
		inet_ntop(AF_INET6, &attr->srv6_vpn->sid, sid_str, BUFSIZ);

	vty_out(vty,
		"\tflags: %" PRIu64
		" med: %u local_pref: %u origin: %u weight: %u label: %u sid: %s\n",
		attr->flag, attr->med, attr->local_pref, attr->origin,
		attr->weight, attr->label, sid_str);
}

void attr_show_all(struct vty *vty)
{
	hash_iterate(attrhash, (void (*)(struct hash_bucket *,
					 void *))attr_show_all_iterator,
		     vty);
}

static void *bgp_attr_hash_alloc(void *p)
{
	struct attr *val = (struct attr *)p;
	struct attr *attr;

	attr = XMALLOC(MTYPE_ATTR, sizeof(struct attr));
	*attr = *val;
	if (val->encap_subtlvs) {
		val->encap_subtlvs = NULL;
	}
#ifdef ENABLE_BGP_VNC
	if (val->vnc_subtlvs) {
		val->vnc_subtlvs = NULL;
	}
#endif
	if (val->srv6_l3vpn)
		val->srv6_l3vpn = NULL;
	if (val->srv6_vpn)
		val->srv6_vpn = NULL;

	attr->refcnt = 0;
	return attr;
}

/* Internet argument attribute. */
struct attr *bgp_attr_intern(struct attr *attr)
{
	struct attr *find;

	/* Intern referenced strucutre. */
	if (attr->aspath) {
		if (!attr->aspath->refcnt)
			attr->aspath = aspath_intern(attr->aspath);
		else
			attr->aspath->refcnt++;
	}
	if (attr->community) {
		if (!attr->community->refcnt)
			attr->community = community_intern(attr->community);
		else
			attr->community->refcnt++;
	}

	if (attr->ecommunity) {
		if (!attr->ecommunity->refcnt)
			attr->ecommunity = ecommunity_intern(attr->ecommunity);
		else
			attr->ecommunity->refcnt++;
	}
	if (attr->lcommunity) {
		if (!attr->lcommunity->refcnt)
			attr->lcommunity = lcommunity_intern(attr->lcommunity);
		else
			attr->lcommunity->refcnt++;
	}
	if (attr->cluster) {
		if (!attr->cluster->refcnt)
			attr->cluster = cluster_intern(attr->cluster);
		else
			attr->cluster->refcnt++;
	}
	if (attr->transit) {
		if (!attr->transit->refcnt)
			attr->transit = transit_intern(attr->transit);
		else
			attr->transit->refcnt++;
	}
	if (attr->encap_subtlvs) {
		if (!attr->encap_subtlvs->refcnt)
			attr->encap_subtlvs = encap_intern(attr->encap_subtlvs,
							   ENCAP_SUBTLV_TYPE);
		else
			attr->encap_subtlvs->refcnt++;
	}
	if (attr->srv6_l3vpn) {
		if (!attr->srv6_l3vpn->refcnt)
			attr->srv6_l3vpn = srv6_l3vpn_intern(attr->srv6_l3vpn);
		else
			attr->srv6_l3vpn->refcnt++;
	}
	if (attr->srv6_vpn) {
		if (!attr->srv6_vpn->refcnt)
			attr->srv6_vpn = srv6_vpn_intern(attr->srv6_vpn);
		else
			attr->srv6_vpn->refcnt++;
	}
#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs) {
		if (!attr->vnc_subtlvs->refcnt)
			attr->vnc_subtlvs = encap_intern(attr->vnc_subtlvs,
							 VNC_SUBTLV_TYPE);
		else
			attr->vnc_subtlvs->refcnt++;
	}
#endif

	/* At this point, attr only contains intern'd pointers.  that means
	 * if we find it in attrhash, it has all the same pointers and we
	 * correctly updated the refcounts on these.
	 * If we don't find it, we need to allocate a one because in all
	 * cases this returns a new reference to a hashed attr, but the input
	 * wasn't on hash. */
	find = (struct attr *)hash_get(attrhash, attr, bgp_attr_hash_alloc);
	find->refcnt++;

	return find;
}

/* Make network statement's attribute. */
struct attr *bgp_attr_default_set(struct attr *attr, uint8_t origin)
{
	memset(attr, 0, sizeof(struct attr));

	attr->origin = origin;
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGIN);
	attr->aspath = aspath_empty();
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AS_PATH);
	attr->weight = BGP_ATTR_DEFAULT_WEIGHT;
	attr->tag = 0;
	attr->label_index = BGP_INVALID_LABEL_INDEX;
	attr->label = MPLS_INVALID_LABEL;
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
	attr->mp_nexthop_len = IPV6_MAX_BYTELEN;

	return attr;
}

/* Create the attributes for an aggregate */
struct attr *bgp_attr_aggregate_intern(
	struct bgp *bgp, uint8_t origin, struct aspath *aspath,
	struct community *community, struct ecommunity *ecommunity,
	struct lcommunity *lcommunity, struct bgp_aggregate *aggregate,
	uint8_t atomic_aggregate, const struct prefix *p)
{
	struct attr attr;
	struct attr *new;
	int ret;

	memset(&attr, 0, sizeof(struct attr));

	/* Origin attribute. */
	attr.origin = origin;
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGIN);

	/* AS path attribute. */
	if (aspath)
		attr.aspath = aspath_intern(aspath);
	else
		attr.aspath = aspath_empty();
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_AS_PATH);

	/* Next hop attribute.  */
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);

	if (community) {
		uint32_t gshut = COMMUNITY_GSHUT;

		/* If we are not shutting down ourselves and we are
		 * aggregating a route that contains the GSHUT community we
		 * need to remove that community when creating the aggregate */
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)
		    && community_include(community, gshut)) {
			community_del_val(community, &gshut);
		}

		attr.community = community;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);
	}

	if (ecommunity) {
		attr.ecommunity = ecommunity;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
	}

	if (lcommunity) {
		attr.lcommunity = lcommunity;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES);
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
		bgp_attr_add_gshut_community(&attr);

	attr.label_index = BGP_INVALID_LABEL_INDEX;
	attr.label = MPLS_INVALID_LABEL;
	attr.weight = BGP_ATTR_DEFAULT_WEIGHT;
	attr.mp_nexthop_len = IPV6_MAX_BYTELEN;
	if (!aggregate->as_set || atomic_aggregate)
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR);
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
		attr.aggregator_as = bgp->confed_id;
	else
		attr.aggregator_as = bgp->as;
	attr.aggregator_addr = bgp->router_id;
	attr.label_index = BGP_INVALID_LABEL_INDEX;
	attr.label = MPLS_INVALID_LABEL;

	/* Apply route-map */
	if (aggregate->rmap.name) {
		struct attr attr_tmp = attr;
		struct bgp_path_info rmap_path;

		memset(&rmap_path, 0, sizeof(struct bgp_path_info));
		rmap_path.peer = bgp->peer_self;
		rmap_path.attr = &attr_tmp;

		SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_AGGREGATE);

		ret = route_map_apply(aggregate->rmap.map, p, RMAP_BGP,
				      &rmap_path);

		bgp->peer_self->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			/* Free uninterned attribute. */
			bgp_attr_flush(&attr_tmp);

			/* Unintern original. */
			aspath_unintern(&attr.aspath);
			return NULL;
		}

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
			bgp_attr_add_gshut_community(&attr_tmp);

		new = bgp_attr_intern(&attr_tmp);
	} else {

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
			bgp_attr_add_gshut_community(&attr);

		new = bgp_attr_intern(&attr);
	}

	aspath_unintern(&new->aspath);
	return new;
}

/* Unintern just the sub-components of the attr, but not the attr */
void bgp_attr_unintern_sub(struct attr *attr)
{
	/* aspath refcount shoud be decrement. */
	if (attr->aspath)
		aspath_unintern(&attr->aspath);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));

	if (attr->community)
		community_unintern(&attr->community);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES));

	if (attr->ecommunity)
		ecommunity_unintern(&attr->ecommunity);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));

	if (attr->lcommunity)
		lcommunity_unintern(&attr->lcommunity);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES));

	if (attr->cluster)
		cluster_unintern(&attr->cluster);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST));

	if (attr->transit)
		transit_unintern(&attr->transit);

	if (attr->encap_subtlvs)
		encap_unintern(&attr->encap_subtlvs, ENCAP_SUBTLV_TYPE);

#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs)
		encap_unintern(&attr->vnc_subtlvs, VNC_SUBTLV_TYPE);
#endif

	if (attr->srv6_l3vpn)
		srv6_l3vpn_unintern(&attr->srv6_l3vpn);

	if (attr->srv6_vpn)
		srv6_vpn_unintern(&attr->srv6_vpn);
}

/*
 * We have some show commands that let you experimentally
 * apply a route-map.  When we apply the route-map
 * we are reseting values but not saving them for
 * posterity via intern'ing( because route-maps don't
 * do that) but at this point in time we need
 * to compare the new attr to the old and if the
 * routemap has changed it we need to, as Snoop Dog says,
 * Drop it like it's hot
 */
void bgp_attr_undup(struct attr *new, struct attr *old)
{
	if (new->aspath != old->aspath)
		aspath_free(new->aspath);

	if (new->community != old->community)
		community_free(&new->community);

	if (new->ecommunity != old->ecommunity)
		ecommunity_free(&new->ecommunity);

	if (new->lcommunity != old->lcommunity)
		lcommunity_free(&new->lcommunity);
}

/* Free bgp attribute and aspath. */
void bgp_attr_unintern(struct attr **pattr)
{
	struct attr *attr = *pattr;
	struct attr *ret;
	struct attr tmp;

	/* Decrement attribute reference. */
	attr->refcnt--;

	tmp = *attr;

	/* If reference becomes zero then free attribute object. */
	if (attr->refcnt == 0) {
		ret = hash_release(attrhash, attr);
		assert(ret != NULL);
		XFREE(MTYPE_ATTR, attr);
		*pattr = NULL;
	}

	bgp_attr_unintern_sub(&tmp);
}

void bgp_attr_flush(struct attr *attr)
{
	if (attr->aspath && !attr->aspath->refcnt) {
		aspath_free(attr->aspath);
		attr->aspath = NULL;
	}
	if (attr->community && !attr->community->refcnt)
		community_free(&attr->community);
	if (attr->ecommunity && !attr->ecommunity->refcnt)
		ecommunity_free(&attr->ecommunity);
	if (attr->lcommunity && !attr->lcommunity->refcnt)
		lcommunity_free(&attr->lcommunity);
	if (attr->cluster && !attr->cluster->refcnt) {
		cluster_free(attr->cluster);
		attr->cluster = NULL;
	}
	if (attr->transit && !attr->transit->refcnt) {
		transit_free(attr->transit);
		attr->transit = NULL;
	}
	if (attr->encap_subtlvs && !attr->encap_subtlvs->refcnt) {
		encap_free(attr->encap_subtlvs);
		attr->encap_subtlvs = NULL;
	}
#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs && !attr->vnc_subtlvs->refcnt) {
		encap_free(attr->vnc_subtlvs);
		attr->vnc_subtlvs = NULL;
	}
#endif
}

/* Implement draft-scudder-idr-optional-transitive behaviour and
 * avoid resetting sessions for malformed attributes which are
 * are partial/optional and hence where the error likely was not
 * introduced by the sending neighbour.
 */
static bgp_attr_parse_ret_t
bgp_attr_malformed(struct bgp_attr_parser_args *args, uint8_t subcode,
		   bgp_size_t length)
{
	struct peer *const peer = args->peer;
	const uint8_t flags = args->flags;
	/* startp and length must be special-cased, as whether or not to
	 * send the attribute data with the NOTIFY depends on the error,
	 * the caller therefore signals this with the seperate length argument
	 */
	uint8_t *notify_datap = (length > 0 ? args->startp : NULL);

	/* Only relax error handling for eBGP peers */
	if (peer->sort != BGP_PEER_EBGP) {
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR, subcode,
					  notify_datap, length);
		return BGP_ATTR_PARSE_ERROR;
	}

	/* Adjust the stream getp to the end of the attribute, in case we can
	 * still proceed but the caller hasn't read all the attribute.
	 */
	stream_set_getp(BGP_INPUT(peer),
			(args->startp - STREAM_DATA(BGP_INPUT(peer)))
				+ args->total);

	switch (args->type) {
	/* where an attribute is relatively inconsequential, e.g. it does not
	 * affect route selection, and can be safely ignored, then any such
	 * attributes which are malformed should just be ignored and the route
	 * processed as normal.
	 */
	case BGP_ATTR_AS4_AGGREGATOR:
	case BGP_ATTR_AGGREGATOR:
	case BGP_ATTR_ATOMIC_AGGREGATE:
		return BGP_ATTR_PARSE_PROCEED;

	/* Core attributes, particularly ones which may influence route
	 * selection, should be treat-as-withdraw.
	 */
	case BGP_ATTR_ORIGIN:
	case BGP_ATTR_AS_PATH:
	case BGP_ATTR_NEXT_HOP:
	case BGP_ATTR_MULTI_EXIT_DISC:
	case BGP_ATTR_LOCAL_PREF:
	case BGP_ATTR_COMMUNITIES:
	case BGP_ATTR_EXT_COMMUNITIES:
	case BGP_ATTR_LARGE_COMMUNITIES:
	case BGP_ATTR_ORIGINATOR_ID:
	case BGP_ATTR_CLUSTER_LIST:
		return BGP_ATTR_PARSE_WITHDRAW;
	case BGP_ATTR_MP_REACH_NLRI:
	case BGP_ATTR_MP_UNREACH_NLRI:
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR, subcode,
					  notify_datap, length);
		return BGP_ATTR_PARSE_ERROR;
	}

	/* Partial optional attributes that are malformed should not cause
	 * the whole session to be reset. Instead treat it as a withdrawal
	 * of the routes, if possible.
	 */
	if (CHECK_FLAG(flags, BGP_ATTR_FLAG_TRANS)
	    && CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL)
	    && CHECK_FLAG(flags, BGP_ATTR_FLAG_PARTIAL))
		return BGP_ATTR_PARSE_WITHDRAW;

	/* default to reset */
	return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
}

/* Find out what is wrong with the path attribute flag bits and log the error.
   "Flag bits" here stand for Optional, Transitive and Partial, but not for
   Extended Length. Checking O/T/P bits at once implies, that the attribute
   being diagnosed is defined by RFC as either a "well-known" or an "optional,
   non-transitive" attribute. */
static void
bgp_attr_flags_diagnose(struct bgp_attr_parser_args *args,
			uint8_t desired_flags /* how RFC says it must be */
)
{
	uint8_t seen = 0, i;
	uint8_t real_flags = args->flags;
	const uint8_t attr_code = args->type;

	desired_flags &= ~BGP_ATTR_FLAG_EXTLEN;
	real_flags &= ~BGP_ATTR_FLAG_EXTLEN;
	for (i = 0; i <= 2; i++) /* O,T,P, but not E */
		if (CHECK_FLAG(desired_flags, attr_flag_str[i].key)
		    != CHECK_FLAG(real_flags, attr_flag_str[i].key)) {
			flog_err(EC_BGP_ATTR_FLAG,
				 "%s attribute must%s be flagged as \"%s\"",
				 lookup_msg(attr_str, attr_code, NULL),
				 CHECK_FLAG(desired_flags, attr_flag_str[i].key)
					 ? ""
					 : " not",
				 attr_flag_str[i].str);
			seen = 1;
		}
	if (!seen) {
		zlog_debug(
			"Strange, %s called for attr %s, but no problem found with flags"
			" (real flags 0x%x, desired 0x%x)",
			__func__, lookup_msg(attr_str, attr_code, NULL),
			real_flags, desired_flags);
	}
}

/* Required flags for attributes. EXTLEN will be masked off when testing,
 * as will PARTIAL for optional+transitive attributes.
 */
const uint8_t attr_flags_values[] = {
	[BGP_ATTR_ORIGIN] = BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_AS_PATH] = BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_NEXT_HOP] = BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_MULTI_EXIT_DISC] = BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_LOCAL_PREF] = BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_ATOMIC_AGGREGATE] = BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_AGGREGATOR] = BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_COMMUNITIES] = BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_ORIGINATOR_ID] = BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_CLUSTER_LIST] = BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_MP_REACH_NLRI] = BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_MP_UNREACH_NLRI] = BGP_ATTR_FLAG_OPTIONAL,
	[BGP_ATTR_EXT_COMMUNITIES] =
		BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_AS4_PATH] = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_AS4_AGGREGATOR] =
		BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_PMSI_TUNNEL] = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_LARGE_COMMUNITIES] =
		BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_PREFIX_SID] = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
};
static const size_t attr_flags_values_max = array_size(attr_flags_values) - 1;

static bool bgp_attr_flag_invalid(struct bgp_attr_parser_args *args)
{
	uint8_t mask = BGP_ATTR_FLAG_EXTLEN;
	const uint8_t flags = args->flags;
	const uint8_t attr_code = args->type;

	/* there may be attributes we don't know about */
	if (attr_code > attr_flags_values_max)
		return false;
	if (attr_flags_values[attr_code] == 0)
		return false;

	/* RFC4271, "For well-known attributes, the Transitive bit MUST be set
	 * to
	 * 1."
	 */
	if (!CHECK_FLAG(BGP_ATTR_FLAG_OPTIONAL, flags)
	    && !CHECK_FLAG(BGP_ATTR_FLAG_TRANS, flags)) {
		flog_err(
			EC_BGP_ATTR_FLAG,
			"%s well-known attributes must have transitive flag set (%x)",
			lookup_msg(attr_str, attr_code, NULL), flags);
		return true;
	}

	/* "For well-known attributes and for optional non-transitive
	 * attributes,
	 *  the Partial bit MUST be set to 0."
	 */
	if (CHECK_FLAG(flags, BGP_ATTR_FLAG_PARTIAL)) {
		if (!CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL)) {
			flog_err(EC_BGP_ATTR_FLAG,
				 "%s well-known attribute "
				 "must NOT have the partial flag set (%x)",
				 lookup_msg(attr_str, attr_code, NULL), flags);
			return true;
		}
		if (CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL)
		    && !CHECK_FLAG(flags, BGP_ATTR_FLAG_TRANS)) {
			flog_err(EC_BGP_ATTR_FLAG,
				 "%s optional + transitive attribute "
				 "must NOT have the partial flag set (%x)",
				 lookup_msg(attr_str, attr_code, NULL), flags);
			return true;
		}
	}

	/* Optional transitive attributes may go through speakers that don't
	 * reocgnise them and set the Partial bit.
	 */
	if (CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL)
	    && CHECK_FLAG(flags, BGP_ATTR_FLAG_TRANS))
		SET_FLAG(mask, BGP_ATTR_FLAG_PARTIAL);

	if ((flags & ~mask) == attr_flags_values[attr_code])
		return false;

	bgp_attr_flags_diagnose(args, attr_flags_values[attr_code]);
	return true;
}

/* Get origin attribute of the update message. */
static bgp_attr_parse_ret_t bgp_attr_origin(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* If any recognized attribute has Attribute Length that conflicts
	   with the expected length (based on the attribute type code), then
	   the Error Subcode is set to Attribute Length Error.  The Data
	   field contains the erroneous attribute (type, length and
	   value). */
	if (length != 1) {
		flog_err(EC_BGP_ATTR_LEN,
			 "Origin attribute length is not one %d", length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	/* Fetch origin attribute. */
	attr->origin = stream_getc(BGP_INPUT(peer));

	/* If the ORIGIN attribute has an undefined value, then the Error
	   Subcode is set to Invalid Origin Attribute.  The Data field
	   contains the unrecognized attribute (type, length and value). */
	if ((attr->origin != BGP_ORIGIN_IGP) && (attr->origin != BGP_ORIGIN_EGP)
	    && (attr->origin != BGP_ORIGIN_INCOMPLETE)) {
		flog_err(EC_BGP_ATTR_ORIGIN,
			 "Origin attribute value is invalid %d", attr->origin);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_INVAL_ORIGIN,
					  args->total);
	}

	/* Set oring attribute flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGIN);

	return 0;
}

/* Parse AS path information.  This function is wrapper of
   aspath_parse. */
static int bgp_attr_aspath(struct bgp_attr_parser_args *args)
{
	struct attr *const attr = args->attr;
	struct peer *const peer = args->peer;
	const bgp_size_t length = args->length;

	/*
	 * peer with AS4 => will get 4Byte ASnums
	 * otherwise, will get 16 Bit
	 */
	attr->aspath = aspath_parse(peer->curr, length,
				    CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV));

	/* In case of IBGP, length will be zero. */
	if (!attr->aspath) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "Malformed AS path from %s, length is %d", peer->host,
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Codification of AS 0 Processing */
	if (aspath_check_as_zero(attr->aspath)) {
		flog_err(
			EC_BGP_ATTR_MAL_AS_PATH,
			"Malformed AS path, AS number is 0 in the path from %s",
			peer->host);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Set aspath attribute flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AS_PATH);

	return BGP_ATTR_PARSE_PROCEED;
}

static bgp_attr_parse_ret_t bgp_attr_aspath_check(struct peer *const peer,
						  struct attr *const attr)
{
	/* These checks were part of bgp_attr_aspath, but with
	 * as4 we should to check aspath things when
	 * aspath synthesizing with as4_path has already taken place.
	 * Otherwise we check ASPATH and use the synthesized thing, and that is
	 * not right.
	 * So do the checks later, i.e. here
	 */
	struct aspath *aspath;

	/* Confederation sanity check. */
	if ((peer->sort == BGP_PEER_CONFED
	     && !aspath_left_confed_check(attr->aspath))
	    || (peer->sort == BGP_PEER_EBGP
		&& aspath_confed_check(attr->aspath))) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH, "Malformed AS path from %s",
			 peer->host);
		return BGP_ATTR_PARSE_WITHDRAW;
	}

	/* First AS check for EBGP. */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_ENFORCE_FIRST_AS)) {
		if (peer->sort == BGP_PEER_EBGP
		    && !aspath_firstas_check(attr->aspath, peer->as)) {
			flog_err(EC_BGP_ATTR_FIRST_AS,
				 "%s incorrect first AS (must be %u)",
				 peer->host, peer->as);
			return BGP_ATTR_PARSE_WITHDRAW;
		}
	}

	/* local-as prepend */
	if (peer->change_local_as
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND)) {
		aspath = aspath_dup(attr->aspath);
		aspath = aspath_add_seq(aspath, peer->change_local_as);
		aspath_unintern(&attr->aspath);
		attr->aspath = aspath_intern(aspath);
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* Parse AS4 path information.  This function is another wrapper of
   aspath_parse. */
static int bgp_attr_as4_path(struct bgp_attr_parser_args *args,
			     struct aspath **as4_path)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	*as4_path = aspath_parse(peer->curr, length, 1);

	/* In case of IBGP, length will be zero. */
	if (!*as4_path) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "Malformed AS4 path from %s, length is %d", peer->host,
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Codification of AS 0 Processing */
	if (aspath_check_as_zero(*as4_path)) {
		flog_err(
			EC_BGP_ATTR_MAL_AS_PATH,
			"Malformed AS path, AS number is 0 in the path from %s",
			peer->host);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Set aspath attribute flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH);

	return BGP_ATTR_PARSE_PROCEED;
}

/*
 * Check that the nexthop attribute is valid.
 */
bgp_attr_parse_ret_t
bgp_attr_nexthop_valid(struct peer *peer, struct attr *attr)
{
	in_addr_t nexthop_h;

	nexthop_h = ntohl(attr->nexthop.s_addr);
	if ((IPV4_NET0(nexthop_h) || IPV4_NET127(nexthop_h)
	     || IPV4_CLASS_DE(nexthop_h))
	    && !BGP_DEBUG(allow_martians, ALLOW_MARTIANS)) {
		uint8_t data[7]; /* type(2) + length(1) + nhop(4) */
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &attr->nexthop.s_addr, buf,
			  INET_ADDRSTRLEN);
		flog_err(EC_BGP_ATTR_MARTIAN_NH, "Martian nexthop %s",
			 buf);
		data[0] = BGP_ATTR_FLAG_TRANS;
		data[1] = BGP_ATTR_NEXT_HOP;
		data[2] = BGP_ATTR_NHLEN_IPV4;
		memcpy(&data[3], &attr->nexthop.s_addr, BGP_ATTR_NHLEN_IPV4);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR,
					  BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP,
					  data, 7);
		return BGP_ATTR_PARSE_ERROR;
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* Nexthop attribute. */
static bgp_attr_parse_ret_t bgp_attr_nexthop(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* Check nexthop attribute length. */
	if (length != 4) {
		flog_err(EC_BGP_ATTR_LEN,
			 "Nexthop attribute length isn't four [%d]", length);

		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	attr->nexthop.s_addr = stream_get_ipv4(peer->curr);
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);

	return BGP_ATTR_PARSE_PROCEED;
}

/* MED atrribute. */
static bgp_attr_parse_ret_t bgp_attr_med(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* Length check. */
	if (length != 4) {
		flog_err(EC_BGP_ATTR_LEN,
			 "MED attribute length isn't four [%d]", length);

		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	attr->med = stream_getl(peer->curr);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Local preference attribute. */
static bgp_attr_parse_ret_t
bgp_attr_local_pref(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* if received from an internal neighbor, it SHALL be considered
	 * malformed if its length is not equal to 4. If malformed, the
	 * UPDATE message SHALL be handled using the approach of "treat-as-
	 * withdraw".
	 */
	if (peer->sort == BGP_PEER_IBGP && length != 4) {
		flog_err(EC_BGP_ATTR_LEN,
			 "LOCAL_PREF attribute length isn't 4 [%u]", length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	/* If it is contained in an UPDATE message that is received from an
	   external peer, then this attribute MUST be ignored by the
	   receiving speaker. */
	if (peer->sort == BGP_PEER_EBGP) {
		stream_forward_getp(peer->curr, length);
		return BGP_ATTR_PARSE_PROCEED;
	}

	attr->local_pref = stream_getl(peer->curr);

	/* Set the local-pref flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Atomic aggregate. */
static int bgp_attr_atomic(struct bgp_attr_parser_args *args)
{
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* Length check. */
	if (length != 0) {
		flog_err(EC_BGP_ATTR_LEN,
			 "ATOMIC_AGGREGATE attribute length isn't 0 [%u]",
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	/* Set atomic aggregate flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Aggregator attribute */
static int bgp_attr_aggregator(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	as_t aggregator_as;

	int wantedlen = 6;

	/* peer with AS4 will send 4 Byte AS, peer without will send 2 Byte */
	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)
	    && CHECK_FLAG(peer->cap, PEER_CAP_AS4_ADV))
		wantedlen = 8;

	if (length != wantedlen) {
		flog_err(EC_BGP_ATTR_LEN,
			 "AGGREGATOR attribute length isn't %u [%u]", wantedlen,
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV))
		aggregator_as = stream_getl(peer->curr);
	else
		aggregator_as = stream_getw(peer->curr);

	attr->aggregator_as = aggregator_as;
	attr->aggregator_addr.s_addr = stream_get_ipv4(peer->curr);

	/* Set atomic aggregate flag. */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR);

	/* Codification of AS 0 Processing */
	if (aggregator_as == BGP_AS_ZERO)
		flog_err(EC_BGP_ATTR_LEN,
			 "AGGREGATOR AS number is 0 for aspath: %s",
			 aspath_print(attr->aspath));

	return BGP_ATTR_PARSE_PROCEED;
}

/* New Aggregator attribute */
static bgp_attr_parse_ret_t
bgp_attr_as4_aggregator(struct bgp_attr_parser_args *args,
			as_t *as4_aggregator_as,
			struct in_addr *as4_aggregator_addr)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	as_t aggregator_as;

	if (length != 8) {
		flog_err(EC_BGP_ATTR_LEN, "New Aggregator length is not 8 [%d]",
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  0);
	}

	aggregator_as = stream_getl(peer->curr);
	*as4_aggregator_as = aggregator_as;
	as4_aggregator_addr->s_addr = stream_get_ipv4(peer->curr);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR);

	/* Codification of AS 0 Processing */
	if (aggregator_as == BGP_AS_ZERO)
		flog_err(EC_BGP_ATTR_LEN,
			 "AS4_AGGREGATOR AS number is 0 for aspath: %s",
			 aspath_print(attr->aspath));

	return BGP_ATTR_PARSE_PROCEED;
}

/* Munge Aggregator and New-Aggregator, AS_PATH and NEW_AS_PATH.
 */
static bgp_attr_parse_ret_t
bgp_attr_munge_as4_attrs(struct peer *const peer, struct attr *const attr,
			 struct aspath *as4_path, as_t as4_aggregator,
			 struct in_addr *as4_aggregator_addr)
{
	int ignore_as4_path = 0;
	struct aspath *newpath;

	if (!attr->aspath) {
		/* NULL aspath shouldn't be possible as bgp_attr_parse should
		 * have
		 * checked that all well-known, mandatory attributes were
		 * present.
		 *
		 * Can only be a problem with peer itself - hard error
		 */
		return BGP_ATTR_PARSE_ERROR;
	}

	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)) {
		/* peer can do AS4, so we ignore AS4_PATH and AS4_AGGREGATOR
		 * if given.
		 * It is worth a warning though, because the peer really
		 * should not send them
		 */
		if (BGP_DEBUG(as4, AS4)) {
			if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH)))
				zlog_debug("[AS4] %s %s AS4_PATH", peer->host,
					   "AS4 capable peer, yet it sent");

			if (attr->flag
			    & (ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR)))
				zlog_debug("[AS4] %s %s AS4_AGGREGATOR",
					   peer->host,
					   "AS4 capable peer, yet it sent");
		}

		return BGP_ATTR_PARSE_PROCEED;
	}

	/* We have a asn16 peer.  First, look for AS4_AGGREGATOR
	 * because that may override AS4_PATH
	 */
	if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR))) {
		if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
			/* received both.
			 * if the as_number in aggregator is not AS_TRANS,
			 *  then AS4_AGGREGATOR and AS4_PATH shall be ignored
			 *        and the Aggregator shall be taken as
			 *        info on the aggregating node, and the AS_PATH
			 *        shall be taken as the AS_PATH
			 *  otherwise
			 *        the Aggregator shall be ignored and the
			 *        AS4_AGGREGATOR shall be taken as the
			 *        Aggregating node and the AS_PATH is to be
			 *        constructed "as in all other cases"
			 */
			if (attr->aggregator_as != BGP_AS_TRANS) {
				/* ignore */
				if (BGP_DEBUG(as4, AS4))
					zlog_debug(
						"[AS4] %s BGP not AS4 capable peer"
						" send AGGREGATOR != AS_TRANS and"
						" AS4_AGGREGATOR, so ignore"
						" AS4_AGGREGATOR and AS4_PATH",
						peer->host);
				ignore_as4_path = 1;
			} else {
				/* "New_aggregator shall be taken as aggregator"
				 */
				attr->aggregator_as = as4_aggregator;
				attr->aggregator_addr.s_addr =
					as4_aggregator_addr->s_addr;
			}
		} else {
			/* We received a AS4_AGGREGATOR but no AGGREGATOR.
			 * That is bogus - but reading the conditions
			 * we have to handle AS4_AGGREGATOR as if it were
			 * AGGREGATOR in that case
			 */
			if (BGP_DEBUG(as4, AS4))
				zlog_debug(
					"[AS4] %s BGP not AS4 capable peer send"
					" AS4_AGGREGATOR but no AGGREGATOR, will take"
					" it as if AGGREGATOR with AS_TRANS had been there",
					peer->host);
			attr->aggregator_as = as4_aggregator;
			/* sweep it under the carpet and simulate a "good"
			 * AGGREGATOR */
			attr->flag |= (ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR));
		}
	}

	/* need to reconcile NEW_AS_PATH and AS_PATH */
	if (!ignore_as4_path
	    && (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH)))) {
		newpath = aspath_reconcile_as4(attr->aspath, as4_path);
		if (!newpath)
			return BGP_ATTR_PARSE_ERROR;

		aspath_unintern(&attr->aspath);
		attr->aspath = aspath_intern(newpath);
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/* Community attribute. */
static bgp_attr_parse_ret_t
bgp_attr_community(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	if (length == 0) {
		attr->community = NULL;
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	attr->community =
		community_parse((uint32_t *)stream_pnt(peer->curr), length);

	/* XXX: fix community_parse to use stream API and remove this */
	stream_forward_getp(peer->curr, length);

	/* The Community attribute SHALL be considered malformed if its
	 * length is not a non-zero multiple of 4.
	 */
	if (!attr->community)
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Originator ID attribute. */
static bgp_attr_parse_ret_t
bgp_attr_originator_id(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* if received from an internal neighbor, it SHALL be considered
	 * malformed if its length is not equal to 4. If malformed, the
	 * UPDATE message SHALL be handled using the approach of "treat-as-
	 * withdraw".
	 */
	if (length != 4) {
		flog_err(EC_BGP_ATTR_LEN, "Bad originator ID length %d",
			 length);

		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	attr->originator_id.s_addr = stream_get_ipv4(peer->curr);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Cluster list attribute. */
static bgp_attr_parse_ret_t
bgp_attr_cluster_list(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* if received from an internal neighbor, it SHALL be considered
	 * malformed if its length is not a non-zero multiple of 4.  If
	 * malformed, the UPDATE message SHALL be handled using the approach
	 * of "treat-as-withdraw".
	 */
	if (length == 0 || length % 4) {
		flog_err(EC_BGP_ATTR_LEN, "Bad cluster list length %d", length);

		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	attr->cluster =
		cluster_parse((struct in_addr *)stream_pnt(peer->curr), length);

	/* XXX: Fix cluster_parse to use stream API and then remove this */
	stream_forward_getp(peer->curr, length);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Multiprotocol reachability information parse. */
int bgp_mp_reach_parse(struct bgp_attr_parser_args *args,
		       struct bgp_nlri *mp_update)
{
	iana_afi_t pkt_afi;
	afi_t afi;
	iana_safi_t pkt_safi;
	safi_t safi;
	bgp_size_t nlri_len;
	size_t start;
	struct stream *s;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* Set end of packet. */
	s = BGP_INPUT(peer);
	start = stream_get_getp(s);

/* safe to read statically sized header? */
#define BGP_MP_REACH_MIN_SIZE 5
#define LEN_LEFT	(length - (stream_get_getp(s) - start))
	if ((length > STREAM_READABLE(s)) || (length < BGP_MP_REACH_MIN_SIZE)) {
		zlog_info("%s: %s sent invalid length, %lu, of MP_REACH_NLRI",
			  __func__, peer->host, (unsigned long)length);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
	}

	/* Load AFI, SAFI. */
	pkt_afi = stream_getw(s);
	pkt_safi = stream_getc(s);

	/* Convert AFI, SAFI to internal values, check. */
	if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
		/* Log if AFI or SAFI is unrecognized. This is not an error
		 * unless
		 * the attribute is otherwise malformed.
		 */
		if (bgp_debug_update(peer, NULL, NULL, 0))
			zlog_debug(
				"%s sent unrecognizable AFI, %s or, SAFI, %s, of MP_REACH_NLRI",
				peer->host, iana_afi2str(pkt_afi),
				iana_safi2str(pkt_safi));
		return BGP_ATTR_PARSE_ERROR;
	}

	/* Get nexthop length. */
	attr->mp_nexthop_len = stream_getc(s);

	if (LEN_LEFT < attr->mp_nexthop_len) {
		zlog_info(
			"%s: %s sent next-hop length, %u, in MP_REACH_NLRI which goes past the end of attribute",
			__func__, peer->host, attr->mp_nexthop_len);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
	}

	/* Nexthop length check. */
	switch (attr->mp_nexthop_len) {
	case 0:
		if (safi != SAFI_FLOWSPEC) {
			zlog_info("%s: %s sent wrong next-hop length, %d, in MP_REACH_NLRI",
				  __func__, peer->host, attr->mp_nexthop_len);
			return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
		}
		break;
	case BGP_ATTR_NHLEN_VPNV4:
		stream_getl(s); /* RD high */
		stream_getl(s); /* RD low */
				/*
				 * NOTE: intentional fall through
				 * - for consistency in rx processing
				 *
				 * The following comment is to signal GCC this intention
				 * and suppress the warning
				 */
	/* FALLTHRU */
	case BGP_ATTR_NHLEN_IPV4:
		stream_get(&attr->mp_nexthop_global_in, s, IPV4_MAX_BYTELEN);
		/* Probably needed for RFC 2283 */
		if (attr->nexthop.s_addr == INADDR_ANY)
			memcpy(&attr->nexthop.s_addr,
			       &attr->mp_nexthop_global_in, IPV4_MAX_BYTELEN);
		break;
	case BGP_ATTR_NHLEN_IPV6_GLOBAL:
	case BGP_ATTR_NHLEN_VPNV6_GLOBAL:
		if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL) {
			stream_getl(s); /* RD high */
			stream_getl(s); /* RD low */
		}
		stream_get(&attr->mp_nexthop_global, s, IPV6_MAX_BYTELEN);
		if (IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_global)) {
			if (!peer->nexthop.ifp) {
				zlog_warn("%s sent a v6 global attribute but address is a V6 LL and there's no peer interface information. Hence, withdrawing",
					  peer->host);
				return BGP_ATTR_PARSE_WITHDRAW;
			}
			attr->nh_ifindex = peer->nexthop.ifp->ifindex;
		}
		break;
	case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
	case BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL:
		if (attr->mp_nexthop_len
		    == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
			stream_getl(s); /* RD high */
			stream_getl(s); /* RD low */
		}
		stream_get(&attr->mp_nexthop_global, s, IPV6_MAX_BYTELEN);
		if (IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_global)) {
			if (!peer->nexthop.ifp) {
				zlog_warn("%s sent a v6 global and LL attribute but global address is a V6 LL and there's no peer interface information. Hence, withdrawing",
					  peer->host);
				return BGP_ATTR_PARSE_WITHDRAW;
			}
			attr->nh_ifindex = peer->nexthop.ifp->ifindex;
		}
		if (attr->mp_nexthop_len
		    == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
			stream_getl(s); /* RD high */
			stream_getl(s); /* RD low */
		}
		stream_get(&attr->mp_nexthop_local, s, IPV6_MAX_BYTELEN);
		if (!IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_local)) {
			char buf1[INET6_ADDRSTRLEN];
			char buf2[INET6_ADDRSTRLEN];

			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"%s sent next-hops %s and %s. Ignoring non-LL value",
					peer->host,
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_global,
						  buf1, INET6_ADDRSTRLEN),
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_local, buf2,
						  INET6_ADDRSTRLEN));

			attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
		}
		if (!peer->nexthop.ifp) {
			zlog_warn("%s sent a v6 LL next-hop and there's no peer interface information. Hence, withdrawing",
				  peer->host);
			return BGP_ATTR_PARSE_WITHDRAW;
		}
		attr->nh_lla_ifindex = peer->nexthop.ifp->ifindex;
		break;
	default:
		zlog_info("%s: %s sent wrong next-hop length, %d, in MP_REACH_NLRI",
			  __func__, peer->host, attr->mp_nexthop_len);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
	}

	if (!LEN_LEFT) {
		zlog_info("%s: %s sent SNPA which couldn't be read",
			  __func__, peer->host);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
	}

	{
		uint8_t val;
		if ((val = stream_getc(s)))
			flog_warn(
				EC_BGP_DEFUNCT_SNPA_LEN,
				"%s sent non-zero value, %u, for defunct SNPA-length field",
				peer->host, val);
	}

	/* must have nrli_len, what is left of the attribute */
	nlri_len = LEN_LEFT;
	if (nlri_len > STREAM_READABLE(s)) {
		zlog_info("%s: %s sent MP_REACH_NLRI which couldn't be read",
			  __func__, peer->host);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
	}

	if (!nlri_len) {
		zlog_info("%s: %s sent a zero-length NLRI. Hence, treating as a EOR marker",
			  __func__, peer->host);

		mp_update->afi = afi;
		mp_update->safi = safi;
		return BGP_ATTR_PARSE_EOR;
	}

	mp_update->afi = afi;
	mp_update->safi = safi;
	mp_update->nlri = stream_pnt(s);
	mp_update->length = nlri_len;

	stream_forward_getp(s, nlri_len);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI);

	return BGP_ATTR_PARSE_PROCEED;
#undef LEN_LEFT
}

/* Multiprotocol unreachable parse */
int bgp_mp_unreach_parse(struct bgp_attr_parser_args *args,
			 struct bgp_nlri *mp_withdraw)
{
	struct stream *s;
	iana_afi_t pkt_afi;
	afi_t afi;
	iana_safi_t pkt_safi;
	safi_t safi;
	uint16_t withdraw_len;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	s = peer->curr;

#define BGP_MP_UNREACH_MIN_SIZE 3
	if ((length > STREAM_READABLE(s)) || (length < BGP_MP_UNREACH_MIN_SIZE))
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;

	pkt_afi = stream_getw(s);
	pkt_safi = stream_getc(s);

	/* Convert AFI, SAFI to internal values, check. */
	if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
		/* Log if AFI or SAFI is unrecognized. This is not an error
		 * unless
		 * the attribute is otherwise malformed.
		 */
		if (bgp_debug_update(peer, NULL, NULL, 0))
			zlog_debug(
				"%s: MP_UNREACH received AFI %s or SAFI %s is unrecognized",
				peer->host, iana_afi2str(pkt_afi),
				iana_safi2str(pkt_safi));
		return BGP_ATTR_PARSE_ERROR;
	}

	withdraw_len = length - BGP_MP_UNREACH_MIN_SIZE;

	mp_withdraw->afi = afi;
	mp_withdraw->safi = safi;
	mp_withdraw->nlri = stream_pnt(s);
	mp_withdraw->length = withdraw_len;

	stream_forward_getp(s, withdraw_len);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Large Community attribute. */
static bgp_attr_parse_ret_t
bgp_attr_large_community(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/*
	 * Large community follows new attribute format.
	 */
	if (length == 0) {
		attr->lcommunity = NULL;
		/* Empty extcomm doesn't seem to be invalid per se */
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	attr->lcommunity = lcommunity_parse(stream_pnt(peer->curr), length);
	/* XXX: fix ecommunity_parse to use stream API */
	stream_forward_getp(peer->curr, length);

	if (!attr->lcommunity)
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Extended Community attribute. */
static bgp_attr_parse_ret_t
bgp_attr_ext_communities(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	uint8_t sticky = 0;
	bool proxy = false;

	if (length == 0) {
		attr->ecommunity = NULL;
		/* Empty extcomm doesn't seem to be invalid per se */
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	attr->ecommunity =
		ecommunity_parse(stream_pnt(peer->curr), length);
	/* XXX: fix ecommunity_parse to use stream API */
	stream_forward_getp(peer->curr, length);

	/* The Extended Community attribute SHALL be considered malformed if
	 * its length is not a non-zero multiple of 8.
	 */
	if (!attr->ecommunity)
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);

	/* Extract DF election preference and  mobility sequence number */
	attr->df_pref = bgp_attr_df_pref_from_ec(attr, &attr->df_alg);

	/* Extract MAC mobility sequence number, if any. */
	attr->mm_seqnum = bgp_attr_mac_mobility_seqnum(attr, &sticky);
	attr->sticky = sticky;

	/* Check if this is a Gateway MAC-IP advertisement */
	attr->default_gw = bgp_attr_default_gw(attr);

	/* Handle scenario where router flag ecommunity is not
	 * set but default gw ext community is present.
	 * Use default gateway, set and propogate R-bit.
	 */
	if (attr->default_gw)
		attr->router_flag = 1;

	/* Check EVPN Neighbor advertisement flags, R-bit */
	bgp_attr_evpn_na_flag(attr, &attr->router_flag, &proxy);
	if (proxy)
		attr->es_flags |= ATTR_ES_PROXY_ADVERT;

	/* Extract the Rmac, if any */
	if (bgp_attr_rmac(attr, &attr->rmac)) {
		if (bgp_debug_update(peer, NULL, NULL, 1) &&
		    bgp_mac_exist(&attr->rmac)) {
			char buf1[ETHER_ADDR_STRLEN];

			zlog_debug("%s: router mac %s is self mac",
				   __func__,
				   prefix_mac2str(&attr->rmac, buf1,
						  sizeof(buf1)));
		}

	}

	/* Get the tunnel type from encap extended community */
	bgp_attr_extcom_tunnel_type(attr,
		(bgp_encap_types *)&attr->encap_tunneltype);

	/* Extract link bandwidth, if any. */
	(void)ecommunity_linkbw_present(attr->ecommunity, &attr->link_bw);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Parse Tunnel Encap attribute in an UPDATE */
static int bgp_attr_encap(uint8_t type, struct peer *peer, /* IN */
			  bgp_size_t length, /* IN: attr's length field */
			  struct attr *attr, /* IN: caller already allocated */
			  uint8_t flag,      /* IN: attr's flags field */
			  uint8_t *startp)
{
	bgp_size_t total;
	uint16_t tunneltype = 0;

	total = length + (CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

	if (!CHECK_FLAG(flag, BGP_ATTR_FLAG_TRANS)
	    || !CHECK_FLAG(flag, BGP_ATTR_FLAG_OPTIONAL)) {
		zlog_info(
			"Tunnel Encap attribute flag isn't optional and transitive %d",
			flag);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR,
					  BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
					  startp, total);
		return -1;
	}

	if (BGP_ATTR_ENCAP == type) {
		/* read outer TLV type and length */
		uint16_t tlv_length;

		if (length < 4) {
			zlog_info(
				"Tunnel Encap attribute not long enough to contain outer T,L");
			bgp_notify_send_with_data(
				peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, startp, total);
			return -1;
		}
		tunneltype = stream_getw(BGP_INPUT(peer));
		tlv_length = stream_getw(BGP_INPUT(peer));
		length -= 4;

		if (tlv_length != length) {
			zlog_info("%s: tlv_length(%d) != length(%d)",
				  __func__, tlv_length, length);
		}
	}

	while (length >= 4) {
		uint16_t subtype = 0;
		uint16_t sublength = 0;
		struct bgp_attr_encap_subtlv *tlv;

		if (BGP_ATTR_ENCAP == type) {
			subtype = stream_getc(BGP_INPUT(peer));
			sublength = stream_getc(BGP_INPUT(peer));
			length -= 2;
#ifdef ENABLE_BGP_VNC
		} else {
			subtype = stream_getw(BGP_INPUT(peer));
			sublength = stream_getw(BGP_INPUT(peer));
			length -= 4;
#endif
		}

		if (sublength > length) {
			zlog_info(
				"Tunnel Encap attribute sub-tlv length %d exceeds remaining length %d",
				sublength, length);
			bgp_notify_send_with_data(
				peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, startp, total);
			return -1;
		}

		/* alloc and copy sub-tlv */
		/* TBD make sure these are freed when attributes are released */
		tlv = XCALLOC(MTYPE_ENCAP_TLV,
			      sizeof(struct bgp_attr_encap_subtlv) + sublength);
		tlv->type = subtype;
		tlv->length = sublength;
		stream_get(tlv->value, peer->curr, sublength);
		length -= sublength;

		/* attach tlv to encap chain */
		if (BGP_ATTR_ENCAP == type) {
			struct bgp_attr_encap_subtlv *stlv_last;
			for (stlv_last = attr->encap_subtlvs;
			     stlv_last && stlv_last->next;
			     stlv_last = stlv_last->next)
				;
			if (stlv_last) {
				stlv_last->next = tlv;
			} else {
				attr->encap_subtlvs = tlv;
			}
#ifdef ENABLE_BGP_VNC
		} else {
			struct bgp_attr_encap_subtlv *stlv_last;
			for (stlv_last = attr->vnc_subtlvs;
			     stlv_last && stlv_last->next;
			     stlv_last = stlv_last->next)
				;
			if (stlv_last) {
				stlv_last->next = tlv;
			} else {
				attr->vnc_subtlvs = tlv;
			}
#endif
		}
	}

	if (BGP_ATTR_ENCAP == type) {
		attr->encap_tunneltype = tunneltype;
	}

	if (length) {
		/* spurious leftover data */
		zlog_info(
			"Tunnel Encap attribute length is bad: %d leftover octets",
			length);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR,
					  BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  startp, total);
		return -1;
	}

	return 0;
}

/*
 * Read an individual SID value returning how much data we have read
 * Returns 0 if there was an error that needs to be passed up the stack
 */
static bgp_attr_parse_ret_t bgp_attr_psid_sub(uint8_t type, uint16_t length,
					      struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	uint32_t label_index;
	struct in6_addr ipv6_sid;
	uint32_t srgb_base;
	uint32_t srgb_range;
	int srgb_count;
	uint8_t sid_type, sid_flags;
	uint16_t endpoint_behavior;
	char buf[BUFSIZ];

	if (type == BGP_PREFIX_SID_LABEL_INDEX) {
		if (STREAM_READABLE(peer->curr) < length
		    || length != BGP_PREFIX_SID_LABEL_INDEX_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID label index length is %" PRIu16
				 " instead of %u",
				 length, BGP_PREFIX_SID_LABEL_INDEX_LENGTH);
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
						  args->total);
		}

		/* Ignore flags and reserved */
		stream_getc(peer->curr);
		stream_getw(peer->curr);

		/* Fetch the label index and see if it is valid. */
		label_index = stream_getl(peer->curr);
		if (label_index == BGP_INVALID_LABEL_INDEX)
			return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
						  args->total);

		/* Store label index; subsequently, we'll check on
		 * address-family */
		attr->label_index = label_index;
	}

	/* Placeholder code for the IPv6 SID type */
	else if (type == BGP_PREFIX_SID_IPV6) {
		if (STREAM_READABLE(peer->curr) < length
		    || length != BGP_PREFIX_SID_IPV6_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID IPv6 length is %" PRIu16
				 " instead of %u",
				 length, BGP_PREFIX_SID_IPV6_LENGTH);
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
						  args->total);
		}

		/* Ignore reserved */
		stream_getc(peer->curr);
		stream_getw(peer->curr);

		stream_get(&ipv6_sid, peer->curr, 16);
	}

	/* Placeholder code for the Originator SRGB type */
	else if (type == BGP_PREFIX_SID_ORIGINATOR_SRGB) {
		/*
		 * ietf-idr-bgp-prefix-sid-05:
		 *     Length is the total length of the value portion of the
		 *     TLV: 2 + multiple of 6.
		 *
		 * peer->curr stream readp should be at the beginning of the 16
		 * bit flag field at this point in the code.
		 */

		/*
		 * Check that the TLV length field is sane: at least 2 bytes of
		 * flag, and at least 1 SRGB (these are 6 bytes each)
		 */
		if (length < (2 + BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH)) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Prefix SID Originator SRGB length field claims length of %" PRIu16 " bytes, but the minimum for this TLV type is %u",
				length,
				2 + BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH);
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		/*
		 * Check that we actually have at least as much data as
		 * specified by the length field
		 */
		if (STREAM_READABLE(peer->curr) < length) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID Originator SRGB specifies length %" PRIu16 ", but only %zu bytes remain",
				 length, STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		/*
		 * Check that the portion of the TLV containing the sequence of
		 * SRGBs corresponds to a multiple of the SRGB size; to get
		 * that length, we skip the 16 bit flags field
		 */
		stream_getw(peer->curr);
		length -= 2;
		if (length % BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Prefix SID Originator SRGB length field claims attribute SRGB sequence section is %" PRIu16 "bytes, but it must be a multiple of %u",
				length, BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH);
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		srgb_count = length / BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH;

		for (int i = 0; i < srgb_count; i++) {
			stream_get(&srgb_base, peer->curr, 3);
			stream_get(&srgb_range, peer->curr, 3);
		}
	}

	/* Placeholder code for the VPN-SID Service type */
	else if (type == BGP_PREFIX_SID_VPN_SID) {
		if (STREAM_READABLE(peer->curr) < length
		    || length != BGP_PREFIX_SID_VPN_SID_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID VPN SID length is %" PRIu16
				 " instead of %u",
				 length, BGP_PREFIX_SID_VPN_SID_LENGTH);
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
						  args->total);
		}

		/* Parse VPN-SID Sub-TLV */
		stream_getc(peer->curr);               /* reserved  */
		sid_type = stream_getc(peer->curr);    /* sid_type  */
		sid_flags = stream_getc(peer->curr);   /* sid_flags */
		stream_get(&ipv6_sid, peer->curr,
			   sizeof(ipv6_sid)); /* sid_value */

		/* Log VPN-SID Sub-TLV */
		if (BGP_DEBUG(vpn, VPN_LEAK_LABEL)) {
			inet_ntop(AF_INET6, &ipv6_sid, buf, sizeof(buf));
			zlog_debug(
				"%s: vpn-sid: sid %s, sid-type 0x%02x sid-flags 0x%02x",
				__func__, buf, sid_type, sid_flags);
		}

		/* Configure from Info */
		if (attr->srv6_vpn) {
			flog_err(EC_BGP_ATTRIBUTE_REPEATED,
				 "Prefix SID SRv6 VPN field repeated");
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_MAL_ATTR, args->total);
		}
		attr->srv6_vpn = XCALLOC(MTYPE_BGP_SRV6_VPN,
					 sizeof(struct bgp_attr_srv6_vpn));
		attr->srv6_vpn->sid_flags = sid_flags;
		sid_copy(&attr->srv6_vpn->sid, &ipv6_sid);
	}

	/* Placeholder code for the SRv6 L3 Service type */
	else if (type == BGP_PREFIX_SID_SRV6_L3_SERVICE) {
		if (STREAM_READABLE(peer->curr) < length
		    || length != BGP_PREFIX_SID_SRV6_L3_SERVICE_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID SRv6 L3-Service length is %" PRIu16
				 " instead of %u",
				 length, BGP_PREFIX_SID_SRV6_L3_SERVICE_LENGTH);
			return bgp_attr_malformed(args,
				 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				 args->total);
		}

		/* Parse L3-SERVICE Sub-TLV */
		stream_getc(peer->curr);               /* reserved  */
		stream_get(&ipv6_sid, peer->curr,
			   sizeof(ipv6_sid)); /* sid_value */
		sid_flags = stream_getc(peer->curr);   /* sid_flags */
		endpoint_behavior = stream_getw(peer->curr); /* endpoint */
		stream_getc(peer->curr);               /* reserved  */

		/* Log L3-SERVICE Sub-TLV */
		if (BGP_DEBUG(vpn, VPN_LEAK_LABEL)) {
			inet_ntop(AF_INET6, &ipv6_sid, buf, sizeof(buf));
			zlog_debug(
				"%s: srv6-l3-srv sid %s, sid-flags 0x%02x, end-behaviour 0x%04x",
				__func__, buf, sid_flags, endpoint_behavior);
		}

		/* Configure from Info */
		if (attr->srv6_l3vpn) {
			flog_err(EC_BGP_ATTRIBUTE_REPEATED,
				 "Prefix SID SRv6 L3VPN field repeated");
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_MAL_ATTR, args->total);
		}
		attr->srv6_l3vpn = XCALLOC(MTYPE_BGP_SRV6_L3VPN,
					   sizeof(struct bgp_attr_srv6_l3vpn));
		attr->srv6_l3vpn->sid_flags = sid_flags;
		attr->srv6_l3vpn->endpoint_behavior = endpoint_behavior;
		sid_copy(&attr->srv6_l3vpn->sid, &ipv6_sid);
	}

	/* Placeholder code for Unsupported TLV */
	else {

		if (STREAM_READABLE(peer->curr) < length) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Prefix SID SRv6 length is %" PRIu16
				" - too long, only %zu remaining in this UPDATE",
				length, STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		if (bgp_debug_update(peer, NULL, NULL, 1))
			zlog_debug(
				"%s attr Prefix-SID sub-type=%u is not supported, skipped",
				peer->host, type);

		stream_forward_getp(peer->curr, length);
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* Prefix SID attribute
 * draft-ietf-idr-bgp-prefix-sid-05
 */
bgp_attr_parse_ret_t bgp_attr_prefix_sid(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	bgp_attr_parse_ret_t ret;

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID);

	uint8_t type;
	uint16_t length;
	size_t headersz = sizeof(type) + sizeof(length);
	size_t psid_parsed_length = 0;

	while (STREAM_READABLE(peer->curr) > 0
	       && psid_parsed_length < args->length) {

		if (STREAM_READABLE(peer->curr) < headersz) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Malformed Prefix SID attribute - insufficent data (need %zu for attribute header, have %zu remaining in UPDATE)",
				headersz, STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		type = stream_getc(peer->curr);
		length = stream_getw(peer->curr);

		if (STREAM_READABLE(peer->curr) < length) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Malformed Prefix SID attribute - insufficient data (need %" PRIu16
				" for attribute body, have %zu remaining in UPDATE)",
				length, STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
						  args->total);
		}

		ret = bgp_attr_psid_sub(type, length, args);

		if (ret != BGP_ATTR_PARSE_PROCEED)
			return ret;

		psid_parsed_length += length + headersz;

		if (psid_parsed_length > args->length) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Malformed Prefix SID attribute - TLV overflow by attribute (need %zu"
				" for TLV length, have %zu overflowed in UPDATE)",
				length + headersz, psid_parsed_length - (length + headersz));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* PMSI tunnel attribute (RFC 6514)
 * Basic validation checks done here.
 */
static bgp_attr_parse_ret_t
bgp_attr_pmsi_tunnel(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	uint8_t tnl_type;
	int attr_parse_len = 2 + BGP_LABEL_BYTES;

	/* Verify that the receiver is expecting "ingress replication" as we
	 * can only support that.
	 */
	if (length < attr_parse_len) {
		flog_err(EC_BGP_ATTR_LEN, "Bad PMSI tunnel attribute length %d",
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}
	stream_getc(peer->curr); /* Flags */
	tnl_type = stream_getc(peer->curr);
	if (tnl_type > PMSI_TNLTYPE_MAX) {
		flog_err(EC_BGP_ATTR_PMSI_TYPE,
			 "Invalid PMSI tunnel attribute type %d", tnl_type);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}
	if (tnl_type == PMSI_TNLTYPE_INGR_REPL) {
		if (length != 9) {
			flog_err(EC_BGP_ATTR_PMSI_LEN,
				 "Bad PMSI tunnel attribute length %d for IR",
				 length);
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}
	}

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL);
	attr->pmsi_tnl_type = tnl_type;
	stream_get(&attr->label, peer->curr, BGP_LABEL_BYTES);

	/* Forward read pointer of input stream. */
	stream_forward_getp(peer->curr, length - attr_parse_len);

	return BGP_ATTR_PARSE_PROCEED;
}

/* BGP unknown attribute treatment. */
static bgp_attr_parse_ret_t bgp_attr_unknown(struct bgp_attr_parser_args *args)
{
	bgp_size_t total = args->total;
	struct transit *transit;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	uint8_t *const startp = args->startp;
	const uint8_t type = args->type;
	const uint8_t flag = args->flags;
	const bgp_size_t length = args->length;

	if (bgp_debug_update(peer, NULL, NULL, 1))
		zlog_debug(
			"%s Unknown attribute is received (type %d, length %d)",
			peer->host, type, length);

	/* Forward read pointer of input stream. */
	stream_forward_getp(peer->curr, length);

	/* If any of the mandatory well-known attributes are not recognized,
	   then the Error Subcode is set to Unrecognized Well-known
	   Attribute.  The Data field contains the unrecognized attribute
	   (type, length and value). */
	if (!CHECK_FLAG(flag, BGP_ATTR_FLAG_OPTIONAL)) {
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_UNREC_ATTR,
					  args->total);
	}

	/* Unrecognized non-transitive optional attributes must be quietly
	   ignored and not passed along to other BGP peers. */
	if (!CHECK_FLAG(flag, BGP_ATTR_FLAG_TRANS))
		return BGP_ATTR_PARSE_PROCEED;

	/* If a path with recognized transitive optional attribute is
	   accepted and passed along to other BGP peers and the Partial bit
	   in the Attribute Flags octet is set to 1 by some previous AS, it
	   is not set back to 0 by the current AS. */
	SET_FLAG(*startp, BGP_ATTR_FLAG_PARTIAL);

	/* Store transitive attribute to the end of attr->transit. */
	if (!attr->transit)
		attr->transit = XCALLOC(MTYPE_TRANSIT, sizeof(struct transit));

	transit = attr->transit;

	if (transit->val)
		transit->val = XREALLOC(MTYPE_TRANSIT_VAL, transit->val,
					transit->length + total);
	else
		transit->val = XMALLOC(MTYPE_TRANSIT_VAL, total);

	memcpy(transit->val + transit->length, startp, total);
	transit->length += total;

	return BGP_ATTR_PARSE_PROCEED;
}

/* Well-known attribute check. */
static int bgp_attr_check(struct peer *peer, struct attr *attr)
{
	uint8_t type = 0;

	/* BGP Graceful-Restart End-of-RIB for IPv4 unicast is signaled as an
	 * empty UPDATE.  */
	if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV) && !attr->flag)
		return BGP_ATTR_PARSE_PROCEED;

	/* "An UPDATE message that contains the MP_UNREACH_NLRI is not required
	   to carry any other path attributes.", though if MP_REACH_NLRI or NLRI
	   are present, it should.  Check for any other attribute being present
	   instead.
	 */
	if ((!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) &&
	     CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI))))
		return BGP_ATTR_PARSE_PROCEED;

	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN)))
		type = BGP_ATTR_ORIGIN;

	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH)))
		type = BGP_ATTR_AS_PATH;

	/* RFC 2858 makes Next-Hop optional/ignored, if MP_REACH_NLRI is present
	 * and
	 * NLRI is empty. We can't easily check NLRI empty here though.
	 */
	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))
	    && !CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)))
		type = BGP_ATTR_NEXT_HOP;

	if (peer->sort == BGP_PEER_IBGP
	    && !CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		type = BGP_ATTR_LOCAL_PREF;

	/* If any of the well-known mandatory attributes are not present
	 * in an UPDATE message, then "treat-as-withdraw" MUST be used.
	 */
	if (type) {
		flog_warn(EC_BGP_MISSING_ATTRIBUTE,
			  "%s Missing well-known attribute %s.", peer->host,
			  lookup_msg(attr_str, type, NULL));
		return BGP_ATTR_PARSE_WITHDRAW;
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/* Read attribute of update packet.  This function is called from
   bgp_update_receive() in bgp_packet.c.  */
bgp_attr_parse_ret_t bgp_attr_parse(struct peer *peer, struct attr *attr,
				    bgp_size_t size, struct bgp_nlri *mp_update,
				    struct bgp_nlri *mp_withdraw)
{
	bgp_attr_parse_ret_t ret;
	uint8_t flag = 0;
	uint8_t type = 0;
	bgp_size_t length;
	uint8_t *startp, *endp;
	uint8_t *attr_endp;
	uint8_t seen[BGP_ATTR_BITMAP_SIZE];
	/* we need the as4_path only until we have synthesized the as_path with
	 * it */
	/* same goes for as4_aggregator */
	struct aspath *as4_path = NULL;
	as_t as4_aggregator = 0;
	struct in_addr as4_aggregator_addr = {.s_addr = 0};

	/* Initialize bitmap. */
	memset(seen, 0, BGP_ATTR_BITMAP_SIZE);

	/* End pointer of BGP attribute. */
	endp = BGP_INPUT_PNT(peer) + size;

	/* Get attributes to the end of attribute length. */
	while (BGP_INPUT_PNT(peer) < endp) {
		/* Check remaining length check.*/
		if (endp - BGP_INPUT_PNT(peer) < BGP_ATTR_MIN_LEN) {
			/* XXX warning: long int format, int arg (arg 5) */
			flog_warn(
				EC_BGP_ATTRIBUTE_TOO_SMALL,
				"%s: error BGP attribute length %lu is smaller than min len",
				peer->host,
				(unsigned long)(endp
						- stream_pnt(BGP_INPUT(peer))));

			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}

		/* Fetch attribute flag and type. */
		startp = BGP_INPUT_PNT(peer);
		/* "The lower-order four bits of the Attribute Flags octet are
		   unused.  They MUST be zero when sent and MUST be ignored when
		   received." */
		flag = 0xF0 & stream_getc(BGP_INPUT(peer));
		type = stream_getc(BGP_INPUT(peer));

		/* Check whether Extended-Length applies and is in bounds */
		if (CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN)
		    && ((endp - startp) < (BGP_ATTR_MIN_LEN + 1))) {
			flog_warn(
				EC_BGP_EXT_ATTRIBUTE_TOO_SMALL,
				"%s: Extended length set, but just %lu bytes of attr header",
				peer->host,
				(unsigned long)(endp
						- stream_pnt(BGP_INPUT(peer))));

			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}

		/* Check extended attribue length bit. */
		if (CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN))
			length = stream_getw(BGP_INPUT(peer));
		else
			length = stream_getc(BGP_INPUT(peer));

		/* If any attribute appears more than once in the UPDATE
		   message, then the Error Subcode is set to Malformed Attribute
		   List. */

		if (CHECK_BITMAP(seen, type)) {
			flog_warn(
				EC_BGP_ATTRIBUTE_REPEATED,
				"%s: error BGP attribute type %d appears twice in a message",
				peer->host, type);

			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_MAL_ATTR);
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}

		/* Set type to bitmap to check duplicate attribute.  `type' is
		   unsigned char so it never overflow bitmap range. */

		SET_BITMAP(seen, type);

		/* Overflow check. */
		attr_endp = BGP_INPUT_PNT(peer) + length;

		if (attr_endp > endp) {
			flog_warn(
				EC_BGP_ATTRIBUTE_TOO_LARGE,
				"%s: BGP type %d length %d is too large, attribute total length is %d.  attr_endp is %p.  endp is %p",
				peer->host, type, length, size, attr_endp,
				endp);
			/*
			 * RFC 4271 6.3
			 * If any recognized attribute has an Attribute
			 * Length that conflicts with the expected length
			 * (based on the attribute type code), then the
			 * Error Subcode MUST be set to Attribute Length
			 * Error.  The Data field MUST contain the erroneous
			 * attribute (type, length, and value).
			 * ----------
			 * We do not currently have a good way to determine the
			 * length of the attribute independent of the length
			 * received in the message. Instead we send the
			 * minimum between the amount of data we have and the
			 * amount specified by the attribute length field.
			 *
			 * Instead of directly passing in the packet buffer and
			 * offset we use the stream_get* functions to read into
			 * a stack buffer, since they perform bounds checking
			 * and we are working with untrusted data.
			 */
			unsigned char ndata[BGP_MAX_PACKET_SIZE];
			memset(ndata, 0x00, sizeof(ndata));
			size_t lfl =
				CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN) ? 2 : 1;
			/* Rewind to end of flag field */
			stream_forward_getp(BGP_INPUT(peer), -(1 + lfl));
			/* Type */
			stream_get(&ndata[0], BGP_INPUT(peer), 1);
			/* Length */
			stream_get(&ndata[1], BGP_INPUT(peer), lfl);
			/* Value */
			size_t atl = attr_endp - startp;
			size_t ndl = MIN(atl, STREAM_READABLE(BGP_INPUT(peer)));
			stream_get(&ndata[lfl + 1], BGP_INPUT(peer), ndl);

			bgp_notify_send_with_data(
				peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, ndata,
				ndl + lfl + 1);

			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}

		struct bgp_attr_parser_args attr_args = {
			.peer = peer,
			.length = length,
			.attr = attr,
			.type = type,
			.flags = flag,
			.startp = startp,
			.total = attr_endp - startp,
		};


		/* If any recognized attribute has Attribute Flags that conflict
		   with the Attribute Type Code, then the Error Subcode is set
		   to
		   Attribute Flags Error.  The Data field contains the erroneous
		   attribute (type, length and value). */
		if (bgp_attr_flag_invalid(&attr_args)) {
			ret = bgp_attr_malformed(
				&attr_args, BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				attr_args.total);
			if (ret == BGP_ATTR_PARSE_PROCEED)
				continue;
			goto done;
		}

		/* OK check attribute and store it's value. */
		switch (type) {
		case BGP_ATTR_ORIGIN:
			ret = bgp_attr_origin(&attr_args);
			break;
		case BGP_ATTR_AS_PATH:
			ret = bgp_attr_aspath(&attr_args);
			break;
		case BGP_ATTR_AS4_PATH:
			ret = bgp_attr_as4_path(&attr_args, &as4_path);
			break;
		case BGP_ATTR_NEXT_HOP:
			ret = bgp_attr_nexthop(&attr_args);
			break;
		case BGP_ATTR_MULTI_EXIT_DISC:
			ret = bgp_attr_med(&attr_args);
			break;
		case BGP_ATTR_LOCAL_PREF:
			ret = bgp_attr_local_pref(&attr_args);
			break;
		case BGP_ATTR_ATOMIC_AGGREGATE:
			ret = bgp_attr_atomic(&attr_args);
			break;
		case BGP_ATTR_AGGREGATOR:
			ret = bgp_attr_aggregator(&attr_args);
			break;
		case BGP_ATTR_AS4_AGGREGATOR:
			ret = bgp_attr_as4_aggregator(&attr_args,
						      &as4_aggregator,
						      &as4_aggregator_addr);
			break;
		case BGP_ATTR_COMMUNITIES:
			ret = bgp_attr_community(&attr_args);
			break;
		case BGP_ATTR_LARGE_COMMUNITIES:
			ret = bgp_attr_large_community(&attr_args);
			break;
		case BGP_ATTR_ORIGINATOR_ID:
			ret = bgp_attr_originator_id(&attr_args);
			break;
		case BGP_ATTR_CLUSTER_LIST:
			ret = bgp_attr_cluster_list(&attr_args);
			break;
		case BGP_ATTR_MP_REACH_NLRI:
			ret = bgp_mp_reach_parse(&attr_args, mp_update);
			break;
		case BGP_ATTR_MP_UNREACH_NLRI:
			ret = bgp_mp_unreach_parse(&attr_args, mp_withdraw);
			break;
		case BGP_ATTR_EXT_COMMUNITIES:
			ret = bgp_attr_ext_communities(&attr_args);
			break;
#ifdef ENABLE_BGP_VNC_ATTR
		case BGP_ATTR_VNC:
#endif
		case BGP_ATTR_ENCAP:
			ret = bgp_attr_encap(type, peer, length, attr, flag,
					     startp);
			break;
		case BGP_ATTR_PREFIX_SID:
			ret = bgp_attr_prefix_sid(&attr_args);
			break;
		case BGP_ATTR_PMSI_TUNNEL:
			ret = bgp_attr_pmsi_tunnel(&attr_args);
			break;
		default:
			ret = bgp_attr_unknown(&attr_args);
			break;
		}

		if (ret == BGP_ATTR_PARSE_ERROR_NOTIFYPLS) {
			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_MAL_ATTR);
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}

		if (ret == BGP_ATTR_PARSE_EOR) {
			goto done;
		}

		if (ret == BGP_ATTR_PARSE_ERROR) {
			flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
				  "%s: Attribute %s, parse error", peer->host,
				  lookup_msg(attr_str, type, NULL));
			goto done;
		}
		if (ret == BGP_ATTR_PARSE_WITHDRAW) {
			flog_warn(
				EC_BGP_ATTRIBUTE_PARSE_WITHDRAW,
				"%s: Attribute %s, parse error - treating as withdrawal",
				peer->host, lookup_msg(attr_str, type, NULL));
			goto done;
		}

		/* Check the fetched length. */
		if (BGP_INPUT_PNT(peer) != attr_endp) {
			flog_warn(EC_BGP_ATTRIBUTE_FETCH_ERROR,
				  "%s: BGP attribute %s, fetch error",
				  peer->host, lookup_msg(attr_str, type, NULL));
			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}
	}

	/*
	 * draft-ietf-idr-bgp-prefix-sid-27#section-3:
	 * About Prefix-SID path attribute,
	 * Label-Index TLV(type1) and The Originator SRGB TLV(type-3)
	 * may only appear in a BGP Prefix-SID attribute attached to
	 * IPv4/IPv6 Labeled Unicast prefixes ([RFC8277]).
	 * It MUST be ignored when received for other BGP AFI/SAFI combinations.
	 */
	if (!attr->mp_nexthop_len || mp_update->safi != SAFI_LABELED_UNICAST)
		attr->label_index = BGP_INVALID_LABEL_INDEX;

	/* Check final read pointer is same as end pointer. */
	if (BGP_INPUT_PNT(peer) != endp) {
		flog_warn(EC_BGP_ATTRIBUTES_MISMATCH,
			  "%s: BGP attribute %s, length mismatch", peer->host,
			  lookup_msg(attr_str, type, NULL));
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);

		ret = BGP_ATTR_PARSE_ERROR;
		goto done;
	}

	/*
	 * RFC4271: If the NEXT_HOP attribute field is syntactically incorrect,
	 * then the Error Subcode MUST be set to Invalid NEXT_HOP Attribute.
	 * This is implemented below and will result in a NOTIFICATION. If the
	 * NEXT_HOP attribute is semantically incorrect, the error SHOULD be
	 * logged, and the route SHOULD be ignored. In this case, a NOTIFICATION
	 * message SHOULD NOT be sent. This is implemented elsewhere.
	 *
	 * RFC4760: An UPDATE message that carries no NLRI, other than the one
	 * encoded in the MP_REACH_NLRI attribute, SHOULD NOT carry the NEXT_HOP
	 * attribute. If such a message contains the NEXT_HOP attribute, the BGP
	 * speaker that receives the message SHOULD ignore this attribute.
	 */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))
	    && !CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI))) {
		if (bgp_attr_nexthop_valid(peer, attr) < 0) {
			ret = BGP_ATTR_PARSE_ERROR;
			goto done;
		}
	}

	/* Check all mandatory well-known attributes are present */
	if ((ret = bgp_attr_check(peer, attr)) < 0)
		goto done;

	/*
	 * At this place we can see whether we got AS4_PATH and/or
	 * AS4_AGGREGATOR from a 16Bit peer and act accordingly.
	 * We can not do this before we've read all attributes because
	 * the as4 handling does not say whether AS4_PATH has to be sent
	 * after AS_PATH or not - and when AS4_AGGREGATOR will be send
	 * in relationship to AGGREGATOR.
	 * So, to be defensive, we are not relying on any order and read
	 * all attributes first, including these 32bit ones, and now,
	 * afterwards, we look what and if something is to be done for as4.
	 *
	 * It is possible to not have AS_PATH, e.g. GR EoR and sole
	 * MP_UNREACH_NLRI.
	 */
	/* actually... this doesn't ever return failure currently, but
	 * better safe than sorry */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH))
	    && bgp_attr_munge_as4_attrs(peer, attr, as4_path, as4_aggregator,
					&as4_aggregator_addr)) {
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		ret = BGP_ATTR_PARSE_ERROR;
		goto done;
	}

	/*
	 * Finally do the checks on the aspath we did not do yet
	 * because we waited for a potentially synthesized aspath.
	 */
	if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS_PATH))) {
		ret = bgp_attr_aspath_check(peer, attr);
		if (ret != BGP_ATTR_PARSE_PROCEED)
			goto done;
	}

	ret = BGP_ATTR_PARSE_PROCEED;
done:

	/*
	 * At this stage, we have done all fiddling with as4, and the
	 * resulting info is in attr->aggregator resp. attr->aspath so
	 * we can chuck as4_aggregator and as4_path alltogether in order
	 * to save memory
	 */
	if (as4_path) {
		/*
		 * unintern - it is in the hash
		 * The flag that we got this is still there, but that
		 * does not do any trouble
		 */
		aspath_unintern(&as4_path);
	}

	if (ret != BGP_ATTR_PARSE_ERROR) {
		/* Finally intern unknown attribute. */
		if (attr->transit)
			attr->transit = transit_intern(attr->transit);
		if (attr->encap_subtlvs)
			attr->encap_subtlvs = encap_intern(attr->encap_subtlvs,
							   ENCAP_SUBTLV_TYPE);
#ifdef ENABLE_BGP_VNC
		if (attr->vnc_subtlvs)
			attr->vnc_subtlvs = encap_intern(attr->vnc_subtlvs,
							 VNC_SUBTLV_TYPE);
#endif
	} else {
		if (attr->transit) {
			transit_free(attr->transit);
			attr->transit = NULL;
		}

		bgp_attr_flush_encap(attr);
	};

	/* Sanity checks */
	if (attr->transit)
		assert(attr->transit->refcnt > 0);
	if (attr->encap_subtlvs)
		assert(attr->encap_subtlvs->refcnt > 0);
#ifdef ENABLE_BGP_VNC
	if (attr->vnc_subtlvs)
		assert(attr->vnc_subtlvs->refcnt > 0);
#endif

	return ret;
}

/*
 * Extract the tunnel type from extended community
 */
void bgp_attr_extcom_tunnel_type(struct attr *attr,
				 bgp_encap_types *tunnel_type)
{
	struct ecommunity *ecom;
	int i;
	if (!attr)
		return;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return;

	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = pnt[0];
		sub_type = pnt[1];
		if (!(type == ECOMMUNITY_ENCODE_OPAQUE &&
		      sub_type == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP))
			continue;
		*tunnel_type = ((pnt[6] << 8) | pnt[7]);
		return;
	}

	return;
}

size_t bgp_packet_mpattr_start(struct stream *s, struct peer *peer, afi_t afi,
			       safi_t safi, struct bpacket_attr_vec_arr *vecarr,
			       struct attr *attr)
{
	size_t sizep;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;
	afi_t nh_afi;

	/* Set extended bit always to encode the attribute length as 2 bytes */
	stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTLEN);
	stream_putc(s, BGP_ATTR_MP_REACH_NLRI);
	sizep = stream_get_endp(s);
	stream_putw(s, 0); /* Marker: Attribute length. */


	/* Convert AFI, SAFI to values for packet. */
	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	stream_putw(s, pkt_afi);  /* AFI */
	stream_putc(s, pkt_safi); /* SAFI */

	/* Nexthop AFI */
	if (afi == AFI_IP
	    && (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST
		|| safi == SAFI_MPLS_VPN || safi == SAFI_MULTICAST))
		nh_afi = peer_cap_enhe(peer, afi, safi) ? AFI_IP6 : AFI_IP;
	else if (safi == SAFI_FLOWSPEC)
		nh_afi = afi;
	else
		nh_afi = BGP_NEXTHOP_AFI_FROM_NHLEN(attr->mp_nexthop_len);

	/* Nexthop */
	bpacket_attr_vec_arr_set_vec(vecarr, BGP_ATTR_VEC_NH, s, attr);
	switch (nh_afi) {
	case AFI_IP:
		switch (safi) {
		case SAFI_UNICAST:
		case SAFI_MULTICAST:
		case SAFI_LABELED_UNICAST:
			stream_putc(s, 4);
			stream_put_ipv4(s, attr->nexthop.s_addr);
			break;
		case SAFI_MPLS_VPN:
			stream_putc(s, 12);
			stream_putl(s, 0); /* RD = 0, per RFC */
			stream_putl(s, 0);
			stream_put(s, &attr->mp_nexthop_global_in, 4);
			break;
		case SAFI_ENCAP:
		case SAFI_EVPN:
			stream_putc(s, 4);
			stream_put(s, &attr->mp_nexthop_global_in, 4);
			break;
		case SAFI_FLOWSPEC:
			if (attr->mp_nexthop_len == 0)
				stream_putc(s, 0); /* no nexthop for flowspec */
			else {
				stream_putc(s, attr->mp_nexthop_len);
				stream_put_ipv4(s, attr->nexthop.s_addr);
			}
		default:
			break;
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
		case SAFI_MULTICAST:
		case SAFI_LABELED_UNICAST:
		case SAFI_EVPN: {
			if (attr->mp_nexthop_len
			    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
				stream_putc(s,
					    BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL);
				stream_put(s, &attr->mp_nexthop_global,
					   IPV6_MAX_BYTELEN);
				stream_put(s, &attr->mp_nexthop_local,
					   IPV6_MAX_BYTELEN);
			} else {
				stream_putc(s, IPV6_MAX_BYTELEN);
				stream_put(s, &attr->mp_nexthop_global,
					   IPV6_MAX_BYTELEN);
			}
		} break;
		case SAFI_MPLS_VPN: {
			if (attr->mp_nexthop_len
			    == BGP_ATTR_NHLEN_IPV6_GLOBAL) {
				stream_putc(s, 24);
				stream_putl(s, 0); /* RD = 0, per RFC */
				stream_putl(s, 0);
				stream_put(s, &attr->mp_nexthop_global,
					   IPV6_MAX_BYTELEN);
			} else if (attr->mp_nexthop_len
				   == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
				stream_putc(s, 48);
				stream_putl(s, 0); /* RD = 0, per RFC */
				stream_putl(s, 0);
				stream_put(s, &attr->mp_nexthop_global,
					   IPV6_MAX_BYTELEN);
				stream_putl(s, 0); /* RD = 0, per RFC */
				stream_putl(s, 0);
				stream_put(s, &attr->mp_nexthop_local,
					   IPV6_MAX_BYTELEN);
			}
		} break;
		case SAFI_ENCAP:
			stream_putc(s, IPV6_MAX_BYTELEN);
			stream_put(s, &attr->mp_nexthop_global,
				   IPV6_MAX_BYTELEN);
			break;
		case SAFI_FLOWSPEC:
			stream_putc(s, 0); /* no nexthop for flowspec */
		default:
			break;
		}
		break;
	default:
		if (safi != SAFI_FLOWSPEC)
			flog_err(
				EC_BGP_ATTR_NH_SEND_LEN,
				"Bad nexthop when sending to %s, AFI %u SAFI %u nhlen %d",
				peer->host, afi, safi, attr->mp_nexthop_len);
		break;
	}

	/* SNPA */
	stream_putc(s, 0);
	return sizep;
}

void bgp_packet_mpattr_prefix(struct stream *s, afi_t afi, safi_t safi,
			      const struct prefix *p,
			      const struct prefix_rd *prd, mpls_label_t *label,
			      uint32_t num_labels, int addpath_encode,
			      uint32_t addpath_tx_id, struct attr *attr)
{
	if (safi == SAFI_MPLS_VPN) {
		if (addpath_encode)
			stream_putl(s, addpath_tx_id);
		/* Label, RD, Prefix write. */
		stream_putc(s, p->prefixlen + 88);
		stream_put(s, label, BGP_LABEL_BYTES);
		stream_put(s, prd->val, 8);
		stream_put(s, &p->u.prefix, PSIZE(p->prefixlen));
	} else if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
		/* EVPN prefix - contents depend on type */
		bgp_evpn_encode_prefix(s, p, prd, label, num_labels, attr,
				       addpath_encode, addpath_tx_id);
	} else if (safi == SAFI_LABELED_UNICAST) {
		/* Prefix write with label. */
		stream_put_labeled_prefix(s, p, label, addpath_encode,
					  addpath_tx_id);
	} else if (safi == SAFI_FLOWSPEC) {
		stream_putc(s, p->u.prefix_flowspec.prefixlen);
		stream_put(s, (const void *)p->u.prefix_flowspec.ptr,
			   p->u.prefix_flowspec.prefixlen);
	} else
		stream_put_prefix_addpath(s, p, addpath_encode, addpath_tx_id);
}

size_t bgp_packet_mpattr_prefix_size(afi_t afi, safi_t safi,
				     const struct prefix *p)
{
	int size = PSIZE(p->prefixlen);
	if (safi == SAFI_MPLS_VPN)
		size += 88;
	else if (safi == SAFI_LABELED_UNICAST)
		size += BGP_LABEL_BYTES;
	else if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		size += 232; // TODO: Maximum possible for type-2, type-3 and
			     // type-5
	return size;
}

/*
 * Encodes the tunnel encapsulation attribute,
 * and with ENABLE_BGP_VNC the VNC attribute which uses
 * almost the same TLV format
 */
static void bgp_packet_mpattr_tea(struct bgp *bgp, struct peer *peer,
				  struct stream *s, struct attr *attr,
				  uint8_t attrtype)
{
	unsigned int attrlenfield = 0;
	unsigned int attrhdrlen = 0;
	struct bgp_attr_encap_subtlv *subtlvs;
	struct bgp_attr_encap_subtlv *st;
	const char *attrname;

	if (!attr || (attrtype == BGP_ATTR_ENCAP
		      && (!attr->encap_tunneltype
			  || attr->encap_tunneltype == BGP_ENCAP_TYPE_MPLS)))
		return;

	switch (attrtype) {
	case BGP_ATTR_ENCAP:
		attrname = "Tunnel Encap";
		subtlvs = attr->encap_subtlvs;
		if (subtlvs == NULL) /* nothing to do */
			return;
		/*
		 * The tunnel encap attr has an "outer" tlv.
		 * T = tunneltype,
		 * L = total length of subtlvs,
		 * V = concatenated subtlvs.
		 */
		attrlenfield = 2 + 2; /* T + L */
		attrhdrlen = 1 + 1;   /* subTLV T + L */
		break;

#ifdef ENABLE_BGP_VNC_ATTR
	case BGP_ATTR_VNC:
		attrname = "VNC";
		subtlvs = attr->vnc_subtlvs;
		if (subtlvs == NULL) /* nothing to do */
			return;
		attrlenfield = 0;   /* no outer T + L */
		attrhdrlen = 2 + 2; /* subTLV T + L */
		break;
#endif

	default:
		assert(0);
	}

	/* compute attr length */
	for (st = subtlvs; st; st = st->next) {
		attrlenfield += (attrhdrlen + st->length);
	}

	if (attrlenfield > 0xffff) {
		zlog_info("%s attribute is too long (length=%d), can't send it",
			  attrname, attrlenfield);
		return;
	}

	if (attrlenfield > 0xff) {
		/* 2-octet length field */
		stream_putc(s,
			    BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL
				    | BGP_ATTR_FLAG_EXTLEN);
		stream_putc(s, attrtype);
		stream_putw(s, attrlenfield & 0xffff);
	} else {
		/* 1-octet length field */
		stream_putc(s, BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, attrtype);
		stream_putc(s, attrlenfield & 0xff);
	}

	if (attrtype == BGP_ATTR_ENCAP) {
		/* write outer T+L */
		stream_putw(s, attr->encap_tunneltype);
		stream_putw(s, attrlenfield - 4);
	}

	/* write each sub-tlv */
	for (st = subtlvs; st; st = st->next) {
		if (attrtype == BGP_ATTR_ENCAP) {
			stream_putc(s, st->type);
			stream_putc(s, st->length);
#ifdef ENABLE_BGP_VNC
		} else {
			stream_putw(s, st->type);
			stream_putw(s, st->length);
#endif
		}
		stream_put(s, st->value, st->length);
	}
}

void bgp_packet_mpattr_end(struct stream *s, size_t sizep)
{
	/* Set MP attribute length. Don't count the (2) bytes used to encode
	   the attr length */
	stream_putw_at(s, sizep, (stream_get_endp(s) - sizep) - 2);
}

static bool bgp_append_local_as(struct peer *peer, afi_t afi, safi_t safi)
{
	if (!BGP_AS_IS_PRIVATE(peer->local_as)
	    || (BGP_AS_IS_PRIVATE(peer->local_as)
		&& !CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS)
		&& !CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL)
		&& !CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE)
		&& !CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE)))
		return true;
	return false;
}

/* Make attribute packet. */
bgp_size_t bgp_packet_attribute(struct bgp *bgp, struct peer *peer,
				struct stream *s, struct attr *attr,
				struct bpacket_attr_vec_arr *vecarr,
				struct prefix *p, afi_t afi, safi_t safi,
				struct peer *from, struct prefix_rd *prd,
				mpls_label_t *label, uint32_t num_labels,
				int addpath_encode, uint32_t addpath_tx_id)
{
	size_t cp;
	size_t aspath_sizep;
	struct aspath *aspath;
	int send_as4_path = 0;
	int send_as4_aggregator = 0;
	int use32bit = (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)) ? 1 : 0;

	if (!bgp)
		bgp = peer->bgp;

	/* Remember current pointer. */
	cp = stream_get_endp(s);

	if (p
	    && !((afi == AFI_IP && safi == SAFI_UNICAST)
		 && !peer_cap_enhe(peer, afi, safi))) {
		size_t mpattrlen_pos = 0;

		mpattrlen_pos = bgp_packet_mpattr_start(s, peer, afi, safi,
							vecarr, attr);
		bgp_packet_mpattr_prefix(s, afi, safi, p, prd, label,
					 num_labels, addpath_encode,
					 addpath_tx_id, attr);
		bgp_packet_mpattr_end(s, mpattrlen_pos);
	}

	/* Origin attribute. */
	stream_putc(s, BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_ORIGIN);
	stream_putc(s, 1);
	stream_putc(s, attr->origin);

	/* AS path attribute. */

	/* If remote-peer is EBGP */
	if (peer->sort == BGP_PEER_EBGP
	    && (!CHECK_FLAG(peer->af_flags[afi][safi],
			    PEER_FLAG_AS_PATH_UNCHANGED)
		|| attr->aspath->segments == NULL)
	    && (!CHECK_FLAG(peer->af_flags[afi][safi],
			    PEER_FLAG_RSERVER_CLIENT))) {
		aspath = aspath_dup(attr->aspath);

		/* Even though we may not be configured for confederations we
		 * may have
		 * RXed an AS_PATH with AS_CONFED_SEQUENCE or AS_CONFED_SET */
		aspath = aspath_delete_confed_seq(aspath);

		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
			/* Stuff our path CONFED_ID on the front */
			aspath = aspath_add_seq(aspath, bgp->confed_id);
		} else {
			if (peer->change_local_as) {
				/* If replace-as is specified, we only use the
				   change_local_as when
				   advertising routes. */
				if (!CHECK_FLAG(peer->flags,
						PEER_FLAG_LOCAL_AS_REPLACE_AS))
					if (bgp_append_local_as(peer, afi,
								safi))
						aspath = aspath_add_seq(
							aspath, peer->local_as);
				aspath = aspath_add_seq(aspath,
							peer->change_local_as);
			} else {
				aspath = aspath_add_seq(aspath, peer->local_as);
			}
		}
	} else if (peer->sort == BGP_PEER_CONFED) {
		/* A confed member, so we need to do the AS_CONFED_SEQUENCE
		 * thing */
		aspath = aspath_dup(attr->aspath);
		aspath = aspath_add_confed_seq(aspath, peer->local_as);
	} else
		aspath = attr->aspath;

	/* If peer is not AS4 capable, then:
	 * - send the created AS_PATH out as AS4_PATH (optional, transitive),
	 *   but ensure that no AS_CONFED_SEQUENCE and AS_CONFED_SET path
	 * segment
	 *   types are in it (i.e. exclude them if they are there)
	 *   AND do this only if there is at least one asnum > 65535 in the
	 * path!
	 * - send an AS_PATH out, but put 16Bit ASnums in it, not 32bit, and
	 * change
	 *   all ASnums > 65535 to BGP_AS_TRANS
	 */

	stream_putc(s, BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_EXTLEN);
	stream_putc(s, BGP_ATTR_AS_PATH);
	aspath_sizep = stream_get_endp(s);
	stream_putw(s, 0);
	stream_putw_at(s, aspath_sizep, aspath_put(s, aspath, use32bit));

	/* OLD session may need NEW_AS_PATH sent, if there are 4-byte ASNs
	 * in the path
	 */
	if (!use32bit && aspath_has_as4(aspath))
		send_as4_path =
			1; /* we'll do this later, at the correct place */

	/* Nexthop attribute. */
	if (afi == AFI_IP && safi == SAFI_UNICAST
	    && !peer_cap_enhe(peer, afi, safi)) {
		afi_t nh_afi = BGP_NEXTHOP_AFI_FROM_NHLEN(attr->mp_nexthop_len);

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {
			stream_putc(s, BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_NEXT_HOP);
			bpacket_attr_vec_arr_set_vec(vecarr, BGP_ATTR_VEC_NH, s,
						     attr);
			stream_putc(s, 4);
			stream_put_ipv4(s, attr->nexthop.s_addr);
		} else if (peer_cap_enhe(from, afi, safi)
			   || (nh_afi == AFI_IP6)) {
			/*
			 * Likely this is the case when an IPv4 prefix was
			 * received with Extended Next-hop capability in this
			 * or another vrf and is now being advertised to
			 * non-ENHE peers. Since peer_cap_enhe only checks
			 * peers in this vrf, also check the nh_afi to catch
			 * the case where the originator was in another vrf.
			 * Setting the mandatory (ipv4) next-hop attribute here
			 * to enable implicit next-hop self with correct A-F
			 * (ipv4 address family).
			 */
			stream_putc(s, BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_NEXT_HOP);
			bpacket_attr_vec_arr_set_vec(vecarr, BGP_ATTR_VEC_NH, s,
						     NULL);
			stream_putc(s, 4);
			stream_put_ipv4(s, 0);
		}
	}

	/* MED attribute. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)
	    || bgp->maxmed_active) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MULTI_EXIT_DISC);
		stream_putc(s, 4);
		stream_putl(s, (bgp->maxmed_active ? bgp->maxmed_value
						   : attr->med));
	}

	/* Local preference. */
	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_LOCAL_PREF);
		stream_putc(s, 4);
		stream_putl(s, attr->local_pref);
	}

	/* Atomic aggregate. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_ATOMIC_AGGREGATE);
		stream_putc(s, 0);
	}

	/* Aggregator. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)) {
		/* Common to BGP_ATTR_AGGREGATOR, regardless of ASN size */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_AGGREGATOR);

		if (use32bit) {
			/* AS4 capable peer */
			stream_putc(s, 8);
			stream_putl(s, attr->aggregator_as);
		} else {
			/* 2-byte AS peer */
			stream_putc(s, 6);

			/* Is ASN representable in 2-bytes? Or must AS_TRANS be
			 * used? */
			if (attr->aggregator_as > 65535) {
				stream_putw(s, BGP_AS_TRANS);

				/* we have to send AS4_AGGREGATOR, too.
				 * we'll do that later in order to send
				 * attributes in ascending
				 * order.
				 */
				send_as4_aggregator = 1;
			} else
				stream_putw(s, (uint16_t)attr->aggregator_as);
		}
		stream_put_ipv4(s, attr->aggregator_addr.s_addr);
	}

	/* Community attribute. */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
	    && (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		if (attr->community->size * 4 > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putw(s, attr->community->size * 4);
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putc(s, attr->community->size * 4);
		}
		stream_put(s, attr->community->val, attr->community->size * 4);
	}

	/*
	 * Large Community attribute.
	 */
	if (CHECK_FLAG(peer->af_flags[afi][safi],
		       PEER_FLAG_SEND_LARGE_COMMUNITY)
	    && (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))) {
		if (lcom_length(attr->lcommunity) > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putw(s, lcom_length(attr->lcommunity));
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putc(s, lcom_length(attr->lcommunity));
		}
		stream_put(s, attr->lcommunity->val,
			   lcom_length(attr->lcommunity));
	}

	/* Route Reflector. */
	if (peer->sort == BGP_PEER_IBGP && from
	    && from->sort == BGP_PEER_IBGP) {
		/* Originator ID. */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_ORIGINATOR_ID);
		stream_putc(s, 4);

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
			stream_put_in_addr(s, &attr->originator_id);
		else
			stream_put_in_addr(s, &from->remote_id);

		/* Cluster list. */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_CLUSTER_LIST);

		if (attr->cluster) {
			stream_putc(s, attr->cluster->length + 4);
			/* If this peer configuration's parent BGP has
			 * cluster_id. */
			if (bgp->config & BGP_CONFIG_CLUSTER_ID)
				stream_put_in_addr(s, &bgp->cluster_id);
			else
				stream_put_in_addr(s, &bgp->router_id);
			stream_put(s, attr->cluster->list,
				   attr->cluster->length);
		} else {
			stream_putc(s, 4);
			/* If this peer configuration's parent BGP has
			 * cluster_id. */
			if (bgp->config & BGP_CONFIG_CLUSTER_ID)
				stream_put_in_addr(s, &bgp->cluster_id);
			else
				stream_put_in_addr(s, &bgp->router_id);
		}
	}

	/* Extended Communities attribute. */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)
	    && (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
		if (peer->sort == BGP_PEER_IBGP
		    || peer->sort == BGP_PEER_CONFED) {
			if (attr->ecommunity->size * 8 > 255) {
				stream_putc(s,
					    BGP_ATTR_FLAG_OPTIONAL
						    | BGP_ATTR_FLAG_TRANS
						    | BGP_ATTR_FLAG_EXTLEN);
				stream_putc(s, BGP_ATTR_EXT_COMMUNITIES);
				stream_putw(s, attr->ecommunity->size * 8);
			} else {
				stream_putc(s,
					    BGP_ATTR_FLAG_OPTIONAL
						    | BGP_ATTR_FLAG_TRANS);
				stream_putc(s, BGP_ATTR_EXT_COMMUNITIES);
				stream_putc(s, attr->ecommunity->size * 8);
			}
			stream_put(s, attr->ecommunity->val,
				   attr->ecommunity->size * 8);
		} else {
			uint8_t *pnt;
			int tbit;
			int ecom_tr_size = 0;
			int i;

			for (i = 0; i < attr->ecommunity->size; i++) {
				pnt = attr->ecommunity->val + (i * 8);
				tbit = *pnt;

				if (CHECK_FLAG(tbit,
					       ECOMMUNITY_FLAG_NON_TRANSITIVE))
					continue;

				ecom_tr_size++;
			}

			if (ecom_tr_size) {
				if (ecom_tr_size * 8 > 255) {
					stream_putc(
						s,
						BGP_ATTR_FLAG_OPTIONAL
							| BGP_ATTR_FLAG_TRANS
							| BGP_ATTR_FLAG_EXTLEN);
					stream_putc(s,
						    BGP_ATTR_EXT_COMMUNITIES);
					stream_putw(s, ecom_tr_size * 8);
				} else {
					stream_putc(
						s,
						BGP_ATTR_FLAG_OPTIONAL
							| BGP_ATTR_FLAG_TRANS);
					stream_putc(s,
						    BGP_ATTR_EXT_COMMUNITIES);
					stream_putc(s, ecom_tr_size * 8);
				}

				for (i = 0; i < attr->ecommunity->size; i++) {
					pnt = attr->ecommunity->val + (i * 8);
					tbit = *pnt;

					if (CHECK_FLAG(
						    tbit,
						    ECOMMUNITY_FLAG_NON_TRANSITIVE))
						continue;

					stream_put(s, pnt, 8);
				}
			}
		}
	}

	/* Label index attribute. */
	if (safi == SAFI_LABELED_UNICAST) {
		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID)) {
			uint32_t label_index;

			label_index = attr->label_index;

			if (label_index != BGP_INVALID_LABEL_INDEX) {
				stream_putc(s,
					    BGP_ATTR_FLAG_OPTIONAL
						    | BGP_ATTR_FLAG_TRANS);
				stream_putc(s, BGP_ATTR_PREFIX_SID);
				stream_putc(s, 10);
				stream_putc(s, BGP_PREFIX_SID_LABEL_INDEX);
				stream_putw(s,
					    BGP_PREFIX_SID_LABEL_INDEX_LENGTH);
				stream_putc(s, 0); // reserved
				stream_putw(s, 0); // flags
				stream_putl(s, label_index);
			}
		}
	}

	/* SRv6 Service Information Attribute. */
	if (afi == AFI_IP && safi == SAFI_MPLS_VPN) {
		if (attr->srv6_l3vpn) {
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL
					       | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_PREFIX_SID);
			stream_putc(s, 24);     /* tlv len */
			stream_putc(s, BGP_PREFIX_SID_SRV6_L3_SERVICE);
			stream_putw(s, 21);     /* sub-tlv len */
			stream_putc(s, 0);      /* reserved */
			stream_put(s, &attr->srv6_l3vpn->sid,
				   sizeof(attr->srv6_l3vpn->sid)); /* sid */
			stream_putc(s, 0);      /* sid_flags */
			stream_putw(s, 0xffff); /* endpoint */
			stream_putc(s, 0);      /* reserved */
		} else if (attr->srv6_vpn) {
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL
					       | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_PREFIX_SID);
			stream_putc(s, 22);     /* tlv len */
			stream_putc(s, BGP_PREFIX_SID_VPN_SID);
			stream_putw(s, 0x13);   /* tlv len */
			stream_putc(s, 0x00);   /* reserved */
			stream_putc(s, 0x01);   /* sid_type */
			stream_putc(s, 0x00);   /* sif_flags */
			stream_put(s, &attr->srv6_vpn->sid,
				   sizeof(attr->srv6_vpn->sid)); /* sid */
		}
	}

	if (send_as4_path) {
		/* If the peer is NOT As4 capable, AND */
		/* there are ASnums > 65535 in path  THEN
		 * give out AS4_PATH */

		/* Get rid of all AS_CONFED_SEQUENCE and AS_CONFED_SET
		 * path segments!
		 * Hm, I wonder...  confederation things *should* only be at
		 * the beginning of an aspath, right?  Then we should use
		 * aspath_delete_confed_seq for this, because it is already
		 * there! (JK)
		 * Folks, talk to me: what is reasonable here!?
		 */
		aspath = aspath_delete_confed_seq(aspath);

		stream_putc(s,
			    BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL
				    | BGP_ATTR_FLAG_EXTLEN);
		stream_putc(s, BGP_ATTR_AS4_PATH);
		aspath_sizep = stream_get_endp(s);
		stream_putw(s, 0);
		stream_putw_at(s, aspath_sizep, aspath_put(s, aspath, 1));
	}

	if (aspath != attr->aspath)
		aspath_free(aspath);

	if (send_as4_aggregator) {
		/* send AS4_AGGREGATOR, at this place */
		/* this section of code moved here in order to ensure the
		 * correct
		 * *ascending* order of attributes
		 */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_AS4_AGGREGATOR);
		stream_putc(s, 8);
		stream_putl(s, attr->aggregator_as);
		stream_put_ipv4(s, attr->aggregator_addr.s_addr);
	}

	if (((afi == AFI_IP || afi == AFI_IP6)
	     && (safi == SAFI_ENCAP || safi == SAFI_MPLS_VPN))
	    || (afi == AFI_L2VPN && safi == SAFI_EVPN)) {
		/* Tunnel Encap attribute */
		bgp_packet_mpattr_tea(bgp, peer, s, attr, BGP_ATTR_ENCAP);

#ifdef ENABLE_BGP_VNC_ATTR
		/* VNC attribute */
		bgp_packet_mpattr_tea(bgp, peer, s, attr, BGP_ATTR_VNC);
#endif
	}

	/* PMSI Tunnel */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL)) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_PMSI_TUNNEL);
		stream_putc(s, 9); // Length
		stream_putc(s, 0); // Flags
		stream_putc(s, attr->pmsi_tnl_type);
		stream_put(s, &(attr->label),
			   BGP_LABEL_BYTES); // MPLS Label / VXLAN VNI
		stream_put_ipv4(s, attr->nexthop.s_addr);
		// Unicast tunnel endpoint IP address
	}

	/* Unknown transit attribute. */
	if (attr->transit)
		stream_put(s, attr->transit->val, attr->transit->length);

	/* Return total size of attribute. */
	return stream_get_endp(s) - cp;
}

size_t bgp_packet_mpunreach_start(struct stream *s, afi_t afi, safi_t safi)
{
	unsigned long attrlen_pnt;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	/* Set extended bit always to encode the attribute length as 2 bytes */
	stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTLEN);
	stream_putc(s, BGP_ATTR_MP_UNREACH_NLRI);

	attrlen_pnt = stream_get_endp(s);
	stream_putw(s, 0); /* Length of this attribute. */

	/* Convert AFI, SAFI to values for packet. */
	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	stream_putw(s, pkt_afi);
	stream_putc(s, pkt_safi);

	return attrlen_pnt;
}

void bgp_packet_mpunreach_prefix(struct stream *s, const struct prefix *p,
				 afi_t afi, safi_t safi,
				 const struct prefix_rd *prd,
				 mpls_label_t *label, uint32_t num_labels,
				 int addpath_encode, uint32_t addpath_tx_id,
				 struct attr *attr)
{
	uint8_t wlabel[3] = {0x80, 0x00, 0x00};

	if (safi == SAFI_LABELED_UNICAST) {
		label = (mpls_label_t *)wlabel;
		num_labels = 1;
	}

	bgp_packet_mpattr_prefix(s, afi, safi, p, prd, label, num_labels,
				 addpath_encode, addpath_tx_id, attr);
}

void bgp_packet_mpunreach_end(struct stream *s, size_t attrlen_pnt)
{
	bgp_packet_mpattr_end(s, attrlen_pnt);
}

/* Initialization of attribute. */
void bgp_attr_init(void)
{
	aspath_init();
	attrhash_init();
	community_init();
	ecommunity_init();
	lcommunity_init();
	cluster_init();
	transit_init();
	encap_init();
	srv6_init();
}

void bgp_attr_finish(void)
{
	aspath_finish();
	attrhash_finish();
	community_finish();
	ecommunity_finish();
	lcommunity_finish();
	cluster_finish();
	transit_finish();
	encap_finish();
	srv6_finish();
}

/* Make attribute packet. */
void bgp_dump_routes_attr(struct stream *s, struct attr *attr,
			  const struct prefix *prefix)
{
	unsigned long cp;
	unsigned long len;
	size_t aspath_lenp;
	struct aspath *aspath;
	int addpath_encode = 0;
	uint32_t addpath_tx_id = 0;

	/* Remember current pointer. */
	cp = stream_get_endp(s);

	/* Place holder of length. */
	stream_putw(s, 0);

	/* Origin attribute. */
	stream_putc(s, BGP_ATTR_FLAG_TRANS);
	stream_putc(s, BGP_ATTR_ORIGIN);
	stream_putc(s, 1);
	stream_putc(s, attr->origin);

	aspath = attr->aspath;

	stream_putc(s, BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_EXTLEN);
	stream_putc(s, BGP_ATTR_AS_PATH);
	aspath_lenp = stream_get_endp(s);
	stream_putw(s, 0);

	stream_putw_at(s, aspath_lenp, aspath_put(s, aspath, 1));

	/* Nexthop attribute. */
	/* If it's an IPv6 prefix, don't dump the IPv4 nexthop to save space */
	if (prefix != NULL && prefix->family != AF_INET6) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_NEXT_HOP);
		stream_putc(s, 4);
		stream_put_ipv4(s, attr->nexthop.s_addr);
	}

	/* MED attribute. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MULTI_EXIT_DISC);
		stream_putc(s, 4);
		stream_putl(s, attr->med);
	}

	/* Local preference. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_LOCAL_PREF);
		stream_putc(s, 4);
		stream_putl(s, attr->local_pref);
	}

	/* Atomic aggregate. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_ATOMIC_AGGREGATE);
		stream_putc(s, 0);
	}

	/* Aggregator. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_AGGREGATOR);
		stream_putc(s, 8);
		stream_putl(s, attr->aggregator_as);
		stream_put_ipv4(s, attr->aggregator_addr.s_addr);
	}

	/* Community attribute. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)) {
		if (attr->community->size * 4 > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putw(s, attr->community->size * 4);
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putc(s, attr->community->size * 4);
		}
		stream_put(s, attr->community->val, attr->community->size * 4);
	}

	/* Large Community attribute. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES)) {
		if (lcom_length(attr->lcommunity) > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putw(s, lcom_length(attr->lcommunity));
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putc(s, lcom_length(attr->lcommunity));
		}

		stream_put(s, attr->lcommunity->val,
			   lcom_length(attr->lcommunity));
	}

	/* Add a MP_NLRI attribute to dump the IPv6 next hop */
	if (prefix != NULL && prefix->family == AF_INET6
	    && (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL
		|| attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)) {
		int sizep;

		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MP_REACH_NLRI);
		sizep = stream_get_endp(s);

		/* MP header */
		stream_putc(s, 0);	    /* Marker: Attribute length. */
		stream_putw(s, AFI_IP6);      /* AFI */
		stream_putc(s, SAFI_UNICAST); /* SAFI */

		/* Next hop */
		stream_putc(s, attr->mp_nexthop_len);
		stream_put(s, &attr->mp_nexthop_global, IPV6_MAX_BYTELEN);
		if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
			stream_put(s, &attr->mp_nexthop_local,
				   IPV6_MAX_BYTELEN);

		/* SNPA */
		stream_putc(s, 0);

		/* Prefix */
		stream_put_prefix_addpath(s, prefix, addpath_encode,
					  addpath_tx_id);

		/* Set MP attribute length. */
		stream_putc_at(s, sizep, (stream_get_endp(s) - sizep) - 1);
	}

	/* Prefix SID */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID)) {
		if (attr->label_index != BGP_INVALID_LABEL_INDEX) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_PREFIX_SID);
			stream_putc(s, 10);
			stream_putc(s, BGP_PREFIX_SID_LABEL_INDEX);
			stream_putc(s, BGP_PREFIX_SID_LABEL_INDEX_LENGTH);
			stream_putc(s, 0); // reserved
			stream_putw(s, 0); // flags
			stream_putl(s, attr->label_index);
		}
	}

	/* Return total size of attribute. */
	len = stream_get_endp(s) - cp - 2;
	stream_putw_at(s, cp, len);
}
