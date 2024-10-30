// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP attributes management routines.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
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
#include "frrstr.h"

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
	{BGP_ATTR_MP_REACH_NLRI, "MP_REACH_NLRI"},
	{BGP_ATTR_MP_UNREACH_NLRI, "MP_UNREACH_NLRI"},
	{BGP_ATTR_EXT_COMMUNITIES, "EXT_COMMUNITIES"},
	{BGP_ATTR_AS4_PATH, "AS4_PATH"},
	{BGP_ATTR_AS4_AGGREGATOR, "AS4_AGGREGATOR"},
	{BGP_ATTR_PMSI_TUNNEL, "PMSI_TUNNEL_ATTRIBUTE"},
	{BGP_ATTR_ENCAP, "ENCAP"},
	{BGP_ATTR_OTC, "OTC"},
#ifdef ENABLE_BGP_VNC_ATTR
	{BGP_ATTR_VNC, "VNC"},
#endif
	{BGP_ATTR_LARGE_COMMUNITIES, "LARGE_COMMUNITY"},
	{BGP_ATTR_PREFIX_SID, "PREFIX_SID"},
	{BGP_ATTR_IPV6_EXT_COMMUNITIES, "IPV6_EXT_COMMUNITIES"},
	{BGP_ATTR_AIGP, "AIGP"},
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
	if (!*cluster)
		return;

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
	hash_clean_and_free(&cluster_hash, (void (*)(void *))cluster_free);
}

static struct hash *encap_hash = NULL;
#ifdef ENABLE_BGP_VNC
static struct hash *vnc_hash = NULL;
#endif
static struct hash *srv6_l3vpn_hash;
static struct hash *srv6_vpn_hash;
static struct hash *evpn_overlay_hash;

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
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);

	if (vnc_subtlvs) {
		encap_free(vnc_subtlvs);
		bgp_attr_set_vnc_subtlvs(attr, NULL);
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

	if (!*encapp)
		return;

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
	hash_clean_and_free(&encap_hash, (void (*)(void *))encap_free);
#ifdef ENABLE_BGP_VNC
	hash_clean_and_free(&vnc_hash, (void (*)(void *))encap_free);
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

	return bgp_route_evpn_same(bgp_attr_get_evpn_overlay(a1),
				   bgp_attr_get_evpn_overlay(a2));
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
	if (!*transit)
		return;

	if ((*transit)->refcnt)
		(*transit)->refcnt--;

	if ((*transit)->refcnt == 0) {
		hash_release(transit_hash, *transit);
		transit_free(*transit);
		*transit = NULL;
	}
}

static bool bgp_attr_aigp_get_tlv_metric(uint8_t *pnt, int length,
					 uint64_t *aigp)
{
	uint8_t *data = pnt;
	uint8_t tlv_type;
	uint16_t tlv_length;

	while (length) {
		tlv_type = *data;
		ptr_get_be16(data + 1, &tlv_length);
		(void)data;

		/* The value field of the AIGP TLV is always 8 octets
		 * long and its value is interpreted as an unsigned 64-bit
		 * integer.
		 */
		if (tlv_type == BGP_AIGP_TLV_METRIC) {
			(void)ptr_get_be64(data + 3, aigp);

			/* If an AIGP attribute is received and its first AIGP
			 * TLV contains the maximum value 0xffffffffffffffff,
			 * the attribute SHOULD be considered to be malformed
			 * and SHOULD be discarded as specified in this section.
			 */
			if (*aigp == BGP_AIGP_TLV_METRIC_MAX) {
				zlog_err("Bad AIGP TLV (%s) length: %llu",
					 BGP_AIGP_TLV_METRIC_DESC,
					 BGP_AIGP_TLV_METRIC_MAX);
				return false;
			}

			return true;
		}

		data += tlv_length;
		length -= tlv_length;
	}

	return false;
}

static void stream_put_bgp_aigp_tlv_metric(struct stream *s, uint64_t aigp)
{
	stream_putc(s, BGP_AIGP_TLV_METRIC);
	stream_putw(s, BGP_AIGP_TLV_METRIC_LEN);
	stream_putq(s, aigp);
}

static bool bgp_attr_aigp_valid(uint8_t *pnt, int length)
{
	uint8_t *data = pnt;
	uint8_t tlv_type;
	uint16_t tlv_length;
	uint8_t *end = data + length;

	if (length < 3) {
		zlog_err("Bad AIGP attribute length (MUST be minimum 3): %u",
			 length);
		return false;
	}

	while (length) {
		size_t data_len = end - data;

		tlv_type = *data;

		if (data_len - 1 < 2)
			return false;

		ptr_get_be16(data + 1, &tlv_length);
		(void)data;

		if (length < tlv_length) {
			zlog_err(
				"Bad AIGP attribute length: %u, but TLV length: %u",
				length, tlv_length);
			return false;
		}

		if (tlv_length < 3) {
			zlog_err("Bad AIGP TLV length (MUST be minimum 3): %u",
				 tlv_length);
			return false;
		}

		/* AIGP TLV, Length: 11 */
		if (tlv_type == BGP_AIGP_TLV_METRIC &&
		    tlv_length != BGP_AIGP_TLV_METRIC_LEN) {
			zlog_err("Bad AIGP TLV (%s) length: %u",
				 BGP_AIGP_TLV_METRIC_DESC, tlv_length);
			return false;
		}

		data += tlv_length;
		length -= tlv_length;
	}

	return true;
}

static void *evpn_overlay_hash_alloc(void *p)
{
	return p;
}

void evpn_overlay_free(struct bgp_route_evpn *bre)
{
	XFREE(MTYPE_BGP_EVPN_OVERLAY, bre);
}

static struct bgp_route_evpn *evpn_overlay_intern(struct bgp_route_evpn *bre)
{
	struct bgp_route_evpn *find;

	find = hash_get(evpn_overlay_hash, bre, evpn_overlay_hash_alloc);
	if (find != bre)
		evpn_overlay_free(bre);
	find->refcnt++;
	return find;
}

static void evpn_overlay_unintern(struct bgp_route_evpn **brep)
{
	struct bgp_route_evpn *bre = *brep;

	if (!*brep)
		return;

	if (bre->refcnt)
		bre->refcnt--;

	if (bre->refcnt == 0) {
		hash_release(evpn_overlay_hash, bre);
		evpn_overlay_free(bre);
		*brep = NULL;
	}
}

static uint32_t evpn_overlay_hash_key_make(const void *p)
{
	const struct bgp_route_evpn *bre = p;
	uint32_t key = 0;

	if (IS_IPADDR_V4(&bre->gw_ip))
		key = jhash_1word(bre->gw_ip.ipaddr_v4.s_addr, 0);
	else
		key = jhash2(bre->gw_ip.ipaddr_v6.s6_addr32,
			     array_size(bre->gw_ip.ipaddr_v6.s6_addr32), 0);

	key = jhash_1word(bre->type, key);
	key = jhash(bre->eth_s_id.val, sizeof(bre->eth_s_id.val), key);
	return key;
}

static bool evpn_overlay_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_route_evpn *bre1 = p1;
	const struct bgp_route_evpn *bre2 = p2;

	return bgp_route_evpn_same(bre1, bre2);
}

static void evpn_overlay_init(void)
{
	evpn_overlay_hash = hash_create(evpn_overlay_hash_key_make,
					evpn_overlay_hash_cmp,
					"BGP EVPN Overlay");
}

static void evpn_overlay_finish(void)
{
	hash_clean_and_free(&evpn_overlay_hash,
			    (void (*)(void *))evpn_overlay_free);
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

	if (!*l3vpnp)
		return;

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

	if (!*vpnp)
		return;

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
	key = jhash_3words(l3vpn->sid_flags, l3vpn->endpoint_behavior, l3vpn->loc_block_len, key);
	key = jhash_3words(l3vpn->loc_node_len, l3vpn->func_len, l3vpn->arg_len, key);
	key = jhash_2words(l3vpn->transposition_len, l3vpn->transposition_offset, key);
	return key;
}

static bool srv6_l3vpn_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_attr_srv6_l3vpn *l3vpn1 = p1;
	const struct bgp_attr_srv6_l3vpn *l3vpn2 = p2;

	return sid_same(&l3vpn1->sid, &l3vpn2->sid)
	       && l3vpn1->sid_flags == l3vpn2->sid_flags
	       && l3vpn1->endpoint_behavior == l3vpn2->endpoint_behavior
	       && l3vpn1->loc_block_len == l3vpn2->loc_block_len
	       && l3vpn1->loc_node_len == l3vpn2->loc_node_len
	       && l3vpn1->func_len == l3vpn2->func_len
	       && l3vpn1->arg_len == l3vpn2->arg_len
	       && l3vpn1->transposition_len == l3vpn2->transposition_len
	       && l3vpn1->transposition_offset == l3vpn2->transposition_offset;
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
	hash_clean_and_free(&srv6_l3vpn_hash,
			    (void (*)(void *))srv6_l3vpn_free);
	hash_clean_and_free(&srv6_vpn_hash, (void (*)(void *))srv6_vpn_free);
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
	hash_clean_and_free(&transit_hash, (void (*)(void *))transit_free);
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
	if (bgp_attr_get_community(attr))
		MIX(community_hash_make(bgp_attr_get_community(attr)));
	if (bgp_attr_get_lcommunity(attr))
		MIX(lcommunity_hash_make(bgp_attr_get_lcommunity(attr)));
	if (bgp_attr_get_ecommunity(attr))
		MIX(ecommunity_hash_make(bgp_attr_get_ecommunity(attr)));
	if (bgp_attr_get_ipv6_ecommunity(attr))
		MIX(ecommunity_hash_make(bgp_attr_get_ipv6_ecommunity(attr)));
	if (bgp_attr_get_cluster(attr))
		MIX(cluster_hash_key_make(bgp_attr_get_cluster(attr)));
	if (bgp_attr_get_transit(attr))
		MIX(transit_hash_key_make(bgp_attr_get_transit(attr)));
	if (attr->encap_subtlvs)
		MIX(encap_hash_key_make(attr->encap_subtlvs));
	if (attr->srv6_l3vpn)
		MIX(srv6_l3vpn_hash_key_make(attr->srv6_l3vpn));
	if (bgp_attr_get_evpn_overlay(attr))
		MIX(evpn_overlay_hash_key_make(bgp_attr_get_evpn_overlay(attr)));
	if (attr->srv6_vpn)
		MIX(srv6_vpn_hash_key_make(attr->srv6_vpn));
#ifdef ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);
	if (vnc_subtlvs)
		MIX(encap_hash_key_make(vnc_subtlvs));
#endif
	MIX3(attr->mp_nexthop_len, attr->rmap_table_id, attr->nh_type);
	key = jhash(attr->mp_nexthop_global.s6_addr, IPV6_MAX_BYTELEN, key);
	key = jhash(attr->mp_nexthop_local.s6_addr, IPV6_MAX_BYTELEN, key);
	MIX3(attr->nh_ifindex, attr->nh_lla_ifindex, attr->distance);
	MIX3(attr->bh_type, attr->otc, bgp_attr_get_aigp_metric(attr));

	return key;
}

bool attrhash_cmp(const void *p1, const void *p2)
{
	const struct attr *attr1 = p1;
	const struct attr *attr2 = p2;

	if (attr1->flag == attr2->flag && attr1->origin == attr2->origin &&
	    attr1->nexthop.s_addr == attr2->nexthop.s_addr &&
	    attr1->aspath == attr2->aspath &&
	    bgp_attr_get_community(attr1) == bgp_attr_get_community(attr2) &&
	    attr1->med == attr2->med && attr1->local_pref == attr2->local_pref &&
	    attr1->rmap_change_flags == attr2->rmap_change_flags) {
		if (attr1->aggregator_as == attr2->aggregator_as &&
		    attr1->aggregator_addr.s_addr ==
			    attr2->aggregator_addr.s_addr &&
		    attr1->weight == attr2->weight && attr1->tag == attr2->tag &&
		    attr1->label_index == attr2->label_index &&
		    attr1->mp_nexthop_len == attr2->mp_nexthop_len &&
		    bgp_attr_get_ecommunity(attr1) ==
			    bgp_attr_get_ecommunity(attr2) &&
		    bgp_attr_get_ipv6_ecommunity(attr1) ==
			    bgp_attr_get_ipv6_ecommunity(attr2) &&
		    bgp_attr_get_lcommunity(attr1) ==
			    bgp_attr_get_lcommunity(attr2) &&
		    bgp_attr_get_cluster(attr1) == bgp_attr_get_cluster(attr2) &&
		    bgp_attr_get_transit(attr1) == bgp_attr_get_transit(attr2) &&
		    bgp_attr_get_aigp_metric(attr1) ==
			    bgp_attr_get_aigp_metric(attr2) &&
		    attr1->rmap_table_id == attr2->rmap_table_id &&
		    (attr1->encap_tunneltype == attr2->encap_tunneltype) &&
		    encap_same(attr1->encap_subtlvs, attr2->encap_subtlvs)
#ifdef ENABLE_BGP_VNC
		    && encap_same(bgp_attr_get_vnc_subtlvs(attr1),
				  bgp_attr_get_vnc_subtlvs(attr2))
#endif
		    && IPV6_ADDR_SAME(&attr1->mp_nexthop_global,
				      &attr2->mp_nexthop_global) &&
		    IPV6_ADDR_SAME(&attr1->mp_nexthop_local,
				   &attr2->mp_nexthop_local) &&
		    IPV4_ADDR_SAME(&attr1->mp_nexthop_global_in,
				   &attr2->mp_nexthop_global_in) &&
		    IPV4_ADDR_SAME(&attr1->originator_id,
				   &attr2->originator_id) &&
		    overlay_index_same(attr1, attr2) &&
		    !memcmp(&attr1->esi, &attr2->esi, sizeof(esi_t)) &&
		    attr1->es_flags == attr2->es_flags &&
		    attr1->mm_sync_seqnum == attr2->mm_sync_seqnum &&
		    attr1->df_pref == attr2->df_pref &&
		    attr1->df_alg == attr2->df_alg &&
		    attr1->nh_ifindex == attr2->nh_ifindex &&
		    attr1->nh_lla_ifindex == attr2->nh_lla_ifindex &&
		    attr1->nh_flags == attr2->nh_flags &&
		    attr1->distance == attr2->distance &&
		    srv6_l3vpn_same(attr1->srv6_l3vpn, attr2->srv6_l3vpn) &&
		    srv6_vpn_same(attr1->srv6_vpn, attr2->srv6_vpn) &&
		    attr1->srte_color == attr2->srte_color &&
		    attr1->nh_type == attr2->nh_type &&
		    attr1->bh_type == attr2->bh_type && attr1->otc == attr2->otc)
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
	hash_clean_and_free(&attrhash, attr_vfree);
}

static void attr_show_all_iterator(struct hash_bucket *bucket, struct vty *vty)
{
	struct attr *attr = bucket->data;
	struct in6_addr *sid = NULL;

	if (attr->srv6_l3vpn)
		sid = &attr->srv6_l3vpn->sid;
	else if (attr->srv6_vpn)
		sid = &attr->srv6_vpn->sid;

	vty_out(vty, "attr[%ld] nexthop %pI4\n", attr->refcnt, &attr->nexthop);

	vty_out(vty,
		"\tflags: %" PRIu64
		" distance: %u med: %u local_pref: %u origin: %u weight: %u label: %u sid: %pI6 aigp_metric: %" PRIu64
		"\n",
		attr->flag, attr->distance, attr->med, attr->local_pref,
		attr->origin, attr->weight, attr->label, sid, attr->aigp_metric);
	vty_out(vty,
		"\tnh_ifindex: %u nh_flags: %u distance: %u nexthop_global: %pI6 nexthop_local: %pI6 nexthop_local_ifindex: %u\n",
		attr->nh_ifindex, attr->nh_flags, attr->distance, &attr->mp_nexthop_global,
		&attr->mp_nexthop_local, attr->nh_lla_ifindex);
	vty_out(vty, "\taspath: %s Community: %s Large Community: %s\n", aspath_print(attr->aspath),
		community_str(attr->community, false, false),
		lcommunity_str(attr->lcommunity, false, false));
	vty_out(vty, "\tExtended Community: %s Extended IPv6 Community: %s\n",
		ecommunity_str(attr->ecommunity),
		ecommunity_str(attr->ipv6_ecommunity));
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
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(val);

	if (vnc_subtlvs)
		bgp_attr_set_vnc_subtlvs(val, NULL);
#endif

	attr->refcnt = 0;
	return attr;
}

/* Internet argument attribute. */
struct attr *bgp_attr_intern(struct attr *attr)
{
	struct attr *find;
	struct ecommunity *ecomm = NULL;
	struct ecommunity *ipv6_ecomm = NULL;
	struct lcommunity *lcomm = NULL;
	struct community *comm = NULL;
	struct bgp_route_evpn *bre = NULL;

	/* Intern referenced structure. */
	if (attr->aspath) {
		if (!attr->aspath->refcnt)
			attr->aspath = aspath_intern(attr->aspath);
		else
			attr->aspath->refcnt++;
	}

	comm = bgp_attr_get_community(attr);
	if (comm) {
		if (!comm->refcnt)
			bgp_attr_set_community(attr, community_intern(comm));
		else
			comm->refcnt++;
	}

	ecomm = bgp_attr_get_ecommunity(attr);
	if (ecomm) {
		if (!ecomm->refcnt)
			bgp_attr_set_ecommunity(attr, ecommunity_intern(ecomm));
		else
			ecomm->refcnt++;
	}

	ipv6_ecomm = bgp_attr_get_ipv6_ecommunity(attr);
	if (ipv6_ecomm) {
		if (!ipv6_ecomm->refcnt)
			bgp_attr_set_ipv6_ecommunity(
				attr, ecommunity_intern(ipv6_ecomm));
		else
			ipv6_ecomm->refcnt++;
	}

	lcomm = bgp_attr_get_lcommunity(attr);
	if (lcomm) {
		if (!lcomm->refcnt)
			bgp_attr_set_lcommunity(attr, lcommunity_intern(lcomm));
		else
			lcomm->refcnt++;
	}

	struct cluster_list *cluster = bgp_attr_get_cluster(attr);

	if (cluster) {
		if (!cluster->refcnt)
			bgp_attr_set_cluster(attr, cluster_intern(cluster));
		else
			cluster->refcnt++;
	}

	struct transit *transit = bgp_attr_get_transit(attr);

	if (transit) {
		if (!transit->refcnt)
			bgp_attr_set_transit(attr, transit_intern(transit));
		else
			transit->refcnt++;
	}
	if (attr->encap_subtlvs) {
		if (!attr->encap_subtlvs->refcnt)
			attr->encap_subtlvs = encap_intern(attr->encap_subtlvs,
							   ENCAP_SUBTLV_TYPE);
		else
			attr->encap_subtlvs->refcnt++;
	}

	bre = bgp_attr_get_evpn_overlay(attr);
	if (bre) {
		if (!bre->refcnt)
			bgp_attr_set_evpn_overlay(attr,
						  evpn_overlay_intern(bre));
		else
			bre->refcnt++;
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
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);

	if (vnc_subtlvs) {
		if (!vnc_subtlvs->refcnt)
			bgp_attr_set_vnc_subtlvs(
				attr,
				encap_intern(vnc_subtlvs, VNC_SUBTLV_TYPE));
		else
			vnc_subtlvs->refcnt++;
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
struct attr *bgp_attr_default_set(struct attr *attr, struct bgp *bgp,
				  uint8_t origin)
{
	memset(attr, 0, sizeof(struct attr));

	attr->origin = origin;
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN));
	attr->aspath = aspath_empty(bgp->asnotation);
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
	attr->weight = BGP_ATTR_DEFAULT_WEIGHT;
	attr->tag = 0;
	attr->label_index = BGP_INVALID_LABEL_INDEX;
	attr->label = MPLS_INVALID_LABEL;
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
	attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
	attr->local_pref = bgp->default_local_pref;

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
	route_map_result_t ret;

	memset(&attr, 0, sizeof(attr));

	/* Origin attribute. */
	attr.origin = origin;
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN));

	/* MED */
	bgp_attr_set_med(&attr, 0);

	/* AS path attribute. */
	if (aspath)
		attr.aspath = aspath_intern(aspath);
	else
		attr.aspath = aspath_empty(bgp->asnotation);
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));

	if (community) {
		uint32_t gshut = COMMUNITY_GSHUT;

		/* If we are not shutting down ourselves and we are
		 * aggregating a route that contains the GSHUT community we
		 * need to remove that community when creating the aggregate */
		if (!bgp_in_graceful_shutdown(bgp)
		    && community_include(community, gshut)) {
			community_del_val(community, &gshut);
		}

		bgp_attr_set_community(&attr, community);
	}

	if (ecommunity)
		bgp_attr_set_ecommunity(&attr, ecommunity);

	if (lcommunity)
		bgp_attr_set_lcommunity(&attr, lcommunity);

	if (bgp_in_graceful_shutdown(bgp))
		bgp_attr_add_gshut_community(&attr);

	attr.label_index = BGP_INVALID_LABEL_INDEX;
	attr.label = MPLS_INVALID_LABEL;
	attr.weight = BGP_ATTR_DEFAULT_WEIGHT;
	attr.mp_nexthop_len = IPV6_MAX_BYTELEN;
	if (!aggregate->as_set || atomic_aggregate)
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE));
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR));
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
		attr.aggregator_as = bgp->confed_id;
	else
		attr.aggregator_as = bgp->as;
	attr.aggregator_addr = bgp->router_id;

	/* Aggregate are done for IPv4/IPv6 so checking ipv4 family,
	 * This should only be set for IPv4 AFI type
	 * based on RFC-4760:
	 * "An UPDATE message that carries no NLRI,
	 * other than the one encoded in
	 * the MP_REACH_NLRI attribute,
	 * SHOULD NOT carry the NEXT_HOP
	 * attribute"
	 */
	if (p->family == AF_INET) {
		/* Next hop attribute.  */
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
		attr.mp_nexthop_len = IPV4_MAX_BYTELEN;
	}

	/* Apply route-map */
	if (aggregate->rmap.name) {
		struct attr attr_tmp = attr;
		struct bgp_path_info rmap_path;

		memset(&rmap_path, 0, sizeof(rmap_path));
		rmap_path.peer = bgp->peer_self;
		rmap_path.attr = &attr_tmp;

		SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_AGGREGATE);

		ret = route_map_apply(aggregate->rmap.map, p, &rmap_path);

		bgp->peer_self->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			/* Free uninterned attribute. */
			bgp_attr_flush(&attr_tmp);

			/* Unintern original. */
			aspath_unintern(&attr.aspath);
			return NULL;
		}

		if (bgp_in_graceful_shutdown(bgp))
			bgp_attr_add_gshut_community(&attr_tmp);

		new = bgp_attr_intern(&attr_tmp);
	} else {

		if (bgp_in_graceful_shutdown(bgp))
			bgp_attr_add_gshut_community(&attr);

		new = bgp_attr_intern(&attr);
	}

	/* Always release the 'intern()'ed AS Path. */
	aspath_unintern(&attr.aspath);

	return new;
}

/* Unintern just the sub-components of the attr, but not the attr */
void bgp_attr_unintern_sub(struct attr *attr)
{
	struct ecommunity *ecomm = NULL;
	struct ecommunity *ipv6_ecomm = NULL;
	struct cluster_list *cluster;
	struct lcommunity *lcomm = NULL;
	struct community *comm = NULL;
	struct transit *transit;
	struct bgp_route_evpn *bre;

	/* aspath refcount shoud be decrement. */
	aspath_unintern(&attr->aspath);
	UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));

	comm = bgp_attr_get_community(attr);
	community_unintern(&comm);
	bgp_attr_set_community(attr, NULL);

	ecomm = bgp_attr_get_ecommunity(attr);
	ecommunity_unintern(&ecomm);
	bgp_attr_set_ecommunity(attr, NULL);

	ipv6_ecomm = bgp_attr_get_ipv6_ecommunity(attr);
	ecommunity_unintern(&ipv6_ecomm);
	bgp_attr_set_ipv6_ecommunity(attr, NULL);

	lcomm = bgp_attr_get_lcommunity(attr);
	lcommunity_unintern(&lcomm);
	bgp_attr_set_lcommunity(attr, NULL);

	cluster = bgp_attr_get_cluster(attr);
	cluster_unintern(&cluster);
	bgp_attr_set_cluster(attr, NULL);

	transit = bgp_attr_get_transit(attr);
	transit_unintern(&transit);
	bgp_attr_set_transit(attr, NULL);

	encap_unintern(&attr->encap_subtlvs, ENCAP_SUBTLV_TYPE);

#ifdef ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);

	encap_unintern(&vnc_subtlvs, VNC_SUBTLV_TYPE);
	bgp_attr_set_vnc_subtlvs(attr, NULL);
#endif

	srv6_l3vpn_unintern(&attr->srv6_l3vpn);
	srv6_vpn_unintern(&attr->srv6_vpn);

	bre = bgp_attr_get_evpn_overlay(attr);
	evpn_overlay_unintern(&bre);
	bgp_attr_set_evpn_overlay(attr, NULL);
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
	struct ecommunity *ecomm;
	struct ecommunity *ipv6_ecomm;
	struct cluster_list *cluster;
	struct lcommunity *lcomm;
	struct community *comm;
	struct bgp_route_evpn *bre;

	if (attr->aspath && !attr->aspath->refcnt) {
		aspath_free(attr->aspath);
		attr->aspath = NULL;
	}
	comm = bgp_attr_get_community(attr);
	if (comm && !comm->refcnt)
		community_free(&comm);
	bgp_attr_set_community(attr, NULL);

	ecomm = bgp_attr_get_ecommunity(attr);
	if (ecomm && !ecomm->refcnt)
		ecommunity_free(&ecomm);
	bgp_attr_set_ecommunity(attr, NULL);

	ipv6_ecomm = bgp_attr_get_ipv6_ecommunity(attr);
	if (ipv6_ecomm && !ipv6_ecomm->refcnt)
		ecommunity_free(&ipv6_ecomm);
	bgp_attr_set_ipv6_ecommunity(attr, NULL);

	lcomm = bgp_attr_get_lcommunity(attr);
	if (lcomm && !lcomm->refcnt)
		lcommunity_free(&lcomm);
	bgp_attr_set_lcommunity(attr, NULL);

	cluster = bgp_attr_get_cluster(attr);
	if (cluster && !cluster->refcnt) {
		cluster_free(cluster);
		bgp_attr_set_cluster(attr, NULL);
	}

	struct transit *transit = bgp_attr_get_transit(attr);

	if (transit && !transit->refcnt) {
		transit_free(transit);
		bgp_attr_set_transit(attr, NULL);
	}
	if (attr->encap_subtlvs && !attr->encap_subtlvs->refcnt) {
		encap_free(attr->encap_subtlvs);
		attr->encap_subtlvs = NULL;
	}
	if (attr->srv6_l3vpn && !attr->srv6_l3vpn->refcnt) {
		srv6_l3vpn_free(attr->srv6_l3vpn);
		attr->srv6_l3vpn = NULL;
	}
	if (attr->srv6_vpn && !attr->srv6_vpn->refcnt) {
		srv6_vpn_free(attr->srv6_vpn);
		attr->srv6_vpn = NULL;
	}
#ifdef ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);

	if (vnc_subtlvs && !vnc_subtlvs->refcnt) {
		encap_free(vnc_subtlvs);
		bgp_attr_set_vnc_subtlvs(attr, NULL);
	}
#endif
	bre = bgp_attr_get_evpn_overlay(attr);
	if (bre && !bre->refcnt) {
		evpn_overlay_free(bre);
		bgp_attr_set_evpn_overlay(attr, NULL);
	}
}

/* Implement draft-scudder-idr-optional-transitive behaviour and
 * avoid resetting sessions for malformed attributes which are
 * are partial/optional and hence where the error likely was not
 * introduced by the sending neighbour.
 */
static enum bgp_attr_parse_ret
bgp_attr_malformed(struct bgp_attr_parser_args *args, uint8_t subcode,
		   bgp_size_t length)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const uint8_t flags = args->flags;
	/* startp and length must be special-cased, as whether or not to
	 * send the attribute data with the NOTIFY depends on the error,
	 * the caller therefore signals this with the seperate length argument
	 */
	uint8_t *notify_datap = (length > 0 ? args->startp : NULL);

	if (bgp_debug_update(peer, NULL, NULL, 1)) {
		char attr_str[BUFSIZ] = {0};

		bgp_dump_attr(attr, attr_str, sizeof(attr_str));

		zlog_debug("%s: attributes: %s", __func__, attr_str);
	}

	/* Only relax error handling for eBGP peers */
	if (peer->sort != BGP_PEER_EBGP) {
		bgp_notify_send_with_data(peer->connection,
					  BGP_NOTIFY_UPDATE_ERR, subcode,
					  notify_datap, length);
		return BGP_ATTR_PARSE_ERROR;
	}

	/* Adjust the stream getp to the end of the attribute, in case we can
	 * still proceed but the caller hasn't read all the attribute.
	 */
	stream_set_getp(BGP_INPUT(peer),
			(args->startp - STREAM_DATA(BGP_INPUT(peer)))
				+ args->total);

	/* Partial optional attributes that are malformed should not cause
	 * the whole session to be reset. Instead treat it as a withdrawal
	 * of the routes, if possible.
	 */
	if (CHECK_FLAG(flags, BGP_ATTR_FLAG_TRANS) &&
	    CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL) &&
	    CHECK_FLAG(flags, BGP_ATTR_FLAG_PARTIAL))
		return BGP_ATTR_PARSE_WITHDRAW;

	switch (args->type) {
	/* where an attribute is relatively inconsequential, e.g. it does not
	 * affect route selection, and can be safely ignored, then any such
	 * attributes which are malformed should just be ignored and the route
	 * processed as normal.
	 */
	case BGP_ATTR_AS4_AGGREGATOR:
	case BGP_ATTR_AGGREGATOR:
	case BGP_ATTR_ATOMIC_AGGREGATE:
	case BGP_ATTR_PREFIX_SID:
		return BGP_ATTR_PARSE_PROCEED;

	/* Core attributes, particularly ones which may influence route
	 * selection, should be treat-as-withdraw.
	 */
	case BGP_ATTR_ORIGIN:
	case BGP_ATTR_AS_PATH:
	case BGP_ATTR_AS4_PATH:
	case BGP_ATTR_NEXT_HOP:
	case BGP_ATTR_MULTI_EXIT_DISC:
	case BGP_ATTR_LOCAL_PREF:
	case BGP_ATTR_COMMUNITIES:
	case BGP_ATTR_EXT_COMMUNITIES:
	case BGP_ATTR_IPV6_EXT_COMMUNITIES:
	case BGP_ATTR_LARGE_COMMUNITIES:
	case BGP_ATTR_ORIGINATOR_ID:
	case BGP_ATTR_CLUSTER_LIST:
	case BGP_ATTR_PMSI_TUNNEL:
	case BGP_ATTR_ENCAP:
	case BGP_ATTR_OTC:
		return BGP_ATTR_PARSE_WITHDRAW;
	case BGP_ATTR_MP_REACH_NLRI:
	case BGP_ATTR_MP_UNREACH_NLRI:
		bgp_notify_send_with_data(peer->connection,
					  BGP_NOTIFY_UPDATE_ERR, subcode,
					  notify_datap, length);
		return BGP_ATTR_PARSE_ERROR;
	default:
		/* Unknown attributes, that are handled by this function
		 * should be treated as withdraw, to prevent one more CVE
		 * from being introduced.
		 * RFC 7606 says:
		 * The "treat-as-withdraw" approach is generally preferred
		 * and the "session reset" approach is discouraged.
		 */
		flog_err(EC_BGP_ATTR_FLAG,
			 "%s(%u) attribute received, while it is not known how to handle it, treating as withdraw",
			 lookup_msg(attr_str, args->type, NULL), args->type);
		break;
	}

	return BGP_ATTR_PARSE_WITHDRAW;
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

	UNSET_FLAG(desired_flags, BGP_ATTR_FLAG_EXTLEN);
	UNSET_FLAG(real_flags, BGP_ATTR_FLAG_EXTLEN);
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
			"Strange, %s called for attr %s, but no problem found with flags (real flags 0x%x, desired 0x%x)",
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
	[BGP_ATTR_OTC] = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_PREFIX_SID] = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_IPV6_EXT_COMMUNITIES] =
		BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS,
	[BGP_ATTR_AIGP] = BGP_ATTR_FLAG_OPTIONAL,
};
static const size_t attr_flags_values_max = array_size(attr_flags_values) - 1;

static bool bgp_attr_flag_invalid(struct bgp_attr_parser_args *args)
{
	uint8_t mask = BGP_ATTR_FLAG_EXTLEN;
	const uint8_t flags = args->flags;
	const uint8_t attr_code = args->type;
	struct peer *peer = args->peer;

	/* there may be attributes we don't know about */
	if (attr_code > attr_flags_values_max)
		return false;
	if (attr_flags_values[attr_code] == 0)
		return false;

	/* If `neighbor X path-attribute <discard|treat-as-withdraw>` is
	 * configured, then ignore checking optional, trasitive flags.
	 * The attribute/route will be discarded/withdrawned later instead
	 * of dropping the session.
	 */
	if (peer->discard_attrs[attr_code] || peer->withdraw_attrs[attr_code])
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
				 "%s well-known attribute must NOT have the partial flag set (%x)",
				 lookup_msg(attr_str, attr_code, NULL), flags);
			return true;
		}
		if (CHECK_FLAG(flags, BGP_ATTR_FLAG_OPTIONAL)
		    && !CHECK_FLAG(flags, BGP_ATTR_FLAG_TRANS)) {
			flog_err(EC_BGP_ATTR_FLAG,
				 "%s optional + transitive attribute must NOT have the partial flag set (%x)",
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

	if (CHECK_FLAG(flags, ~mask) == attr_flags_values[attr_code])
		return false;

	bgp_attr_flags_diagnose(args, attr_flags_values[attr_code]);
	return true;
}

/* Get origin attribute of the update message. */
static enum bgp_attr_parse_ret
bgp_attr_origin(struct bgp_attr_parser_args *args)
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
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN));

	return 0;
}

/* Parse AS path information.  This function is wrapper of
   aspath_parse. */
static int bgp_attr_aspath(struct bgp_attr_parser_args *args)
{
	struct attr *const attr = args->attr;
	struct peer *const peer = args->peer;
	const bgp_size_t length = args->length;
	enum asnotation_mode asnotation;

	asnotation = bgp_get_asnotation(
		args->peer && args->peer->bgp ? args->peer->bgp : NULL);
	/*
	 * peer with AS4 => will get 4Byte ASnums
	 * otherwise, will get 16 Bit
	 */
	attr->aspath =
		aspath_parse(peer->curr, length,
			     CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV) &&
				     CHECK_FLAG(peer->cap, PEER_CAP_AS4_ADV),
			     asnotation);

	/* In case of IBGP, length will be zero. */
	if (!attr->aspath) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "Malformed AS path from %s, length is %d", peer->host,
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Conformant BGP speakers SHOULD NOT send BGP
	 * UPDATE messages containing AS_SET or AS_CONFED_SET.  Upon receipt of
	 * such messages, conformant BGP speakers SHOULD use the "Treat-as-
	 * withdraw" error handling behavior as per [RFC7606].
	 */
	if (peer->bgp && peer->bgp->reject_as_sets &&
	    aspath_check_as_sets(attr->aspath)) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "AS_SET and AS_CONFED_SET are deprecated from %pBP",
			 peer);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Set aspath attribute flag. */
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));

	return BGP_ATTR_PARSE_PROCEED;
}

static enum bgp_attr_parse_ret bgp_attr_aspath_check(struct peer *const peer,
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

	/* Refresh peer's type. If we set e.g.: AS_EXTERNAL/AS_INTERNAL,
	 * then peer->sort remains BGP_PEER_EBGP/IBGP, hence we need to
	 * have an actual type before checking.
	 * This is especially a case for BGP confederation peers, to avoid
	 * receiving and treating AS_PATH as malformed.
	 */
	(void)peer_sort(peer);

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

	/* Codification of AS 0 Processing */
	if (peer->sort == BGP_PEER_EBGP && aspath_check_as_zero(attr->aspath)) {
		flog_err(
			EC_BGP_ATTR_MAL_AS_PATH,
			"Malformed AS path, AS number is 0 in the path from %s",
			peer->host);
		return BGP_ATTR_PARSE_WITHDRAW;
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
	enum asnotation_mode asnotation;

	asnotation = bgp_get_asnotation(peer->bgp);

	*as4_path = aspath_parse(peer->curr, length, 1, asnotation);

	/* In case of IBGP, length will be zero. */
	if (!*as4_path) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "Malformed AS4 path from %s, length is %d", peer->host,
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Conformant BGP speakers SHOULD NOT send BGP
	 * UPDATE messages containing AS_SET or AS_CONFED_SET.  Upon receipt of
	 * such messages, conformant BGP speakers SHOULD use the "Treat-as-
	 * withdraw" error handling behavior as per [RFC7606].
	 */
	if (peer->bgp->reject_as_sets && aspath_check_as_sets(attr->aspath)) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH,
			 "AS_SET and AS_CONFED_SET are deprecated from %pBP",
			 peer);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  0);
	}

	/* Set aspath attribute flag. */
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH));

	return BGP_ATTR_PARSE_PROCEED;
}

/*
 * Check that the nexthop attribute is valid.
 */
enum bgp_attr_parse_ret bgp_attr_nexthop_valid(struct peer *peer,
					       struct attr *attr)
{
	struct bgp *bgp = peer->bgp;

	if (ipv4_martian(&attr->nexthop) && !bgp->allow_martian) {
		uint8_t data[7]; /* type(2) + length(1) + nhop(4) */

		flog_err(EC_BGP_ATTR_MARTIAN_NH, "Martian nexthop %pI4",
			 &attr->nexthop);
		data[0] = BGP_ATTR_FLAG_TRANS;
		data[1] = BGP_ATTR_NEXT_HOP;
		data[2] = BGP_ATTR_NHLEN_IPV4;
		memcpy(&data[3], &attr->nexthop.s_addr, BGP_ATTR_NHLEN_IPV4);
		bgp_notify_send_with_data(peer->connection,
					  BGP_NOTIFY_UPDATE_ERR,
					  BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP,
					  data, 7);
		return BGP_ATTR_PARSE_ERROR;
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* Nexthop attribute. */
static enum bgp_attr_parse_ret
bgp_attr_nexthop(struct bgp_attr_parser_args *args)
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
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));

	return BGP_ATTR_PARSE_PROCEED;
}

/* MED atrribute. */
static enum bgp_attr_parse_ret bgp_attr_med(struct bgp_attr_parser_args *args)
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

	bgp_attr_set_med(attr, stream_getl(peer->curr));

	return BGP_ATTR_PARSE_PROCEED;
}

/* Local preference attribute. */
static enum bgp_attr_parse_ret
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
	if ((peer->sort == BGP_PEER_IBGP ||
	     peer->sub_sort == BGP_PEER_EBGP_OAD) &&
	    length != 4) {
		flog_err(EC_BGP_ATTR_LEN,
			 "LOCAL_PREF attribute length isn't 4 [%u]", length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	/* If it is contained in an UPDATE message that is received from an
	   external peer, then this attribute MUST be ignored by the
	   receiving speaker. */
	if (peer->sort == BGP_PEER_EBGP && peer->sub_sort != BGP_PEER_EBGP_OAD) {
		STREAM_FORWARD_GETP(peer->curr, length);
		return BGP_ATTR_PARSE_PROCEED;
	}

	STREAM_GETL(peer->curr, attr->local_pref);

	/* Set the local-pref flag. */
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));

	return BGP_ATTR_PARSE_PROCEED;

stream_failure:
	return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				  args->total);
}

/* Atomic aggregate. */
static int bgp_attr_atomic(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
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

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto atomic_ignore;

	/* Set atomic aggregate flag. */
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE));

	return BGP_ATTR_PARSE_PROCEED;

atomic_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
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

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto aggregator_ignore;

	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV))
		aggregator_as = stream_getl(peer->curr);
	else
		aggregator_as = stream_getw(peer->curr);

	attr->aggregator_as = aggregator_as;
	attr->aggregator_addr.s_addr = stream_get_ipv4(peer->curr);

	/* Codification of AS 0 Processing */
	if (aggregator_as == BGP_AS_ZERO) {
		flog_err(EC_BGP_ATTR_LEN,
			 "%s: AGGREGATOR AS number is 0 for aspath: %s",
			 peer->host, aspath_print(attr->aspath));

		if (bgp_debug_update(peer, NULL, NULL, 1)) {
			char attr_str[BUFSIZ] = {0};

			bgp_dump_attr(attr, attr_str, sizeof(attr_str));

			zlog_debug("%s: attributes: %s", __func__, attr_str);
		}
	} else {
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR));
	}

	return BGP_ATTR_PARSE_PROCEED;

aggregator_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* New Aggregator attribute */
static enum bgp_attr_parse_ret
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

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto as4_aggregator_ignore;

	aggregator_as = stream_getl(peer->curr);

	*as4_aggregator_as = aggregator_as;
	as4_aggregator_addr->s_addr = stream_get_ipv4(peer->curr);

	/* Codification of AS 0 Processing */
	if (aggregator_as == BGP_AS_ZERO) {
		flog_err(EC_BGP_ATTR_LEN,
			 "%s: AS4_AGGREGATOR AS number is 0 for aspath: %s",
			 peer->host, aspath_print(attr->aspath));

		if (bgp_debug_update(peer, NULL, NULL, 1)) {
			char attr_str[BUFSIZ] = {0};

			bgp_dump_attr(attr, attr_str, sizeof(attr_str));

			zlog_debug("%s: attributes: %s", __func__, attr_str);
		}
	} else {
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR));
	}

	return BGP_ATTR_PARSE_PROCEED;

as4_aggregator_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* Munge Aggregator and New-Aggregator, AS_PATH and NEW_AS_PATH.
 */
static enum bgp_attr_parse_ret
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
			if (CHECK_FLAG(attr->flag,
				       (ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH))))
				zlog_debug("[AS4] %s %s AS4_PATH", peer->host,
					   "AS4 capable peer, yet it sent");

			if (CHECK_FLAG(attr->flag,
				       (ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR))))
				zlog_debug("[AS4] %s %s AS4_AGGREGATOR",
					   peer->host,
					   "AS4 capable peer, yet it sent");
		}

		return BGP_ATTR_PARSE_PROCEED;
	}

	/* We have a asn16 peer.  First, look for AS4_AGGREGATOR
	 * because that may override AS4_PATH
	 */
	if (CHECK_FLAG(attr->flag, (ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR)))) {
		if (CHECK_FLAG(attr->flag,
			       (ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))) {
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
						"[AS4] %s BGP not AS4 capable peer send AGGREGATOR != AS_TRANS and AS4_AGGREGATOR, so ignore AS4_AGGREGATOR and AS4_PATH",
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
					"[AS4] %s BGP not AS4 capable peer send AS4_AGGREGATOR but no AGGREGATOR, will take it as if AGGREGATOR with AS_TRANS had been there",
					peer->host);
			attr->aggregator_as = as4_aggregator;
			/* sweep it under the carpet and simulate a "good"
			 * AGGREGATOR */
			SET_FLAG(attr->flag,
				 (ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)));
		}
	}

	/* need to reconcile NEW_AS_PATH and AS_PATH */
	if (!ignore_as4_path &&
	    (CHECK_FLAG(attr->flag, (ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH))))) {
		newpath = aspath_reconcile_as4(attr->aspath, as4_path);
		if (!newpath)
			return BGP_ATTR_PARSE_ERROR;

		aspath_unintern(&attr->aspath);
		attr->aspath = aspath_intern(newpath);
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/* Community attribute. */
static enum bgp_attr_parse_ret
bgp_attr_community(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	if (length == 0) {
		bgp_attr_set_community(attr, NULL);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto community_ignore;

	bgp_attr_set_community(
		attr,
		community_parse((uint32_t *)stream_pnt(peer->curr), length));

	/* XXX: fix community_parse to use stream API and remove this */
	stream_forward_getp(peer->curr, length);

	/* The Community attribute SHALL be considered malformed if its
	 * length is not a non-zero multiple of 4.
	 */
	if (!bgp_attr_get_community(attr))
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	return BGP_ATTR_PARSE_PROCEED;

community_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* Originator ID attribute. */
static enum bgp_attr_parse_ret
bgp_attr_originator_id(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* if the ORIGINATOR_ID attribute is received from an external
	 * neighbor, it SHALL be discarded using the approach of "attribute
	 * discard".
	 */
	if (peer->sort == BGP_PEER_EBGP) {
		stream_forward_getp(peer->curr, length);
		return BGP_ATTR_PARSE_PROCEED;
	}

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

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto originator_id_ignore;

	attr->originator_id.s_addr = stream_get_ipv4(peer->curr);

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));

	return BGP_ATTR_PARSE_PROCEED;

originator_id_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* Cluster list attribute. */
static enum bgp_attr_parse_ret
bgp_attr_cluster_list(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* if the CLUSTER_LIST attribute is received from an external
	 * neighbor, it SHALL be discarded using the approach of "attribute
	 * discard".
	 */
	if (peer->sort == BGP_PEER_EBGP) {
		stream_forward_getp(peer->curr, length);
		return BGP_ATTR_PARSE_PROCEED;
	}

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

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto cluster_list_ignore;

	bgp_attr_set_cluster(
		attr, cluster_parse((struct in_addr *)stream_pnt(peer->curr),
				    length));

	/* XXX: Fix cluster_parse to use stream API and then remove this */
	stream_forward_getp(peer->curr, length);

	return BGP_ATTR_PARSE_PROCEED;

cluster_list_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* get locally configure or received srte-color value*/
uint32_t bgp_attr_get_color(struct attr *attr)
{
	if (attr->srte_color)
		return attr->srte_color;
	if (attr->ecommunity)
		return ecommunity_select_color(attr->ecommunity);
	return 0;
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
				 */
		fallthrough;
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
			if (if_is_operative(peer->nexthop.ifp))
				SET_FLAG(attr->nh_flags,
					 BGP_ATTR_NH_IF_OPERSTATE);
			else
				UNSET_FLAG(attr->nh_flags,
					   BGP_ATTR_NH_IF_OPERSTATE);
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
			if (if_is_operative(peer->nexthop.ifp))
				SET_FLAG(attr->nh_flags,
					 BGP_ATTR_NH_IF_OPERSTATE);
			else
				UNSET_FLAG(attr->nh_flags,
					   BGP_ATTR_NH_IF_OPERSTATE);
		}
		if (attr->mp_nexthop_len
		    == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
			stream_getl(s); /* RD high */
			stream_getl(s); /* RD low */
		}
		stream_get(&attr->mp_nexthop_local, s, IPV6_MAX_BYTELEN);
		if (!IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_local)) {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"%s sent next-hops %pI6 and %pI6. Ignoring non-LL value",
					peer->host, &attr->mp_nexthop_global,
					&attr->mp_nexthop_local);

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
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_ATTR, 0);
	}

	mp_update->afi = afi;
	mp_update->safi = safi;
	mp_update->nlri = stream_pnt(s);
	mp_update->length = nlri_len;

	stream_forward_getp(s, nlri_len);

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI));

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

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI));

	return BGP_ATTR_PARSE_PROCEED;
}

/* Large Community attribute. */
static enum bgp_attr_parse_ret
bgp_attr_large_community(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/*
	 * Large community follows new attribute format.
	 */
	if (length == 0) {
		bgp_attr_set_lcommunity(attr, NULL);
		/* Empty extcomm doesn't seem to be invalid per se */
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto large_community_ignore;

	bgp_attr_set_lcommunity(
		attr, lcommunity_parse(stream_pnt(peer->curr), length));
	/* XXX: fix ecommunity_parse to use stream API */
	stream_forward_getp(peer->curr, length);

	if (!bgp_attr_get_lcommunity(attr))
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	return BGP_ATTR_PARSE_PROCEED;

large_community_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* Extended Community attribute. */
static enum bgp_attr_parse_ret
bgp_attr_ext_communities(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	bool proxy = false;
	struct ecommunity *ecomm;

	if (length == 0) {
		bgp_attr_set_ecommunity(attr, NULL);
		/* Empty extcomm doesn't seem to be invalid per se */
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	ecomm = ecommunity_parse(stream_pnt(peer->curr), length,
				 CHECK_FLAG(peer->flags,
					    PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE));
	bgp_attr_set_ecommunity(attr, ecomm);
	/* XXX: fix ecommunity_parse to use stream API */
	stream_forward_getp(peer->curr, length);

	/* The Extended Community attribute SHALL be considered malformed if
	 * its length is not a non-zero multiple of 8.
	 */
	if (!bgp_attr_get_ecommunity(attr))
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	/* Extract DF election preference and  mobility sequence number */
	attr->df_pref = bgp_attr_df_pref_from_ec(attr, &attr->df_alg);

	/* Extract MAC mobility sequence number, if any. */
	attr->mm_seqnum = bgp_attr_mac_mobility_seqnum(attr);

	/* Check if this is a Gateway MAC-IP advertisement */
	bgp_attr_default_gw(attr);

	/* Handle scenario where router flag ecommunity is not
	 * set but default gw ext community is present.
	 * Use default gateway, set and propogate R-bit.
	 */
	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW))
		SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_ROUTER);

	/* Check EVPN Neighbor advertisement flags, R-bit */
	bgp_attr_evpn_na_flag(attr, &proxy);
	if (proxy)
		SET_FLAG(attr->es_flags, ATTR_ES_PROXY_ADVERT);

	/* Extract the Rmac, if any */
	if (bgp_attr_rmac(attr, &attr->rmac)) {
		if (bgp_debug_update(peer, NULL, NULL, 1)
		    && bgp_mac_exist(&attr->rmac))
			zlog_debug("%s: router mac %pEA is self mac", __func__,
				   &attr->rmac);
	}

	/* Get the tunnel type from encap extended community */
	bgp_attr_extcom_tunnel_type(attr,
		(bgp_encap_types *)&attr->encap_tunneltype);

	/* Extract link bandwidth, if any. */
	(void)ecommunity_linkbw_present(bgp_attr_get_ecommunity(attr),
					&attr->link_bw);

	return BGP_ATTR_PARSE_PROCEED;
}

/* IPv6 Extended Community attribute. */
static enum bgp_attr_parse_ret
bgp_attr_ipv6_ext_communities(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	struct ecommunity *ipv6_ecomm = NULL;

	if (length == 0) {
		bgp_attr_set_ipv6_ecommunity(attr, ipv6_ecomm);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto ipv6_ext_community_ignore;

	ipv6_ecomm = ecommunity_parse_ipv6(stream_pnt(peer->curr), length);
	bgp_attr_set_ipv6_ecommunity(attr, ipv6_ecomm);

	/* XXX: fix ecommunity_parse to use stream API */
	stream_forward_getp(peer->curr, length);

	if (!ipv6_ecomm)
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);

	/* Extract link bandwidth, if any. */
	(void)ecommunity_linkbw_present(bgp_attr_get_ipv6_ecommunity(attr),
					&attr->link_bw);

	return BGP_ATTR_PARSE_PROCEED;

ipv6_ext_community_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* Parse Tunnel Encap attribute in an UPDATE */
static int bgp_attr_encap(struct bgp_attr_parser_args *args)
{
	uint16_t tunneltype = 0;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	bgp_size_t length = args->length;
	uint8_t type = args->type;
	uint8_t flag = args->flags;

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto encap_ignore;

	if (!CHECK_FLAG(flag, BGP_ATTR_FLAG_TRANS)
	    || !CHECK_FLAG(flag, BGP_ATTR_FLAG_OPTIONAL)) {
		zlog_err("Tunnel Encap attribute flag isn't optional and transitive %d",
			 flag);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	if (BGP_ATTR_ENCAP == type) {
		/* read outer TLV type and length */
		uint16_t tlv_length;

		if (length < 4) {
			zlog_err(
				"Tunnel Encap attribute not long enough to contain outer T,L");
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
						  args->total);
		}
		tunneltype = stream_getw(BGP_INPUT(peer));
		tlv_length = stream_getw(BGP_INPUT(peer));
		length -= 4;

		if (tlv_length != length) {
			zlog_info("%s: tlv_length(%d) != length(%d)",
				  __func__, tlv_length, length);
		}
	}

	while (STREAM_READABLE(BGP_INPUT(peer)) >= 4) {
		uint16_t subtype = 0;
		uint16_t sublength = 0;
		struct bgp_attr_encap_subtlv *tlv;

		if (BGP_ATTR_ENCAP == type) {
			subtype = stream_getc(BGP_INPUT(peer));
			if (subtype < 128) {
				sublength = stream_getc(BGP_INPUT(peer));
				length -= 2;
			} else {
				sublength = stream_getw(BGP_INPUT(peer));
				length -= 3;
			}
#ifdef ENABLE_BGP_VNC
		} else {
			subtype = stream_getw(BGP_INPUT(peer));
			sublength = stream_getw(BGP_INPUT(peer));
			length -= 4;
#endif
		}

		if (sublength > length) {
			zlog_err("Tunnel Encap attribute sub-tlv length %d exceeds remaining length %d",
				 sublength, length);
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
						  args->total);
		}

		if (STREAM_READABLE(BGP_INPUT(peer)) < sublength) {
			zlog_err("Tunnel Encap attribute sub-tlv length %d exceeds remaining stream length %zu",
				 sublength, STREAM_READABLE(BGP_INPUT(peer)));
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
						  args->total);
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
			struct bgp_attr_encap_subtlv *vnc_subtlvs =
				bgp_attr_get_vnc_subtlvs(attr);

			for (stlv_last = vnc_subtlvs;
			     stlv_last && stlv_last->next;
			     stlv_last = stlv_last->next)
				;
			if (stlv_last)
				stlv_last->next = tlv;
			else
				bgp_attr_set_vnc_subtlvs(attr, tlv);
#endif
		}
	}

	if (BGP_ATTR_ENCAP == type) {
		attr->encap_tunneltype = tunneltype;
	}

	if (length) {
		/* spurious leftover data */
		zlog_err("Tunnel Encap attribute length is bad: %d leftover octets",
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->total);
	}

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ENCAP));

	return BGP_ATTR_PARSE_PROCEED;

encap_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, type);
}


/* SRv6 Service Data Sub-Sub-TLV attribute
 * draft-ietf-bess-srv6-services-07
 */
static enum bgp_attr_parse_ret
bgp_attr_srv6_service_data(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	uint8_t type, loc_block_len, loc_node_len, func_len, arg_len,
		transposition_len, transposition_offset;
	uint16_t length;
	size_t headersz = sizeof(type) + sizeof(length);

	if (STREAM_READABLE(peer->curr) < headersz) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Malformed SRv6 Service Data Sub-Sub-TLV attribute - insufficent data (need %zu for attribute header, have %zu remaining in UPDATE)",
			headersz, STREAM_READABLE(peer->curr));
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	type = stream_getc(peer->curr);
	length = stream_getw(peer->curr);

	if (STREAM_READABLE(peer->curr) < length) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Malformed SRv6 Service Data Sub-Sub-TLV attribute - insufficent data (need %hu for attribute data, have %zu remaining in UPDATE)",
			length, STREAM_READABLE(peer->curr));
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (length < BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Malformed SRv6 Service Data Sub-Sub-TLV attribute - insufficient data (need %u, have %hu remaining in UPDATE)",
			BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH,
			length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (type == BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE) {
		if (STREAM_READABLE(peer->curr) <
		    BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Malformed SRv6 Service Data Sub-Sub-TLV attribute - insufficient data (need %u, have %zu remaining in UPDATE)",
				BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH,
				STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}

		loc_block_len = stream_getc(peer->curr);
		loc_node_len = stream_getc(peer->curr);
		func_len = stream_getc(peer->curr);
		arg_len = stream_getc(peer->curr);
		transposition_len = stream_getc(peer->curr);
		transposition_offset = stream_getc(peer->curr);

		/* Log SRv6 Service Data Sub-Sub-TLV */
		if (BGP_DEBUG(vpn, VPN_LEAK_LABEL)) {
			zlog_debug(
				"%s: srv6-l3-srv-data loc-block-len=%u, loc-node-len=%u func-len=%u, arg-len=%u, transposition-len=%u, transposition-offset=%u",
				__func__, loc_block_len, loc_node_len, func_len,
				arg_len, transposition_len,
				transposition_offset);
		}

		attr->srv6_l3vpn->loc_block_len = loc_block_len;
		attr->srv6_l3vpn->loc_node_len = loc_node_len;
		attr->srv6_l3vpn->func_len = func_len;
		attr->srv6_l3vpn->arg_len = arg_len;
		attr->srv6_l3vpn->transposition_len = transposition_len;
		attr->srv6_l3vpn->transposition_offset = transposition_offset;
	}

	else {
		if (bgp_debug_update(peer, NULL, NULL, 1))
			zlog_debug(
				"%s attr SRv6 Service Data Sub-Sub-TLV sub-sub-type=%u is not supported, skipped",
				peer->host, type);

		stream_forward_getp(peer->curr, length);
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/* SRv6 Service Sub-TLV attribute
 * draft-ietf-bess-srv6-services-07
 */
static enum bgp_attr_parse_ret
bgp_attr_srv6_service(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	struct in6_addr ipv6_sid;
	uint8_t type, sid_flags;
	uint16_t length, endpoint_behavior;
	size_t headersz = sizeof(type) + sizeof(length);
	enum bgp_attr_parse_ret err;

	if (STREAM_READABLE(peer->curr) < headersz) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Malformed SRv6 Service Sub-TLV attribute - insufficent data (need %zu for attribute header, have %zu remaining in UPDATE)",
			headersz, STREAM_READABLE(peer->curr));
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	type = stream_getc(peer->curr);
	length = stream_getw(peer->curr);

	if (STREAM_READABLE(peer->curr) < length) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Malformed SRv6 Service Sub-TLV attribute - insufficent data (need %hu for attribute data, have %zu remaining in UPDATE)",
			length, STREAM_READABLE(peer->curr));
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (type == BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO) {
		if (STREAM_READABLE(peer->curr) <
		    BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Malformed SRv6 Service Sub-TLV attribute - insufficent data (need %d for attribute data, have %zu remaining in UPDATE)",
				BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH,
				STREAM_READABLE(peer->curr));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}
		stream_getc(peer->curr);
		stream_get(&ipv6_sid, peer->curr, sizeof(ipv6_sid));
		sid_flags = stream_getc(peer->curr);
		endpoint_behavior = stream_getw(peer->curr);
		stream_getc(peer->curr);

		/* Log SRv6 Service Sub-TLV */
		if (BGP_DEBUG(vpn, VPN_LEAK_LABEL))
			zlog_debug(
				"%s: srv6-l3-srv sid %pI6, sid-flags 0x%02x, end-behaviour 0x%04x",
				__func__, &ipv6_sid, sid_flags,
				endpoint_behavior);

		/* Configure from Info */
		if (attr->srv6_l3vpn) {
			flog_err(EC_BGP_ATTRIBUTE_REPEATED,
				 "Prefix SID SRv6 L3VPN field repeated");
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_MAL_ATTR, args->total);
		}
		attr->srv6_l3vpn = XCALLOC(MTYPE_BGP_SRV6_L3VPN,
					   sizeof(struct bgp_attr_srv6_l3vpn));
		sid_copy(&attr->srv6_l3vpn->sid, &ipv6_sid);
		attr->srv6_l3vpn->sid_flags = sid_flags;
		attr->srv6_l3vpn->endpoint_behavior = endpoint_behavior;
		attr->srv6_l3vpn->loc_block_len = 0;
		attr->srv6_l3vpn->loc_node_len = 0;
		attr->srv6_l3vpn->func_len = 0;
		attr->srv6_l3vpn->arg_len = 0;
		attr->srv6_l3vpn->transposition_len = 0;
		attr->srv6_l3vpn->transposition_offset = 0;

		// Sub-Sub-TLV found
		if (length > BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH) {
			err = bgp_attr_srv6_service_data(args);

			if (err != BGP_ATTR_PARSE_PROCEED)
				return err;
		}

		attr->srv6_l3vpn = srv6_l3vpn_intern(attr->srv6_l3vpn);
	}

	/* Placeholder code for unsupported type */
	else {
		if (bgp_debug_update(peer, NULL, NULL, 1))
			zlog_debug(
				"%s attr SRv6 Service Sub-TLV sub-type=%u is not supported, skipped",
				peer->host, type);

		stream_forward_getp(peer->curr, length);
	}

	return BGP_ATTR_PARSE_PROCEED;
}

/*
 * Read an individual SID value returning how much data we have read
 * Returns 0 if there was an error that needs to be passed up the stack
 */
static enum bgp_attr_parse_ret
bgp_attr_psid_sub(uint8_t type, uint16_t length,
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

	/*
	 * Check that we actually have at least as much data as
	 * specified by the length field
	 */
	if (STREAM_READABLE(peer->curr) < length) {
		flog_err(
			EC_BGP_ATTR_LEN,
			"Prefix SID specifies length %hu, but only %zu bytes remain",
			length, STREAM_READABLE(peer->curr));
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (type == BGP_PREFIX_SID_LABEL_INDEX) {
		if (length != BGP_PREFIX_SID_LABEL_INDEX_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID label index length is %hu instead of %u",
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
	} else if (type == BGP_PREFIX_SID_IPV6) {
		if (length != BGP_PREFIX_SID_IPV6_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID IPv6 length is %hu instead of %u",
				 length, BGP_PREFIX_SID_IPV6_LENGTH);
			return bgp_attr_malformed(args,
						  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
						  args->total);
		}

		/* Ignore reserved */
		stream_getc(peer->curr);
		stream_getw(peer->curr);

		stream_get(&ipv6_sid, peer->curr, 16);
	} else if (type == BGP_PREFIX_SID_ORIGINATOR_SRGB) {
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
				"Prefix SID Originator SRGB length field claims length of %hu bytes, but the minimum for this TLV type is %u",
				length,
				2 + BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH);
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
				"Prefix SID Originator SRGB length field claims attribute SRGB sequence section is %hubytes, but it must be a multiple of %u",
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
	} else if (type == BGP_PREFIX_SID_VPN_SID) {
		if (length != BGP_PREFIX_SID_VPN_SID_LENGTH) {
			flog_err(EC_BGP_ATTR_LEN,
				 "Prefix SID VPN SID length is %hu instead of %u",
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
		if (BGP_DEBUG(vpn, VPN_LEAK_LABEL))
			zlog_debug(
				"%s: vpn-sid: sid %pI6, sid-type 0x%02x sid-flags 0x%02x",
				__func__, &ipv6_sid, sid_type, sid_flags);

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
		attr->srv6_vpn = srv6_vpn_intern(attr->srv6_vpn);
	} else if (type == BGP_PREFIX_SID_SRV6_L3_SERVICE) {
		if (STREAM_READABLE(peer->curr) < 1) {
			flog_err(
				EC_BGP_ATTR_LEN,
				"Prefix SID SRV6 L3 Service not enough data left, it must be at least 1 byte");
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}
		/* ignore reserved */
		stream_getc(peer->curr);

		return bgp_attr_srv6_service(args);
	}
	/* Placeholder code for Unsupported TLV */
	else {
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
enum bgp_attr_parse_ret bgp_attr_prefix_sid(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	enum bgp_attr_parse_ret ret;

	uint8_t type;
	uint16_t length;
	size_t headersz = sizeof(type) + sizeof(length);
	size_t psid_parsed_length = 0;

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto prefix_sid_ignore;

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
				"Malformed Prefix SID attribute - insufficient data (need %hu for attribute body, have %zu remaining in UPDATE)",
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
				"Malformed Prefix SID attribute - TLV overflow by attribute (need %zu for TLV length, have %zu overflowed in UPDATE)",
				length + headersz, psid_parsed_length - (length + headersz));
			return bgp_attr_malformed(
				args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
				args->total);
		}
	}

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));

	return BGP_ATTR_PARSE_PROCEED;

prefix_sid_ignore:
	stream_forward_getp(peer->curr, args->length);

	return bgp_attr_ignore(peer, args->type);
}

/* PMSI tunnel attribute (RFC 6514)
 * Basic validation checks done here.
 */
static enum bgp_attr_parse_ret
bgp_attr_pmsi_tunnel(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	uint8_t tnl_type;
	int attr_parse_len = 2 + BGP_LABEL_BYTES;

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto pmsi_tunnel_ignore;

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

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL));
	bgp_attr_set_pmsi_tnl_type(attr, tnl_type);
	stream_get(&attr->label, peer->curr, BGP_LABEL_BYTES);

	/* Forward read pointer of input stream. */
	stream_forward_getp(peer->curr, length - attr_parse_len);

	return BGP_ATTR_PARSE_PROCEED;

pmsi_tunnel_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* AIGP attribute (rfc7311) */
static enum bgp_attr_parse_ret bgp_attr_aigp(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	uint8_t *s = stream_pnt(peer->curr);
	uint64_t aigp = 0;

	/* If an AIGP attribute is received on a BGP session for which
	 * AIGP_SESSION is disabled, the attribute MUST be treated exactly
	 * as if it were an unrecognized non-transitive attribute.
	 * That is, it "MUST be quietly ignored and not passed along to
	 * other BGP peers".
	 * For Internal BGP (IBGP) sessions, and for External BGP (EBGP)
	 * sessions between members of the same BGP Confederation,
	 * the default value of AIGP_SESSION SHOULD be "enabled".
	 */
	if (peer->sort == BGP_PEER_EBGP &&
	    (!CHECK_FLAG(peer->flags, PEER_FLAG_AIGP) ||
	     peer->sub_sort != BGP_PEER_EBGP_OAD)) {
		zlog_warn(
			"%pBP received AIGP attribute, but eBGP peer do not support it",
			peer);
		goto aigp_ignore;
	}

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto aigp_ignore;

	if (!bgp_attr_aigp_valid(s, length))
		goto aigp_ignore;

	/* Extract AIGP Metric TLV */
	if (bgp_attr_aigp_get_tlv_metric(s, length, &aigp))
		bgp_attr_set_aigp_metric(attr, aigp);

aigp_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* OTC attribute. */
static enum bgp_attr_parse_ret bgp_attr_otc(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;

	/* Length check. */
	if (length != 4) {
		flog_err(EC_BGP_ATTR_LEN, "OTC attribute length isn't 4 [%u]",
			 length);
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
					  args->total);
	}

	if (peer->discard_attrs[args->type] || peer->withdraw_attrs[args->type])
		goto otc_ignore;

	attr->otc = stream_getl(peer->curr);
	if (!attr->otc) {
		flog_err(EC_BGP_ATTR_MAL_AS_PATH, "OTC attribute value is 0");
		return bgp_attr_malformed(args, BGP_NOTIFY_UPDATE_MAL_AS_PATH,
					  args->total);
	}

	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC));

	return BGP_ATTR_PARSE_PROCEED;

otc_ignore:
	stream_forward_getp(peer->curr, length);

	return bgp_attr_ignore(peer, args->type);
}

/* BGP unknown attribute treatment. */
static enum bgp_attr_parse_ret
bgp_attr_unknown(struct bgp_attr_parser_args *args)
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

	if (peer->discard_attrs[type] || peer->withdraw_attrs[type])
		return bgp_attr_ignore(peer, type);

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
	transit = bgp_attr_get_transit(attr);
	if (!transit)
		transit = XCALLOC(MTYPE_TRANSIT, sizeof(struct transit));

	transit->val = XREALLOC(MTYPE_TRANSIT_VAL, transit->val,
				transit->length + total);

	memcpy(transit->val + transit->length, startp, total);
	transit->length += total;
	bgp_attr_set_transit(attr, transit);

	return BGP_ATTR_PARSE_PROCEED;
}

/* Well-known attribute check. */
static int bgp_attr_check(struct peer *peer, struct attr *attr,
			  bgp_size_t length)
{
	uint8_t type = 0;

	/* BGP Graceful-Restart End-of-RIB for IPv4 unicast is signaled as an
	 * empty UPDATE. Treat-as-withdraw, otherwise if we just ignore it,
	 * we will pass it to be processed as a normal UPDATE without mandatory
	 * attributes, that could lead to harmful behavior.
	 */
	if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV) && !attr->flag &&
	    !length)
		return BGP_ATTR_PARSE_WITHDRAW;

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

	/* An UPDATE message that contains the MP_UNREACH_NLRI is not required
	 * to carry any other path attributes. Though if MP_REACH_NLRI or NLRI
	 * are present, it should. Check for any other attribute being present
	 * instead.
	 */
	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) &&
	    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI)))
		return type ? BGP_ATTR_PARSE_MISSING_MANDATORY
			    : BGP_ATTR_PARSE_PROCEED;

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
enum bgp_attr_parse_ret bgp_attr_parse(struct peer *peer, struct attr *attr,
				       bgp_size_t size,
				       struct bgp_nlri *mp_update,
				       struct bgp_nlri *mp_withdraw)
{
	enum bgp_attr_parse_ret ret;
	uint8_t flag = 0;
	uint8_t type = 0;
	bgp_size_t length = 0;
	uint8_t *startp, *endp;
	uint8_t *attr_endp;
	uint8_t seen[BGP_ATTR_BITMAP_SIZE];
	/* we need the as4_path only until we have synthesized the as_path with
	 * it */
	/* same goes for as4_aggregator */
	struct aspath *as4_path = NULL;
	as_t as4_aggregator = 0;
	struct in_addr as4_aggregator_addr = {.s_addr = 0};
	struct transit *transit;

	/* Initialize bitmap. */
	memset(seen, 0, BGP_ATTR_BITMAP_SIZE);

	/* End pointer of BGP attribute. */
	endp = BGP_INPUT_PNT(peer) + size;

	/* Get attributes to the end of attribute length. */
	while (BGP_INPUT_PNT(peer) < endp) {
		startp = BGP_INPUT_PNT(peer);

		/* Fewer than three octets remain (or fewer than four
		 * octets, if the Attribute Flags field has the Extended
		 * Length bit set) when beginning to parse the attribute.
		 * That is, this case exists if there remains unconsumed
		 * data in the path attributes but yet insufficient data
		 * to encode a single minimum-sized path attribute.
		 *
		 * An error condition exists and the "treat-as-withdraw"
		 * approach MUST be used (unless some other, more severe
		 * error is encountered dictating a stronger approach),
		 * and the Total Attribute Length MUST be relied upon to
		 * enable the beginning of the NLRI field to be located.
		 */

		/* Check remaining length check.*/
		if ((endp - startp) < BGP_ATTR_MIN_LEN) {
			/* XXX warning: long int format, int arg (arg 5) */
			flog_warn(
				EC_BGP_ATTRIBUTE_TOO_SMALL,
				"%s: error BGP attribute length %lu is smaller than min len",
				peer->host,
				(unsigned long)(endp
						- stream_pnt(BGP_INPUT(peer))));

			if (peer->sort != BGP_PEER_EBGP) {
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_UPDATE_ERR,
						BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
				ret = BGP_ATTR_PARSE_ERROR;
			} else {
				ret = BGP_ATTR_PARSE_WITHDRAW;
			}

			goto done;
		}

		/* Fetch attribute flag and type.
		 * The lower-order four bits of the Attribute Flags octet are
		 * unused. They MUST be zero when sent and MUST be ignored when
		 * received.
		 */
		flag = CHECK_FLAG(0xF0, stream_getc(BGP_INPUT(peer)));
		type = stream_getc(BGP_INPUT(peer));

		/* Check whether Extended-Length applies and is in bounds */
		if (CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN)
		    && ((endp - startp) < (BGP_ATTR_MIN_LEN + 1))) {
			flog_warn(EC_BGP_EXT_ATTRIBUTE_TOO_SMALL,
				  "%s: Extended length set, but just %lu bytes of attr header",
				  peer->host,
				  (unsigned long)(endp -
						  stream_pnt(BGP_INPUT(peer))));

			if (peer->sort != BGP_PEER_EBGP) {
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_UPDATE_ERR,
						BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
				ret = BGP_ATTR_PARSE_ERROR;
			} else {
				ret = BGP_ATTR_PARSE_WITHDRAW;
			}

			goto done;
		}

		/* Check extended attribue length bit. */
		if (CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN))
			length = stream_getw(BGP_INPUT(peer));
		else
			length = stream_getc(BGP_INPUT(peer));

		/* Overflow check. */
		attr_endp = BGP_INPUT_PNT(peer) + length;

		if (attr_endp > endp) {
			flog_warn(
				EC_BGP_ATTRIBUTE_TOO_LARGE,
				"%s: BGP type %d length %d is too large, attribute total length is %d.  attr_endp is %p.  endp is %p",
				peer->host, type, length, size, attr_endp,
				endp);

			/* Only relax error handling for eBGP peers */
			if (peer->sort != BGP_PEER_EBGP) {
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
				unsigned char ndata[peer->max_packet_size];

				memset(ndata, 0x00, sizeof(ndata));
				size_t lfl =
					CHECK_FLAG(flag, BGP_ATTR_FLAG_EXTLEN) ? 2 : 1;
				/* Rewind to end of flag field */
				stream_rewind_getp(BGP_INPUT(peer), (1 + lfl));
				/* Type */
				stream_get(&ndata[0], BGP_INPUT(peer), 1);
				/* Length */
				stream_get(&ndata[1], BGP_INPUT(peer), lfl);
				/* Value */
				size_t atl = attr_endp - startp;
				size_t ndl = MIN(atl, STREAM_READABLE(BGP_INPUT(peer)));

				stream_get(&ndata[lfl + 1], BGP_INPUT(peer), ndl);

				bgp_notify_send_with_data(peer->connection,
							  BGP_NOTIFY_UPDATE_ERR,
							  BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
							  ndata, ndl + lfl + 1);

				ret = BGP_ATTR_PARSE_ERROR;
				goto done;
			} else {
				/* Handling as per RFC7606 section 4, treat-as-withdraw approach
				 * must be followed when the total attribute length is in conflict
				 * with the enclosed path attribute length.
				 */
				flog_warn(
					EC_BGP_ATTRIBUTE_PARSE_WITHDRAW,
					"%s: Attribute %s, parse error - treating as withdrawal",
					peer->host, lookup_msg(attr_str, type, NULL));
				ret = BGP_ATTR_PARSE_WITHDRAW;
				stream_forward_getp(BGP_INPUT(peer), endp - BGP_INPUT_PNT(peer));
				goto done;
			}
		}

		/* If attribute appears more than once in the UPDATE message,
		 * for MP_REACH_NLRI & MP_UNREACH_NLRI attributes
		 * the Error Subcode is set to Malformed Attribute List.
		 * For all other attributes, all the occurances of the attribute
		 * other than the first occurence is discarded. (RFC7606 3g)
		 */

		if (CHECK_BITMAP(seen, type)) {
			/* Only relax error handling for eBGP peers */
			if (peer->sort != BGP_PEER_EBGP ||
					type == BGP_ATTR_MP_REACH_NLRI || type == BGP_ATTR_MP_UNREACH_NLRI) {
				flog_warn(
					EC_BGP_ATTRIBUTE_REPEATED,
					"%s: error BGP attribute type %d appears twice in a message",
					peer->host, type);

				bgp_notify_send(peer->connection,
						BGP_NOTIFY_UPDATE_ERR,
						BGP_NOTIFY_UPDATE_MAL_ATTR);
				ret = BGP_ATTR_PARSE_ERROR;
				goto done;
			} else {
				flog_warn(
					EC_BGP_ATTRIBUTE_REPEATED,
					"%s: error BGP attribute type %d appears twice in a message - discard attribute",
					peer->host, type);
				/* Adjust the stream getp to the end of the attribute, in case we
				 * haven't read all the attributes.
				 */
				stream_set_getp(BGP_INPUT(peer),
					(startp - STREAM_DATA(BGP_INPUT(peer))) + (attr_endp - startp));
				continue;
			}
		}

		/* Set type to bitmap to check duplicate attribute.  `type' is
		   unsigned char so it never overflow bitmap range. */

		SET_BITMAP(seen, type);

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
			stream_forward_getp(BGP_INPUT(peer), endp - BGP_INPUT_PNT(peer));
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
			ret = bgp_attr_encap(&attr_args);
			break;
		case BGP_ATTR_PREFIX_SID:
			ret = bgp_attr_prefix_sid(&attr_args);
			break;
		case BGP_ATTR_PMSI_TUNNEL:
			ret = bgp_attr_pmsi_tunnel(&attr_args);
			break;
		case BGP_ATTR_IPV6_EXT_COMMUNITIES:
			ret = bgp_attr_ipv6_ext_communities(&attr_args);
			break;
		case BGP_ATTR_OTC:
			ret = bgp_attr_otc(&attr_args);
			break;
		case BGP_ATTR_AIGP:
			ret = bgp_attr_aigp(&attr_args);
			break;
		default:
			ret = bgp_attr_unknown(&attr_args);
			break;
		}

		if (ret == BGP_ATTR_PARSE_ERROR_NOTIFYPLS) {
			bgp_notify_send(peer->connection, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_MAL_ATTR);
			ret = BGP_ATTR_PARSE_ERROR;
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
			stream_forward_getp(BGP_INPUT(peer), endp - BGP_INPUT_PNT(peer));
			goto done;
		}

		/* Check the fetched length. */
		if (BGP_INPUT_PNT(peer) != attr_endp) {
			flog_warn(EC_BGP_ATTRIBUTE_FETCH_ERROR,
				  "%s: BGP attribute %s, fetch error",
				  peer->host, lookup_msg(attr_str, type, NULL));
			bgp_notify_send(peer->connection, BGP_NOTIFY_UPDATE_ERR,
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
		bgp_notify_send(peer->connection, BGP_NOTIFY_UPDATE_ERR,
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
	ret = bgp_attr_check(peer, attr, length);
	if (ret < 0)
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
		bgp_notify_send(peer->connection, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		ret = BGP_ATTR_PARSE_ERROR;
		goto done;
	}

	/*
	 * Finally do the checks on the aspath we did not do yet
	 * because we waited for a potentially synthesized aspath.
	 */
	if (CHECK_FLAG(attr->flag, (ATTR_FLAG_BIT(BGP_ATTR_AS_PATH)))) {
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
	/*
	 * unintern - it is in the hash
	 * The flag that we got this is still there, but that
	 * does not do any trouble
	 */
	aspath_unintern(&as4_path);

	transit = bgp_attr_get_transit(attr);
	/* If we received an UPDATE with mandatory attributes, then
	 * the unrecognized transitive optional attribute of that
	 * path MUST be passed. Otherwise, it's an error, and from
	 * security perspective it might be very harmful if we continue
	 * here with the unrecognized attributes.
	 */
	if (ret == BGP_ATTR_PARSE_PROCEED) {
		/* Finally intern unknown attribute. */
		if (transit)
			bgp_attr_set_transit(attr, transit_intern(transit));
		if (attr->encap_subtlvs)
			attr->encap_subtlvs = encap_intern(attr->encap_subtlvs,
							   ENCAP_SUBTLV_TYPE);
#ifdef ENABLE_BGP_VNC
		struct bgp_attr_encap_subtlv *vnc_subtlvs =
			bgp_attr_get_vnc_subtlvs(attr);

		if (vnc_subtlvs)
			bgp_attr_set_vnc_subtlvs(
				attr,
				encap_intern(vnc_subtlvs, VNC_SUBTLV_TYPE));
#endif
	} else {
		if (transit) {
			transit_free(transit);
			bgp_attr_set_transit(attr, NULL);
		}

		bgp_attr_flush_encap(attr);
	};

	/* Sanity checks */
	transit = bgp_attr_get_transit(attr);
	if (transit)
		assert(transit->refcnt > 0);
	if (attr->encap_subtlvs)
		assert(attr->encap_subtlvs->refcnt > 0);
#ifdef ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs =
		bgp_attr_get_vnc_subtlvs(attr);

	if (vnc_subtlvs)
		assert(vnc_subtlvs->refcnt > 0);
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
	uint32_t i;

	if (!attr)
		return;

	ecom = bgp_attr_get_ecommunity(attr);
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
	iana_afi_t pkt_afi = IANA_AFI_IPV4;
	iana_safi_t pkt_safi = IANA_SAFI_UNICAST;
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
			break;
		case SAFI_UNSPEC:
		case SAFI_MAX:
			assert(!"SAFI's UNSPEC or MAX being specified are a DEV ESCAPE");
			break;
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
		case SAFI_MULTICAST:
		case SAFI_LABELED_UNICAST:
		case SAFI_EVPN: {
			if (attr->mp_nexthop_len ==
			    BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
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
			if (attr->mp_nexthop_len ==
			    BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL)
				stream_putc(s, attr->mp_nexthop_len);
			else
				stream_putc(s, BGP_ATTR_NHLEN_VPNV6_GLOBAL);
			stream_putl(s, 0); /* RD = 0, per RFC */
			stream_putl(s, 0);
			stream_put(s, &attr->mp_nexthop_global,
				   IPV6_MAX_BYTELEN);
			if (attr->mp_nexthop_len ==
			    BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
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
			break;
		case SAFI_UNSPEC:
		case SAFI_MAX:
			assert(!"SAFI's UNSPEC or MAX being specified are a DEV ESCAPE");
			break;
		}
		break;
	case AFI_L2VPN:
		if (safi != SAFI_FLOWSPEC)
			flog_err(
				EC_BGP_ATTR_NH_SEND_LEN,
				"Bad nexthop when sending to %s, AFI %u SAFI %u nhlen %d",
				peer->host, afi, safi, attr->mp_nexthop_len);
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		assert(!"DEV ESCAPE: AFI_UNSPEC or AFI_MAX should not be used here");
		break;
	}

	/* SNPA */
	stream_putc(s, 0);
	return sizep;
}

void bgp_packet_mpattr_prefix(struct stream *s, afi_t afi, safi_t safi,
			      const struct prefix *p,
			      const struct prefix_rd *prd, mpls_label_t *label,
			      uint8_t num_labels, bool addpath_capable,
			      uint32_t addpath_tx_id, struct attr *attr)
{
	switch (safi) {
	case SAFI_UNSPEC:
	case SAFI_MAX:
		assert(!"Dev escape usage of SAFI_UNSPEC or MAX");
		break;
	case SAFI_MPLS_VPN:
		if (addpath_capable)
			stream_putl(s, addpath_tx_id);
		/* Label, RD, Prefix write. */
		stream_putc(s, p->prefixlen + 88);
		stream_put(s, label, BGP_LABEL_BYTES);
		stream_put(s, prd->val, 8);
		stream_put(s, &p->u.prefix, PSIZE(p->prefixlen));
		break;
	case SAFI_EVPN:
		if (afi == AFI_L2VPN)
			/* EVPN prefix - contents depend on type */
			bgp_evpn_encode_prefix(s, p, prd, label, num_labels,
					       attr, addpath_capable,
					       addpath_tx_id);
		else
			assert(!"Add encoding bits here for other AFI's");
		break;
	case SAFI_LABELED_UNICAST:
		/* Prefix write with label. */
		stream_put_labeled_prefix(s, p, label, addpath_capable,
					  addpath_tx_id);
		break;
	case SAFI_FLOWSPEC:
		stream_putc(s, p->u.prefix_flowspec.prefixlen);
		stream_put(s, (const void *)p->u.prefix_flowspec.ptr,
			   p->u.prefix_flowspec.prefixlen);
		break;

	case SAFI_UNICAST:
	case SAFI_MULTICAST:
		stream_put_prefix_addpath(s, p, addpath_capable, addpath_tx_id);
		break;
	case SAFI_ENCAP:
		assert(!"Please add proper encoding of SAFI_ENCAP");
		break;
	}
}

size_t bgp_packet_mpattr_prefix_size(afi_t afi, safi_t safi,
				     const struct prefix *p)
{
	int size = PSIZE(p->prefixlen);

	switch (safi) {
	case SAFI_UNSPEC:
	case SAFI_MAX:
		assert(!"Attempting to figure size for a SAFI_UNSPEC/SAFI_MAX this is a DEV ESCAPE");
		break;
	case SAFI_UNICAST:
	case SAFI_MULTICAST:
		break;
	case SAFI_MPLS_VPN:
		size += 88;
		break;
	case SAFI_ENCAP:
		/* This has to be wrong, but I don't know what to put here */
		assert(!"Do we try to use this?");
		break;
	case SAFI_LABELED_UNICAST:
		size += BGP_LABEL_BYTES;
		break;
	case SAFI_EVPN:
		/*
		 * TODO: Maximum possible for type-2, type-3 and type-5
		 */
		if (afi == AFI_L2VPN)
			size += 232;
		else
			assert(!"Attempting to figure size for SAFI_EVPN and !AFI_L2VPN and FRR will not have the proper values");
		break;
	case SAFI_FLOWSPEC:
		size = ((struct prefix_fs *)p)->prefix.prefixlen;
		break;
	}

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
		subtlvs = bgp_attr_get_vnc_subtlvs(attr);
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
		stream_putw(s, CHECK_FLAG(attrlenfield, 0xffff));
	} else {
		/* 1-octet length field */
		stream_putc(s, BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, attrtype);
		stream_putc(s, CHECK_FLAG(attrlenfield, 0xff));
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

static void bgp_packet_ecommunity_attribute(struct stream *s, struct peer *peer,
					    struct ecommunity *ecomm, int attribute)
{
	if (!ecomm || !ecomm->size)
		return;

	if (ecomm->size * ecomm->unit_size > 255) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_EXTLEN);
		stream_putc(s, attribute);
		stream_putw(s, ecomm->size * ecomm->unit_size);
	} else {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, attribute);
		stream_putc(s, ecomm->size * ecomm->unit_size);
	}

	stream_put(s, ecomm->val, ecomm->size * ecomm->unit_size);
}

/* Make attribute packet. */
bgp_size_t bgp_packet_attribute(struct bgp *bgp, struct peer *peer, struct stream *s,
				struct attr *attr, struct bpacket_attr_vec_arr *vecarr,
				struct prefix *p, afi_t afi, safi_t safi, struct peer *from,
				struct prefix_rd *prd, mpls_label_t *label, uint8_t num_labels,
				bool addpath_capable, uint32_t addpath_tx_id)
{
	size_t cp;
	size_t aspath_sizep;
	struct aspath *aspath;
	int send_as4_path = 0;
	int send_as4_aggregator = 0;
	bool use32bit = CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)
			&& CHECK_FLAG(peer->cap, PEER_CAP_AS4_ADV);

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
					 num_labels, addpath_capable,
					 addpath_tx_id, attr);
		bgp_packet_mpattr_end(s, mpattrlen_pos);
	}

	(void)peer_sort(peer);

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
			/* A confed member, so we need to do the
			 * AS_CONFED_SEQUENCE thing if it's outside a common
			 * administration.
			 * Configured confederation peers MUST be validated
			 * under BGP_PEER_CONFED, but if we have configured
			 * remote-as as AS_EXTERNAL, we need to check again
			 * if the peer belongs to us.
			 */
			if (bgp_confederation_peers_check(bgp, peer->as)) {
				aspath = aspath_add_confed_seq(aspath,
							       peer->local_as);
			} else {
				/* Stuff our path CONFED_ID on the front */
				aspath = aspath_add_seq(aspath, bgp->confed_id);
			}
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

		if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))) {
			stream_putc(s, BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_NEXT_HOP);
			bpacket_attr_vec_arr_set_vec(vecarr, BGP_ATTR_VEC_NH, s,
						     attr);
			stream_putc(s, 4);
			stream_put_ipv4(s, attr->nexthop.s_addr);
		} else if (peer_cap_enhe(from, afi, safi) ||
			   (nh_afi == AFI_IP6)) {
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
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) ||
	    bgp->maxmed_active) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MULTI_EXIT_DISC);
		stream_putc(s, 4);
		stream_putl(s, (bgp->maxmed_active ? bgp->maxmed_value
						   : attr->med));
	}

	/* Local preference. */
	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED ||
	    peer->sub_sort == BGP_PEER_EBGP_OAD) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_LOCAL_PREF);
		stream_putc(s, 4);
		stream_putl(s, attr->local_pref);
	}

	/* Atomic aggregate. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_ATOMIC_AGGREGATE);
		stream_putc(s, 0);
	}

	/* Aggregator. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
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
			if (attr->aggregator_as > UINT16_MAX) {
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
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY) &&
	    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		struct community *comm = NULL;

		comm = bgp_attr_get_community(attr);
		if (comm->size * 4 > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putw(s, comm->size * 4);
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putc(s, comm->size * 4);
		}
		stream_put(s, comm->val, comm->size * 4);
	}

	/*
	 * Large Community attribute.
	 */
	if (CHECK_FLAG(peer->af_flags[afi][safi],
		       PEER_FLAG_SEND_LARGE_COMMUNITY) &&
	    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))) {
		if (lcom_length(bgp_attr_get_lcommunity(attr)) > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putw(s,
				    lcom_length(bgp_attr_get_lcommunity(attr)));
		} else {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL
					    | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putc(s,
				    lcom_length(bgp_attr_get_lcommunity(attr)));
		}
		stream_put(s, bgp_attr_get_lcommunity(attr)->val,
			   lcom_length(bgp_attr_get_lcommunity(attr)));
	}

	/* Route Reflector. */
	if (peer->sort == BGP_PEER_IBGP && from
	    && from->sort == BGP_PEER_IBGP) {
		struct cluster_list *cluster = bgp_attr_get_cluster(attr);

		/* Originator ID. */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_ORIGINATOR_ID);
		stream_putc(s, 4);

		if (CHECK_FLAG(attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
			stream_put_in_addr(s, &attr->originator_id);
		else
			stream_put_in_addr(s, &from->remote_id);

		/* Cluster list. */
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_CLUSTER_LIST);

		if (cluster) {
			stream_putc(s, cluster->length + 4);
			/* If this peer configuration's parent BGP has
			 * cluster_id. */
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID))
				stream_put_in_addr(s, &bgp->cluster_id);
			else
				stream_put_in_addr(s, &bgp->router_id);
			stream_put(s, cluster->list, cluster->length);
		} else {
			stream_putc(s, 4);
			/* If this peer configuration's parent BGP has
			 * cluster_id. */
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID))
				stream_put_in_addr(s, &bgp->cluster_id);
			else
				stream_put_in_addr(s, &bgp->router_id);
		}
	}

	/* Extended IPv6/Communities attributes. */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)) {
		if (CHECK_FLAG(attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
			struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

			bgp_packet_ecommunity_attribute(s, peer, ecomm, BGP_ATTR_EXT_COMMUNITIES);
		}

		if (CHECK_FLAG(attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_IPV6_EXT_COMMUNITIES))) {
			struct ecommunity *ecomm =
				bgp_attr_get_ipv6_ecommunity(attr);

			bgp_packet_ecommunity_attribute(s, peer, ecomm,
							BGP_ATTR_IPV6_EXT_COMMUNITIES);
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
	if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_MPLS_VPN) {
		if (attr->srv6_l3vpn) {
			uint8_t subtlv_len =
				BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH
				+ BGP_ATTR_MIN_LEN
				+ BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH;
			uint8_t tlv_len = subtlv_len + BGP_ATTR_MIN_LEN + 1;
			uint8_t attr_len = tlv_len + BGP_ATTR_MIN_LEN;
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL
					       | BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_PREFIX_SID);
			stream_putc(s, attr_len);
			stream_putc(s, BGP_PREFIX_SID_SRV6_L3_SERVICE);
			stream_putw(s, tlv_len);
			stream_putc(s, 0); /* reserved */
			stream_putc(s, BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO);
			stream_putw(s, subtlv_len);
			stream_putc(s, 0);      /* reserved */
			stream_put(s, &attr->srv6_l3vpn->sid,
				   sizeof(attr->srv6_l3vpn->sid)); /* sid */
			stream_putc(s, 0);      /* sid_flags */
			stream_putw(s,
				    attr->srv6_l3vpn
					    ->endpoint_behavior); /* endpoint */
			stream_putc(s, 0);      /* reserved */
			stream_putc(
				s,
				BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE);
			stream_putw(
				s,
				BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH);
			stream_putc(s, attr->srv6_l3vpn->loc_block_len);
			stream_putc(s, attr->srv6_l3vpn->loc_node_len);
			stream_putc(s, attr->srv6_l3vpn->func_len);
			stream_putc(s, attr->srv6_l3vpn->arg_len);
			stream_putc(s, attr->srv6_l3vpn->transposition_len);
			stream_putc(s, attr->srv6_l3vpn->transposition_offset);
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

		/* Make sure dup aspath before the modification */
		if (aspath == attr->aspath)
			aspath = aspath_dup(attr->aspath);
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
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL))) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_PMSI_TUNNEL);
		stream_putc(s, 9); // Length
		stream_putc(s, 0); // Flags
		stream_putc(s, bgp_attr_get_pmsi_tnl_type(attr));
		stream_put(s, &(attr->label),
			   BGP_LABEL_BYTES); // MPLS Label / VXLAN VNI
		stream_put_ipv4(s, attr->nexthop.s_addr);
		// Unicast tunnel endpoint IP address
	}

	/* OTC */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC))) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_OTC);
		stream_putc(s, 4);
		stream_putl(s, attr->otc);
	}

	/* AIGP */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)) && AIGP_TRANSMIT_ALLOWED(peer)) {
		/* At the moment only AIGP Metric TLV exists for AIGP
		 * attribute. If more comes in, do not forget to update
		 * attr_len variable to include new ones.
		 */
		uint8_t attr_len = BGP_AIGP_TLV_METRIC_LEN;

		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_AIGP);
		stream_putc(s, attr_len);
		stream_put_bgp_aigp_tlv_metric(s, attr->aigp_metric);
	}

	/* Unknown transit attribute. */
	struct transit *transit = bgp_attr_get_transit(attr);

	if (transit)
		stream_put(s, transit->val, transit->length);

	/* Return total size of attribute. */
	return stream_get_endp(s) - cp;
}

size_t bgp_packet_mpunreach_start(struct stream *s, afi_t afi, safi_t safi)
{
	unsigned long attrlen_pnt;
	iana_afi_t pkt_afi = IANA_AFI_IPV4;
	iana_safi_t pkt_safi = IANA_SAFI_UNICAST;

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
				 mpls_label_t *label, uint8_t num_labels,
				 bool addpath_capable, uint32_t addpath_tx_id,
				 struct attr *attr)
{
	uint8_t wlabel[4] = {0x80, 0x00, 0x00};

	if (safi == SAFI_LABELED_UNICAST) {
		label = (mpls_label_t *)wlabel;
		num_labels = 1;
	}

	bgp_packet_mpattr_prefix(s, afi, safi, p, prd, label, num_labels,
				 addpath_capable, addpath_tx_id, attr);
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
	evpn_overlay_init();
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
	evpn_overlay_finish();
}

/* Make attribute packet. */
void bgp_dump_routes_attr(struct stream *s, struct bgp_path_info *bpi,
			  const struct prefix *prefix)
{
	unsigned long cp;
	unsigned long len;
	size_t aspath_lenp;
	struct aspath *aspath;
	bool addpath_capable = false;
	uint32_t addpath_tx_id = 0;
	struct attr *attr = bpi->attr;

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
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MULTI_EXIT_DISC);
		stream_putc(s, 4);
		stream_putl(s, attr->med);
	}

	/* Local preference. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_LOCAL_PREF);
		stream_putc(s, 4);
		stream_putl(s, attr->local_pref);
	}

	/* Atomic aggregate. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))) {
		stream_putc(s, BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_ATOMIC_AGGREGATE);
		stream_putc(s, 0);
	}

	/* Aggregator. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_AGGREGATOR);
		stream_putc(s, 8);
		stream_putl(s, attr->aggregator_as);
		stream_put_ipv4(s, attr->aggregator_addr.s_addr);
	}

	/* Community attribute. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		struct community *comm = NULL;

		comm = bgp_attr_get_community(attr);
		if (comm->size * 4 > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putw(s, comm->size * 4);
		} else {
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL |
					       BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_COMMUNITIES);
			stream_putc(s, comm->size * 4);
		}
		stream_put(s, comm->val, comm->size * 4);
	}

	/* Large Community attribute. */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))) {
		if (lcom_length(bgp_attr_get_lcommunity(attr)) > 255) {
			stream_putc(s,
				    BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
					    | BGP_ATTR_FLAG_EXTLEN);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putw(s,
				    lcom_length(bgp_attr_get_lcommunity(attr)));
		} else {
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL |
					       BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_LARGE_COMMUNITIES);
			stream_putc(s,
				    lcom_length(bgp_attr_get_lcommunity(attr)));
		}

		stream_put(s, bgp_attr_get_lcommunity(attr)->val,
			   lcom_length(bgp_attr_get_lcommunity(attr)));
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
		stream_put_prefix_addpath(s, prefix, addpath_capable,
					  addpath_tx_id);

		/* Set MP attribute length. */
		stream_putc_at(s, sizep, (stream_get_endp(s) - sizep) - 1);
	}

	/* Prefix SID */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID))) {
		if (attr->label_index != BGP_INVALID_LABEL_INDEX) {
			stream_putc(s, BGP_ATTR_FLAG_OPTIONAL |
					       BGP_ATTR_FLAG_TRANS);
			stream_putc(s, BGP_ATTR_PREFIX_SID);
			stream_putc(s, 10);
			stream_putc(s, BGP_PREFIX_SID_LABEL_INDEX);
			stream_putc(s, BGP_PREFIX_SID_LABEL_INDEX_LENGTH);
			stream_putc(s, 0); // reserved
			stream_putw(s, 0); // flags
			stream_putl(s, attr->label_index);
		}
	}

	/* OTC */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC))) {
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_OTC);
		stream_putc(s, 4);
		stream_putl(s, attr->otc);
	}

	/* AIGP */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP))) {
		/* At the moment only AIGP Metric TLV exists for AIGP
		 * attribute. If more comes in, do not forget to update
		 * attr_len variable to include new ones.
		 */
		uint8_t attr_len = BGP_AIGP_TLV_METRIC_LEN;

		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS);
		stream_putc(s, BGP_ATTR_AIGP);
		stream_putc(s, attr_len);
		stream_put_bgp_aigp_tlv_metric(s, attr->aigp_metric);
	}

	/* Return total size of attribute. */
	len = stream_get_endp(s) - cp - 2;
	stream_putw_at(s, cp, len);
}

void bgp_path_attribute_discard_vty(struct vty *vty, struct peer *peer,
				    const char *discard_attrs, bool set)
{
	int i, num_attributes;
	char **attributes;
	afi_t afi;
	safi_t safi;


	/* If `no` command specified without arbitrary attributes,
	 * then flush all.
	 */
	if (!discard_attrs) {
		for (i = 1; i <= BGP_ATTR_MAX; i++)
			peer->discard_attrs[i] = false;
		goto discard_soft_clear;
	}

	if (discard_attrs) {
		frrstr_split(discard_attrs, " ", &attributes, &num_attributes);

		if (set)
			for (i = 1; i <= BGP_ATTR_MAX; i++)
				peer->discard_attrs[i] = false;

		for (i = 0; i < num_attributes; i++) {
			uint8_t attr_num = strtoul(attributes[i], NULL, 10);

			XFREE(MTYPE_TMP, attributes[i]);

			/* Some of the attributes, just can't be ignored. */
			if (attr_num == BGP_ATTR_ORIGIN ||
			    attr_num == BGP_ATTR_AS_PATH ||
			    attr_num == BGP_ATTR_NEXT_HOP ||
			    attr_num == BGP_ATTR_MULTI_EXIT_DISC ||
			    attr_num == BGP_ATTR_MP_REACH_NLRI ||
			    attr_num == BGP_ATTR_MP_UNREACH_NLRI ||
			    attr_num == BGP_ATTR_EXT_COMMUNITIES) {
				vty_out(vty,
					"%% Can't discard path-attribute %s, ignoring.\n",
					lookup_msg(attr_str, attr_num, NULL));
				continue;
			}

			/* Ignore local-pref, originator-id, cluster-list only
			 * for eBGP.
			 */
			if (peer->sort != BGP_PEER_EBGP &&
			    (attr_num == BGP_ATTR_LOCAL_PREF ||
			     attr_num == BGP_ATTR_ORIGINATOR_ID ||
			     attr_num == BGP_ATTR_CLUSTER_LIST)) {
				vty_out(vty,
					"%% Can discard path-attribute %s only for eBGP, ignoring.\n",
					lookup_msg(attr_str, attr_num, NULL));
				continue;
			}

			peer->discard_attrs[attr_num] = set;
		}
		XFREE(MTYPE_TMP, attributes);
	discard_soft_clear:
		/* Configuring path attributes to be discarded will trigger
		 * an inbound Route Refresh to ensure that the routing table
		 * is up to date.
		 */
		FOREACH_AFI_SAFI (afi, safi)
			peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
	}
}

void bgp_path_attribute_withdraw_vty(struct vty *vty, struct peer *peer,
				     const char *withdraw_attrs, bool set)
{
	int i, num_attributes;
	char **attributes;
	afi_t afi;
	safi_t safi;

	/* If `no` command specified without arbitrary attributes,
	 * then flush all.
	 */
	if (!withdraw_attrs) {
		for (i = 1; i <= BGP_ATTR_MAX; i++)
			peer->withdraw_attrs[i] = false;
		goto withdraw_soft_clear;
	}

	if (withdraw_attrs) {
		frrstr_split(withdraw_attrs, " ", &attributes, &num_attributes);

		if (set)
			for (i = 1; i <= BGP_ATTR_MAX; i++)
				peer->withdraw_attrs[i] = false;

		for (i = 0; i < num_attributes; i++) {
			uint8_t attr_num = strtoul(attributes[i], NULL, 10);

			XFREE(MTYPE_TMP, attributes[i]);

			/* Some of the attributes, just can't be ignored. */
			if (attr_num == BGP_ATTR_ORIGIN ||
			    attr_num == BGP_ATTR_AS_PATH ||
			    attr_num == BGP_ATTR_NEXT_HOP ||
			    attr_num == BGP_ATTR_MULTI_EXIT_DISC ||
			    attr_num == BGP_ATTR_MP_REACH_NLRI ||
			    attr_num == BGP_ATTR_MP_UNREACH_NLRI ||
			    attr_num == BGP_ATTR_EXT_COMMUNITIES) {
				vty_out(vty,
					"%% Can't treat-as-withdraw path-attribute %s, ignoring.\n",
					lookup_msg(attr_str, attr_num, NULL));
				continue;
			}

			/* Ignore local-pref, originator-id, cluster-list only
			 * for eBGP.
			 */
			if (peer->sort != BGP_PEER_EBGP &&
			    (attr_num == BGP_ATTR_LOCAL_PREF ||
			     attr_num == BGP_ATTR_ORIGINATOR_ID ||
			     attr_num == BGP_ATTR_CLUSTER_LIST)) {
				vty_out(vty,
					"%% Can treat-as-withdraw path-attribute %s only for eBGP, ignoring.\n",
					lookup_msg(attr_str, attr_num, NULL));
				continue;
			}

			peer->withdraw_attrs[attr_num] = set;
		}
		XFREE(MTYPE_TMP, attributes);
	withdraw_soft_clear:
		/* Configuring path attributes to be treated as withdraw will
		 * trigger
		 * an inbound Route Refresh to ensure that the routing table
		 * is up to date.
		 */
		FOREACH_AFI_SAFI (afi, safi)
			peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
	}
}

enum bgp_attr_parse_ret bgp_attr_ignore(struct peer *peer, uint8_t type)
{
	bool discard = peer->discard_attrs[type];
	bool withdraw = peer->withdraw_attrs[type];

	if (bgp_debug_update(peer, NULL, NULL, 1) && (discard || withdraw))
		zlog_debug("%pBP: Ignoring attribute %s (%s)", peer,
			   lookup_msg(attr_str, type, NULL),
			   withdraw ? "treat-as-withdraw" : "discard");

	return withdraw ? BGP_ATTR_PARSE_WITHDRAW : BGP_ATTR_PARSE_PROCEED;
}

bool route_matches_soo(struct bgp_path_info *pi, struct ecommunity *soo)
{
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;

	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return false;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return false;

	return soo_in_ecom(ecom, soo);
}
