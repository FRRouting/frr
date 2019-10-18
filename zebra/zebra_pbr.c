/* Zebra Policy Based Routing (PBR) main handling.
 * Copyright (C) 2018  Cumulus Networks, Inc.
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

#include <jhash.h>
#include <hash.h>
#include <memory.h>
#include <hook.h>

#include "zebra/zebra_router.h"
#include "zebra/zebra_pbr.h"
#include "zebra/rt.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_memory.h"
#include "zebra/zserv.h"

/* definitions */
DEFINE_MTYPE_STATIC(ZEBRA, PBR_IPTABLE_IFNAME, "PBR interface list")

/* definitions */
static const struct message ipset_type_msg[] = {
	{IPSET_NET_PORT_NET, "net,port,net"},
	{IPSET_NET_PORT, "net,port"},
	{IPSET_NET_NET, "net,net"},
	{IPSET_NET, "net"},
	{0}
};

const struct message icmp_typecode_str[] = {
	{ 0 << 8, "echo-reply"},
	{ 0 << 8, "pong"},
	{ 3 << 8, "network-unreachable"},
	{ (3 << 8) + 1, "host-unreachable"},
	{ (3 << 8) + 2, "protocol-unreachable"},
	{ (3 << 8) + 3, "port-unreachable"},
	{ (3 << 8) + 4, "fragmentation-needed"},
	{ (3 << 8) + 5, "source-route-failed"},
	{ (3 << 8) + 6, "network-unknown"},
	{ (3 << 8) + 7, "host-unknown"},
	{ (3 << 8) + 9, "network-prohibited"},
	{ (3 << 8) + 10, "host-prohibited"},
	{ (3 << 8) + 11, "TOS-network-unreachable"},
	{ (3 << 8) + 12, "TOS-host-unreachable"},
	{ (3 << 8) + 13, "communication-prohibited"},
	{ (3 << 8) + 14, "host-precedence-violation"},
	{ (3 << 8) + 15, "precedence-cutoff"},
	{ 4 << 8, "source-quench"},
	{ 5 << 8, "network-redirect"},
	{ (5 << 8) +  1, "host-redirect"},
	{ (5 << 8) +  2, "TOS-network-redirect"},
	{ (5 << 8) +  3, "TOS-host-redirect"},
	{ 8 << 8, "echo-request"},
	{ 8 << 8, "ping"},
	{ 9 << 8, "router-advertisement"},
	{ 10 << 8, "router-solicitation"},
	{ 11 << 8, "ttl-zero-during-transit"},
	{ (11 << 8) + 1, "ttl-zero-during-reassembly"},
	{ 12 << 8, "ip-header-bad"},
	{ (12 << 8) + 1, "required-option-missing"},
	{ 13 << 8, "timestamp-request"},
	{ 14 << 8, "timestamp-reply"},
	{ 17 << 8, "address-mask-request"},
	{ 18 << 8, "address-mask-reply"},
	{0}
};

/* definitions */
static const struct message tcp_value_str[] = {
	{TCP_HEADER_FIN, "FIN"},
	{TCP_HEADER_SYN, "SYN"},
	{TCP_HEADER_RST, "RST"},
	{TCP_HEADER_PSH, "PSH"},
	{TCP_HEADER_ACK, "ACK"},
	{TCP_HEADER_URG, "URG"},
	{0}
};

static const struct message fragment_value_str[] = {
	{1, "dont-fragment"},
	{2, "is-fragment"},
	{4, "first-fragment"},
	{8, "last-fragment"},
	{0}
};

/* static function declarations */
DEFINE_HOOK(zebra_pbr_ipset_entry_get_stat,
	    (struct zebra_pbr_ipset_entry *ipset, uint64_t *pkts,
	     uint64_t *bytes),
	    (ipset, pkts, bytes))

DEFINE_HOOK(zebra_pbr_iptable_get_stat,
	    (struct zebra_pbr_iptable *iptable, uint64_t *pkts,
	     uint64_t *bytes),
	    (iptable, pkts, bytes))

DEFINE_HOOK(zebra_pbr_iptable_update,
	    (int cmd, struct zebra_pbr_iptable *iptable), (cmd, iptable));

DEFINE_HOOK(zebra_pbr_ipset_entry_update,
	    (int cmd, struct zebra_pbr_ipset_entry *ipset), (cmd, ipset));

DEFINE_HOOK(zebra_pbr_ipset_update,
	    (int cmd, struct zebra_pbr_ipset *ipset), (cmd, ipset));

/* Private functions */

/* Public functions */
void zebra_pbr_rules_free(void *arg)
{
	struct zebra_pbr_rule *rule;

	rule = (struct zebra_pbr_rule *)arg;

	(void)kernel_del_pbr_rule(rule);
	XFREE(MTYPE_TMP, rule);
}

uint32_t zebra_pbr_rules_hash_key(const void *arg)
{
	const struct zebra_pbr_rule *rule;
	uint32_t key;

	rule = arg;
	key = jhash_3words(rule->rule.seq, rule->rule.priority,
			   rule->rule.action.table,
			   prefix_hash_key(&rule->rule.filter.src_ip));

	if (rule->rule.filter.fwmark)
		key = jhash_3words(rule->rule.filter.fwmark, rule->vrf_id,
				   rule->rule.ifindex, key);
	else
		key = jhash_2words(rule->vrf_id, rule->rule.ifindex, key);

	return jhash_3words(rule->rule.filter.src_port,
			    rule->rule.filter.dst_port,
			    prefix_hash_key(&rule->rule.filter.dst_ip),
			    jhash_1word(rule->rule.unique, key));
}

bool zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_rule *r1, *r2;

	r1 = (const struct zebra_pbr_rule *)arg1;
	r2 = (const struct zebra_pbr_rule *)arg2;

	if (r1->rule.seq != r2->rule.seq)
		return false;

	if (r1->rule.priority != r2->rule.priority)
		return false;

	if (r1->rule.unique != r2->rule.unique)
		return false;

	if (r1->rule.action.table != r2->rule.action.table)
		return false;

	if (r1->rule.filter.src_port != r2->rule.filter.src_port)
		return false;

	if (r1->rule.filter.dst_port != r2->rule.filter.dst_port)
		return false;

	if (r1->rule.filter.fwmark != r2->rule.filter.fwmark)
		return false;

	if (!prefix_same(&r1->rule.filter.src_ip, &r2->rule.filter.src_ip))
		return false;

	if (!prefix_same(&r1->rule.filter.dst_ip, &r2->rule.filter.dst_ip))
		return false;

	if (r1->rule.ifindex != r2->rule.ifindex)
		return false;

	if (r1->vrf_id != r2->vrf_id)
		return false;

	return true;
}

struct pbr_rule_unique_lookup {
	struct zebra_pbr_rule *rule;
	uint32_t unique;
	ifindex_t ifindex;
	vrf_id_t vrf_id;
};

static int pbr_rule_lookup_unique_walker(struct hash_bucket *b, void *data)
{
	struct pbr_rule_unique_lookup *pul = data;
	struct zebra_pbr_rule *rule = b->data;

	if (pul->unique == rule->rule.unique
	    && pul->ifindex == rule->rule.ifindex
	    && pul->vrf_id == rule->vrf_id) {
		pul->rule = rule;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static struct zebra_pbr_rule *
pbr_rule_lookup_unique(struct zebra_pbr_rule *zrule)
{
	struct pbr_rule_unique_lookup pul;

	pul.unique = zrule->rule.unique;
	pul.ifindex = zrule->rule.ifindex;
	pul.rule = NULL;
	pul.vrf_id = zrule->vrf_id;
	hash_walk(zrouter.rules_hash, &pbr_rule_lookup_unique_walker, &pul);

	return pul.rule;
}

void zebra_pbr_ipset_free(void *arg)
{
	struct zebra_pbr_ipset *ipset;

	ipset = (struct zebra_pbr_ipset *)arg;
	hook_call(zebra_pbr_ipset_update, 0, ipset);
	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_hash_key(const void *arg)
{
	const struct zebra_pbr_ipset *ipset = arg;
	uint32_t *pnt = (uint32_t *)&ipset->ipset_name;
	uint32_t key = jhash_1word(ipset->vrf_id, 0x63ab42de);

	return jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE, key);
}

bool zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset *r1, *r2;

	r1 = (const struct zebra_pbr_ipset *)arg1;
	r2 = (const struct zebra_pbr_ipset *)arg2;

	if (r1->type != r2->type)
		return false;
	if (r1->unique != r2->unique)
		return false;
	if (r1->vrf_id != r2->vrf_id)
		return false;

	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return false;
	return true;
}

void zebra_pbr_ipset_entry_free(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;

	ipset = (struct zebra_pbr_ipset_entry *)arg;

	hook_call(zebra_pbr_ipset_entry_update, 0, ipset);

	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_entry_hash_key(const void *arg)
{
	const struct zebra_pbr_ipset_entry *ipset;
	uint32_t key;

	ipset = arg;
	key = prefix_hash_key(&ipset->src);
	key = jhash_1word(ipset->unique, key);
	key = jhash_1word(prefix_hash_key(&ipset->dst), key);
	key = jhash(&ipset->dst_port_min, 2, key);
	key = jhash(&ipset->dst_port_max, 2, key);
	key = jhash(&ipset->src_port_min, 2, key);
	key = jhash(&ipset->src_port_max, 2, key);
	key = jhash(&ipset->proto, 1, key);

	return key;
}

bool zebra_pbr_ipset_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset_entry *r1, *r2;

	r1 = (const struct zebra_pbr_ipset_entry *)arg1;
	r2 = (const struct zebra_pbr_ipset_entry *)arg2;

	if (r1->unique != r2->unique)
		return false;

	if (!prefix_same(&r1->src, &r2->src))
		return false;

	if (!prefix_same(&r1->dst, &r2->dst))
		return false;

	if (r1->src_port_min != r2->src_port_min)
		return false;

	if (r1->src_port_max != r2->src_port_max)
		return false;

	if (r1->dst_port_min != r2->dst_port_min)
		return false;

	if (r1->dst_port_max != r2->dst_port_max)
		return false;

	if (r1->proto != r2->proto)
		return false;
	return true;
}

void zebra_pbr_iptable_free(void *arg)
{
	struct zebra_pbr_iptable *iptable;
	struct listnode *node, *nnode;
	char *name;

	iptable = (struct zebra_pbr_iptable *)arg;
	hook_call(zebra_pbr_iptable_update, 0, iptable);

	for (ALL_LIST_ELEMENTS(iptable->interface_name_list,
					node, nnode, name)) {
		XFREE(MTYPE_PBR_IPTABLE_IFNAME, name);
		list_delete_node(iptable->interface_name_list,
				 node);
	}
	XFREE(MTYPE_TMP, iptable);
}

uint32_t zebra_pbr_iptable_hash_key(const void *arg)
{
	const struct zebra_pbr_iptable *iptable = arg;
	uint32_t *pnt = (uint32_t *)&(iptable->ipset_name);
	uint32_t key;

	key = jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE,
		     0x63ab42de);
	key = jhash_1word(iptable->fwmark, key);
	key = jhash_1word(iptable->pkt_len_min, key);
	key = jhash_1word(iptable->pkt_len_max, key);
	key = jhash_1word(iptable->tcp_flags, key);
	key = jhash_1word(iptable->tcp_mask_flags, key);
	key = jhash_1word(iptable->dscp_value, key);
	key = jhash_1word(iptable->protocol, key);
	key = jhash_1word(iptable->fragment, key);
	key = jhash_1word(iptable->vrf_id, key);

	return jhash_3words(iptable->filter_bm, iptable->type,
			    iptable->unique, key);
}

bool zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_iptable *r1, *r2;

	r1 = (const struct zebra_pbr_iptable *)arg1;
	r2 = (const struct zebra_pbr_iptable *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return false;
	if (r1->type != r2->type)
		return false;
	if (r1->unique != r2->unique)
		return false;
	if (r1->filter_bm != r2->filter_bm)
		return false;
	if (r1->fwmark != r2->fwmark)
		return false;
	if (r1->action != r2->action)
		return false;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return false;
	if (r1->pkt_len_min != r2->pkt_len_min)
		return false;
	if (r1->pkt_len_max != r2->pkt_len_max)
		return false;
	if (r1->tcp_flags != r2->tcp_flags)
		return false;
	if (r1->tcp_mask_flags != r2->tcp_mask_flags)
		return false;
	if (r1->dscp_value != r2->dscp_value)
		return false;
	if (r1->fragment != r2->fragment)
		return false;
	if (r1->protocol != r2->protocol)
		return false;
	return true;
}

static void *pbr_rule_alloc_intern(void *arg)
{
	struct zebra_pbr_rule *zpr;
	struct zebra_pbr_rule *new;

	zpr = (struct zebra_pbr_rule *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(*new));

	memcpy(new, zpr, sizeof(*zpr));

	return new;
}

void zebra_pbr_add_rule(struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *unique =
		pbr_rule_lookup_unique(rule);

	(void)hash_get(zrouter.rules_hash, rule, pbr_rule_alloc_intern);
	(void)kernel_add_pbr_rule(rule);
	/*
	 * Rule Replace semantics, if we have an old, install the
	 * new rule, look above, and then delete the old
	 */
	if (unique)
		zebra_pbr_del_rule(unique);
}

void zebra_pbr_del_rule(struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *lookup;

	lookup = hash_lookup(zrouter.rules_hash, rule);
	(void)kernel_del_pbr_rule(rule);

	if (lookup) {
		hash_release(zrouter.rules_hash, lookup);
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_debug("%s: Rule being deleted we know nothing about",
			   __PRETTY_FUNCTION__);
}

static void zebra_pbr_cleanup_rules(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_rule *rule = b->data;
	int *sock = data;

	if (rule->sock == *sock) {
		(void)kernel_del_pbr_rule(rule);
		if (hash_release(zrouter.rules_hash, rule))
			XFREE(MTYPE_TMP, rule);
		else
			zlog_debug(
				"%s: Rule seq: %u is being cleaned but we can't find it in our tables",
				__func__, rule->rule.seq);
	}
}

static void zebra_pbr_cleanup_ipset(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_ipset *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		hook_call(zebra_pbr_ipset_update, 0, ipset);
		hash_release(zrouter.ipset_hash, ipset);
	}
}

static void zebra_pbr_cleanup_ipset_entry(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_ipset_entry *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		hook_call(zebra_pbr_ipset_entry_update, 0, ipset);
		hash_release(zrouter.ipset_entry_hash, ipset);
	}
}

static void zebra_pbr_cleanup_iptable(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_iptable *iptable = b->data;
	int *sock = data;

	if (iptable->sock == *sock) {
		hook_call(zebra_pbr_iptable_update, 0, iptable);
		hash_release(zrouter.iptable_hash, iptable);
	}
}

static int zebra_pbr_client_close_cleanup(struct zserv *client)
{
	int sock = client->sock;

	if (!sock)
		return 0;
	hash_iterate(zrouter.rules_hash, zebra_pbr_cleanup_rules, &sock);
	hash_iterate(zrouter.iptable_hash, zebra_pbr_cleanup_iptable, &sock);
	hash_iterate(zrouter.ipset_entry_hash, zebra_pbr_cleanup_ipset_entry,
		     &sock);
	hash_iterate(zrouter.ipset_hash, zebra_pbr_cleanup_ipset, &sock);
	return 1;
}

void zebra_pbr_init(void)
{
	hook_register(zserv_client_close, zebra_pbr_client_close_cleanup);
}

static void *pbr_ipset_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_pbr_ipset *new;

	zpi = (struct zebra_pbr_ipset *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_ipset));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_create_ipset(struct zebra_pbr_ipset *ipset)
{
	int ret;

	(void)hash_get(zrouter.ipset_hash, ipset, pbr_ipset_alloc_intern);
	ret = hook_call(zebra_pbr_ipset_update, 1, ipset);
	kernel_pbr_ipset_add_del_status(ipset,
					ret ? ZEBRA_DPLANE_INSTALL_SUCCESS
					: ZEBRA_DPLANE_INSTALL_FAILURE);
}

void zebra_pbr_destroy_ipset(struct zebra_pbr_ipset *ipset)
{
	struct zebra_pbr_ipset *lookup;

	lookup = hash_lookup(zrouter.ipset_hash, ipset);
	hook_call(zebra_pbr_ipset_update, 0, ipset);
	if (lookup) {
		hash_release(zrouter.ipset_hash, lookup);
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_debug(
			"%s: IPSet Entry being deleted we know nothing about",
			__PRETTY_FUNCTION__);
}

struct pbr_ipset_name_lookup {
	struct zebra_pbr_ipset *ipset;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

const char *zebra_pbr_ipset_type2str(uint32_t type)
{
	return lookup_msg(ipset_type_msg, type,
			  "Unrecognized IPset Type");
}

static int zebra_pbr_ipset_pername_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct pbr_ipset_name_lookup *pinl =
		(struct pbr_ipset_name_lookup *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)bucket->data;

	if (!strncmp(pinl->ipset_name, zpi->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		pinl->ipset = zpi;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(char *ipsetname)
{
	struct pbr_ipset_name_lookup pinl;
	struct pbr_ipset_name_lookup *ptr = &pinl;

	if (!ipsetname)
		return NULL;
	memset(ptr, 0, sizeof(struct pbr_ipset_name_lookup));
	snprintf((char *)ptr->ipset_name, ZEBRA_IPSET_NAME_SIZE, "%s",
		ipsetname);
	hash_walk(zrouter.ipset_hash, zebra_pbr_ipset_pername_walkcb, ptr);
	return ptr->ipset;
}

static void *pbr_ipset_entry_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset_entry *zpi;
	struct zebra_pbr_ipset_entry *new;

	zpi = (struct zebra_pbr_ipset_entry *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_ipset_entry));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_add_ipset_entry(struct zebra_pbr_ipset_entry *ipset)
{
	int ret;

	(void)hash_get(zrouter.ipset_entry_hash, ipset,
		       pbr_ipset_entry_alloc_intern);
	ret = hook_call(zebra_pbr_ipset_entry_update, 1, ipset);
	kernel_pbr_ipset_entry_add_del_status(ipset,
					ret ? ZEBRA_DPLANE_INSTALL_SUCCESS
					: ZEBRA_DPLANE_INSTALL_FAILURE);
}

void zebra_pbr_del_ipset_entry(struct zebra_pbr_ipset_entry *ipset)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zrouter.ipset_entry_hash, ipset);
	hook_call(zebra_pbr_ipset_entry_update, 0, ipset);
	if (lookup) {
		hash_release(zrouter.ipset_entry_hash, lookup);
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_debug("%s: IPSet being deleted we know nothing about",
			   __PRETTY_FUNCTION__);
}

static void *pbr_iptable_alloc_intern(void *arg)
{
	struct zebra_pbr_iptable *zpi;
	struct zebra_pbr_iptable *new;

	zpi = (struct zebra_pbr_iptable *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_iptable));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_add_iptable(struct zebra_pbr_iptable *iptable)
{
	int ret;

	(void)hash_get(zrouter.iptable_hash, iptable, pbr_iptable_alloc_intern);
	ret = hook_call(zebra_pbr_iptable_update, 1, iptable);
	kernel_pbr_iptable_add_del_status(iptable,
					  ret ? ZEBRA_DPLANE_INSTALL_SUCCESS
					  : ZEBRA_DPLANE_INSTALL_FAILURE);
}

void zebra_pbr_del_iptable(struct zebra_pbr_iptable *iptable)
{
	struct zebra_pbr_iptable *lookup;

	lookup = hash_lookup(zrouter.iptable_hash, iptable);
	hook_call(zebra_pbr_iptable_update, 0, iptable);
	if (lookup) {
		struct listnode *node, *nnode;
		char *name;

		hash_release(zrouter.iptable_hash, lookup);
		for (ALL_LIST_ELEMENTS(iptable->interface_name_list,
				       node, nnode, name)) {
			XFREE(MTYPE_PBR_IPTABLE_IFNAME, name);
			list_delete_node(iptable->interface_name_list,
					 node);
		}
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_debug("%s: IPTable being deleted we know nothing about",
			   __PRETTY_FUNCTION__);
}

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
				    enum zebra_dplane_status res)
{
	switch (res) {
	case ZEBRA_DPLANE_INSTALL_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_INSTALLED);
		break;
	case ZEBRA_DPLANE_INSTALL_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_FAIL_INSTALL);
		break;
	case ZEBRA_DPLANE_DELETE_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_REMOVED);
		break;
	case ZEBRA_DPLANE_DELETE_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_FAIL_REMOVE);
		break;
	case ZEBRA_DPLANE_STATUS_NONE:
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_add_del_status(struct zebra_pbr_ipset *ipset,
				    enum zebra_dplane_status res)
{
	switch (res) {
	case ZEBRA_DPLANE_INSTALL_SUCCESS:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_INSTALLED);
		break;
	case ZEBRA_DPLANE_INSTALL_FAILURE:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_FAIL_INSTALL);
		break;
	case ZEBRA_DPLANE_DELETE_SUCCESS:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_REMOVED);
		break;
	case ZEBRA_DPLANE_DELETE_FAILURE:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_FAIL_REMOVE);
		break;
	case ZEBRA_DPLANE_STATUS_NONE:
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_entry_add_del_status(
			struct zebra_pbr_ipset_entry *ipset,
			enum zebra_dplane_status res)
{
	switch (res) {
	case ZEBRA_DPLANE_INSTALL_SUCCESS:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_INSTALLED);
		break;
	case ZEBRA_DPLANE_INSTALL_FAILURE:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_FAIL_INSTALL);
		break;
	case ZEBRA_DPLANE_DELETE_SUCCESS:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_REMOVED);
		break;
	case ZEBRA_DPLANE_DELETE_FAILURE:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_FAIL_REMOVE);
		break;
	case ZEBRA_DPLANE_STATUS_NONE:
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_iptable_add_del_status(struct zebra_pbr_iptable *iptable,
				       enum zebra_dplane_status res)
{
	switch (res) {
	case ZEBRA_DPLANE_INSTALL_SUCCESS:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_INSTALLED);
		break;
	case ZEBRA_DPLANE_INSTALL_FAILURE:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_FAIL_INSTALL);
		break;
	case ZEBRA_DPLANE_DELETE_SUCCESS:
		zsend_iptable_notify_owner(iptable,
					   ZAPI_IPTABLE_REMOVED);
		break;
	case ZEBRA_DPLANE_DELETE_FAILURE:
		zsend_iptable_notify_owner(iptable,
					   ZAPI_IPTABLE_FAIL_REMOVE);
		break;
	case ZEBRA_DPLANE_STATUS_NONE:
		break;
	}
}

/*
 * Handle rule delete notification from kernel.
 */
int kernel_pbr_rule_del(struct zebra_pbr_rule *rule)
{
	return 0;
}

struct zebra_pbr_ipset_entry_unique_display {
	struct zebra_pbr_ipset *zpi;
	struct vty *vty;
	struct zebra_ns *zns;
};

struct zebra_pbr_env_display {
	struct zebra_ns *zns;
	struct vty *vty;
	char *name;
};

static const char *zebra_pbr_prefix2str(union prefixconstptr pu,
					char *str, int size)
{
	const struct prefix *p = pu.p;
	char buf[PREFIX2STR_BUFFER];

	if (p->family == AF_INET && p->prefixlen == IPV4_MAX_PREFIXLEN) {
		snprintf(str, size, "%s", inet_ntop(p->family, &p->u.prefix,
						    buf, PREFIX2STR_BUFFER));
		return str;
	}
	return prefix2str(pu, str, size);
}

static void zebra_pbr_display_icmp(struct vty *vty,
				   struct zebra_pbr_ipset_entry *zpie)
{
	char decoded_str[20];
	uint16_t port;

	/* range icmp type */
	if (zpie->src_port_max || zpie->dst_port_max) {
		vty_out(vty, ":icmp:[type <%d:%d>;code <%d:%d>",
			zpie->src_port_min, zpie->src_port_max,
			zpie->dst_port_min, zpie->dst_port_max);
	} else {
		port = ((zpie->src_port_min << 8) & 0xff00) +
			(zpie->dst_port_min & 0xff);
		memset(decoded_str, 0, sizeof(decoded_str));
		sprintf(decoded_str, "%d/%d",
			zpie->src_port_min,
			zpie->dst_port_min);
		vty_out(vty, ":icmp:%s",
			lookup_msg(icmp_typecode_str,
				   port, decoded_str));
	}
}

static void zebra_pbr_display_port(struct vty *vty, uint32_t filter_bm,
			    uint16_t port_min, uint16_t port_max,
			    uint8_t proto)
{
	if (!(filter_bm & PBR_FILTER_PROTO)) {
		if (port_max)
			vty_out(vty, ":udp/tcp:%d-%d",
				port_min, port_max);
		else
			vty_out(vty, ":udp/tcp:%d",
				port_min);
	} else {
		if (port_max)
			vty_out(vty, ":proto %d:%d-%d",
				proto, port_min, port_max);
		else
			vty_out(vty, ":proto %d:%d",
				proto, port_min);
	}
}

static int zebra_pbr_show_ipset_entry_walkcb(struct hash_bucket *bucket,
					     void *arg)
{
	struct zebra_pbr_ipset_entry_unique_display *unique =
		(struct zebra_pbr_ipset_entry_unique_display *)arg;
	struct zebra_pbr_ipset *zpi = unique->zpi;
	struct vty *vty = unique->vty;
	struct zebra_pbr_ipset_entry *zpie =
		(struct zebra_pbr_ipset_entry *)bucket->data;
	uint64_t pkts = 0, bytes = 0;
	int ret = 0;

	if (zpie->backpointer != zpi)
		return HASHWALK_CONTINUE;

	if ((zpi->type == IPSET_NET_NET) ||
	    (zpi->type == IPSET_NET_PORT_NET)) {
		char buf[PREFIX_STRLEN];

		zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
		vty_out(vty, "\tfrom %s", buf);
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		vty_out(vty, " to ");
		zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		if (zpie->filter_bm & PBR_FILTER_DST_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
		if (zpie->proto == IPPROTO_ICMP)
			zebra_pbr_display_icmp(vty, zpie);
	} else if ((zpi->type == IPSET_NET) ||
		   (zpi->type == IPSET_NET_PORT)) {
		char buf[PREFIX_STRLEN];

		if (zpie->filter_bm & PBR_FILTER_SRC_IP) {
			zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
			vty_out(vty, "\tfrom %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		if (zpie->filter_bm & PBR_FILTER_DST_IP) {
			zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
			vty_out(vty, "\tto %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_DST_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
		if (zpie->proto == IPPROTO_ICMP)
			zebra_pbr_display_icmp(vty, zpie);
	}
	vty_out(vty, " (%u)\n", zpie->unique);

	ret = hook_call(zebra_pbr_ipset_entry_get_stat, zpie, &pkts,
			&bytes);
	if (ret && pkts > 0)
		vty_out(vty, "\t pkts %" PRIu64 ", bytes %" PRIu64"\n",
			pkts, bytes);
	return HASHWALK_CONTINUE;
}

static int zebra_pbr_show_ipset_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_env_display *uniqueipset =
		(struct zebra_pbr_env_display *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)bucket->data;
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct vty *vty = uniqueipset->vty;
	struct zebra_ns *zns = uniqueipset->zns;

	vty_out(vty, "IPset %s type %s\n", zpi->ipset_name,
		zebra_pbr_ipset_type2str(zpi->type));
	unique.vty = vty;
	unique.zpi = zpi;
	unique.zns = zns;
	hash_walk(zrouter.ipset_entry_hash, zebra_pbr_show_ipset_entry_walkcb,
		  &unique);
	vty_out(vty, "\n");
	return HASHWALK_CONTINUE;
}

size_t zebra_pbr_tcpflags_snprintf(char *buffer, size_t len,
				   uint16_t tcp_val)
{
	size_t len_written = 0;
	static struct message nt = {0};
	const struct message *pnt;
	int incr = 0;

	for (pnt = tcp_value_str;
	     memcmp(pnt, &nt, sizeof(struct message)); pnt++)
		if (pnt->key & tcp_val) {
			len_written += snprintf(buffer + len_written,
						len - len_written,
						"%s%s", incr ?
						",":"", pnt->str);
			incr++;
		}
	return len_written;
}

/*
 */
void zebra_pbr_show_ipset_list(struct vty *vty, char *ipsetname)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct zebra_pbr_env_display uniqueipset;

	if (ipsetname) {
		zpi = zebra_pbr_lookup_ipset_pername(ipsetname);
		if (!zpi) {
			vty_out(vty, "No IPset %s found\n", ipsetname);
			return;
		}
		vty_out(vty, "IPset %s type %s\n", ipsetname,
			zebra_pbr_ipset_type2str(zpi->type));

		unique.vty = vty;
		unique.zpi = zpi;
		unique.zns = zns;
		hash_walk(zrouter.ipset_entry_hash,
			  zebra_pbr_show_ipset_entry_walkcb, &unique);
		return;
	}
	uniqueipset.zns = zns;
	uniqueipset.vty = vty;
	uniqueipset.name = NULL;
	hash_walk(zrouter.ipset_hash, zebra_pbr_show_ipset_walkcb,
		  &uniqueipset);
}

struct pbr_rule_fwmark_lookup {
	struct zebra_pbr_rule *ptr;
	uint32_t fwmark;
};

static int zebra_pbr_rule_lookup_fwmark_walkcb(struct hash_bucket *bucket,
					       void *arg)
{
	struct pbr_rule_fwmark_lookup *iprule =
		(struct pbr_rule_fwmark_lookup *)arg;
	struct zebra_pbr_rule *zpr = (struct zebra_pbr_rule *)bucket->data;

	if (iprule->fwmark == zpr->rule.filter.fwmark) {
		iprule->ptr = zpr;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static void zebra_pbr_show_iptable_unit(struct zebra_pbr_iptable *iptable,
				       struct vty *vty,
				       struct zebra_ns *zns)
{
	int ret;
	uint64_t pkts = 0, bytes = 0;

	vty_out(vty, "IPtable %s action %s (%u)\n", iptable->ipset_name,
		iptable->action == ZEBRA_IPTABLES_DROP ? "drop" : "redirect",
		iptable->unique);
	if (iptable->type == IPSET_NET_PORT ||
	    iptable->type == IPSET_NET_PORT_NET) {
		if (!(iptable->filter_bm & MATCH_ICMP_SET)) {
			if (iptable->filter_bm & PBR_FILTER_DST_PORT)
				vty_out(vty, "\t lookup dst port\n");
			else if (iptable->filter_bm & PBR_FILTER_SRC_PORT)
				vty_out(vty, "\t lookup src port\n");
		}
	}
	if (iptable->pkt_len_min || iptable->pkt_len_max) {
		if (!iptable->pkt_len_max)
			vty_out(vty, "\t pkt len %u\n",
				iptable->pkt_len_min);
		else
			vty_out(vty, "\t pkt len [%u;%u]\n",
				iptable->pkt_len_min,
				iptable->pkt_len_max);
	}
	if (iptable->tcp_flags || iptable->tcp_mask_flags) {
		char tcp_flag_str[64];
		char tcp_flag_mask_str[64];

		zebra_pbr_tcpflags_snprintf(tcp_flag_str,
					    sizeof(tcp_flag_str),
					    iptable->tcp_flags);
		zebra_pbr_tcpflags_snprintf(tcp_flag_mask_str,
					    sizeof(tcp_flag_mask_str),
					    iptable->tcp_mask_flags);
		vty_out(vty, "\t tcpflags [%s/%s]\n",
			tcp_flag_str, tcp_flag_mask_str);
	}
	if (iptable->filter_bm & (MATCH_DSCP_SET | MATCH_DSCP_INVERSE_SET)) {
		vty_out(vty, "\t dscp %s %d\n",
			iptable->filter_bm & MATCH_DSCP_INVERSE_SET ?
			"not" : "", iptable->dscp_value);
	}
	if (iptable->fragment) {
		char val_str[10];

		sprintf(val_str, "%d", iptable->fragment);
		vty_out(vty, "\t fragment%s %s\n",
			iptable->filter_bm & MATCH_FRAGMENT_INVERSE_SET ?
			" not" : "", lookup_msg(fragment_value_str,
					       iptable->fragment, val_str));
	}
	if (iptable->protocol) {
		vty_out(vty, "\t protocol %d\n",
			iptable->protocol);
	}
	ret = hook_call(zebra_pbr_iptable_get_stat, iptable, &pkts,
			&bytes);
	if (ret && pkts > 0)
		vty_out(vty, "\t pkts %" PRIu64 ", bytes %" PRIu64"\n",
			pkts, bytes);
	if (iptable->action != ZEBRA_IPTABLES_DROP) {
		struct pbr_rule_fwmark_lookup prfl;

		prfl.fwmark = iptable->fwmark;
		prfl.ptr = NULL;
		hash_walk(zrouter.rules_hash,
			  &zebra_pbr_rule_lookup_fwmark_walkcb, &prfl);
		if (prfl.ptr) {
			struct zebra_pbr_rule *zpr = prfl.ptr;

			vty_out(vty, "\t table %u, fwmark %u\n",
				zpr->rule.action.table,
				prfl.fwmark);
		}
	}
}

static int zebra_pbr_show_iptable_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_iptable *iptable =
		(struct zebra_pbr_iptable *)bucket->data;
	struct zebra_pbr_env_display *env = (struct zebra_pbr_env_display *)arg;
	struct vty *vty = env->vty;
	struct zebra_ns *zns = env->zns;
	char *iptable_name = env->name;

	if (!iptable_name)
		zebra_pbr_show_iptable_unit(iptable, vty, zns);
	else if (!strncmp(iptable_name,
			  iptable->ipset_name,
			  ZEBRA_IPSET_NAME_SIZE))
		zebra_pbr_show_iptable_unit(iptable, vty, zns);
	return HASHWALK_CONTINUE;
}

void zebra_pbr_show_iptable(struct vty *vty, char *iptable_name)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_env_display env;

	env.vty = vty;
	env.zns = zns;
	env.name = iptable_name;
	hash_walk(zrouter.iptable_hash, zebra_pbr_show_iptable_walkcb, &env);
}

void zebra_pbr_iptable_update_interfacelist(struct stream *s,
					    struct zebra_pbr_iptable *zpi)
{
	uint32_t i = 0, index;
	struct interface *ifp;
	char *name;

	for (i = 0; i < zpi->nb_interface; i++) {
		STREAM_GETL(s, index);
		ifp = if_lookup_by_index(index, zpi->vrf_id);
		if (!ifp)
			continue;
		name = XSTRDUP(MTYPE_PBR_IPTABLE_IFNAME, ifp->name);
		listnode_add(zpi->interface_name_list, name);
	}
stream_failure:
	return;
}
