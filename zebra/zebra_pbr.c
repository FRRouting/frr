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

#include "zebra/zebra_pbr.h"
#include "zebra/rt.h"
#include "zebra/zapi_msg.h"

/* definitions */

/* static function declarations */

/* Private functions */

/* Public functions */
void zebra_pbr_rules_free(void *arg)
{
	struct zebra_pbr_rule *rule;

	rule = (struct zebra_pbr_rule *)arg;

	kernel_del_pbr_rule(rule);
	XFREE(MTYPE_TMP, rule);
}

uint32_t zebra_pbr_rules_hash_key(void *arg)
{
	struct zebra_pbr_rule *rule;
	uint32_t key;

	rule = (struct zebra_pbr_rule *)arg;
	key = jhash_3words(rule->rule.seq, rule->rule.priority,
			   rule->rule.action.table,
			   prefix_hash_key(&rule->rule.filter.src_ip));
	if (rule->ifp)
		key = jhash_1word(rule->ifp->ifindex, key);
	else
		key = jhash_1word(0, key);

	if (rule->rule.filter.fwmark)
		key = jhash_1word(rule->rule.filter.fwmark, key);
	else
		key = jhash_1word(0, key);
	return jhash_3words(rule->rule.filter.src_port,
			    rule->rule.filter.dst_port,
			    prefix_hash_key(&rule->rule.filter.dst_ip),
			    jhash_1word(rule->rule.unique, key));
}

int zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_rule *r1, *r2;

	r1 = (const struct zebra_pbr_rule *)arg1;
	r2 = (const struct zebra_pbr_rule *)arg2;

	if (r1->rule.seq != r2->rule.seq)
		return 0;

	if (r1->rule.priority != r2->rule.priority)
		return 0;

	if (r1->rule.unique != r2->rule.unique)
		return 0;

	if (r1->rule.action.table != r2->rule.action.table)
		return 0;

	if (r1->rule.filter.src_port != r2->rule.filter.src_port)
		return 0;

	if (r1->rule.filter.dst_port != r2->rule.filter.dst_port)
		return 0;

	if (r1->rule.filter.fwmark != r2->rule.filter.fwmark)
		return 0;

	if (!prefix_same(&r1->rule.filter.src_ip, &r2->rule.filter.src_ip))
		return 0;

	if (!prefix_same(&r1->rule.filter.dst_ip, &r2->rule.filter.dst_ip))
		return 0;

	if (r1->ifp != r2->ifp)
		return 0;

	return 1;
}

struct pbr_rule_unique_lookup {
	struct zebra_pbr_rule *rule;
	uint32_t unique;
	struct interface *ifp;
};

static int pbr_rule_lookup_unique_walker(struct hash_backet *b, void *data)
{
	struct pbr_rule_unique_lookup *pul = data;
	struct zebra_pbr_rule *rule = b->data;

	if (pul->unique == rule->rule.unique && pul->ifp == rule->ifp) {
		pul->rule = rule;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static struct zebra_pbr_rule *pbr_rule_lookup_unique(struct zebra_ns *zns,
						     uint32_t unique,
						     struct interface *ifp)
{
	struct pbr_rule_unique_lookup pul;

	pul.unique = unique;
	pul.ifp = ifp;
	pul.rule = NULL;
	hash_walk(zns->rules_hash, &pbr_rule_lookup_unique_walker, &pul);

	return pul.rule;
}

void zebra_pbr_ipset_free(void *arg)
{
	struct zebra_pbr_ipset *ipset;

	ipset = (struct zebra_pbr_ipset *)arg;

	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_hash_key(void *arg)
{
	struct zebra_pbr_ipset *ipset = (struct zebra_pbr_ipset *)arg;
	uint32_t *pnt = (uint32_t *)&ipset->ipset_name;

	return jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE, 0x63ab42de);
}

int zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset *r1, *r2;

	r1 = (const struct zebra_pbr_ipset *)arg1;
	r2 = (const struct zebra_pbr_ipset *)arg2;

	if (r1->type != r2->type)
		return 0;
	if (r1->unique != r2->unique)
		return 0;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return 0;
	return 1;
}

void zebra_pbr_ipset_entry_free(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;

	ipset = (struct zebra_pbr_ipset_entry *)arg;

	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_entry_hash_key(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;
	uint32_t key;

	ipset = (struct zebra_pbr_ipset_entry *)arg;
	key = prefix_hash_key(&ipset->src);
	key = jhash_1word(ipset->unique, key);
	key = jhash_1word(prefix_hash_key(&ipset->dst), key);

	return key;
}

int zebra_pbr_ipset_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset_entry *r1, *r2;

	r1 = (const struct zebra_pbr_ipset_entry *)arg1;
	r2 = (const struct zebra_pbr_ipset_entry *)arg2;

	if (r1->unique != r2->unique)
		return 0;

	if (!prefix_same(&r1->src, &r2->src))
		return 0;

	if (!prefix_same(&r1->dst, &r2->dst))
		return 0;

	return 1;
}

void zebra_pbr_iptable_free(void *arg)
{
	struct zebra_pbr_iptable *iptable;

	iptable = (struct zebra_pbr_iptable *)arg;

	XFREE(MTYPE_TMP, iptable);
}

uint32_t zebra_pbr_iptable_hash_key(void *arg)
{
	struct zebra_pbr_iptable *iptable = (struct zebra_pbr_iptable *)arg;
	uint32_t *pnt = (uint32_t *)&(iptable->ipset_name);
	uint32_t key;

	key = jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE,
		     0x63ab42de);
	key = jhash_1word(iptable->fwmark, key);
	return jhash_3words(iptable->filter_bm, iptable->type,
			    iptable->unique, key);
}

int zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_iptable *r1, *r2;

	r1 = (const struct zebra_pbr_iptable *)arg1;
	r2 = (const struct zebra_pbr_iptable *)arg2;

	if (r1->type != r2->type)
		return 0;
	if (r1->unique != r2->unique)
		return 0;
	if (r1->filter_bm != r2->filter_bm)
		return 0;
	if (r1->fwmark != r2->fwmark)
		return 0;
	if (r1->action != r2->action)
		return 0;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return 0;
	return 1;
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

void zebra_pbr_add_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *unique =
		pbr_rule_lookup_unique(zns, rule->rule.unique, rule->ifp);

	(void)hash_get(zns->rules_hash, rule, pbr_rule_alloc_intern);
	kernel_add_pbr_rule(rule);

	/*
	 * Rule Replace semantics, if we have an old, install the
	 * new rule, look above, and then delete the old
	 */
	if (unique)
		zebra_pbr_del_rule(zns, unique);
}

void zebra_pbr_del_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *lookup;

	lookup = hash_lookup(zns->rules_hash, rule);
	kernel_del_pbr_rule(rule);

	if (lookup) {
		hash_release(zns->rules_hash, lookup);
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_warn("%s: Rule being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

static void zebra_pbr_cleanup_rules(struct hash_backet *b, void *data)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_rule *rule = b->data;
	int *sock = data;

	if (rule->sock == *sock) {
		kernel_del_pbr_rule(rule);
		hash_release(zns->rules_hash, rule);
		XFREE(MTYPE_TMP, rule);
	}
}

static int zebra_pbr_client_close_cleanup(struct zserv *client)
{
	int sock = client->sock;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	if (!sock)
		return 0;
	hash_iterate(zns->rules_hash, zebra_pbr_cleanup_rules, &sock);
	return 1;
}

void zebra_pbr_init(void)
{
	hook_register(zapi_client_close, zebra_pbr_client_close_cleanup);
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

void zebra_pbr_create_ipset(struct zebra_ns *zns,
			    struct zebra_pbr_ipset *ipset)
{
	(void)hash_get(zns->ipset_hash, ipset, pbr_ipset_alloc_intern);
	/* TODO:
	 * - Netlink call
	 */
}

void zebra_pbr_destroy_ipset(struct zebra_ns *zns,
			     struct zebra_pbr_ipset *ipset)
{
	struct zebra_pbr_ipset *lookup;

	lookup = hash_lookup(zns->ipset_hash, ipset);
	/* TODO:
	 * - Netlink destroy from kernel
	 * - ?? destroy ipset entries before
	 */
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPSet Entry being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

struct pbr_ipset_name_lookup {
	struct zebra_pbr_ipset *ipset;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

static int zebra_pbr_ipset_pername_walkcb(struct hash_backet *backet, void *arg)
{
	struct pbr_ipset_name_lookup *pinl =
		(struct pbr_ipset_name_lookup *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)backet->data;

	if (!strncmp(pinl->ipset_name, zpi->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		pinl->ipset = zpi;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(struct zebra_ns *zns,
						       char *ipsetname)
{
	struct pbr_ipset_name_lookup pinl;
	struct pbr_ipset_name_lookup *ptr = &pinl;

	if (!ipsetname)
		return NULL;
	memset(ptr, 0, sizeof(struct pbr_ipset_name_lookup));
	snprintf((char *)ptr->ipset_name, ZEBRA_IPSET_NAME_SIZE, "%s",
		ipsetname);
	hash_walk(zns->ipset_hash, zebra_pbr_ipset_pername_walkcb, ptr);
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

void zebra_pbr_add_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset)
{
	(void)hash_get(zns->ipset_entry_hash, ipset,
		       pbr_ipset_entry_alloc_intern);
	/* TODO:
	 * - attach to ipset list
	 * - Netlink add to kernel
	 */
}

void zebra_pbr_del_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zns->ipset_entry_hash, ipset);
	/* TODO:
	 * - Netlink destroy
	 * - detach from ipset list
	 * - ?? if no more entres, delete ipset
	 */
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPSet being deleted we know nothing about",
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

void zebra_pbr_add_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable)
{
	(void)hash_get(zns->iptable_hash, iptable,
		       pbr_iptable_alloc_intern);
	/* TODO call netlink layer */
}

void zebra_pbr_del_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zns->iptable_hash, iptable);
	/* TODO:
	 * - call netlink layer
	 * - detach from iptable list
	 */
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPTable being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
				    enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_REMOVED);
		break;
	case SOUTHBOUND_DELETE_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_REMOVED);
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_add_del_status(struct zebra_pbr_ipset *ipset,
				    enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_entry_add_del_status(
			struct zebra_pbr_ipset_entry *ipset,
			enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_iptable_add_del_status(struct zebra_pbr_iptable *iptable,
				       enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
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
