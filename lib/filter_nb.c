/*
 * FRR filter northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include "zebra.h"

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/prefix.h"

#include "lib/filter.h"
#include "lib/plist.h"
#include "lib/plist_int.h"

/*
 * XPath: /frr-filter:lib/access-list-legacy
 */
static int lib_access_list_legacy_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct access_list *acl;
	const char *acl_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl_name = yang_dnode_get_string(dnode, "./number");
	acl = access_list_get(AFI_IP, acl_name);
	nb_running_set_entry(dnode, acl);

	return NB_OK;
}

static int lib_access_list_legacy_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct access_master *am;
	struct access_list *acl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(dnode);
	am = acl->master;
	if (am->delete_hook)
		am->delete_hook(acl);

	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/remark
 */
static int lib_access_list_legacy_remark_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct access_list *acl;
	const char *remark;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	remark = yang_dnode_get_string(dnode, NULL);
	acl->remark = XSTRDUP(MTYPE_TMP, remark);

	return NB_OK;
}

static int lib_access_list_legacy_remark_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct access_list *acl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	acl->remark = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry
 */
static int lib_access_list_legacy_entry_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct access_list *acl;
	struct filter *f;
	uint32_t aclno;

	/* TODO: validate `filter_lookup_cisco` returns NULL. */

	if (event != NB_EV_APPLY)
		return NB_OK;

	aclno = yang_dnode_get_uint16(dnode, "../number");

	f = filter_new();
	f->cisco = 1;
	f->seq = yang_dnode_get_uint32(dnode, "./sequence");
	fc = &f->u.cfilter;
	if ((aclno >= 1 && aclno <= 99) || (aclno >= 1300 && aclno <= 1999))
		fc->extended = 0;
	else
		fc->extended = 1;

	acl = nb_running_get_entry(dnode, NULL, true);
	f->acl = acl;
	access_list_filter_add(acl, f);
	nb_running_set_entry(dnode, f);

	return NB_OK;
}

static int lib_access_list_legacy_entry_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	struct access_list *acl;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	acl = f->acl;
	access_list_filter_delete(acl, f);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/action
 */
static int
lib_access_list_legacy_entry_action_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	const char *filter_type;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	filter_type = yang_dnode_get_string(dnode, NULL);
	if (strcmp(filter_type, "permit") == 0)
		f->type = FILTER_PERMIT;
	else
		f->type = FILTER_DENY;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/host
 */
static int
lib_access_list_legacy_entry_host_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr, dnode, NULL);
	fc->addr_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_host_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/network
 */
static int
lib_access_list_legacy_entry_network_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_prefix(&p, dnode, NULL);
	fc->addr.s_addr = ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
	masklen2ip(p.prefixlen, &fc->addr_mask);

	return NB_OK;
}

static int
lib_access_list_legacy_entry_network_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/any
 */
static int lib_access_list_legacy_entry_any_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_any_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-host
 */
static int lib_access_list_legacy_entry_destination_host_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->mask, dnode, NULL);
	fc->mask_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_host_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-network
 */
static int lib_access_list_legacy_entry_destination_network_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_prefix(&p, dnode, NULL);
	fc->addr.s_addr = ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
	masklen2ip(p.prefixlen, &fc->addr_mask);

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_network_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-any
 */
static int lib_access_list_legacy_entry_destination_any_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_any_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list
 */
static int lib_access_list_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	struct access_list *acl;
	const char *acl_name;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "./type");
	acl_name = yang_dnode_get_string(dnode, "./name");

	switch (type) {
	case 0: /* ipv4 */
		acl = access_list_get(AFI_IP, acl_name);
		break;
	case 1: /* ipv6 */
		acl = access_list_get(AFI_IP6, acl_name);
		break;
	case 2: /* mac */
		acl = access_list_get(AFI_L2VPN, acl_name);
		break;
	}

	nb_running_set_entry(dnode, acl);

	return NB_OK;
}

static int lib_access_list_destroy(enum nb_event event,
				   const struct lyd_node *dnode)
{
	struct access_master *am;
	struct access_list *acl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(dnode);
	am = acl->master;
	if (am->delete_hook)
		am->delete_hook(acl);

	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/remark
 */
static int lib_access_list_remark_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	return lib_access_list_legacy_remark_modify(event, dnode, resource);
}

static int lib_access_list_remark_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	return lib_access_list_legacy_remark_destroy(event, dnode);
}

/*
 * XPath: /frr-filter:lib/access-list/entry
 */
static int lib_access_list_entry_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct access_list *acl;
	struct filter *f;

	/* TODO: validate `filter_lookup_zebra` returns NULL. */

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = filter_new();
	f->seq = yang_dnode_get_uint32(dnode, "./sequence");

	acl = nb_running_get_entry(dnode, NULL, true);
	f->acl = acl;
	access_list_filter_add(acl, f);
	nb_running_set_entry(dnode, f);

	return NB_OK;
}

static int lib_access_list_entry_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct access_list *acl;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	acl = f->acl;
	access_list_filter_delete(acl, f);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/action
 */
static int lib_access_list_entry_action_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	return lib_access_list_legacy_entry_action_modify(event, dnode,
							  resource);
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-prefix
 */
static int
lib_access_list_entry_ipv4_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	yang_dnode_get_prefix(&fz->prefix, dnode, NULL);

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	memset(&fz->prefix, 0, sizeof(fz->prefix));

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-exact-match
 */
static int
lib_access_list_entry_ipv4_exact_match_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->exact = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_exact_match_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->exact = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv6-prefix
 */
static int
lib_access_list_entry_ipv6_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	return lib_access_list_entry_ipv4_prefix_modify(event, dnode, resource);
}

static int
lib_access_list_entry_ipv6_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	return lib_access_list_entry_ipv4_prefix_destroy(event, dnode);
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv6-exact-match
 */
static int
lib_access_list_entry_ipv6_exact_match_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	return lib_access_list_entry_ipv4_exact_match_modify(event, dnode,
							     resource);
}

static int
lib_access_list_entry_ipv6_exact_match_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	return lib_access_list_entry_ipv4_exact_match_destroy(event, dnode);
}

/*
 * XPath: /frr-filter:lib/access-list/entry/mac
 */
static int lib_access_list_entry_mac_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	return lib_access_list_entry_ipv4_prefix_modify(event, dnode, resource);
}

static int lib_access_list_entry_mac_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	return lib_access_list_entry_ipv4_prefix_destroy(event, dnode);
}

/*
 * XPath: /frr-filter:lib/access-list/entry/any
 */
static int lib_access_list_entry_any_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct filter_zebra *fz;
	struct filter *f;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	memset(&fz->prefix, 0, sizeof(fz->prefix));

	type = yang_dnode_get_enum(dnode, "../../type");
	switch (type) {
	case 0: /* ipv4 */
		fz->prefix.family = AF_INET;
		break;
	case 1: /* ipv6 */
		fz->prefix.family = AF_INET6;
		break;
	case 2: /* mac */
		fz->prefix.family = AF_ETHERNET;
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_any_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->prefix.family = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list
 */
static int lib_prefix_list_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	struct prefix_list *pl;
	const char *name;
	int type;

	/* TODO: validate prefix_entry_dup_check() passes. */

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "./type");
	name = yang_dnode_get_string(dnode, "./name");
	switch (type) {
	case 0: /* ipv4 */
		pl = prefix_list_get(AFI_IP, 0, name);
		break;
	case 1: /* ipv6 */
		pl = prefix_list_get(AFI_IP6, 0, name);
		break;
	}

	nb_running_set_entry(dnode, pl);

	return NB_OK;
}

static int lib_prefix_list_destroy(enum nb_event event,
				   const struct lyd_node *dnode)
{
	struct prefix_list *pl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_unset_entry(dnode);
	prefix_list_delete(pl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/description
 */
static int lib_prefix_list_description_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct prefix_list *pl;
	const char *remark;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_get_entry(dnode, NULL, true);
	if (pl->desc)
		XFREE(MTYPE_TMP, pl->desc);

	remark = yang_dnode_get_string(dnode, NULL);
	pl->desc = XSTRDUP(MTYPE_TMP, remark);

	return NB_OK;
}

static int lib_prefix_list_description_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	struct prefix_list *pl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_get_entry(dnode, NULL, true);
	if (pl->desc)
		XFREE(MTYPE_TMP, pl->desc);

	pl->desc = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry
 */
static int lib_prefix_list_entry_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct prefix_list_entry *ple;
	struct prefix_list *pl;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	memset(&p, 0, sizeof(p));

	pl = nb_running_get_entry(dnode, NULL, true);
	ple = prefix_list_entry_new();
	ple->pl = pl;
	ple->any = 1;
	ple->seq = yang_dnode_get_int64(dnode, "./sequence");

	return NB_OK;
}

static int lib_prefix_list_entry_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_unset_entry(dnode);
	prefix_list_entry_delete(ple->pl, ple, 1);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/action
 */
static int lib_prefix_list_entry_action_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct prefix_list_entry *ple;
	const char *action_str;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	action_str = yang_dnode_get_string(dnode, "./action");
	if (strcmp(action_str, "permit") == 0)
		ple->type = PREFIX_PERMIT;
	else
		ple->type = PREFIX_DENY;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix
 */
static int
lib_prefix_list_entry_ipv4_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_prefix(&ple->prefix, dnode, NULL);

	return NB_OK;
}

static int
lib_prefix_list_entry_ipv4_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	memset(&ple->prefix, 0, sizeof(ple->prefix));
	ple->any = 1;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	ple->ge = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	ple->ge = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	ple->le = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	ple->le = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix
 */
static int
lib_prefix_list_entry_ipv6_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	return lib_prefix_list_entry_ipv4_prefix_modify(event, dnode, resource);
}

static int
lib_prefix_list_entry_ipv6_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	return lib_prefix_list_entry_ipv4_prefix_destroy(event, dnode);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify(
		event, dnode, resource);
}

static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy(
		event, dnode);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify(
		event, dnode, resource);
}

static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy(
		event, dnode);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/any
 */
static int lib_prefix_list_entry_any_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	memset(&ple->prefix, 0, sizeof(ple->prefix));
	ple->any = 1;

	return NB_OK;
}

static int lib_prefix_list_entry_any_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct prefix_list_entry *ple;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(dnode, NULL, true);
	memset(&ple->prefix, 0, sizeof(ple->prefix));
	ple->any = 1;

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_filter_info = {
	.name = "frr-filter",
	.nodes = {
		{
			.xpath = "/frr-filter:lib/access-list-legacy",
			.cbs = {
				.create = lib_access_list_legacy_create,
				.destroy = lib_access_list_legacy_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/remark",
			.cbs = {
				.modify = lib_access_list_legacy_remark_modify,
				.destroy = lib_access_list_legacy_remark_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry",
			.cbs = {
				.create = lib_access_list_legacy_entry_create,
				.destroy = lib_access_list_legacy_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/action",
			.cbs = {
				.modify = lib_access_list_legacy_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/host",
			.cbs = {
				.modify = lib_access_list_legacy_entry_host_modify,
				.destroy = lib_access_list_legacy_entry_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/network",
			.cbs = {
				.modify = lib_access_list_legacy_entry_network_modify,
				.destroy = lib_access_list_legacy_entry_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/any",
			.cbs = {
				.create = lib_access_list_legacy_entry_any_create,
				.destroy = lib_access_list_legacy_entry_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-host",
			.cbs = {
				.modify = lib_access_list_legacy_entry_destination_host_modify,
				.destroy = lib_access_list_legacy_entry_destination_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-network",
			.cbs = {
				.modify = lib_access_list_legacy_entry_destination_network_modify,
				.destroy = lib_access_list_legacy_entry_destination_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-any",
			.cbs = {
				.create = lib_access_list_legacy_entry_destination_any_create,
				.destroy = lib_access_list_legacy_entry_destination_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list",
			.cbs = {
				.create = lib_access_list_create,
				.destroy = lib_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/remark",
			.cbs = {
				.modify = lib_access_list_remark_modify,
				.destroy = lib_access_list_remark_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry",
			.cbs = {
				.create = lib_access_list_entry_create,
				.destroy = lib_access_list_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/action",
			.cbs = {
				.modify = lib_access_list_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv4-prefix",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_prefix_modify,
				.destroy = lib_access_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv4-exact-match",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_exact_match_modify,
				.destroy = lib_access_list_entry_ipv4_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv6-prefix",
			.cbs = {
				.modify = lib_access_list_entry_ipv6_prefix_modify,
				.destroy = lib_access_list_entry_ipv6_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv6-exact-match",
			.cbs = {
				.modify = lib_access_list_entry_ipv6_exact_match_modify,
				.destroy = lib_access_list_entry_ipv6_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/mac",
			.cbs = {
				.modify = lib_access_list_entry_mac_modify,
				.destroy = lib_access_list_entry_mac_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/any",
			.cbs = {
				.create = lib_access_list_entry_any_create,
				.destroy = lib_access_list_entry_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list",
			.cbs = {
				.create = lib_prefix_list_create,
				.destroy = lib_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/description",
			.cbs = {
				.modify = lib_prefix_list_description_modify,
				.destroy = lib_prefix_list_description_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry",
			.cbs = {
				.create = lib_prefix_list_entry_create,
				.destroy = lib_prefix_list_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/action",
			.cbs = {
				.modify = lib_prefix_list_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/any",
			.cbs = {
				.create = lib_prefix_list_entry_any_create,
				.destroy = lib_prefix_list_entry_any_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
