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

#include "lib/northbound.h"
#include "lib/prefix.h"

#include "lib/filter.h"
#include "lib/plist.h"
#include "lib/plist_int.h"

/* Helper function. */
static in_addr_t
ipv4_network_addr(in_addr_t hostaddr, int masklen)
{
	struct in_addr mask;

	masklen2ip(masklen, &mask);
	return hostaddr & mask.s_addr;
}

static enum nb_error
prefix_list_length_validate(const struct lyd_node *dnode)
{
	int type = yang_dnode_get_enum(dnode, "../../type");
	const char *xpath_le = NULL, *xpath_ge = NULL;
	struct prefix p;
	uint8_t le, ge;

	if (type == YPLT_IPV4) {
		yang_dnode_get_prefix(&p, dnode, "../ipv4-prefix");
		xpath_le = "../ipv4-prefix-length-lesser-or-equal";
		xpath_ge = "../ipv4-prefix-length-greater-or-equal";
	} else {
		yang_dnode_get_prefix(&p, dnode, "../ipv6-prefix");
		xpath_le = "../ipv6-prefix-length-lesser-or-equal";
		xpath_ge = "../ipv6-prefix-length-greater-or-equal";
	}

	/*
	 * Check rule:
	 * prefix length <= le.
	 */
	if (yang_dnode_exists(dnode, xpath_le)) {
		le = yang_dnode_get_uint8(dnode, xpath_le);
		if (p.prefixlen > le)
			goto log_and_fail;

	}

	/*
	 * Check rule:
	 * prefix length < ge.
	 */
	if (yang_dnode_exists(dnode, xpath_ge)) {
		ge = yang_dnode_get_uint8(dnode, xpath_ge);
		if (p.prefixlen >= ge)
			goto log_and_fail;
	}

	/*
	 * Check rule:
	 * ge <= le.
	 */
	if (yang_dnode_exists(dnode, xpath_le) &&
	    yang_dnode_exists(dnode, xpath_ge)) {
		le = yang_dnode_get_uint8(dnode, xpath_le);
		ge = yang_dnode_get_uint8(dnode, xpath_ge);
		if (ge > le)
			goto log_and_fail;
	}

	return NB_OK;

  log_and_fail:
	zlog_info("prefix-list: invalid prefix range for %pFX: Make sure that mask length < ge <= le", &p);
	return NB_ERR_VALIDATION;
}

/**
 * Sets prefix list entry to blank value.
 *
 * \param[out] ple prefix list entry to modify.
 */
static void prefix_list_entry_set_empty(struct prefix_list_entry *ple)
{
	ple->any = false;
	memset(&ple->prefix, 0, sizeof(ple->prefix));
	ple->ge = 0;
	ple->le = 0;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy
 */
static int lib_access_list_legacy_create(struct nb_cb_create_args *args)
{
	struct access_list *acl;
	const char *acl_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl_name = yang_dnode_get_string(args->dnode, "./number");
	acl = access_list_get(AFI_IP, acl_name);
	nb_running_set_entry(args->dnode, acl);

	return NB_OK;
}

static int lib_access_list_legacy_destroy(struct nb_cb_destroy_args *args)
{
	struct access_master *am;
	struct access_list *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(args->dnode);
	am = acl->master;
	if (am->delete_hook)
		am->delete_hook(acl);

	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/remark
 */
static int lib_access_list_legacy_remark_modify(struct nb_cb_modify_args *args)
{
	struct access_list *acl;
	const char *remark;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(args->dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	remark = yang_dnode_get_string(args->dnode, NULL);
	acl->remark = XSTRDUP(MTYPE_TMP, remark);

	return NB_OK;
}

static int
lib_access_list_legacy_remark_destroy(struct nb_cb_destroy_args *args)
{
	struct access_list *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(args->dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry
 */
static int lib_access_list_legacy_entry_create(struct nb_cb_create_args *args)
{
	struct filter_cisco *fc;
	struct access_list *acl;
	struct filter *f;
	uint32_t aclno;

	/* TODO: validate `filter_lookup_cisco` returns NULL. */

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	aclno = yang_dnode_get_uint16(args->dnode, "../number");

	f = filter_new();
	f->cisco = 1;
	f->seq = yang_dnode_get_uint32(args->dnode, "./sequence");
	fc = &f->u.cfilter;
	if ((aclno >= 1 && aclno <= 99) || (aclno >= 1300 && aclno <= 1999))
		fc->extended = 0;
	else
		fc->extended = 1;

	acl = nb_running_get_entry(args->dnode, NULL, true);
	f->acl = acl;
	access_list_filter_add(acl, f);
	nb_running_set_entry(args->dnode, f);

	return NB_OK;
}

static int lib_access_list_legacy_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct access_list *acl;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(args->dnode);
	acl = f->acl;
	access_list_filter_delete(acl, f);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/action
 */
static int
lib_access_list_legacy_entry_action_modify(struct nb_cb_modify_args *args)
{
	const char *filter_type;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	filter_type = yang_dnode_get_string(args->dnode, NULL);
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
lib_access_list_legacy_entry_host_modify(struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr, args->dnode, NULL);
	fc->addr_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_host_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/network
 */
static int
lib_access_list_legacy_entry_network_modify(struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_prefix(&p, args->dnode, NULL);
	fc->addr.s_addr = ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
	masklen2ip(p.prefixlen, &fc->addr_mask);

	return NB_OK;
}

static int
lib_access_list_legacy_entry_network_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/any
 */
static int
lib_access_list_legacy_entry_any_create(struct nb_cb_create_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_any_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-host
 */
static int lib_access_list_legacy_entry_destination_host_modify(
	struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->mask, args->dnode, NULL);
	fc->mask_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_host_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-network
 */
static int lib_access_list_legacy_entry_destination_network_modify(
	struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	yang_dnode_get_prefix(&p, args->dnode, NULL);
	fc->mask.s_addr = ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
	masklen2ip(p.prefixlen, &fc->mask_mask);

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_network_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-any
 */
static int lib_access_list_legacy_entry_destination_any_create(
	struct nb_cb_create_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_any_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list
 */
static int lib_access_list_create(struct nb_cb_create_args *args)
{
	struct access_list *acl = NULL;
	const char *acl_name;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(args->dnode, "./type");
	acl_name = yang_dnode_get_string(args->dnode, "./name");

	switch (type) {
	case YALT_IPV4:
		acl = access_list_get(AFI_IP, acl_name);
		break;
	case YALT_IPV6:
		acl = access_list_get(AFI_IP6, acl_name);
		break;
	case YALT_MAC:
		acl = access_list_get(AFI_L2VPN, acl_name);
		break;
	}

	nb_running_set_entry(args->dnode, acl);

	return NB_OK;
}

static int lib_access_list_destroy(struct nb_cb_destroy_args *args)
{
	struct access_master *am;
	struct access_list *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(args->dnode);
	am = acl->master;
	if (am->delete_hook)
		am->delete_hook(acl);

	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry
 */
static int lib_access_list_entry_create(struct nb_cb_create_args *args)
{
	struct access_list *acl;
	struct filter *f;

	/* TODO: validate `filter_lookup_zebra` returns NULL. */

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = filter_new();
	f->seq = yang_dnode_get_uint32(args->dnode, "./sequence");

	acl = nb_running_get_entry(args->dnode, NULL, true);
	f->acl = acl;
	access_list_filter_add(acl, f);
	nb_running_set_entry(args->dnode, f);

	return NB_OK;
}

static int lib_access_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct access_list *acl;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(args->dnode);
	acl = f->acl;
	access_list_filter_delete(acl, f);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-prefix
 */
static int
lib_access_list_entry_ipv4_prefix_modify(struct nb_cb_modify_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	yang_dnode_get_prefix(&fz->prefix, args->dnode, NULL);

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_prefix_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	memset(&fz->prefix, 0, sizeof(fz->prefix));

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-exact-match
 */
static int
lib_access_list_entry_ipv4_exact_match_modify(struct nb_cb_modify_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->exact = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_exact_match_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->exact = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/any
 */
static int lib_access_list_entry_any_create(struct nb_cb_create_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	memset(&fz->prefix, 0, sizeof(fz->prefix));

	type = yang_dnode_get_enum(args->dnode, "../../type");
	switch (type) {
	case YALT_IPV4:
		fz->prefix.family = AF_INET;
		break;
	case YALT_IPV6:
		fz->prefix.family = AF_INET6;
		break;
	case YALT_MAC:
		fz->prefix.family = AF_ETHERNET;
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_any_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fz = &f->u.zfilter;
	fz->prefix.family = 0;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list
 */
static int lib_prefix_list_create(struct nb_cb_create_args *args)
{
	struct prefix_list *pl = NULL;
	const char *name;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(args->dnode, "./type");
	name = yang_dnode_get_string(args->dnode, "./name");
	switch (type) {
	case 0: /* ipv4 */
		pl = prefix_list_get(AFI_IP, 0, name);
		break;
	case 1: /* ipv6 */
		pl = prefix_list_get(AFI_IP6, 0, name);
		break;
	}

	nb_running_set_entry(args->dnode, pl);

	return NB_OK;
}

static int lib_prefix_list_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list *pl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_unset_entry(args->dnode);
	prefix_list_delete(pl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/remark
 */
static int lib_prefix_list_remark_modify(struct nb_cb_modify_args *args)
{
	struct prefix_list *pl;
	const char *remark;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_get_entry(args->dnode, NULL, true);
	if (pl->desc)
		XFREE(MTYPE_TMP, pl->desc);

	remark = yang_dnode_get_string(args->dnode, NULL);
	pl->desc = XSTRDUP(MTYPE_TMP, remark);

	return NB_OK;
}

static int lib_prefix_list_remark_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list *pl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_get_entry(args->dnode, NULL, true);
	if (pl->desc)
		XFREE(MTYPE_TMP, pl->desc);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry
 */
static int lib_prefix_list_entry_create(struct nb_cb_create_args *args)
{
	struct prefix_list_entry *ple;
	struct prefix_list *pl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pl = nb_running_get_entry(args->dnode, NULL, true);
	ple = prefix_list_entry_new();
	ple->pl = pl;
	ple->seq = yang_dnode_get_uint32(args->dnode, "./sequence");
	prefix_list_entry_set_empty(ple);
	nb_running_set_entry(args->dnode, ple);

	return NB_OK;
}

static int lib_prefix_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_unset_entry(args->dnode);
	if (ple->installed)
		prefix_list_entry_delete2(ple);
	else
		prefix_list_entry_free(ple);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/action
 */
static int lib_prefix_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;
	int action_type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	action_type = yang_dnode_get_enum(args->dnode, NULL);
	if (action_type == YPLA_PERMIT)
		ple->type = PREFIX_PERMIT;
	else
		ple->type = PREFIX_DENY;

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix
 */
static int
lib_prefix_list_entry_ipv4_prefix_modify(struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;
	struct prefix p;

	if (args->event == NB_EV_VALIDATE) {
		/*
		 * TODO: validate prefix_entry_dup_check() passes.
		 *
		 * This needs to be implemented using YANG lyd_node
		 * navigation, because the `priv` data structures are not
		 * available at `NB_EV_VALIDATE` phase. An easier
		 * alternative would be mark `ipvx-prefix` as unique
		 * (see RFC 7950, Section 7.8.3. The list "unique" Statement).
		 */
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	yang_dnode_get_prefix(&ple->prefix, args->dnode, NULL);

	/* Apply mask and correct original address if necessary. */
	prefix_copy(&p, &ple->prefix);
	apply_mask(&p);
	if (!prefix_same(&ple->prefix, &p)) {
		zlog_info("%s: bad network %pFX correcting it to %pFX",
			  __func__, &ple->prefix, &p);
		prefix_copy(&ple->prefix, &p);
	}


	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

static int
lib_prefix_list_entry_ipv4_prefix_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	memset(&ple->prefix, 0, sizeof(ple->prefix));

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event == NB_EV_VALIDATE &&
	    prefix_list_length_validate(args->dnode) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->ge = yang_dnode_get_uint8(args->dnode, NULL);

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->ge = 0;

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event == NB_EV_VALIDATE &&
	    prefix_list_length_validate(args->dnode) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->le = yang_dnode_get_uint8(args->dnode, NULL);

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->le = 0;

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/any
 */
static int lib_prefix_list_entry_any_create(struct nb_cb_create_args *args)
{
	struct prefix_list_entry *ple;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->any = true;

	/* Fill prefix struct from scratch. */
	memset(&ple->prefix, 0, sizeof(ple->prefix));

	type = yang_dnode_get_enum(args->dnode, "../../type");
	switch (type) {
	case YPLT_IPV4:
		ple->prefix.family = AF_INET;
		ple->ge = 0;
		ple->le = IPV4_MAX_BITLEN;
		break;
	case YPLT_IPV6:
		ple->prefix.family = AF_INET6;
		ple->ge = 0;
		ple->le = IPV6_MAX_BITLEN;
		break;
	}

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

	return NB_OK;
}

static int lib_prefix_list_entry_any_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	prefix_list_entry_set_empty(ple);

	/* Finish prefix entry update procedure. */
	prefix_list_entry_update_finish(ple);

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
				.cli_show = access_list_legacy_remark_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry",
			.cbs = {
				.create = lib_access_list_legacy_entry_create,
				.destroy = lib_access_list_legacy_entry_destroy,
				.cli_show = access_list_legacy_show,
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
				.modify = lib_access_list_legacy_remark_modify,
				.destroy = lib_access_list_legacy_remark_destroy,
				.cli_show = access_list_remark_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry",
			.cbs = {
				.create = lib_access_list_entry_create,
				.destroy = lib_access_list_entry_destroy,
				.cli_show = access_list_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/action",
			.cbs = {
				.modify = lib_access_list_legacy_entry_action_modify,
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
				.modify = lib_access_list_entry_ipv4_prefix_modify,
				.destroy = lib_access_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv6-exact-match",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_exact_match_modify,
				.destroy = lib_access_list_entry_ipv4_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/mac",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_prefix_modify,
				.destroy = lib_access_list_entry_ipv4_prefix_destroy,
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
			.xpath = "/frr-filter:lib/prefix-list/remark",
			.cbs = {
				.modify = lib_prefix_list_remark_modify,
				.destroy = lib_prefix_list_remark_destroy,
				.cli_show = prefix_list_remark_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry",
			.cbs = {
				.create = lib_prefix_list_entry_create,
				.destroy = lib_prefix_list_entry_destroy,
				.cli_show = prefix_list_show,
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
				.modify = lib_prefix_list_entry_ipv4_prefix_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy,
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
