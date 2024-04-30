// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR filter northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include "zebra.h"

#include "lib/northbound.h"
#include "lib/prefix.h"
#include "lib/printfrr.h"

#include "lib/filter.h"
#include "lib/plist.h"
#include "lib/plist_int.h"
#include "lib/routemap.h"

static enum nb_error prefix_list_length_validate(struct nb_cb_modify_args *args)
{
	int type = yang_dnode_get_enum(args->dnode, "../../type");
	const char *xpath_le = NULL, *xpath_ge = NULL;
	struct prefix p;
	uint8_t le, ge;

	if (type == YPLT_IPV4) {
		yang_dnode_get_prefix(&p, args->dnode, "../ipv4-prefix");
		xpath_le = "../ipv4-prefix-length-lesser-or-equal";
		xpath_ge = "../ipv4-prefix-length-greater-or-equal";
	} else {
		yang_dnode_get_prefix(&p, args->dnode, "../ipv6-prefix");
		xpath_le = "../ipv6-prefix-length-lesser-or-equal";
		xpath_ge = "../ipv6-prefix-length-greater-or-equal";
	}

	/*
	 * Check rule:
	 * prefix length <= le.
	 */
	if (yang_dnode_exists(args->dnode, xpath_le)) {
		le = yang_dnode_get_uint8(args->dnode, "%s", xpath_le);
		if (p.prefixlen > le)
			goto log_and_fail;
	}

	/*
	 * Check rule:
	 * prefix length <= ge.
	 */
	if (yang_dnode_exists(args->dnode, xpath_ge)) {
		ge = yang_dnode_get_uint8(args->dnode, "%s", xpath_ge);
		if (p.prefixlen > ge)
			goto log_and_fail;
	}

	/*
	 * Check rule:
	 * ge <= le.
	 */
	if (yang_dnode_exists(args->dnode, xpath_le)
	    && yang_dnode_exists(args->dnode, xpath_ge)) {
		le = yang_dnode_get_uint8(args->dnode, "%s", xpath_le);
		ge = yang_dnode_get_uint8(args->dnode, "%s", xpath_ge);
		if (ge > le)
			goto log_and_fail;
	}

	return NB_OK;

log_and_fail:
	snprintfrr(
		args->errmsg, args->errmsg_len,
		"Invalid prefix range for %pFX: Make sure that mask length <= ge <= le",
		&p);
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

static int
prefix_list_nb_validate_v4_af_type(const struct lyd_node *plist_dnode,
				   char *errmsg, size_t errmsg_len)
{
	int af_type;

	af_type = yang_dnode_get_enum(plist_dnode, "type");
	if (af_type != YPLT_IPV4) {
		snprintf(errmsg, errmsg_len,
			 "prefix-list type %u is mismatched.", af_type);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int
prefix_list_nb_validate_v6_af_type(const struct lyd_node *plist_dnode,
				   char *errmsg, size_t errmsg_len)
{
	int af_type;

	af_type = yang_dnode_get_enum(plist_dnode, "type");
	if (af_type != YPLT_IPV6) {
		snprintf(errmsg, errmsg_len,
			 "prefix-list type %u is mismatched.", af_type);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_length_greater_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->ge = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_length_lesser_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->le = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_length_greater_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->ge = 0;

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_length_lesser_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	ple->le = 0;

	return NB_OK;
}

/**
 * Unsets the cisco style rule for addresses so it becomes disabled (the
 * equivalent of setting: `0.0.0.0/32`).
 *
 * \param addr address part.
 * \param mask mask part.
 */
static void cisco_unset_addr_mask(struct in_addr *addr, struct in_addr *mask)
{
	addr->s_addr = INADDR_ANY;
	mask->s_addr = CISCO_BIN_HOST_WILDCARD_MASK;
}

static int _acl_is_dup(const struct lyd_node *dnode, void *arg)
{
	struct acl_dup_args *ada = arg;
	int idx;

	/* This entry is the caller, so skip it. */
	if (ada->ada_entry_dnode
	    && ada->ada_entry_dnode == dnode)
		return YANG_ITER_CONTINUE;

	if (strcmp(yang_dnode_get_string(dnode, "action"), ada->ada_action))
		return YANG_ITER_CONTINUE;

	/* Check if all values match. */
	for (idx = 0; idx < ADA_MAX_VALUES; idx++) {
		/* No more values. */
		if (ada->ada_xpath[idx] == NULL)
			break;

		/* Not same type, just skip it. */
		if (!yang_dnode_exists(dnode, ada->ada_xpath[idx]))
			return YANG_ITER_CONTINUE;

		/* Check if different value. */
		if (strcmp(yang_dnode_get_string(dnode, "%s",
						 ada->ada_xpath[idx]),
			   ada->ada_value[idx]))
			return YANG_ITER_CONTINUE;
	}

	ada->ada_found = true;
	ada->ada_seq = yang_dnode_get_uint32(dnode, "sequence");

	return YANG_ITER_STOP;
}

bool acl_is_dup(const struct lyd_node *dnode, struct acl_dup_args *ada)
{
	ada->ada_found = false;

	yang_dnode_iterate(
		_acl_is_dup, ada, dnode,
		"/frr-filter:lib/access-list[type='%s'][name='%s']/entry",
		ada->ada_type, ada->ada_name);

	return ada->ada_found;
}

static bool acl_cisco_is_dup(const struct lyd_node *dnode)
{
	const struct lyd_node *entry_dnode =
		yang_dnode_get_parent(dnode, "entry");
	struct acl_dup_args ada = {};
	int idx = 0, arg_idx = 0;
	static const char *cisco_entries[] = {
		"./host",
		"./network/address",
		"./network/mask",
		"./source-any",
		"./destination-host",
		"./destination-network/address",
		"./destination-network/mask",
		"./destination-any",
		NULL
	};

	/* Initialize. */
	ada.ada_type = "ipv4";
	ada.ada_name = yang_dnode_get_string(entry_dnode, "../name");
	ada.ada_action = yang_dnode_get_string(entry_dnode, "action");
	ada.ada_entry_dnode = entry_dnode;

	/* Load all values/XPaths. */
	while (cisco_entries[idx] != NULL) {
		if (!yang_dnode_exists(entry_dnode, cisco_entries[idx])) {
			idx++;
			continue;
		}

		ada.ada_xpath[arg_idx] = cisco_entries[idx];
		ada.ada_value[arg_idx] = yang_dnode_get_string(
			entry_dnode, "%s", cisco_entries[idx]);
		arg_idx++;
		idx++;
	}

	return acl_is_dup(entry_dnode, &ada);
}

static bool acl_zebra_is_dup(const struct lyd_node *dnode,
			     enum yang_access_list_type type)
{
	const struct lyd_node *entry_dnode =
		yang_dnode_get_parent(dnode, "entry");
	struct acl_dup_args ada = {};
	int idx = 0, arg_idx = 0;
	static const char *zebra_entries[] = {
		"./ipv4-prefix",
		"./ipv4-exact-match",
		"./ipv6-prefix",
		"./ipv6-exact-match",
		"./mac",
		"./any",
		NULL
	};

	/* Initialize. */
	switch (type) {
	case YALT_IPV4:
		ada.ada_type = "ipv4";
		break;
	case YALT_IPV6:
		ada.ada_type = "ipv6";
		break;
	case YALT_MAC:
		ada.ada_type = "mac";
		break;
	}
	ada.ada_name = yang_dnode_get_string(entry_dnode, "../name");
	ada.ada_action = yang_dnode_get_string(entry_dnode, "action");
	ada.ada_entry_dnode = entry_dnode;

	/* Load all values/XPaths. */
	while (zebra_entries[idx] != NULL) {
		if (!yang_dnode_exists(entry_dnode, zebra_entries[idx])) {
			idx++;
			continue;
		}

		ada.ada_xpath[arg_idx] = zebra_entries[idx];
		ada.ada_value[arg_idx] = yang_dnode_get_string(
			entry_dnode, "%s", zebra_entries[idx]);
		arg_idx++;
		idx++;
	}

	return acl_is_dup(entry_dnode, &ada);
}

static void plist_dnode_to_prefix(const struct lyd_node *dnode, bool *any,
				  struct prefix *p, int *ge, int *le)
{
	*any = false;
	*ge = 0;
	*le = 0;

	if (yang_dnode_exists(dnode, "any")) {
		*any = true;
		return;
	}

	switch (yang_dnode_get_enum(dnode, "../type")) {
	case YPLT_IPV4:
		yang_dnode_get_prefix(p, dnode, "ipv4-prefix");
		if (yang_dnode_exists(dnode,
				      "./ipv4-prefix-length-greater-or-equal"))
			*ge = yang_dnode_get_uint8(
				dnode, "./ipv4-prefix-length-greater-or-equal");
		if (yang_dnode_exists(dnode,
				      "./ipv4-prefix-length-lesser-or-equal"))
			*le = yang_dnode_get_uint8(
				dnode, "./ipv4-prefix-length-lesser-or-equal");
		break;
	case YPLT_IPV6:
		yang_dnode_get_prefix(p, dnode, "ipv6-prefix");
		if (yang_dnode_exists(dnode,
				      "./ipv6-prefix-length-greater-or-equal"))
			*ge = yang_dnode_get_uint8(
				dnode, "./ipv6-prefix-length-greater-or-equal");
		if (yang_dnode_exists(dnode,
				      "./ipv6-prefix-length-lesser-or-equal"))
			*le = yang_dnode_get_uint8(
				dnode, "./ipv6-prefix-length-lesser-or-equal");
		break;
	}
}

static int _plist_is_dup(const struct lyd_node *dnode, void *arg)
{
	struct plist_dup_args *pda = arg;
	struct prefix p = {};
	int ge, le;
	bool any;

	/* This entry is the caller, so skip it. */
	if (pda->pda_entry_dnode
	    && pda->pda_entry_dnode == dnode)
		return YANG_ITER_CONTINUE;

	if (strcmp(yang_dnode_get_string(dnode, "action"), pda->pda_action))
		return YANG_ITER_CONTINUE;

	plist_dnode_to_prefix(dnode, &any, &p, &ge, &le);

	if (pda->any) {
		if (!any)
			return YANG_ITER_CONTINUE;
	} else {
		if (!prefix_same(&pda->prefix, &p) || pda->ge != ge
		    || pda->le != le)
			return YANG_ITER_CONTINUE;
	}

	pda->pda_found = true;
	pda->pda_seq = yang_dnode_get_uint32(dnode, "sequence");

	return YANG_ITER_STOP;
}

bool plist_is_dup(const struct lyd_node *dnode, struct plist_dup_args *pda)
{
	pda->pda_found = false;

	yang_dnode_iterate(
		_plist_is_dup, pda, dnode,
		"/frr-filter:lib/prefix-list[type='%s'][name='%s']/entry",
		pda->pda_type, pda->pda_name);

	return pda->pda_found;
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

	type = yang_dnode_get_enum(args->dnode, "type");
	acl_name = yang_dnode_get_string(args->dnode, "name");

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
	struct access_list *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(args->dnode);
	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/remark
 */
static int lib_access_list_remark_modify(struct nb_cb_modify_args *args)
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
lib_access_list_remark_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-filter:lib/access-list/entry
 */
static int lib_access_list_entry_create(struct nb_cb_create_args *args)
{
	struct access_list *acl;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = filter_new();
	f->seq = yang_dnode_get_uint32(args->dnode, "sequence");

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

static void
lib_access_list_entry_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct filter *f;

	f = nb_running_get_entry(args->dnode, NULL, true);
	access_list_filter_update(f->acl);
}

/*
 * XPath: /frr-filter:lib/access-list/entry/action
 */
static int
lib_access_list_entry_action_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-filter:lib/access-list/entry/ipv4-prefix
 */
static int
lib_access_list_entry_ipv4_prefix_modify(struct nb_cb_modify_args *args)
{
	struct filter_zebra *fz;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_zebra_is_dup(
			    args->dnode,
			    yang_dnode_get_enum(args->dnode, "../../type"))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 0;
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

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_zebra_is_dup(
			    args->dnode,
			    yang_dnode_get_enum(args->dnode, "../../type"))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

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
 * XPath: /frr-filter:lib/access-list/entry/host
 */
static int
lib_access_list_entry_host_modify(struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 1;
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr, args->dnode, NULL);
	fc->addr_mask.s_addr = CISCO_BIN_HOST_WILDCARD_MASK;

	return NB_OK;
}

static int
lib_access_list_entry_host_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	cisco_unset_addr_mask(&fc->addr, &fc->addr_mask);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/network
 */
static int lib_access_list_entry_network_create(struct nb_cb_create_args *args)
{
	/* Nothing to do here, everything is done in children callbacks */
	return NB_OK;
}

static int lib_access_list_entry_network_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	cisco_unset_addr_mask(&fc->addr, &fc->addr_mask);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/network/address
 */
static int
lib_access_list_entry_network_address_modify(struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 1;
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr, args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/network/mask
 */
static int
lib_access_list_entry_network_mask_modify(struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 1;
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr_mask, args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/source-any
 */
static int
lib_access_list_entry_source_any_create(struct nb_cb_create_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 1;
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = CISCO_BIN_ANY_WILDCARD_MASK;

	return NB_OK;
}

static int
lib_access_list_entry_source_any_destroy(struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	cisco_unset_addr_mask(&fc->addr, &fc->addr_mask);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/destination-host
 */
static int lib_access_list_entry_destination_host_modify(
	struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 1;
	yang_dnode_get_ipv4(&fc->mask, args->dnode, NULL);
	fc->mask_mask.s_addr = CISCO_BIN_HOST_WILDCARD_MASK;

	return NB_OK;
}

static int lib_access_list_entry_destination_host_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 0;
	cisco_unset_addr_mask(&fc->mask, &fc->mask_mask);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/destination-network
 */
static int
lib_access_list_entry_destination_network_create(struct nb_cb_create_args *args)
{
	/* Nothing to do here, everything is done in children callbacks */
	return NB_OK;
}

static int lib_access_list_entry_destination_network_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 0;
	cisco_unset_addr_mask(&fc->mask, &fc->mask_mask);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/destination-network/address
 */
static int lib_access_list_entry_destination_network_address_modify(
	struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 1;
	yang_dnode_get_ipv4(&fc->mask, args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/destination-network/mask
 */
static int lib_access_list_entry_destination_network_mask_modify(
	struct nb_cb_modify_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 1;
	yang_dnode_get_ipv4(&fc->mask_mask, args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/destination-any
 */
static int lib_access_list_entry_destination_any_create(
	struct nb_cb_create_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_cisco_is_dup(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 1;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = CISCO_BIN_ANY_WILDCARD_MASK;

	return NB_OK;
}

static int lib_access_list_entry_destination_any_destroy(
	struct nb_cb_destroy_args *args)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	fc = &f->u.cfilter;
	fc->extended = 0;
	cisco_unset_addr_mask(&fc->mask, &fc->mask_mask);

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

	/* Don't allow duplicated values. */
	if (args->event == NB_EV_VALIDATE) {
		if (acl_zebra_is_dup(
			    args->dnode,
			    yang_dnode_get_enum(args->dnode, "../../type"))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "duplicated access list value: %s",
				   yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_get_entry(args->dnode, NULL, true);
	f->cisco = 0;
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
	fz->prefix.family = AF_UNSPEC;

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

	type = yang_dnode_get_enum(args->dnode, "type");
	name = yang_dnode_get_string(args->dnode, "name");
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
	ple->seq = yang_dnode_get_uint32(args->dnode, "sequence");
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

static void
lib_prefix_list_entry_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct prefix_list_entry *ple;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/*
	 * Finish prefix entry update procedure. The procedure is started in
	 * children callbacks. `prefix_list_entry_update_start` can be called
	 * multiple times if multiple children are modified, but it is actually
	 * executed only once because of the protection by `ple->installed`.
	 */
	prefix_list_entry_update_finish(ple);
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

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_modify(struct nb_cb_modify_args *args)
{
	struct prefix_list_entry *ple;
	struct prefix p;

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

	return NB_OK;
}

static int lib_prefix_list_entry_prefix_destroy(struct nb_cb_destroy_args *args)
{
	struct prefix_list_entry *ple;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ple = nb_running_get_entry(args->dnode, NULL, true);

	/* Start prefix entry update procedure. */
	prefix_list_entry_update_start(ple);

	memset(&ple->prefix, 0, sizeof(ple->prefix));

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix
 */
static int
lib_prefix_list_entry_ipv4_prefix_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v4_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_modify(args);
}

static int
lib_prefix_list_entry_ipv4_prefix_destroy(struct nb_cb_destroy_args *args)
{

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return lib_prefix_list_entry_prefix_destroy(args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix
 */
static int
lib_prefix_list_entry_ipv6_prefix_modify(struct nb_cb_modify_args *args)
{

	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v6_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_modify(args);
}

static int
lib_prefix_list_entry_ipv6_prefix_destroy(struct nb_cb_destroy_args *args)
{

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return lib_prefix_list_entry_prefix_destroy(args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE
	    && prefix_list_length_validate(args) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v4_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_greater_or_equal_modify(
		args);
}

static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v4_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_greater_or_equal_destroy(
		args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE
	    && prefix_list_length_validate(args) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v4_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_lesser_or_equal_modify(
		args);
}

static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v4_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_lesser_or_equal_destroy(
		args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE
	    && prefix_list_length_validate(args) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v6_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_greater_or_equal_modify(
		args);
}

static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v6_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_greater_or_equal_destroy(
		args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE
	    && prefix_list_length_validate(args) != NB_OK)
		return NB_ERR_VALIDATION;

	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v6_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_lesser_or_equal_modify(
		args);
}

static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *plist_dnode =
			yang_dnode_get_parent(args->dnode, "prefix-list");

		return prefix_list_nb_validate_v6_af_type(
			plist_dnode, args->errmsg, args->errmsg_len);
	}

	return lib_prefix_list_entry_prefix_length_lesser_or_equal_destroy(
		args);
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/any
 */
static int lib_prefix_list_entry_any_create(struct nb_cb_create_args *args)
{
	struct prefix_list_entry *ple;
	int type;

	/*
	 * If we have gotten to this point, it's legal
	 */
	if (args->event == NB_EV_VALIDATE)
		return NB_OK;

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

	ple->any = false;

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_filter_info = {
	.name = "frr-filter",
	.nodes = {
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
				.cli_show = access_list_remark_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry",
			.cbs = {
				.create = lib_access_list_entry_create,
				.destroy = lib_access_list_entry_destroy,
				.apply_finish = lib_access_list_entry_apply_finish,
				.cli_cmp = access_list_cmp,
				.cli_show = access_list_show,
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
			.xpath = "/frr-filter:lib/access-list/entry/host",
			.cbs = {
				.modify = lib_access_list_entry_host_modify,
				.destroy = lib_access_list_entry_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/network",
			.cbs = {
				.create = lib_access_list_entry_network_create,
				.destroy = lib_access_list_entry_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/network/address",
			.cbs = {
				.modify = lib_access_list_entry_network_address_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/network/mask",
			.cbs = {
				.modify = lib_access_list_entry_network_mask_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/source-any",
			.cbs = {
				.create = lib_access_list_entry_source_any_create,
				.destroy = lib_access_list_entry_source_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/destination-host",
			.cbs = {
				.modify = lib_access_list_entry_destination_host_modify,
				.destroy = lib_access_list_entry_destination_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/destination-network",
			.cbs = {
				.create = lib_access_list_entry_destination_network_create,
				.destroy = lib_access_list_entry_destination_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/destination-network/address",
			.cbs = {
				.modify = lib_access_list_entry_destination_network_address_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/destination-network/mask",
			.cbs = {
				.modify = lib_access_list_entry_destination_network_mask_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/destination-any",
			.cbs = {
				.create = lib_access_list_entry_destination_any_create,
				.destroy = lib_access_list_entry_destination_any_destroy,
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
				.apply_finish = lib_prefix_list_entry_apply_finish,
				.cli_cmp = prefix_list_cmp,
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

const struct frr_yang_module_info frr_filter_cli_info = {
	.name = "frr-filter",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-filter:lib/access-list/remark",
			.cbs.cli_show = access_list_remark_show,
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry",
			.cbs = {
				.cli_cmp = access_list_cmp,
				.cli_show = access_list_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/remark",
			.cbs.cli_show = prefix_list_remark_show,
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry",
			.cbs = {
				.cli_cmp = prefix_list_cmp,
				.cli_show = prefix_list_show,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
