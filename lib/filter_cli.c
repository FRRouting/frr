// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR filter CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include "zebra.h"
#include "northbound.h"
#include "prefix.h"

#include "lib/command.h"
#include "lib/filter.h"
#include "lib/northbound_cli.h"
#include "lib/plist.h"
#include "lib/plist_int.h"
#include "lib/printfrr.h"

#include "lib/filter_cli_clippy.c"

#define ACCESS_LIST_STR "Access list entry\n"
#define ACCESS_LIST_ZEBRA_STR "Access list name\n"
#define ACCESS_LIST_SEQ_STR                                                    \
	"Sequence number of an entry\n"                                        \
	"Sequence number\n"
#define ACCESS_LIST_ACTION_STR                                                 \
	"Specify packets to reject\n"                                          \
	"Specify packets to forward\n"
#define ACCESS_LIST_REMARK_STR "Access list entry comment\n"
#define ACCESS_LIST_REMARK_LINE_STR "Comment up to 100 characters\n"

#define PREFIX_LIST_NAME_STR "Prefix list entry name\n"

/*
 * Helper function to generate a sequence number for legacy commands.
 */
static int acl_get_seq_cb(const struct lyd_node *dnode, void *arg)
{
	int64_t *seq = arg;
	int64_t cur_seq = yang_dnode_get_uint32(dnode, "sequence");

	if (cur_seq > *seq)
		*seq = cur_seq;

	return YANG_ITER_CONTINUE;
}

/**
 * Helper function that iterates over the XPath `xpath` on the candidate
 * configuration in `vty->candidate_config`.
 *
 * \param[in] vty shell context with the candidate configuration.
 * \param[in] xpath the XPath to look for the sequence leaf.
 * \returns next unused sequence number, -1 if out of range when adding.
 */
static int64_t acl_get_seq(struct vty *vty, const char *xpath, bool is_remove)
{
	int64_t seq = 0;

	yang_dnode_iterate(acl_get_seq_cb, &seq, vty->candidate_config->dnode,
			   "%s/entry", xpath);

	seq += 5;
	if (!is_remove && seq > UINT32_MAX) {
		vty_out(vty, "%% Malformed sequence value\n");
		return -1;
	}
	return seq;
}

/**
 * Remove main data structure filter list if there are no more entries or
 * remark. This fixes compatibility with old CLI and tests.
 */
static int filter_remove_check_empty(struct vty *vty, const char *ftype,
				     const char *iptype, const char *name,
				     uint32_t del_seq, bool del_remark)
{
	const struct lyd_node *remark_dnode = NULL;
	const struct lyd_node *entry_dnode = NULL;
	char xpath[XPATH_MAXLEN];
	uint32_t count;

	/* Count existing entries */
	count = yang_dnode_count(vty->candidate_config->dnode,
				 "/frr-filter:lib/%s-list[type='%s'][name='%s']/entry",
				 ftype, iptype, name);

	/* Check entry-to-delete actually exists */
	if (del_seq) {
		snprintf(xpath, sizeof(xpath),
			 "/frr-filter:lib/%s-list[type='%s'][name='%s']/entry[sequence='%u']",
			 ftype, iptype, name, del_seq);
		entry_dnode = yang_dnode_get(vty->candidate_config->dnode,
					     xpath);

		/* If exists, delete and don't count it, we need only remaining entries */
		if (entry_dnode) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
			count--;
		}
	}

	/* Delete the remark, or check whether it exists if we're keeping it */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/%s-list[type='%s'][name='%s']/remark", ftype,
		 iptype, name);
	if (del_remark)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		remark_dnode = yang_dnode_get(vty->candidate_config->dnode,
					      xpath);

	/* If there are no entries left and no remark, delete the whole list */
	if (count == 0 && !remark_dnode) {
		snprintf(xpath, sizeof(xpath),
			 "/frr-filter:lib/%s-list[type='%s'][name='%s']", ftype,
			 iptype, name);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Cisco (legacy) access lists.
 */
DEFPY_YANG(
	access_list_std, access_list_std_cmd,
	"access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask>",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;
	if (host_str && mask_str == NULL) {
		ada.ada_xpath[0] = "./host";
		ada.ada_value[0] = host_str;
	} else if (host_str && mask_str) {
		ada.ada_xpath[0] = "./network/address";
		ada.ada_value[0] = host_str;
		ada.ada_xpath[1] = "./network/mask";
		ada.ada_value[1] = mask_str;
	} else {
		ada.ada_xpath[0] = "./source-any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		return CMD_SUCCESS;

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (host_str != NULL && mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./host", NB_OP_MODIFY, host_str);
	} else if (host_str != NULL && mask_str != NULL) {
		nb_cli_enqueue_change(vty, "./network/address", NB_OP_MODIFY,
				      host_str);
		nb_cli_enqueue_change(vty, "./network/mask", NB_OP_MODIFY,
				      mask_str);
	} else {
		nb_cli_enqueue_change(vty, "./source-any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_access_list_std, no_access_list_std_cmd,
	"no access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL)
		return filter_remove_check_empty(vty, "access", "ipv4", name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;
	if (host_str && mask_str == NULL) {
		ada.ada_xpath[0] = "./host";
		ada.ada_value[0] = host_str;
	} else if (host_str && mask_str) {
		ada.ada_xpath[0] = "./network/address";
		ada.ada_value[0] = host_str;
		ada.ada_xpath[1] = "./network/mask";
		ada.ada_value[1] = mask_str;
	} else {
		ada.ada_xpath[0] = "./source-any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		sseq = ada.ada_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "access", "ipv4", name, sseq,
					 false);
}

DEFPY_YANG(
	access_list_ext, access_list_ext_cmd,
	"access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv4 address\n"
	"Source address to match\n"
	"Source address mask to apply\n"
	"Single source host\n"
	"Source address to match\n"
	"Any source host\n"
	"Destination address to match\n"
	"Destination address mask to apply\n"
	"Single destination host\n"
	"Destination address to match\n"
	"Any destination host\n")
{
	int idx = 0;
	int64_t sseq;
	struct acl_dup_args ada = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;
	if (src_str && src_mask_str == NULL) {
		ada.ada_xpath[idx] = "./host";
		ada.ada_value[idx] = src_str;
		idx++;
	} else if (src_str && src_mask_str) {
		ada.ada_xpath[idx] = "./network/address";
		ada.ada_value[idx] = src_str;
		idx++;
		ada.ada_xpath[idx] = "./network/mask";
		ada.ada_value[idx] = src_mask_str;
		idx++;
	} else {
		ada.ada_xpath[idx] = "./source-any";
		ada.ada_value[idx] = "";
		idx++;
	}

	if (dst_str && dst_mask_str == NULL) {
		ada.ada_xpath[idx] = "./destination-host";
		ada.ada_value[idx] = dst_str;
		idx++;
	} else if (dst_str && dst_mask_str) {
		ada.ada_xpath[idx] = "./destination-network/address";
		ada.ada_value[idx] = dst_str;
		idx++;
		ada.ada_xpath[idx] = "./destination-network/mask";
		ada.ada_value[idx] = dst_mask_str;
		idx++;
	} else {
		ada.ada_xpath[idx] = "./destination-any";
		ada.ada_value[idx] = "";
		idx++;
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		return CMD_SUCCESS;

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (src_str != NULL && src_mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./host", NB_OP_MODIFY, src_str);
	} else if (src_str != NULL && src_mask_str != NULL) {
		nb_cli_enqueue_change(vty, "./network/address", NB_OP_MODIFY,
				      src_str);
		nb_cli_enqueue_change(vty, "./network/mask", NB_OP_MODIFY,
				      src_mask_str);
	} else {
		nb_cli_enqueue_change(vty, "./source-any", NB_OP_CREATE, NULL);
	}

	if (dst_str != NULL && dst_mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./destination-host", NB_OP_MODIFY,
				      dst_str);
	} else if (dst_str != NULL && dst_mask_str != NULL) {
		nb_cli_enqueue_change(vty, "./destination-network/address",
				      NB_OP_MODIFY, dst_str);
		nb_cli_enqueue_change(vty, "./destination-network/mask",
				      NB_OP_MODIFY, dst_mask_str);
	} else {
		nb_cli_enqueue_change(vty, "./destination-any", NB_OP_CREATE,
				      NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_access_list_ext, no_access_list_ext_cmd,
	"no access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any Internet Protocol\n"
	"Source address to match\n"
	"Source address mask to apply\n"
	"Single source host\n"
	"Source address to match\n"
	"Any source host\n"
	"Destination address to match\n"
	"Destination address mask to apply\n"
	"Single destination host\n"
	"Destination address to match\n"
	"Any destination host\n")
{
	int idx = 0;
	int64_t sseq;
	struct acl_dup_args ada = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL)
		return filter_remove_check_empty(vty, "access", "ipv4", name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;
	if (src_str && src_mask_str == NULL) {
		ada.ada_xpath[idx] = "./host";
		ada.ada_value[idx] = src_str;
		idx++;
	} else if (src_str && src_mask_str) {
		ada.ada_xpath[idx] = "./network/address";
		ada.ada_value[idx] = src_str;
		idx++;
		ada.ada_xpath[idx] = "./network/mask";
		ada.ada_value[idx] = src_mask_str;
		idx++;
	} else {
		ada.ada_xpath[idx] = "./source-any";
		ada.ada_value[idx] = "";
		idx++;
	}

	if (dst_str && dst_mask_str == NULL) {
		ada.ada_xpath[idx] = "./destination-host";
		ada.ada_value[idx] = dst_str;
		idx++;
	} else if (dst_str && dst_mask_str) {
		ada.ada_xpath[idx] = "./destination-network/address";
		ada.ada_value[idx] = dst_str;
		idx++;
		ada.ada_xpath[idx] = "./destination-network/mask";
		ada.ada_value[idx] = dst_mask_str;
		idx++;
	} else {
		ada.ada_xpath[idx] = "./destination-any";
		ada.ada_value[idx] = "";
		idx++;
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		sseq = ada.ada_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "access", "ipv4", name, sseq,
					 false);
}

/*
 * Zebra access lists.
 */
DEFPY_YANG(
	access_list, access_list_cmd,
	"access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;

	if (prefix_str) {
		ada.ada_xpath[0] = "./ipv4-prefix";
		ada.ada_value[0] = prefix_str;
		if (exact) {
			ada.ada_xpath[1] = "./ipv4-exact-match";
			ada.ada_value[1] = "true";
		}
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		return CMD_SUCCESS;

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv4-prefix", NB_OP_MODIFY,
				      prefix_str);
		nb_cli_enqueue_change(vty, "./ipv4-exact-match", NB_OP_MODIFY,
				      exact ? "true" : "false");
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_access_list, no_access_list_cmd,
	"no access-list ACCESSLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL)
		return filter_remove_check_empty(vty, "access", "ipv4", name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	ada.ada_type = "ipv4";
	ada.ada_name = name;
	ada.ada_action = action;

	if (prefix_str) {
		ada.ada_xpath[0] = "./ipv4-prefix";
		ada.ada_value[0] = prefix_str;
		if (exact) {
			ada.ada_xpath[1] = "./ipv4-exact-match";
			ada.ada_value[1] = "true";
		}
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		sseq = ada.ada_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "access", "ipv4", name, sseq,
					 false);
}

DEFPY_YANG(
	no_access_list_all, no_access_list_all_cmd,
	"no access-list ACCESSLIST4_NAME$name",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	access_list_remark, access_list_remark_cmd,
	"access-list ACCESSLIST4_NAME$name remark LINE...",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, "%s", xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY_YANG(
	no_access_list_remark, no_access_list_remark_cmd,
	"no access-list ACCESSLIST4_NAME$name remark",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	return filter_remove_check_empty(vty, "access", "ipv4", name, 0, true);
}

ALIAS(
	no_access_list_remark, no_access_list_remark_line_cmd,
	"no access-list ACCESSLIST4_NAME$name remark LINE...",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY_YANG(
	ipv6_access_list, ipv6_access_list_cmd,
	"ipv6 access-list ACCESSLIST6_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv6 prefix\n"
	"Exact match of the prefixes\n"
	"Match any IPv6\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	ada.ada_type = "ipv6";
	ada.ada_name = name;
	ada.ada_action = action;

	if (prefix_str) {
		ada.ada_xpath[0] = "./ipv6-prefix";
		ada.ada_value[0] = prefix_str;
		if (exact) {
			ada.ada_xpath[1] = "./ipv6-exact-match";
			ada.ada_value[1] = "true";
		}
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		return CMD_SUCCESS;

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv6-prefix", NB_OP_MODIFY,
				      prefix_str);
		nb_cli_enqueue_change(vty, "./ipv6-exact-match", NB_OP_MODIFY,
				      exact ? "true" : "false");
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_ipv6_access_list, no_ipv6_access_list_cmd,
	"no ipv6 access-list ACCESSLIST6_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv6 prefix\n"
	"Exact match of the prefixes\n"
	"Match any IPv6\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL)
		return filter_remove_check_empty(vty, "access", "ipv6", name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	ada.ada_type = "ipv6";
	ada.ada_name = name;
	ada.ada_action = action;

	if (prefix_str) {
		ada.ada_xpath[0] = "./ipv6-prefix";
		ada.ada_value[0] = prefix_str;
		if (exact) {
			ada.ada_xpath[1] = "./ipv6-exact-match";
			ada.ada_value[1] = "true";
		}
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		sseq = ada.ada_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "access", "ipv6", name, sseq,
					 false);
}

DEFPY_YANG(
	no_ipv6_access_list_all, no_ipv6_access_list_all_cmd,
	"no ipv6 access-list ACCESSLIST6_NAME$name",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	ipv6_access_list_remark, ipv6_access_list_remark_cmd,
	"ipv6 access-list ACCESSLIST6_NAME$name remark LINE...",
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, "%s", xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY_YANG(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_cmd,
	"no ipv6 access-list ACCESSLIST6_NAME$name remark",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	return filter_remove_check_empty(vty, "access", "ipv6", name, 0, true);
}

ALIAS(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_line_cmd,
	"no ipv6 access-list ACCESSLIST6_NAME$name remark LINE...",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY_YANG(
	mac_access_list, mac_access_list_cmd,
	"mac access-list ACCESSLIST_MAC_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X:X:X:X:X$mac|any>",
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Match any MAC address\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	ada.ada_type = "mac";
	ada.ada_name = name;
	ada.ada_action = action;

	if (mac_str) {
		ada.ada_xpath[0] = "./mac";
		ada.ada_value[0] = mac_str;
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		return CMD_SUCCESS;

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (mac_str != NULL) {
		nb_cli_enqueue_change(vty, "./mac", NB_OP_MODIFY, mac_str);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_mac_access_list, no_mac_access_list_cmd,
	"no mac access-list ACCESSLIST_MAC_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X:X:X:X:X$mac|any>",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Match any MAC address\n")
{
	int64_t sseq;
	struct acl_dup_args ada = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL)
		return filter_remove_check_empty(vty, "access", "mac", name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	ada.ada_type = "mac";
	ada.ada_name = name;
	ada.ada_action = action;

	if (mac_str) {
		ada.ada_xpath[0] = "./mac";
		ada.ada_value[0] = mac_str;
	} else {
		ada.ada_xpath[0] = "./any";
		ada.ada_value[0] = "";
	}

	if (acl_is_dup(vty->candidate_config->dnode, &ada))
		sseq = ada.ada_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "access", "mac", name, sseq,
					 false);
}

DEFPY_YANG(
	no_mac_access_list_all, no_mac_access_list_all_cmd,
	"no mac access-list ACCESSLIST_MAC_NAME$name",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	mac_access_list_remark, mac_access_list_remark_cmd,
	"mac access-list ACCESSLIST_MAC_NAME$name remark LINE...",
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, "%s", xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY_YANG(
	no_mac_access_list_remark, no_mac_access_list_remark_cmd,
	"no mac access-list ACCESSLIST_MAC_NAME$name remark",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	return filter_remove_check_empty(vty, "access", "mac", name, 0, true);
}

ALIAS(
	no_mac_access_list_remark, no_mac_access_list_remark_line_cmd,
	"no mac access-list ACCESSLIST_MAC_NAME$name remark LINE...",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

int access_list_cmp(const struct lyd_node *dnode1,
		    const struct lyd_node *dnode2)
{
	uint32_t seq1 = yang_dnode_get_uint32(dnode1, "sequence");
	uint32_t seq2 = yang_dnode_get_uint32(dnode2, "sequence");

	return seq1 - seq2;
}

void access_list_show(struct vty *vty, const struct lyd_node *dnode,
		      bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");
	struct prefix p;
	bool is_any;
	bool is_exact = false;
	bool cisco_style = false;
	bool cisco_extended = false;
	struct in_addr addr, mask;
	char macstr[PREFIX2STR_BUFFER];

	is_any = yang_dnode_exists(dnode, "any");
	switch (type) {
	case YALT_IPV4:
		if (is_any)
			break;

		if (yang_dnode_exists(dnode, "host")
		    || yang_dnode_exists(dnode, "network/address")
		    || yang_dnode_exists(dnode, "source-any")) {
			cisco_style = true;
			if (yang_dnode_exists(dnode, "destination-host")
			    || yang_dnode_exists(
				    dnode, "./destination-network/address")
			    || yang_dnode_exists(dnode, "destination-any"))
				cisco_extended = true;
		} else {
			yang_dnode_get_prefix(&p, dnode, "ipv4-prefix");
			is_exact = yang_dnode_get_bool(dnode,
						       "./ipv4-exact-match");
		}
		break;
	case YALT_IPV6: /* ipv6 */
		vty_out(vty, "ipv6 ");
		if (is_any)
			break;

		yang_dnode_get_prefix(&p, dnode, "ipv6-prefix");
		is_exact = yang_dnode_get_bool(dnode, "ipv6-exact-match");
		break;
	case YALT_MAC: /* mac */
		vty_out(vty, "mac ");
		if (is_any)
			break;

		yang_dnode_get_prefix(&p, dnode, "mac");
		break;
	}

	vty_out(vty, "access-list %s seq %s %s",
		yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, "sequence"),
		yang_dnode_get_string(dnode, "action"));

	/* Handle Cisco style access lists. */
	if (cisco_style) {
		if (cisco_extended)
			vty_out(vty, " ip");

		if (yang_dnode_exists(dnode, "network")) {
			yang_dnode_get_ipv4(&addr, dnode, "network/address");
			yang_dnode_get_ipv4(&mask, dnode, "network/mask");
			vty_out(vty, " %pI4 %pI4", &addr, &mask);
		} else if (yang_dnode_exists(dnode, "host")) {
			if (cisco_extended)
				vty_out(vty, " host");

			vty_out(vty, " %s",
				yang_dnode_get_string(dnode, "host"));
		} else if (yang_dnode_exists(dnode, "source-any"))
			vty_out(vty, " any");

		/* Not extended, exit earlier. */
		if (!cisco_extended) {
			vty_out(vty, "\n");
			return;
		}

		/* Handle destination address. */
		if (yang_dnode_exists(dnode, "destination-network")) {
			yang_dnode_get_ipv4(&addr, dnode,
					    "./destination-network/address");
			yang_dnode_get_ipv4(&mask, dnode,
					    "./destination-network/mask");
			vty_out(vty, " %pI4 %pI4", &addr, &mask);
		} else if (yang_dnode_exists(dnode, "destination-host"))
			vty_out(vty, " host %s",
				yang_dnode_get_string(dnode,
						      "./destination-host"));
		else if (yang_dnode_exists(dnode, "destination-any"))
			vty_out(vty, " any");

		vty_out(vty, "\n");
		return;
	}

	/* Zebra style access list. */
	if (!is_any) {
		/* If type is MAC don't show '/mask'. */
		if (type == 2 /* mac */) {
			prefix_mac2str(&p.u.prefix_eth, macstr, sizeof(macstr));
			vty_out(vty, " %s", macstr);
		} else
			vty_out(vty, " %pFX", &p);
	} else
		vty_out(vty, " any");

	if (is_exact)
		vty_out(vty, " exact-match");

	vty_out(vty, "\n");
}

void access_list_remark_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");

	switch (type) {
	case YALT_IPV4:
		break;
	case YALT_IPV6:
		vty_out(vty, "ipv6 ");
		break;
	case YALT_MAC:
		vty_out(vty, "mac ");
		break;
	}

	vty_out(vty, "access-list %s remark %s\n",
		yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, NULL));
}

/*
 * Prefix lists.
 */

static int plist_remove(struct vty *vty, const char *iptype, const char *name,
			uint32_t seq, const char *action,
			union prefixconstptr prefix, int ge, int le)
{
	int64_t sseq;
	struct plist_dup_args pda = {};

	/* If the user provided sequence number, then just go for it. */
	if (seq != 0)
		return filter_remove_check_empty(vty, "prefix", iptype, name,
						 seq, false);

	/* Otherwise, to keep compatibility, we need to figure it out. */
	pda.pda_type = iptype;
	pda.pda_name = name;
	pda.pda_action = action;
	if (prefix.p) {
		prefix_copy(&pda.prefix, prefix);
		apply_mask(&pda.prefix);
		pda.ge = ge;
		pda.le = le;
	} else {
		pda.any = true;
	}

	if (plist_is_dup(vty->candidate_config->dnode, &pda))
		sseq = pda.pda_seq;
	else
		return CMD_WARNING_CONFIG_FAILED;

	return filter_remove_check_empty(vty, "prefix", iptype, name, sseq,
					 false);
}

DEFPY_YANG(
	ip_prefix_list, ip_prefix_list_cmd,
	"ip prefix-list PREFIXLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <any|A.B.C.D/M$prefix [{ge (0-32)$ge|le (0-32)$le}]>",
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n"
	"IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
	"Minimum prefix length to be matched\n"
	"Minimum prefix length\n"
	"Maximum prefix length to be matched\n"
	"Maximum prefix length\n")
{
	int64_t sseq;
	struct plist_dup_args pda = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	pda.pda_type = "ipv4";
	pda.pda_name = name;
	pda.pda_action = action;
	if (prefix_str) {
		prefix_copy(&pda.prefix, prefix);
		pda.ge = ge;
		pda.le = le;
	} else {
		pda.any = true;
	}

	/*
	 * Create the prefix-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv4'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv4-prefix", NB_OP_MODIFY,
				      prefix_str);

		if (ge_str) {
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-greater-or-equal",
				NB_OP_MODIFY, ge_str);
		} else {
			/*
			 * Remove old ge if not being modified
			 */
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-greater-or-equal",
				NB_OP_DESTROY, NULL);
		}

		if (le_str) {
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-lesser-or-equal",
				NB_OP_MODIFY, le_str);
		} else {
			/*
			 * Remove old le if not being modified
			 */
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-lesser-or-equal",
				NB_OP_DESTROY, NULL);
		}
		nb_cli_enqueue_change(vty, "./any", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_ip_prefix_list, no_ip_prefix_list_cmd,
	"no ip prefix-list PREFIXLIST4_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <any|A.B.C.D/M$prefix [{ge (0-32)|le (0-32)}]>",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n"
	"IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
	"Minimum prefix length to be matched\n"
	"Minimum prefix length\n"
	"Maximum prefix length to be matched\n"
	"Maximum prefix length\n")
{
	return plist_remove(vty, "ipv4", name, seq, action,
			    prefix_str ? prefix : NULL, ge, le);
}

DEFPY_YANG(
	no_ip_prefix_list_seq, no_ip_prefix_list_seq_cmd,
	"no ip prefix-list PREFIXLIST4_NAME$name seq (1-4294967295)$seq",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR)
{
	return plist_remove(vty, "ipv4", name, seq, NULL, NULL, 0, 0);
}

DEFPY_YANG(
	no_ip_prefix_list_all, no_ip_prefix_list_all_cmd,
	"no ip prefix-list PREFIXLIST4_NAME$name",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	ip_prefix_list_remark, ip_prefix_list_remark_cmd,
	"ip prefix-list PREFIXLIST4_NAME$name description LINE...",
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, "%s", xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY_YANG(
	no_ip_prefix_list_remark, no_ip_prefix_list_remark_cmd,
	"no ip prefix-list PREFIXLIST4_NAME$name description",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR)
{
	return filter_remove_check_empty(vty, "prefix", "ipv4", name, 0, true);
}

ALIAS(
	no_ip_prefix_list_remark, no_ip_prefix_list_remark_line_cmd,
	"no ip prefix-list PREFIXLIST4_NAME$name description LINE...",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY_YANG(
	ipv6_prefix_list, ipv6_prefix_list_cmd,
	"ipv6 prefix-list PREFIXLIST6_NAME$name [seq (1-4294967295)] <deny|permit>$action <any|X:X::X:X/M$prefix [{ge (0-128)$ge|le (0-128)$le}]>",
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any prefix match.  Same as \"::0/0 le 128\"\n"
	"IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
	"Maximum prefix length to be matched\n"
	"Maximum prefix length\n"
	"Minimum prefix length to be matched\n"
	"Minimum prefix length\n")
{
	int64_t sseq;
	struct plist_dup_args pda = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Backward compatibility: don't complain about duplicated values,
	 * just silently accept.
	 */
	pda.pda_type = "ipv6";
	pda.pda_name = name;
	pda.pda_action = action;
	if (prefix_str) {
		prefix_copy(&pda.prefix, prefix);
		pda.ge = ge;
		pda.le = le;
	} else {
		pda.any = true;
	}

	/*
	 * Create the prefix-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv6'][name='%s']", name);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath, false);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv6-prefix", NB_OP_MODIFY,
				      prefix_str);

		if (ge_str) {
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-greater-or-equal",
				NB_OP_MODIFY, ge_str);
		} else {
			/*
			 * Remove old ge if not being modified
			 */
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-greater-or-equal",
				NB_OP_DESTROY, NULL);
		}

		if (le_str) {
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-lesser-or-equal",
				NB_OP_MODIFY, le_str);
		} else {
			/*
			 * Remove old le if not being modified
			 */
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-lesser-or-equal",
				NB_OP_DESTROY, NULL);
		}
		nb_cli_enqueue_change(vty, "./any", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_ipv6_prefix_list, no_ipv6_prefix_list_cmd,
	"no ipv6 prefix-list PREFIXLIST6_NAME$name [seq (1-4294967295)$seq] <deny|permit>$action <any|X:X::X:X/M$prefix [{ge (0-128)$ge|le (0-128)$le}]>",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any prefix match.  Same as \"::0/0 le 128\"\n"
	"IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
	"Maximum prefix length to be matched\n"
	"Maximum prefix length\n"
	"Minimum prefix length to be matched\n"
	"Minimum prefix length\n")
{
	return plist_remove(vty, "ipv6", name, seq, action,
			    prefix_str ? prefix : NULL, ge, le);
}

DEFPY_YANG(
	no_ipv6_prefix_list_seq, no_ipv6_prefix_list_seq_cmd,
	"no ipv6 prefix-list PREFIXLIST6_NAME$name seq (1-4294967295)$seq",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR)
{
	return plist_remove(vty, "ipv6", name, seq, NULL, NULL, 0, 0);
}

DEFPY_YANG(
	no_ipv6_prefix_list_all, no_ipv6_prefix_list_all_cmd,
	"no ipv6 prefix-list PREFIXLIST6_NAME$name",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	ipv6_prefix_list_remark, ipv6_prefix_list_remark_cmd,
	"ipv6 prefix-list PREFIXLIST6_NAME$name description LINE...",
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, "%s", xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY_YANG(
	no_ipv6_prefix_list_remark, no_ipv6_prefix_list_remark_cmd,
	"no ipv6 prefix-list PREFIXLIST6_NAME$name description",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR)
{
	return filter_remove_check_empty(vty, "prefix", "ipv6", name, 0, true);
}

ALIAS(
	no_ipv6_prefix_list_remark, no_ipv6_prefix_list_remark_line_cmd,
	"no ipv6 prefix-list PREFIXLIST6_NAME$name description LINE...",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

int prefix_list_cmp(const struct lyd_node *dnode1,
		    const struct lyd_node *dnode2)
{
	uint32_t seq1 = yang_dnode_get_uint32(dnode1, "sequence");
	uint32_t seq2 = yang_dnode_get_uint32(dnode2, "sequence");

	return seq1 - seq2;
}

void prefix_list_show(struct vty *vty, const struct lyd_node *dnode,
		      bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");
	const char *ge_str = NULL, *le_str = NULL;
	bool is_any;
	struct prefix p;

	is_any = yang_dnode_exists(dnode, "any");
	switch (type) {
	case YPLT_IPV4:
		if (!is_any)
			yang_dnode_get_prefix(&p, dnode, "ipv4-prefix");
		if (yang_dnode_exists(dnode,
				      "./ipv4-prefix-length-greater-or-equal"))
			ge_str = yang_dnode_get_string(
				dnode, "./ipv4-prefix-length-greater-or-equal");
		if (yang_dnode_exists(dnode,
				      "./ipv4-prefix-length-lesser-or-equal"))
			le_str = yang_dnode_get_string(
				dnode, "./ipv4-prefix-length-lesser-or-equal");

		vty_out(vty, "ip ");
		break;
	case YPLT_IPV6:
		if (!is_any)
			yang_dnode_get_prefix(&p, dnode, "ipv6-prefix");
		if (yang_dnode_exists(dnode,
				      "./ipv6-prefix-length-greater-or-equal"))
			ge_str = yang_dnode_get_string(
				dnode, "./ipv6-prefix-length-greater-or-equal");
		if (yang_dnode_exists(dnode,
				      "./ipv6-prefix-length-lesser-or-equal"))
			le_str = yang_dnode_get_string(
				dnode, "./ipv6-prefix-length-lesser-or-equal");

		vty_out(vty, "ipv6 ");
		break;
	}

	vty_out(vty, "prefix-list %s seq %s %s",
		yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, "sequence"),
		yang_dnode_get_string(dnode, "action"));

	if (is_any) {
		vty_out(vty, " any\n");
		return;
	}

	vty_out(vty, " %pFX", &p);
	if (ge_str)
		vty_out(vty, " ge %s", ge_str);
	if (le_str)
		vty_out(vty, " le %s", le_str);

	vty_out(vty, "\n");
}

void prefix_list_remark_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");

	switch (type) {
	case YPLT_IPV4:
		vty_out(vty, "ip ");
		break;
	case YPLT_IPV6:
		vty_out(vty, "ipv6 ");
		break;
	}

	vty_out(vty, "prefix-list %s description %s\n",
		yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, NULL));
}

void filter_cli_init(void)
{
	/* access-list cisco-style (legacy). */
	install_element(CONFIG_NODE, &access_list_std_cmd);
	install_element(CONFIG_NODE, &no_access_list_std_cmd);
	install_element(CONFIG_NODE, &access_list_ext_cmd);
	install_element(CONFIG_NODE, &no_access_list_ext_cmd);

	/* access-list zebra-style. */
	install_element(CONFIG_NODE, &access_list_cmd);
	install_element(CONFIG_NODE, &no_access_list_cmd);
	install_element(CONFIG_NODE, &no_access_list_all_cmd);
	install_element(CONFIG_NODE, &access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_line_cmd);

	install_element(CONFIG_NODE, &ipv6_access_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_all_cmd);
	install_element(CONFIG_NODE, &ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_line_cmd);

	install_element(CONFIG_NODE, &mac_access_list_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_all_cmd);
	install_element(CONFIG_NODE, &mac_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_remark_line_cmd);

	/* prefix lists. */
	install_element(CONFIG_NODE, &ip_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_seq_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_all_cmd);
	install_element(CONFIG_NODE, &ip_prefix_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_remark_line_cmd);

	install_element(CONFIG_NODE, &ipv6_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_seq_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_all_cmd);
	install_element(CONFIG_NODE, &ipv6_prefix_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_remark_line_cmd);
}
