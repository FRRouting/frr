/*
 * FRR filter CLI implementation.
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
#include "northbound.h"
#include "prefix.h"

#include "lib/command.h"
#include "lib/filter.h"
#include "lib/northbound_cli.h"
#include "lib/plist.h"
#include "lib/plist_int.h"
#include "lib/printfrr.h"

#ifndef VTYSH_EXTRACT_PL
#include "lib/filter_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

#define ACCESS_LIST_STR "Access list entry\n"
#define ACCESS_LIST_LEG_STR "IP standard access list\n"
#define ACCESS_LIST_LEG_EXT_STR "IP standard access list (expanded range)\n"
#define ACCESS_LIST_ELEG_STR "IP extended access list\n"
#define ACCESS_LIST_ELEG_EXT_STR "IP extended access list (expanded range)\n"
#define ACCESS_LIST_XLEG_STR                                                   \
	ACCESS_LIST_LEG_STR                                                    \
	ACCESS_LIST_LEG_EXT_STR                                                \
	ACCESS_LIST_ELEG_STR                                                   \
	ACCESS_LIST_ELEG_EXT_STR
#define ACCESS_LIST_ZEBRA_STR "Access list entry\n"
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
 * Helper function to locate filter data structures for Cisco-style ACLs.
 */
static int64_t acl_cisco_get_seq(struct access_list *acl, const char *action,
				 const char *src, const char *src_mask,
				 const char *dst, const char *dst_mask)
{
	struct filter_cisco *fc;
	struct filter f, *fn;

	memset(&f, 0, sizeof(f));
	memset(&fc, 0, sizeof(fc));
	f.cisco = 1;
	if (strcmp(action, "permit") == 0)
		f.type = FILTER_PERMIT;
	else
		f.type = FILTER_DENY;

	fc = &f.u.cfilter;
	inet_pton(AF_INET, src, &fc->addr);
	inet_pton(AF_INET, src_mask, &fc->addr_mask);
	fc->addr.s_addr &= ~fc->addr_mask.s_addr;
	if (dst != NULL) {
		fc->extended = 1;
		inet_pton(AF_INET, dst, &fc->mask);
		inet_pton(AF_INET, dst_mask, &fc->mask_mask);
		fc->mask.s_addr &= ~fc->mask_mask.s_addr;
	}

	fn = filter_lookup_cisco(acl, &f);
	if (fn == NULL)
		return -1;

	return fn->seq;
}

/*
 * Helper function to locate filter data structures for zebra-style ACLs.
 */
static int64_t acl_zebra_get_seq(struct access_list *acl, const char *action,
				 const struct prefix *p, bool exact)
{
	struct filter_zebra *fz;
	struct filter f, *fn;

	memset(&f, 0, sizeof(f));
	memset(&fz, 0, sizeof(fz));
	if (strcmp(action, "permit") == 0)
		f.type = FILTER_PERMIT;
	else
		f.type = FILTER_DENY;

	fz = &f.u.zfilter;
	fz->prefix = *p;
	fz->exact = exact;

	fn = filter_lookup_zebra(acl, &f);
	if (fn == NULL)
		return -1;

	return fn->seq;
}

/*
 * Helper function to concatenate address with mask in Cisco style.
 */
static void concat_addr_mask_v4(const char *addr, const char *mask, char *dst,
				size_t dstlen)
{
	struct in_addr ia;
	int plen;

	assert(inet_pton(AF_INET, mask, &ia) == 1);
	plen = ip_masklen(ia);
	snprintf(dst, dstlen, "%s/%d", addr, plen);
}

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
 * \returns next unused sequence number.
 */
static long acl_get_seq(struct vty *vty, const char *xpath)
{
	int64_t seq = 0;

	yang_dnode_iterate(acl_get_seq_cb, &seq, vty->candidate_config->dnode,
			   "%s/entry", xpath);

	return seq + 5;
}

/*
 * Cisco (legacy) access lists.
 */
DEFPY(
	access_list_std, access_list_std_cmd,
	"access-list <(1-99)|(1300-1999)>$number [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_LEG_STR
	ACCESS_LIST_LEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n"
	"Any source host\n")
{
	int64_t sseq;
	char ipmask[64];
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (host_str != NULL && mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./host", NB_OP_MODIFY, host_str);
	} else if (host_str != NULL && mask_str != NULL) {
		concat_addr_mask_v4(host_str, mask_str, ipmask, sizeof(ipmask));
		nb_cli_enqueue_change(vty, "./network", NB_OP_MODIFY, ipmask);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_access_list_std, no_access_list_std_cmd,
	"no access-list <(1-99)|(1300-1999)>$number [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_LEG_STR
	ACCESS_LIST_LEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n"
	"Any source host\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list-legacy[number='%s']/entry[sequence='%s']",
			number_str, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (host_str != NULL)
		sseq = acl_cisco_get_seq(acl, action, host_str,
					 mask_str ? mask_str : "0.0.0.0", NULL,
					 NULL);
	else
		sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
					 "255.255.255.255", NULL, NULL);
	if (sseq == -1)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	access_list_ext, access_list_ext_cmd,
	"access-list <(100-199)|(2000-2699)>$number [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ELEG_STR
	ACCESS_LIST_ELEG_EXT_STR
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
	int64_t sseq;
	char ipmask[64];
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (src_str != NULL && src_mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./host", NB_OP_MODIFY, src_str);
	} else if (src_str != NULL && src_mask_str != NULL) {
		concat_addr_mask_v4(src_str, src_mask_str, ipmask,
				    sizeof(ipmask));
		nb_cli_enqueue_change(vty, "./network", NB_OP_MODIFY, ipmask);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	if (dst_str != NULL && dst_mask_str == NULL) {
		nb_cli_enqueue_change(vty, "./destination-host", NB_OP_MODIFY,
				      src_str);
	} else if (dst_str != NULL && dst_mask_str != NULL) {
		concat_addr_mask_v4(dst_str, dst_mask_str, ipmask,
				    sizeof(ipmask));
		nb_cli_enqueue_change(vty, "./destination-network",
				      NB_OP_MODIFY, ipmask);
	} else {
		nb_cli_enqueue_change(vty, "./destination-any", NB_OP_CREATE,
				      NULL);
	}

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_access_list_ext, no_access_list_ext_cmd,
	"no access-list <(100-199)|(2000-2699)>$number [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ELEG_STR
	ACCESS_LIST_ELEG_EXT_STR
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
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintfrr(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list-legacy[number='%s']/entry[sequence='%s']",
			number_str, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (src_str != NULL) {
		if (dst_str != NULL)
			sseq = acl_cisco_get_seq(
				acl, action, src_str,
				src_mask_str ? src_mask_str : "0.0.0.0",
				dst_str,
				dst_mask_str ? dst_mask_str : "0.0.0.0");
		else
			sseq = acl_cisco_get_seq(acl, action, src_str,
						 src_mask_str ? src_mask_str
							      : "0.0.0.0",
						 "0.0.0.0", "255.255.255.255");
	} else {
		if (dst_str != NULL)
			sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
						 "255.255.255.255", dst_str,
						 dst_mask_str ? dst_mask_str
							      : "0.0.0.0");
		else
			sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
						 "255.255.255.255", "0.0.0.0",
						 "255.255.255.255");
	}
	if (sseq == -1)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_legacy, no_access_list_legacy_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void access_list_legacy_show(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults)
{
	uint16_t number = yang_dnode_get_uint16(dnode, "../number");
	bool extended;
	struct prefix p;
	struct in_addr mask;

	vty_out(vty, "access-list %d seq %s %s", number,
		yang_dnode_get_string(dnode, "./sequence"),
		yang_dnode_get_string(dnode, "./action"));

	extended = (number >= 100 && number <= 199)
		   || (number >= 2000 && number <= 2699);
	if (extended)
		vty_out(vty, " ip");

	if (yang_dnode_exists(dnode, "./network")) {
		yang_dnode_get_prefix(&p, dnode, "./network");
		masklen2ip(p.prefixlen, &mask);
		vty_out(vty, " %pI4 %pI4", &p.u.prefix4, &mask);
	} else if (yang_dnode_exists(dnode, "./host")) {
		if (extended)
			vty_out(vty, " host");

		vty_out(vty, " %s", yang_dnode_get_string(dnode, "./host"));
	} else if (yang_dnode_exists(dnode, "./any"))
		vty_out(vty, " any");

	if (extended) {
		if (yang_dnode_exists(dnode, "./destination-network")) {
			yang_dnode_get_prefix(&p, dnode,
					      "./destination-network");
			masklen2ip(p.prefixlen, &mask);
			vty_out(vty, " %pI4 %pI4", &p.u.prefix4, &mask);
		} else if (yang_dnode_exists(dnode, "./destination-host"))
			vty_out(vty, " host %s",
				yang_dnode_get_string(dnode,
						      "./destination-host"));
		else if (yang_dnode_exists(dnode, "./destination-any"))
			vty_out(vty, " any");
	}

	vty_out(vty, "\n");
}

DEFPY(
	access_list_legacy_remark, access_list_legacy_remark_cmd,
	"access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark LINE...",
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	remark = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, "./remark", NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_access_list_legacy_remark, no_access_list_legacy_remark_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']/remark",
		 number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_access_list_legacy_remark, no_access_list_legacy_remark_line_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark LINE...",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

void access_list_legacy_remark_show(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "access-list %s remark %s\n",
		yang_dnode_get_string(dnode, "../number"),
		yang_dnode_get_string(dnode, NULL));
}

/*
 * Zebra access lists.
 */
DEFPY(
	access_list, access_list_cmd,
	"access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

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

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_access_list, no_access_list_cmd,
	"no access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='ipv4'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_INET;
		sseq = acl_zebra_get_seq(acl, action, &pany, exact);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 exact);
	if (sseq == -1)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_all, no_access_list_all_cmd,
	"no access-list WORD$name",
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

DEFPY(
	access_list_remark, access_list_remark_cmd,
	"access-list WORD$name remark LINE...",
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
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_access_list_remark, no_access_list_remark_cmd,
	"no access-list WORD$name remark",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_access_list_remark, no_access_list_remark_line_cmd,
	"no access-list WORD$name remark LINE...",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY(
	ipv6_access_list, ipv6_access_list_cmd,
	"ipv6 access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
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
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

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

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_ipv6_access_list, no_ipv6_access_list_cmd,
	"no ipv6 access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
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
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='ipv6'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_INET6;
		sseq = acl_zebra_get_seq(acl, action, &pany, exact);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 exact);
	if (sseq == -1)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_ipv6_access_list_all, no_ipv6_access_list_all_cmd,
	"no ipv6 access-list WORD$name",
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

DEFPY(
	ipv6_access_list_remark, ipv6_access_list_remark_cmd,
	"ipv6 access-list WORD$name remark LINE...",
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
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_cmd,
	"no ipv6 access-list WORD$name remark",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_line_cmd,
	"no ipv6 access-list WORD$name remark LINE...",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY(
	mac_access_list, mac_access_list_cmd,
	"mac access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X:X:X:X:X$mac|any>",
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Match any MAC address\n")
{
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (mac_str != NULL) {
		nb_cli_enqueue_change(vty, "./mac", NB_OP_MODIFY, mac_str);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_mac_access_list, no_mac_access_list_cmd,
	"no mac access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X:X:X:X:X$prefix|any>",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Match any MAC address\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='mac'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_ETHERNET;
		sseq = acl_zebra_get_seq(acl, action, &pany, false);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 false);
	if (sseq == -1)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_mac_access_list_all, no_mac_access_list_all_cmd,
	"no mac access-list WORD$name",
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

DEFPY(
	mac_access_list_remark, mac_access_list_remark_cmd,
	"mac access-list WORD$name remark LINE...",
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
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_mac_access_list_remark, no_mac_access_list_remark_cmd,
	"no mac access-list WORD$name remark",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_mac_access_list_remark, no_mac_access_list_remark_line_cmd,
	"no mac access-list WORD$name remark LINE...",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

void access_list_show(struct vty *vty, struct lyd_node *dnode,
		      bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");
	struct prefix p;
	bool is_any;
	bool is_exact = false;
	char macstr[PREFIX2STR_BUFFER];

	is_any = yang_dnode_exists(dnode, "./any");
	switch (type) {
	case YALT_IPV4:
		if (is_any)
			break;

		yang_dnode_get_prefix(&p, dnode, "./ipv4-prefix");
		is_exact = yang_dnode_get_bool(dnode, "./ipv4-exact-match");
		break;
	case YALT_IPV6: /* ipv6 */
		vty_out(vty, "ipv6 ");
		if (is_any)
			break;

		yang_dnode_get_prefix(&p, dnode, "./ipv6-prefix");
		is_exact = yang_dnode_get_bool(dnode, "./ipv6-exact-match");
		break;
	case YALT_MAC: /* mac */
		vty_out(vty, "mac ");
		if (is_any)
			break;

		yang_dnode_get_prefix(&p, dnode, "./mac");
		break;
	}

	vty_out(vty, "access-list %s seq %s %s",
		yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, "./sequence"),
		yang_dnode_get_string(dnode, "./action"));

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

void access_list_remark_show(struct vty *vty, struct lyd_node *dnode,
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

/**
 * Remove main data structure prefix list if there are no more entries or
 * remark. This fixes compatibility with old CLI and tests.
 */
static int plist_remove_if_empty(struct vty *vty, const char *iptype,
				 const char *name)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='%s'][name='%s']/remark",
		 iptype, name);
	/* List is not empty if there is a remark, check that: */
	if (yang_dnode_exists(vty->candidate_config->dnode, xpath))
		return CMD_SUCCESS;

	/* Check if we have any entries: */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='%s'][name='%s']", iptype,
		 name);
	/*
	 * NOTE: if the list is empty it will return the first sequence
	 * number: 5.
	 */
	if (acl_get_seq(vty, xpath) != 5)
		return CMD_SUCCESS;

	/* Nobody is using this list, lets remove it. */
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int plist_remove(struct vty *vty, const char *iptype, const char *name,
			const char *seq, const char *action, struct prefix *p,
			long ge, long le)
{
	struct prefix_list_entry *pentry;
	enum prefix_list_type plt;
	struct prefix_list *pl;
	struct lyd_node *dnode;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	int rv;

	/* If the user provided sequence number, then just go for it. */
	if (seq != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/prefix-list[type='%s'][name='%s']/entry[sequence='%s']",
			iptype, name, seq);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

		rv = nb_cli_apply_changes(vty, NULL);
		if (rv == CMD_SUCCESS)
			return plist_remove_if_empty(vty, iptype, name);

		return rv;
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='%s'][name='%s']", iptype,
		 name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	assert(action != NULL);
	if (strcmp(action, "permit") == 0)
		plt = PREFIX_PERMIT;
	else
		plt = PREFIX_DENY;

	dnode = yang_dnode_get(running_config->dnode, xpath);
	pl = nb_running_get_entry(dnode, NULL, true);
	pentry = prefix_list_entry_lookup(pl, p, plt, -1, le, ge);
	if (pentry == NULL)
		return CMD_WARNING;

	snprintfrr(xpath_entry, sizeof(xpath_entry),
		   "%s/entry[sequence='%" PRId64 "']", xpath, pentry->seq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		return plist_remove_if_empty(vty, iptype, name);

	return rv;
}

DEFPY(
	ip_prefix_list, ip_prefix_list_cmd,
	"ip prefix-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <any|A.B.C.D/M$prefix [{ge (0-32)$ge|le (0-32)$le}]>",
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
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the prefix-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv4-prefix", NB_OP_MODIFY,
				      prefix_str);

		if (ge_str)
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-greater-or-equal",
				NB_OP_MODIFY, ge_str);
		if (le_str)
			nb_cli_enqueue_change(
				vty, "./ipv4-prefix-length-lesser-or-equal",
				NB_OP_MODIFY, le_str);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_ip_prefix_list, no_ip_prefix_list_cmd,
	"no ip prefix-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <any|A.B.C.D/M$prefix [{ge (0-32)|le (0-32)}]>",
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
	return plist_remove(vty, "ipv4", name, seq_str, action,
			    (struct prefix *)prefix, ge, le);
}

DEFPY(
	no_ip_prefix_list_seq, no_ip_prefix_list_seq_cmd,
	"no ip prefix-list WORD$name seq (1-4294967295)$seq",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR)
{
	return plist_remove(vty, "ipv4", name, seq_str, NULL, NULL, 0, 0);
}

DEFPY(
	no_ip_prefix_list_all, no_ip_prefix_list_all_cmd,
	"no ip prefix-list WORD$name",
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

DEFPY(
	ip_prefix_list_remark, ip_prefix_list_remark_cmd,
	"ip prefix-list WORD$name description LINE...",
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
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_ip_prefix_list_remark, no_ip_prefix_list_remark_cmd,
	"no ip prefix-list WORD$name description",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv4'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_ip_prefix_list_remark, no_ip_prefix_list_remark_line_cmd,
	"no ip prefix-list WORD$name description LINE...",
	NO_STR
	IP_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY(
	ipv6_prefix_list, ipv6_prefix_list_cmd,
	"ipv6 prefix-list WORD$name [seq (1-4294967295)] <deny|permit>$action <any|X:X::X:X/M$prefix [{ge (0-128)$ge|le (0-128)$le}]>",
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
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];

	/*
	 * Create the prefix-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (seq_str == NULL) {
		/* Use XPath to find the next sequence number. */
		sseq = acl_get_seq(vty, xpath);
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintfrr(xpath_entry, sizeof(xpath_entry),
			   "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	if (prefix_str != NULL) {
		nb_cli_enqueue_change(vty, "./ipv6-prefix", NB_OP_MODIFY,
				      prefix_str);

		if (ge_str)
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-greater-or-equal",
				NB_OP_MODIFY, ge_str);
		if (le_str)
			nb_cli_enqueue_change(
				vty, "./ipv6-prefix-length-lesser-or-equal",
				NB_OP_MODIFY, le_str);
	} else {
		nb_cli_enqueue_change(vty, "./any", NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, xpath_entry);
}

DEFPY(
	no_ipv6_prefix_list, no_ipv6_prefix_list_cmd,
	"no ipv6 prefix-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <any|X:X::X:X/M$prefix [{ge (0-128)$ge|le (0-128)$le}]>",
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
	return plist_remove(vty, "ipv6", name, seq_str, action,
			    (struct prefix *)prefix, ge, le);
}

DEFPY(
	no_ipv6_prefix_list_seq, no_ipv6_prefix_list_seq_cmd,
	"no ipv6 prefix-list WORD$name seq (1-4294967295)$seq",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_SEQ_STR)
{
	return plist_remove(vty, "ipv6", name, seq_str, NULL, NULL, 0, 0);
}

DEFPY(
	no_ipv6_prefix_list_all, no_ipv6_prefix_list_all_cmd,
	"no ipv6 prefix-list WORD$name",
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

DEFPY(
	ipv6_prefix_list_remark, ipv6_prefix_list_remark_cmd,
	"ipv6 prefix-list WORD$name description LINE...",
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
	rv = nb_cli_apply_changes(vty, xpath);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_ipv6_prefix_list_remark, no_ipv6_prefix_list_remark_cmd,
	"no ipv6 prefix-list WORD$name description",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/prefix-list[type='ipv6'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_ipv6_prefix_list_remark, no_ipv6_prefix_list_remark_line_cmd,
	"no ipv6 prefix-list WORD$name description LINE...",
	NO_STR
	IPV6_STR
	PREFIX_LIST_STR
	PREFIX_LIST_NAME_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

void prefix_list_show(struct vty *vty, struct lyd_node *dnode,
		      bool show_defaults)
{
	int type = yang_dnode_get_enum(dnode, "../type");
	const char *ge_str = NULL, *le_str = NULL;
	bool is_any;
	struct prefix p;

	is_any = yang_dnode_exists(dnode, "./any");
	switch (type) {
	case YPLT_IPV4:
		if (!is_any)
			yang_dnode_get_prefix(&p, dnode, "./ipv4-prefix");
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
		yang_dnode_get_string(dnode, "./sequence"),
		yang_dnode_get_string(dnode, "./action"));

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

void prefix_list_remark_show(struct vty *vty, struct lyd_node *dnode,
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
	install_element(CONFIG_NODE, &no_access_list_legacy_cmd);
	install_element(CONFIG_NODE, &access_list_legacy_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_remark_line_cmd);

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
