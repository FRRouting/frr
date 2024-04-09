// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include <float.h>
#include <math.h>
#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "command.h"
#include "mpls.h"
#include "northbound_cli.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"
#include "pathd/path_cli_clippy.c"
#include "pathd/path_ted.h"

#define XPATH_MAXATTRSIZE 64
#define XPATH_MAXKEYSIZE 42
#define XPATH_POLICY_BASELEN 100
#define XPATH_POLICY_MAXLEN (XPATH_POLICY_BASELEN + XPATH_MAXATTRSIZE)
#define XPATH_CANDIDATE_BASELEN (XPATH_POLICY_BASELEN + XPATH_MAXKEYSIZE)
#define XPATH_CANDIDATE_MAXLEN (XPATH_CANDIDATE_BASELEN + XPATH_MAXATTRSIZE)


static int config_write_segment_routing(struct vty *vty);
static int segment_list_has_src_dst(
	struct vty *vty, char *xpath, long index, const char *index_str,
	struct in_addr adj_src_ipv4, struct in_addr adj_dst_ipv4,
	struct in6_addr adj_src_ipv6, struct in6_addr adj_dst_ipv6,
	const char *adj_src_ipv4_str, const char *adj_dst_ipv4_str,
	const char *adj_src_ipv6_str, const char *adj_dst_ipv6_str);
static int segment_list_has_prefix(
	struct vty *vty, char *xpath, long index, const char *index_str,
	const struct prefix_ipv4 *prefix_ipv4, const char *prefix_ipv4_str,
	const struct prefix_ipv6 *prefix_ipv6, const char *prefix_ipv6_str,
	const char *has_algo, long algo, const char *algo_str,
	const char *has_iface_id, long iface_id, const char *iface_id_str);

DEFINE_MTYPE_STATIC(PATHD, PATH_CLI, "Client");

DEFINE_HOOK(pathd_srte_config_write, (struct vty *vty), (vty));

/* Vty node structures. */
static struct cmd_node segment_routing_node = {
	.name = "segment-routing",
	.node = SEGMENT_ROUTING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-sr)# ",
	.config_write = config_write_segment_routing,
};

static struct cmd_node sr_traffic_eng_node = {
	.name = "sr traffic-eng",
	.node = SR_TRAFFIC_ENG_NODE,
	.parent_node = SEGMENT_ROUTING_NODE,
	.prompt = "%s(config-sr-te)# ",
};

static struct cmd_node srte_segment_list_node = {
	.name = "srte segment-list",
	.node = SR_SEGMENT_LIST_NODE,
	.parent_node = SR_TRAFFIC_ENG_NODE,
	.prompt = "%s(config-sr-te-segment-list)# ",
};

static struct cmd_node srte_policy_node = {
	.name = "srte policy",
	.node = SR_POLICY_NODE,
	.parent_node = SR_TRAFFIC_ENG_NODE,
	.prompt = "%s(config-sr-te-policy)# ",
};

static struct cmd_node srte_candidate_dyn_node = {
	.name = "srte candidate-dyn",
	.node = SR_CANDIDATE_DYN_NODE,
	.parent_node = SR_POLICY_NODE,
	.prompt = "%s(config-sr-te-candidate)# ",
};


/*
 * Show SR-TE info
 */
DEFPY(show_srte_policy,
      show_srte_policy_cmd,
      "show sr-te policy",
      SHOW_STR
      "SR-TE info\n"
      "SR-TE Policy\n")
{
	struct ttable *tt;
	struct srte_policy *policy;
	char *table;

	if (RB_EMPTY(srte_policy_head, &srte_policies)) {
		vty_out(vty, "No SR Policies to display.\n\n");
		return CMD_SUCCESS;
	}

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Endpoint|Color|Name|BSID|Status");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		char endpoint[ENDPOINT_STR_LENGTH];
		char binding_sid[16] = "-";

		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		if (policy->binding_sid != MPLS_LABEL_NONE)
			snprintf(binding_sid, sizeof(binding_sid), "%u",
				 policy->binding_sid);

		ttable_add_row(tt, "%s|%u|%s|%s|%s", endpoint, policy->color,
			       policy->name, binding_sid,
			       policy->status == SRTE_POLICY_STATUS_UP
				       ? "Active"
				       : "Inactive");
	}

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_del(tt);

	return CMD_SUCCESS;
}


/*
 * Show detailed SR-TE info
 */
DEFPY(show_srte_policy_detail,
      show_srte_policy_detail_cmd,
      "show sr-te policy detail",
      SHOW_STR
      "SR-TE info\n"
      "SR-TE Policy\n"
      "Show a detailed summary\n")
{
	struct srte_policy *policy;

	if (RB_EMPTY(srte_policy_head, &srte_policies)) {
		vty_out(vty, "No SR Policies to display.\n\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "\n");
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;
		char endpoint[ENDPOINT_STR_LENGTH];
		char binding_sid[16] = "-";
		char *segment_list_info;
		static char undefined_info[] = "(undefined)";
		static char created_by_pce_info[] = "(created by PCE)";


		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		if (policy->binding_sid != MPLS_LABEL_NONE)
			snprintf(binding_sid, sizeof(binding_sid), "%u",
				 policy->binding_sid);
		vty_out(vty,
			"Endpoint: %s  Color: %u  Name: %s  BSID: %s  Status: %s\n",
			endpoint, policy->color, policy->name, binding_sid,
			policy->status == SRTE_POLICY_STATUS_UP ? "Active"
								: "Inactive");

		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
			struct srte_segment_list *segment_list;

			segment_list = candidate->lsp->segment_list;
			if (segment_list == NULL)
				segment_list_info = undefined_info;
			else if (segment_list->protocol_origin
				 == SRTE_ORIGIN_PCEP)
				segment_list_info = created_by_pce_info;
			else
				segment_list_info =
					candidate->lsp->segment_list->name;

			vty_out(vty,
				"  %s Preference: %d  Name: %s  Type: %s  Segment-List: %s  Protocol-Origin: %s\n",
				CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)
					? "*"
					: " ",
				candidate->preference, candidate->name,
				candidate->type == SRTE_CANDIDATE_TYPE_EXPLICIT
					? "explicit"
					: "dynamic",
				segment_list_info,
				srte_origin2str(
					candidate->lsp->protocol_origin));
		}

		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFPY_NOSH(
      segment_routing_list,
      segment_routing_cmd,
      "segment-routing",
      "Configure segment routing\n")
{
	VTY_PUSH_CONTEXT_NULL(SEGMENT_ROUTING_NODE);
	return CMD_SUCCESS;
}

DEFPY_NOSH(
      sr_traffic_eng_list,
      sr_traffic_eng_cmd,
      "traffic-eng",
      "Configure SR traffic engineering\n")
{
	VTY_PUSH_CONTEXT_NULL(SR_TRAFFIC_ENG_NODE);
	return CMD_SUCCESS;
}

/*
 * XPath: /frr-pathd:pathd/srte/segment-list
 */
DEFPY_NOSH(
      srte_segment_list,
      srte_segment_list_cmd,
      "segment-list WORD$name",
      "Segment List\n"
      "Segment List Name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/segment-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/segment-list[name='%s']/protocol-origin",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "local");

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/segment-list[name='%s']/originator", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "config");

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS) {
		snprintf(xpath, sizeof(xpath),
			 "/frr-pathd:pathd/srte/segment-list[name='%s']", name);
		VTY_PUSH_XPATH(SR_SEGMENT_LIST_NODE, xpath);
	}

	return ret;
}

DEFPY(srte_no_segment_list,
      srte_no_segment_list_cmd,
      "no segment-list WORD$name",
      NO_STR
      "Segment List\n"
      "Segment List Name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/segment-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_srte_segment_list(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, "  segment-list %s\n",
		yang_dnode_get_string(dnode, "name"));
}

void cli_show_srte_segment_list_end(struct vty *vty,
				    const struct lyd_node *dnode)
{
	vty_out(vty, "  exit\n");
}

static int segment_list_has_src_dst(
	struct vty *vty, char *xpath, long index, const char *index_str,
	struct in_addr adj_src_ipv4, struct in_addr adj_dst_ipv4,
	struct in6_addr adj_src_ipv6, struct in6_addr adj_dst_ipv6,
	const char *adj_src_ipv4_str, const char *adj_dst_ipv4_str,
	const char *adj_src_ipv6_str, const char *adj_dst_ipv6_str)
{
	const char *node_src_id;
	uint32_t ted_sid = MPLS_LABEL_NONE;

	struct ipaddr ip_src = {};
	struct ipaddr ip_dst = {};
	if (adj_src_ipv4_str != NULL) {
		ip_src.ipa_type = IPADDR_V4;
		ip_src.ip._v4_addr = adj_src_ipv4;
		ip_dst.ipa_type = IPADDR_V4;
		ip_dst.ip._v4_addr = adj_dst_ipv4;
	} else if (adj_src_ipv6_str != NULL) {
		ip_src.ipa_type = IPADDR_V6;
		ip_src.ip._v6_addr = adj_src_ipv6;
		ip_dst.ipa_type = IPADDR_V6;
		ip_dst.ip._v6_addr = adj_dst_ipv6;
	} else {
		return CMD_ERR_NO_MATCH;
	}
	ted_sid = path_ted_query_type_f(&ip_src, &ip_dst);
	if (ted_sid == MPLS_LABEL_NONE) {
		zlog_warn(
			"%s: [rcv ted] CLI NOT FOUND Continue query_type_f SRC (%pIA) DST (%pIA)!",
			__func__, &ip_src, &ip_dst);
	}
	/* type */
	snprintf(xpath, XPATH_MAXLEN, "./segment[index='%s']/nai/type",
		 index_str);
	if (adj_src_ipv4_str != NULL) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
				      "ipv4_adjacency");
		node_src_id = adj_src_ipv4_str;
	} else if (adj_src_ipv6_str != NULL) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
				      "ipv6_adjacency");
		node_src_id = adj_src_ipv6_str;
	} else {
		/*
		 * This is just to make the compiler happy about
		 * node_src_id not being initialized.  This
		 * should never happen unless we change the cli
		 * function.
		 */
		assert(!"We must have a adj_src_ipv4_str or a adj_src_ipv6_str");
	}

	/* addresses */
	snprintf(xpath, XPATH_MAXLEN, "./segment[index='%s']/nai/local-address",
		 index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, node_src_id);
	snprintf(xpath, XPATH_MAXLEN,
		 "./segment[index='%s']/nai/remote-address", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      adj_dst_ipv4_str ? adj_dst_ipv4_str
					       : adj_dst_ipv6_str);
	return CMD_SUCCESS;
}
int segment_list_has_prefix(
	struct vty *vty, char *xpath, long index, const char *index_str,
	const struct prefix_ipv4 *prefix_ipv4, const char *prefix_ipv4_str,
	const struct prefix_ipv6 *prefix_ipv6, const char *prefix_ipv6_str,
	const char *has_algo, long algo, const char *algo_str,
	const char *has_iface_id, long iface_id, const char *iface_id_str)
{
	char buf_prefix[INET6_ADDRSTRLEN];

	uint32_t ted_sid = MPLS_LABEL_NONE;
	struct prefix prefix_cli = {};
	struct ipaddr pre_ipaddr = {};
	/* prefix with algorithm or local interface id */
	/* Type */
	snprintf(xpath, XPATH_MAXLEN, "./segment[index='%s']/nai/type",
		 index_str);
	if (has_iface_id != NULL) {
		if (prefix_ipv4_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv4_local_iface");
		} else if (prefix_ipv6_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv6_local_iface");
		} else {
			return CMD_ERR_NO_MATCH;
		}
	} else {
		if (prefix_ipv4_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv4_algo");
		} else if (prefix_ipv6_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv6_algo");
		} else {
			return CMD_ERR_NO_MATCH;
		}
	}
	/* Prefix */
	if (prefix_ipv4_str != NULL) {
		if (!str2prefix(prefix_ipv4_str, &prefix_cli)) {
			vty_out(vty, "%% Malformed prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		inet_ntop(AF_INET, &prefix_cli.u.prefix4, buf_prefix,
			  sizeof(buf_prefix));
		pre_ipaddr.ipa_type = IPADDR_V4;
		pre_ipaddr.ip._v4_addr = prefix_cli.u.prefix4;
	} else if (prefix_ipv6_str != NULL) {
		if (!str2prefix(prefix_ipv6_str, &prefix_cli)) {
			vty_out(vty, "%% Malformed prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		inet_ntop(AF_INET6, &prefix_cli.u.prefix6, buf_prefix,
			  sizeof(buf_prefix));
		pre_ipaddr.ipa_type = IPADDR_V6;
		pre_ipaddr.ip._v6_addr = prefix_cli.u.prefix6;
	}
	snprintf(xpath, XPATH_MAXLEN, "./segment[index='%s']/nai/local-address",
		 index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, buf_prefix);
	snprintf(xpath, XPATH_MAXLEN,
		 "./segment[index='%s']/nai/local-prefix-len", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      prefix_ipv4_str
				      ? strchr(prefix_ipv4_str, '/') + 1
				      : strchr(prefix_ipv6_str, '/') + 1);
	/* Alg / Iface */
	if (has_algo != NULL) {
		snprintf(xpath, XPATH_MAXLEN,
			 "./segment[index='%s']/nai/algorithm", index_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, algo_str);
	} else {
		if (has_iface_id != NULL) {
			snprintf(xpath, XPATH_MAXLEN,
				 "./segment[index='%s']/nai/local-interface",
				 index_str);
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      iface_id_str);
		}
	}
	if (has_algo != NULL) {
		ted_sid = path_ted_query_type_c(&prefix_cli, algo);
		if (ted_sid == MPLS_LABEL_NONE) {
			zlog_err(
				"%s: [rcv ted] CLI NOT FOUND Continue query_type_c PREFIX (%pIA/%d) ALGO (%ld) sid:(%d)!",
				__func__, &pre_ipaddr, prefix_cli.prefixlen,
				algo, ted_sid);
		}
	}
	if (has_iface_id != NULL) {
		ted_sid = path_ted_query_type_e(&prefix_cli, iface_id);
		if (ted_sid == MPLS_LABEL_NONE) {
			zlog_err(
				"%s: [rcv ted] CLI NOT FOUND Continue query_type_e PREFIX (%pIA/%d) IFACE (%ld) sid:(%d)!",
				__func__, &pre_ipaddr, prefix_cli.prefixlen,
				iface_id, ted_sid);
		}
	}
	return CMD_SUCCESS;
}
/*
 * XPath: /frr-pathd:pathd/srte/segment-list/segment
 */
/* clang-format off */
DEFPY(srte_segment_list_segment, srte_segment_list_segment_cmd,
      "index (0-4294967295)$index <[mpls$has_mpls_label label (16-1048575)$label] "
      "|"
      "[nai$has_nai <"
      "prefix <A.B.C.D/M$prefix_ipv4|X:X::X:X/M$prefix_ipv6>"
      "<algorithm$has_algo (0-1)$algo| iface$has_iface_id (0-4294967295)$iface_id>"
      "| adjacency$has_adj "
      "<A.B.C.D$adj_src_ipv4 A.B.C.D$adj_dst_ipv4|X:X::X:X$adj_src_ipv6 X:X::X:X$adj_dst_ipv6>"
      ">]"
      ">",
      "Index\n"
      "Index Value\n"
      "MPLS or IP Label\n"
      "Label\n"
      "Label Value\n"
      "Segment NAI\n"
      "NAI prefix identifier\n"
      "NAI IPv4 prefix identifier\n"
      "NAI IPv6 prefix identifier\n"
      "IGP Algorithm\n"
      "Algorithm Value SPF or Strict-SPF\n"
      "Interface Id\n"
      "Interface Value\n"
      "ADJ identifier\n"
      "ADJ IPv4 src identifier\n"
      "ADJ IPv4 dst identifier\n"
      "ADJ IPv6 src identifier\n"
      "ADJ IPv6 dst identifier\n")
/* clang-format on */
{
	char xpath[XPATH_MAXLEN];
	int status = CMD_SUCCESS;


	snprintf(xpath, sizeof(xpath), "./segment[index='%s']", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (has_mpls_label != NULL) {
		snprintf(xpath, sizeof(xpath),
			 "./segment[index='%s']/sid-value", index_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, label_str);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (has_adj != NULL) {
		status = segment_list_has_src_dst(vty, xpath, index, index_str,
					 adj_src_ipv4, adj_dst_ipv4,
					 adj_src_ipv6, adj_dst_ipv6,
					 adj_src_ipv4_str, adj_dst_ipv4_str,
					 adj_src_ipv6_str, adj_dst_ipv6_str);
		if (status != CMD_SUCCESS)
			return status;
	} else {
		status = segment_list_has_prefix(
			vty, xpath, index, index_str, prefix_ipv4,
			prefix_ipv4_str, prefix_ipv6, prefix_ipv6_str, has_algo,
			algo, algo_str, has_iface_id, iface_id, iface_id_str);
		if (status != CMD_SUCCESS)
			return status;
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_segment_list_no_segment,
      srte_segment_list_no_segment_cmd,
      "no index (0-4294967295)$index",
      NO_STR
      "Index\n"
      "Index Value\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_srte_segment_list_segment(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "   index %s", yang_dnode_get_string(dnode, "index"));
	if (yang_dnode_exists(dnode, "sid-value")) {
		vty_out(vty, " mpls label %s",
			yang_dnode_get_string(dnode, "sid-value"));
	}
	if (yang_dnode_exists(dnode, "nai")) {
		struct ipaddr addr;
		struct ipaddr addr_rmt;

		switch (yang_dnode_get_enum(dnode, "nai/type")) {
		case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
		case SRTE_SEGMENT_NAI_TYPE_IPV4_LOCAL_IFACE:
		case SRTE_SEGMENT_NAI_TYPE_IPV4_ALGORITHM:
			yang_dnode_get_ip(&addr, dnode, "nai/local-address");
			vty_out(vty, " nai prefix %pI4", &addr.ipaddr_v4);
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_LOCAL_IFACE:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_ALGORITHM:
			yang_dnode_get_ip(&addr, dnode, "nai/local-address");
			vty_out(vty, " nai prefix %pI6", &addr.ipaddr_v6);
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
			yang_dnode_get_ip(&addr, dnode, "nai/local-address");
			yang_dnode_get_ip(&addr_rmt, dnode,
					  "./nai/remote-address");
			vty_out(vty, " nai adjacency %pI4", &addr.ipaddr_v4);
			vty_out(vty, " %pI4", &addr_rmt.ipaddr_v4);
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
			yang_dnode_get_ip(&addr, dnode, "nai/local-address");
			yang_dnode_get_ip(&addr_rmt, dnode,
					  "./nai/remote-address");
			vty_out(vty, " nai adjacency %pI6", &addr.ipaddr_v6);
			vty_out(vty, " %pI6", &addr_rmt.ipaddr_v6);
			break;
		default:
			break;
		}
		if (yang_dnode_exists(dnode, "nai/local-prefix-len")) {
			vty_out(vty, "/%s",
				yang_dnode_get_string(
					dnode, "./nai/local-prefix-len"));
		}
		if (yang_dnode_exists(dnode, "nai/local-interface")) {
			vty_out(vty, " iface %s",
				yang_dnode_get_string(dnode,
						      "./nai/local-interface"));
		}
		if (yang_dnode_exists(dnode, "nai/algorithm")) {
			vty_out(vty, " algorithm %s",
				yang_dnode_get_string(dnode,
						      "./nai/algorithm"));
		}
	}
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-pathd:pathd/policy
 */
DEFPY_NOSH(
	srte_policy,
	srte_policy_cmd,
	"policy color (0-4294967295)$num endpoint <A.B.C.D|X:X::X:X>$endpoint",
	"Segment Routing Policy\n"
	"SR Policy color\n"
	"SR Policy color value\n"
	"SR Policy endpoint\n"
	"SR Policy endpoint IPv4 address\n"
	"SR Policy endpoint IPv6 address\n")
{
	char xpath[XPATH_POLICY_BASELEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/policy[color='%s'][endpoint='%s']",
		 num_str, endpoint_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SR_POLICY_NODE, xpath);

	return ret;
}

DEFPY(srte_no_policy,
      srte_no_policy_cmd,
      "no policy color (0-4294967295)$num endpoint <A.B.C.D|X:X::X:X>$endpoint",
      NO_STR
      "Segment Routing Policy\n"
      "SR Policy color\n"
      "SR Policy color value\n"
      "SR Policy endpoint\n"
      "SR Policy endpoint IPv4 address\n"
      "SR Policy endpoint IPv6 address\n")
{
	char xpath[XPATH_POLICY_BASELEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/srte/policy[color='%s'][endpoint='%s']",
		 num_str, endpoint_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_srte_policy(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, "  policy color %s endpoint %s\n",
		yang_dnode_get_string(dnode, "color"),
		yang_dnode_get_string(dnode, "endpoint"));
}

void cli_show_srte_policy_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "  exit\n");
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/name
 */
DEFPY(srte_policy_name,
      srte_policy_name_cmd,
      "name WORD$name",
      "Segment Routing Policy name\n"
      "SR Policy name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_CREATE, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_policy_no_name,
      srte_policy_no_name_cmd,
      "no name [WORD]",
      NO_STR
      "Segment Routing Policy name\n"
      "SR Policy name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


void cli_show_srte_policy_name(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, "   name %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/binding-sid
 */
DEFPY(srte_policy_binding_sid,
      srte_policy_binding_sid_cmd,
      "binding-sid (16-1048575)$label",
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	nb_cli_enqueue_change(vty, "./binding-sid", NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_policy_no_binding_sid,
      srte_policy_no_binding_sid_cmd,
      "no binding-sid [(16-1048575)]",
      NO_STR
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	nb_cli_enqueue_change(vty, "./binding-sid", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_srte_policy_binding_sid(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "   binding-sid %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/candidate-path
 */
DEFPY(srte_policy_candidate_exp,
      srte_policy_candidate_exp_cmd,
      "candidate-path preference (0-4294967295)$preference name WORD$name \
	 explicit segment-list WORD$list_name",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Explicit Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "local");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "explicit");
	nb_cli_enqueue_change(vty, "./segment-list-name", NB_OP_MODIFY,
			      list_name);
	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY_NOSH(
	srte_policy_candidate_dyn,
	srte_policy_candidate_dyn_cmd,
	"candidate-path preference (0-4294967295)$preference name WORD$name dynamic",
	"Segment Routing Policy Candidate Path\n"
	"Segment Routing Policy Candidate Path Preference\n"
	"Administrative Preference\n"
	"Segment Routing Policy Candidate Path Name\n"
	"Symbolic Name\n"
	"Dynamic Path\n")
{
	char xpath[XPATH_MAXLEN + XPATH_CANDIDATE_BASELEN];
	int ret;

	snprintf(xpath, sizeof(xpath), "%s/candidate-path[preference='%s']",
		 VTY_CURR_XPATH, preference_str);

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "local");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "dynamic");
	ret = nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				   preference_str);

	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SR_CANDIDATE_DYN_NODE, xpath);

	return ret;
}

DEFPY(srte_candidate_bandwidth,
      srte_candidate_bandwidth_cmd,
      "bandwidth BANDWIDTH$value [required$required]",
      "Define a bandwidth constraint\n"
      "Bandwidth value\n"
      "Required constraint\n")
{
	nb_cli_enqueue_change(vty, "./constraints/bandwidth/required",
			      NB_OP_MODIFY, required ? "true" : "false");
	nb_cli_enqueue_change(vty, "./constraints/bandwidth/value",
	                      NB_OP_MODIFY, value);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_no_bandwidth,
      srte_candidate_no_bandwidth_cmd,
      "no bandwidth [BANDWIDTH$value] [required$required]",
      NO_STR
      "Remove a bandwidth constraint\n"
      "Bandwidth value\n"
      "Required constraint\n")
{
	nb_cli_enqueue_change(vty, "./constraints/bandwidth", NB_OP_DESTROY,
	                      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_affinity_filter, srte_candidate_affinity_filter_cmd,
      "affinity <exclude-any|include-any|include-all>$type BITPATTERN$value",
      "Affinity constraint\n"
      "Exclude any matching link\n"
      "Include any matching link\n"
      "Include all matching links\n"
      "Attribute filter bit pattern as an hexadecimal value from 0x00000000 to 0xFFFFFFFF\n")
{
	uint32_t filter;
	char xpath[XPATH_CANDIDATE_MAXLEN];
	char decimal_value[11];

	if (sscanf(value, "0x%x", &filter) != 1) {
		vty_out(vty, "affinity type: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(decimal_value, sizeof(decimal_value), "%u", filter);
	snprintf(xpath, sizeof(xpath), "./constraints/affinity/%s", type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, decimal_value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_no_affinity_filter, srte_candidate_no_affinity_filter_cmd,
      "no affinity <exclude-any|include-any|include-all>$type [BITPATTERN$value]",
      NO_STR
      "Affinity constraint\n"
      "Exclude any matching link\n"
      "Include any matching link\n"
      "Include all matching links\n"
      "Attribute filter bit pattern as an hexadecimal value from 0x00000000 to 0xFFFFFFFF\n")
{
	char xpath[XPATH_CANDIDATE_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./constraints/affinity/%s", type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_metric,
      srte_candidate_metric_cmd,
      "metric [bound$bound] <igp|te|hc|abc|lmll|cigp|cte|pigp|pte|phc|msd|pd|pdv|pl|ppd|ppdv|ppl|nap|nlp|dc|bnc>$type METRIC$value [required$required] [computed$computed]",
      "Define a metric constraint\n"
      "If the metric is bounded\n"
      "IGP metric\n"
      "TE metric\n"
      "Hop Counts\n"
      "Aggregate bandwidth consumption\n"
      "Load of the most loaded link\n"
      "Cumulative IGP cost\n"
      "Cumulative TE cost\n"
      "P2MP IGP metric\n"
      "P2MP TE metric\n"
      "P2MP hop count metric\n"
      "Segment-ID (SID) Depth.\n"
      "Path Delay metric\n"
      "Path Delay Variation metric\n"
      "Path Loss metric\n"
      "P2MP Path Delay metric\n"
      "P2MP Path Delay variation metric\n"
      "P2MP Path Loss metric\n"
      "Number of adaptations on a path\n"
      "Number of layers on a path\n"
      "Domain Count metric\n"
      "Border Node Count metric\n"
      "Metric value\n"
      "Required constraint\n"
      "Force the PCE to provide the computed path metric\n")
{
	char xpath[XPATH_CANDIDATE_MAXLEN];
	snprintf(xpath, sizeof(xpath), "./constraints/metrics[type='%s']/value",
	         type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);
	snprintf(xpath, sizeof(xpath),
	         "./constraints/metrics[type='%s']/is-bound", type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      (bound != NULL) ? "true" : "false");
	snprintf(xpath, sizeof(xpath),
	         "./constraints/metrics[type='%s']/required", type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      required ? "true" : "false");
	snprintf(xpath, sizeof(xpath),
		 "./constraints/metrics[type='%s']/is-computed", type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      computed ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_no_metric,
      srte_candidate_no_metric_cmd,
      "no metric [bound] <igp|te|hc|abc|lmll|cigp|cte|pigp|pte|phc|msd|pd|pdv|pl|ppd|ppdv|ppl|nap|nlp|dc|bnc>$type [METRIC$value] [required$required] [computed$computed]",
      NO_STR
      "Remove a metric constraint\n"
      "If the metric is bounded\n"
      "IGP metric\n"
      "TE metric\n"
      "Hop Counts\n"
      "Aggregate bandwidth consumption\n"
      "Load of the most loaded link\n"
      "Cumulative IGP cost\n"
      "Cumulative TE cost\n"
      "P2MP IGP metric\n"
      "P2MP TE metric\n"
      "P2MP hop count metric\n"
      "Segment-ID (SID) Depth.\n"
      "Path Delay metric\n"
      "Path Delay Variation metric\n"
      "Path Loss metric\n"
      "P2MP Path Delay metric\n"
      "P2MP Path Delay variation metric\n"
      "P2MP Path Loss metric\n"
      "Number of adaptations on a path\n"
      "Number of layers on a path\n"
      "Domain Count metric\n"
      "Border Node Count metric\n"
      "Metric value\n"
      "Required constraint\n"
      "Force the PCE to provide the computed path metric\n")
{
	char xpath[XPATH_CANDIDATE_MAXLEN];
	snprintf(xpath, sizeof(xpath), "./constraints/metrics[type='%s']",
	         type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_policy_no_candidate,
      srte_policy_no_candidate_cmd,
      "no candidate-path\
	preference (0-4294967295)$preference\
	[name WORD\
	<\
	  explicit segment-list WORD\
	  |dynamic\
	>]",
      NO_STR
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Explicit Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n"
      "Dynamic Path\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY(srte_candidate_objfun,
      srte_candidate_objfun_cmd,
      "objective-function <mcp|mlp|mbp|mbc|mll|mcc|spt|mct|mplp|mup|mrup|mtd|mbn|mctd|msl|mss|msn>$type [required$required]",
      "Define an objective function constraint\n"
      "Minimum Cost Path\n"
      "Minimum Load Path\n"
      "Maximum residual Bandwidth Path\n"
      "Minimize aggregate Bandwidth Consumption\n"
      "Minimize the Load of the most loaded Link\n"
      "Minimize the Cumulative Cost of a set of paths\n"
      "Shortest Path Tree\n"
      "Minimum Cost Tree\n"
      "Minimum Packet Loss Path\n"
      "Maximum Under-Utilized Path\n"
      "Maximum Reserved Under-Utilized Path\n"
      "Minimize the number of Transit Domains\n"
      "Minimize the number of Border Nodes\n"
      "Minimize the number of Common Transit Domains\n"
      "Minimize the number of Shared Links\n"
      "Minimize the number of Shared SRLGs\n"
      "Minimize the number of Shared Nodes\n"
      "Required constraint\n")
{
	char xpath[XPATH_CANDIDATE_MAXLEN];
	nb_cli_enqueue_change(vty, "./constraints/objective-function",
	                      NB_OP_DESTROY, NULL);
	snprintf(xpath, sizeof(xpath),
	         "./constraints/objective-function/required");
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      required ? "true" : "false");
	nb_cli_enqueue_change(vty, "./constraints/objective-function/type",
	                      NB_OP_MODIFY, type);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_candidate_no_objfun,
      srte_candidate_no_objfun_cmd,
      "no objective-function [<mcp|mlp|mbp|mbc|mll|mcc|spt|mct|mplp|mup|mrup|mtd|mbn|mctd|msl|mss|msn>] [required$required]",
      NO_STR
      "Remove an objective function constraint\n"
      "Minimum Cost Path\n"
      "Minimum Load Path\n"
      "Maximum residual Bandwidth Path\n"
      "Minimize aggregate Bandwidth Consumption\n"
      "Minimize the Load of the most loaded Link\n"
      "Minimize the Cumulative Cost of a set of paths\n"
      "Shortest Path Tree\n"
      "Minimum Cost Tree\n"
      "Minimum Packet Loss Path\n"
      "Maximum Under-Utilized Path\n"
      "Maximum Reserved Under-Utilized Path\n"
      "Minimize the number of Transit Domains\n"
      "Minimize the number of Border Nodes\n"
      "Minimize the number of Common Transit Domains\n"
      "Minimize the number of Shared Links\n"
      "Minimize the number of Shared SRLGs\n"
      "Minimize the number of Shared Nodes\n"
      "Required constraint\n")
{
	nb_cli_enqueue_change(vty, "./constraints/objective-function",
	                      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static const char *objfun_type_name(enum objfun_type type)
{
	switch (type) {
	case OBJFUN_MCP:
		return "mcp";
	case OBJFUN_MLP:
		return "mlp";
	case OBJFUN_MBP:
		return "mbp";
	case OBJFUN_MBC:
		return "mbc";
	case OBJFUN_MLL:
		return "mll";
	case OBJFUN_MCC:
		return "mcc";
	case OBJFUN_SPT:
		return "spt";
	case OBJFUN_MCT:
		return "mct";
	case OBJFUN_MPLP:
		return "mplp";
	case OBJFUN_MUP:
		return "mup";
	case OBJFUN_MRUP:
		return "mrup";
	case OBJFUN_MTD:
		return "mtd";
	case OBJFUN_MBN:
		return "mbn";
	case OBJFUN_MCTD:
		return "mctd";
	case OBJFUN_MSL:
		return "msl";
	case OBJFUN_MSS:
		return "mss";
	case OBJFUN_MSN:
		return "msn";
	case OBJFUN_UNDEFINED:
		return NULL;
	}

	assert(!"Reached end of function we should never hit");
}

DEFPY_NOSH(show_debugging_pathd, show_debugging_pathd_cmd,
	   "show debugging [pathd]",
	   SHOW_STR
	   "State of each debugging option\n"
	   "pathd module debugging\n")
{

	vty_out(vty, "Path debugging status:\n");

	cmd_show_lib_debugs(vty);
	/* nothing to do here */
	path_ted_show_debugging(vty);
	path_policy_show_debugging(vty);
	return CMD_SUCCESS;
}

DEFPY(debug_path_policy, debug_path_policy_cmd, "[no] debug pathd policy",
      NO_STR DEBUG_STR
      "path debugging\n"
      "policy debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no_debug = no;

	DEBUG_MODE_SET(&path_policy_debug, mode, !no);
	DEBUG_FLAGS_SET(&path_policy_debug, PATH_POLICY_DEBUG_BASIC, !no_debug);
	return CMD_SUCCESS;
}

static const char *metric_type_name(enum srte_candidate_metric_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_IGP:
		return "igp";
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		return "te";
	case SRTE_CANDIDATE_METRIC_TYPE_HC:
		return "hc";
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		return "abc";
	case SRTE_CANDIDATE_METRIC_TYPE_LMLL:
		return "lmll";
	case SRTE_CANDIDATE_METRIC_TYPE_CIGP:
		return "cigp";
	case SRTE_CANDIDATE_METRIC_TYPE_CTE:
		return "cte";
	case SRTE_CANDIDATE_METRIC_TYPE_PIGP:
		return "pigp";
	case SRTE_CANDIDATE_METRIC_TYPE_PTE:
		return "pte";
	case SRTE_CANDIDATE_METRIC_TYPE_PHC:
		return "phc";
	case SRTE_CANDIDATE_METRIC_TYPE_MSD:
		return "msd";
	case SRTE_CANDIDATE_METRIC_TYPE_PD:
		return "pd";
	case SRTE_CANDIDATE_METRIC_TYPE_PDV:
		return "pdv";
	case SRTE_CANDIDATE_METRIC_TYPE_PL:
		return "pl";
	case SRTE_CANDIDATE_METRIC_TYPE_PPD:
		return "ppd";
	case SRTE_CANDIDATE_METRIC_TYPE_PPDV:
		return "ppdv";
	case SRTE_CANDIDATE_METRIC_TYPE_PPL:
		return "ppl";
	case SRTE_CANDIDATE_METRIC_TYPE_NAP:
		return "nap";
	case SRTE_CANDIDATE_METRIC_TYPE_NLP:
		return "nlp";
	case SRTE_CANDIDATE_METRIC_TYPE_DC:
		return "dc";
	case SRTE_CANDIDATE_METRIC_TYPE_BNC:
		return "bnc";
	default:
		return NULL;
	}
}

static void config_write_float(struct vty *vty, float value)
{
	if (fabs(truncf(value) - value) < FLT_EPSILON) {
		vty_out(vty, " %d", (int)value);
		return;
	} else {
		vty_out(vty, " %f", value);
	}
}

static void config_write_metric(struct vty *vty,
				enum srte_candidate_metric_type type,
				float value, bool required, bool is_bound,
				bool is_computed)
{
	const char *name = metric_type_name(type);
	if (name == NULL)
		return;
	vty_out(vty, "    metric %s%s", is_bound ? "bound " : "",
	        metric_type_name(type));
	config_write_float(vty, value);
	vty_out(vty, required ? " required" : "");
	vty_out(vty, is_computed ? " computed" : "");
	vty_out(vty, "\n");
}

static int config_write_metric_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;
	enum srte_candidate_metric_type type;
	bool required, is_bound = false, is_computed = false;
	float value;

	type = yang_dnode_get_enum(dnode, "type");
	value = (float)yang_dnode_get_dec64(dnode, "value");
	required = yang_dnode_get_bool(dnode, "required");
	if (yang_dnode_exists(dnode, "is-bound"))
		is_bound = yang_dnode_get_bool(dnode, "is-bound");
	if (yang_dnode_exists(dnode, "is-computed"))
		is_computed = yang_dnode_get_bool(dnode, "is-computed");

	config_write_metric(vty, type, value, required, is_bound, is_computed);
	return YANG_ITER_CONTINUE;
}

void cli_show_srte_policy_candidate_path(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults)
{
	float bandwidth;
	uint32_t affinity;
	bool required;
	enum objfun_type objfun_type;
	const char *type = yang_dnode_get_string(dnode, "type");

	vty_out(vty, "   candidate-path preference %s name %s %s",
		yang_dnode_get_string(dnode, "preference"),
		yang_dnode_get_string(dnode, "name"), type);
	if (strmatch(type, "explicit"))
		vty_out(vty, " segment-list %s",
			yang_dnode_get_string(dnode, "segment-list-name"));
	vty_out(vty, "\n");

	if (strmatch(type, "dynamic")) {
		if (yang_dnode_exists(dnode, "constraints/bandwidth")) {
			bandwidth = (float)yang_dnode_get_dec64(
				dnode, "./constraints/bandwidth/value");
			required = yang_dnode_get_bool(
				dnode, "./constraints/bandwidth/required");
			vty_out(vty, "    bandwidth");
			config_write_float(vty, bandwidth);
			if (required)
				vty_out(vty, " required");
			vty_out(vty, "\n");
		}
		if (yang_dnode_exists(dnode,
				      "./constraints/affinity/exclude-any")) {
			affinity = yang_dnode_get_uint32(
				dnode, "./constraints/affinity/exclude-any");
			vty_out(vty, "    affinity exclude-any 0x%08x\n",
				affinity);
		}
		if (yang_dnode_exists(dnode,
				      "./constraints/affinity/include-any")) {
			affinity = yang_dnode_get_uint32(
				dnode, "./constraints/affinity/include-any");
			vty_out(vty, "    affinity include-any 0x%08x\n",
				affinity);
		}
		if (yang_dnode_exists(dnode,
				      "./constraints/affinity/include-all")) {
			affinity = yang_dnode_get_uint32(
				dnode, "./constraints/affinity/include-all");
			vty_out(vty, "    affinity include-all 0x%08x\n",
				affinity);
		}
		yang_dnode_iterate(config_write_metric_cb, vty, dnode,
				   "./constraints/metrics");
		if (yang_dnode_exists(dnode,
		                      "./constraints/objective-function")) {
			objfun_type = yang_dnode_get_enum(dnode,
				"./constraints/objective-function/type");
			required = yang_dnode_get_bool(dnode,
				"./constraints/objective-function/required");
			vty_out(vty, "    objective-function %s%s\n",
			        objfun_type_name(objfun_type),
				required ? " required" : "");
		}
	}
}

void cli_show_srte_policy_candidate_path_end(struct vty *vty,
					     const struct lyd_node *dnode)
{
	const char *type = yang_dnode_get_string(dnode, "type");

	if (strmatch(type, "dynamic"))
		vty_out(vty, "   exit\n");
}

static int config_write_dnode(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;

	nb_cli_show_dnode_cmds(vty, dnode, false);

	return YANG_ITER_CONTINUE;
}

int config_write_segment_routing(struct vty *vty)
{
	vty_out(vty, "segment-routing\n");
	vty_out(vty, " traffic-eng\n");

	path_ted_config_write(vty);

	yang_dnode_iterate(config_write_dnode, vty, running_config->dnode,
			   "/frr-pathd:pathd/srte/segment-list");
	yang_dnode_iterate(config_write_dnode, vty, running_config->dnode,
			   "/frr-pathd:pathd/srte/policy");

	hook_call(pathd_srte_config_write, vty);

	vty_out(vty, " exit\n");
	vty_out(vty, "exit\n");

	return 1;
}

static int path_policy_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&path_policy_debug, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&path_policy_debug,
				      PATH_POLICY_DEBUG_BASIC))
			vty_out(vty, "debug pathd policy\n");
		return 1;
	}
	return 0;
}

static int path_policy_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&path_policy_debug, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&path_policy_debug, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&path_policy_debug);

	return 0;
}

void path_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      path_policy_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, path_policy_cli_debug_set_all);

	install_node(&segment_routing_node);
	install_node(&sr_traffic_eng_node);
	install_node(&srte_segment_list_node);
	install_node(&srte_policy_node);
	install_node(&srte_candidate_dyn_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SR_TRAFFIC_ENG_NODE);
	install_default(SR_SEGMENT_LIST_NODE);
	install_default(SR_POLICY_NODE);
	install_default(SR_CANDIDATE_DYN_NODE);

	install_element(ENABLE_NODE, &show_debugging_pathd_cmd);
	install_element(ENABLE_NODE, &show_srte_policy_cmd);
	install_element(ENABLE_NODE, &show_srte_policy_detail_cmd);

	install_element(ENABLE_NODE, &debug_path_policy_cmd);
	install_element(CONFIG_NODE, &debug_path_policy_cmd);

	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &sr_traffic_eng_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &srte_segment_list_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &srte_no_segment_list_cmd);
	install_element(SR_SEGMENT_LIST_NODE,
			&srte_segment_list_segment_cmd);
	install_element(SR_SEGMENT_LIST_NODE,
			&srte_segment_list_no_segment_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &srte_policy_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &srte_no_policy_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_name_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_no_name_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_binding_sid_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_no_binding_sid_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_candidate_exp_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_candidate_dyn_cmd);
	install_element(SR_POLICY_NODE, &srte_policy_no_candidate_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_bandwidth_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_no_bandwidth_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_affinity_filter_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_no_affinity_filter_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_metric_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_no_metric_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_objfun_cmd);
	install_element(SR_CANDIDATE_DYN_NODE,
			&srte_candidate_no_objfun_cmd);
}
