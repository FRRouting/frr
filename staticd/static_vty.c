// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vty code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "vrf.h"
#include "prefix.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"
#ifdef HAVE_STATICD_MGMTD
#include "mgmt_be_client.h"
#endif /* HAVE_STATICD_MGMTD */
#include "mpls.h"
#ifdef HAVE_STATICD_NB
#include "northbound.h"
#include "routing_nb.h"
#include "northbound_cli.h"
#endif /* HAVE_STATICD_NB */
#include "libfrr.h"
#include "frrdistance.h"

#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_debug.h"
#include "static_pm.h"
#include "staticd/static_vty_clippy.c"
#ifdef HAVE_STATICD_NB
#include "static_nb.h"
#endif /* HAVE_STATICD_NB */

#define STATICD_STR "Static route daemon\n"

#ifndef HAVE_STATICD_NB
#define CMD_ATTR_YANG 0

DEFINE_MTYPE_STATIC(STATIC, STATIC_ARGS, "Static config args");
DEFINE_MTYPE_STATIC(STATIC, STATIC_ARGS_ATTR, "Static config args attributes");


static void static_args_set_prefix(struct static_route_args *args, struct prefix *p)
{
	struct in_addr mask;

	memset(p, 0, sizeof(struct prefix));
	assert(!!str2prefix(args->prefix, p));
	str2prefix(args->prefix, p);
	if (args->afi == AFI_IP && args->prefix_mask) {
		/* Cisco like mask notation. */
		inet_pton(AF_INET, args->prefix_mask, &mask);
		p->prefixlen = ip_masklen(mask);
	}
	/* Apply mask for given prefix. */
	apply_mask(p);
}

static struct static_route_args *static_args_find(struct static_vrf *svrf,
						  struct static_route_args *args)
{
	struct static_route_args *run_args;

	frr_each(static_route_args_list, &svrf->route_args_list, run_args) {
		if (run_args->afi != args->afi)
			continue;
		if (run_args->safi != args->safi)
			continue;

		if (!prefix_same(&run_args->p, &args->p))
			continue;

		/* compare args attributes except values that can be overriden:
		 * - labels,
		 * - color,
		 * - segs,
		 * - tags
		 * - onlink
		 * - pm
		 * - distance
		 * - bfd arguments
		 * - blackhole flags */
		if ((!!run_args->gateway != !!args->gateway) ||
		    ((run_args->gateway && args->gateway &&
		      strcmp(run_args->gateway, args->gateway))))
			continue;
		if ((!!run_args->interface_name != !!args->interface_name) ||
		    ((run_args->interface_name && args->interface_name &&
		      strcmp(run_args->interface_name, args->interface_name))))
			continue;
		if ((!!run_args->source != !!args->source) ||
		    ((run_args->source && args->source && strcmp(run_args->source, args->source))))
			continue;
		if ((!!run_args->nexthop_vrf != !!args->nexthop_vrf) ||
		    ((run_args->nexthop_vrf && args->nexthop_vrf &&
		      strcmp(run_args->nexthop_vrf, args->nexthop_vrf))))
			continue;
		if ((!!run_args->table != !!args->table) ||
		    ((run_args->table && args->table && strcmp(run_args->table, args->table))))
			continue;

		return run_args;
	}

	return NULL;
}

static struct static_route_args *static_args_copy(struct static_route_args *args)
{
	struct static_route_args *run_args;

	run_args = XCALLOC(MTYPE_STATIC_ARGS, sizeof(struct static_route_args));

	run_args->onlink = args->onlink;
	run_args->pm = args->pm;
	run_args->bfd = args->bfd;
	run_args->bfd_auto_hop = args->bfd_auto_hop;
	run_args->bfd_multi_hop = args->bfd_multi_hop;
	run_args->afi = args->afi;
	run_args->safi = args->safi;

	prefix_copy(&run_args->p, &args->p);

	if (args->vrf)
		run_args->vrf = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->vrf);
	if (args->nexthop_vrf)
		run_args->nexthop_vrf = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->nexthop_vrf);
	if (args->prefix)
		run_args->prefix = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->prefix);
	if (args->prefix_mask)
		run_args->prefix_mask = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->prefix_mask);
	if (args->source)
		run_args->source = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->source);
	if (args->gateway)
		run_args->gateway = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->gateway);
	if (args->interface_name)
		run_args->interface_name = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->interface_name);
	if (args->segs)
		run_args->segs = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->segs);
	if (args->flag)
		run_args->flag = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->flag);
	if (args->tag)
		run_args->tag = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->tag);
	if (args->distance)
		run_args->distance = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->distance);
	if (args->label)
		run_args->label = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->label);
	if (args->table)
		run_args->table = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->table);
	if (args->color)
		run_args->color = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->color);
	if (args->bfd_profile)
		run_args->bfd_profile = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->bfd_profile);
	if (args->bfd_source)
		run_args->bfd_source = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, args->bfd_source);

	return run_args;
}

static void static_args_update_string(char **dst, const char *src)
{
	if (*dst && src) {
		if (strcmp(*dst, src) != 0) {
			XFREE(MTYPE_STATIC_ARGS_ATTR, *dst);
			*dst = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, src);
		}
	} else if (!*dst && src) {
		*dst = XSTRDUP(MTYPE_STATIC_ARGS_ATTR, src);
	} else if (*dst && !src) {
		XFREE(MTYPE_STATIC_ARGS_ATTR, *dst);
		*dst = NULL;
	}
}

static void static_args_update(struct static_route_args *dst_args,
			       struct static_route_args *src_args)
{
	dst_args->onlink = src_args->onlink;
	dst_args->pm = src_args->pm;
	dst_args->bfd = src_args->bfd;
	dst_args->bfd_auto_hop = src_args->bfd_auto_hop;
	dst_args->bfd_multi_hop = src_args->bfd_multi_hop;

	static_args_update_string((char **)&dst_args->bfd_source, src_args->bfd_source);
	static_args_update_string((char **)&dst_args->bfd_profile, src_args->bfd_profile);
	static_args_update_string((char **)&dst_args->color, src_args->color);
	static_args_update_string((char **)&dst_args->label, src_args->label);
	static_args_update_string((char **)&dst_args->segs, src_args->segs);
}

static void static_args_free_arg(void **arg)
{
	if (*arg) {
		XFREE(MTYPE_STATIC_ARGS_ATTR, *arg);
		*arg = NULL;
	}
}

void static_args_free(struct static_route_args *args)
{
	static_args_free_arg((void **)&args->vrf);
	static_args_free_arg((void **)&args->nexthop_vrf);
	static_args_free_arg((void **)&args->prefix);
	static_args_free_arg((void **)&args->prefix_mask);
	static_args_free_arg((void **)&args->source);
	static_args_free_arg((void **)&args->gateway);
	static_args_free_arg((void **)&args->interface_name);
	static_args_free_arg((void **)&args->segs);
	static_args_free_arg((void **)&args->flag);
	static_args_free_arg((void **)&args->tag);
	static_args_free_arg((void **)&args->distance);
	static_args_free_arg((void **)&args->label);
	static_args_free_arg((void **)&args->table);
	static_args_free_arg((void **)&args->color);
	static_args_free_arg((void **)&args->bfd_profile);
	static_args_free_arg((void **)&args->bfd_source);

	XFREE(MTYPE_STATIC_ARGS, args);
}
#endif /* !HAVE_STATICD_NB */

#ifdef HAVE_STATICD_NB
static int static_route_nb_run(struct vty *vty, struct static_route_args *args)
{
	int ret;
	struct prefix p, src;
	struct in_addr mask;
	enum static_nh_type type;
	const char *bh_type;
	char xpath_prefix[XPATH_MAXLEN];
	char xpath_nexthop[XPATH_MAXLEN];
	char xpath_mpls[XPATH_MAXLEN];
	char xpath_label[XPATH_MAXLEN];
	char xpath_segs[XPATH_MAXLEN];
	char xpath_seg[XPATH_MAXLEN];
	char ab_xpath[XPATH_MAXLEN];
	char buf_prefix[PREFIX_STRLEN];
	char buf_src_prefix[PREFIX_STRLEN] = {};
	char buf_nh_type[PREFIX_STRLEN] = {};
	char buf_tag[PREFIX_STRLEN];
	uint8_t label_stack_id = 0;
	uint8_t segs_stack_id = 0;
	char *orig_label = NULL, *orig_seg = NULL;
	const char *buf_gate_str;
	uint8_t distance = ZEBRA_STATIC_DISTANCE_DEFAULT;
	route_tag_t tag = 0;
	uint32_t table_id = 0;
	const struct lyd_node *dnode;
	const struct lyd_node *vrf_dnode;

	if (args->xpath_vrf) {
		vrf_dnode = yang_dnode_get(vty->candidate_config->dnode,
					   VTY_CURR_XPATH);
		if (vrf_dnode == NULL) {
			vty_out(vty,
				"%% Failed to get vrf dnode in candidate db\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		args->vrf = yang_dnode_get_string(vrf_dnode, "name");
	} else {
		if (args->vrf == NULL)
			args->vrf = VRF_DEFAULT_NAME;
	}
	if (args->nexthop_vrf == NULL)
		args->nexthop_vrf = args->vrf;

	if (args->bfd_multi_hop && args->bfd_auto_hop) {
		if (vty)
			vty_out(vty, "%% multi-hop and auto-hop options can not be used together\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (args->interface_name &&
	    !strcasecmp(args->interface_name, "Null0")) {
		args->flag = "Null0";
		args->interface_name = NULL;
	}

	if (!args->gateway && args->pm) {
		if (vty)
			vty_out(vty, "%% PM can not be set without gateway\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	assert(!!str2prefix(args->prefix, &p));

	switch (args->afi) {
	case AFI_IP:
		/* Cisco like mask notation. */
		if (args->prefix_mask) {
			assert(inet_pton(AF_INET, args->prefix_mask, &mask) ==
			       1);
			p.prefixlen = ip_masklen(mask);
		}
		break;
	case AFI_IP6:
		/* srcdest routing */
		if (args->source)
			assert(!!str2prefix(args->source, &src));
		break;
	case AFI_L2VPN:
	case AFI_LINKSTATE:
	case AFI_UNSPEC:
	case AFI_MAX:
		break;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);
	prefix2str(&p, buf_prefix, sizeof(buf_prefix));

	if (args->bfd && args->gateway == NULL) {
		vty_out(vty, "%% Route monitoring requires a gateway\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (args->source)
		prefix2str(&src, buf_src_prefix, sizeof(buf_src_prefix));
	if (args->gateway)
		buf_gate_str = args->gateway;
	else
		buf_gate_str = "";

	if (args->gateway == NULL && args->interface_name == NULL)
		type = STATIC_BLACKHOLE;
	else if (args->gateway && args->interface_name) {
		if (args->afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY_IFNAME;
		else
			type = STATIC_IPV6_GATEWAY_IFNAME;
	} else if (args->interface_name)
		type = STATIC_IFNAME;
	else {
		if (args->afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY;
		else
			type = STATIC_IPV6_GATEWAY;
	}

	/* Administrative distance. */
	if (args->distance)
		distance = strtol(args->distance, NULL, 10);

	/* tag */
	if (args->tag)
		tag = strtoul(args->tag, NULL, 10);

	/* TableID */
	if (args->table)
		table_id = strtol(args->table, NULL, 10);

	static_get_nh_type(type, buf_nh_type, sizeof(buf_nh_type));
	if (!args->delete) {
		if (args->source)
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_SRC_NH_KEY_NO_DISTANCE_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 buf_src_prefix, table_id, buf_nh_type,
				 args->nexthop_vrf, buf_gate_str,
				 args->interface_name);
		else
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 table_id, buf_nh_type, args->nexthop_vrf,
				 buf_gate_str, args->interface_name);

		/*
		 * If there's already the same nexthop but with a different
		 * distance, then remove it for the replacement.
		 */
		dnode = yang_dnode_get(vty->candidate_config->dnode, ab_xpath);
		if (dnode) {
			dnode = yang_get_subtree_with_no_sibling(dnode);
			assert(dnode);
			yang_dnode_get_path(dnode, ab_xpath, XPATH_MAXLEN);

			nb_cli_enqueue_change(vty, ab_xpath, NB_OP_DESTROY,
					      NULL);
		}

		/* route + path procesing */
		if (args->source)
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_S_ROUTE_SRC_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 buf_src_prefix, table_id, distance);
		else
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_STATIC_ROUTE_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 table_id, distance);

		nb_cli_enqueue_change(vty, xpath_prefix, NB_OP_CREATE, NULL);

		/* Tag processing */
		snprintf(buf_tag, sizeof(buf_tag), "%u", tag);
		strlcpy(ab_xpath, xpath_prefix, sizeof(ab_xpath));
		strlcat(ab_xpath, FRR_STATIC_ROUTE_PATH_TAG_XPATH,
			sizeof(ab_xpath));
		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_MODIFY, buf_tag);

		/* nexthop processing */

		snprintf(ab_xpath, sizeof(ab_xpath),
			 FRR_STATIC_ROUTE_NH_KEY_XPATH, buf_nh_type,
			 args->nexthop_vrf, buf_gate_str, args->interface_name);
		strlcpy(xpath_nexthop, xpath_prefix, sizeof(xpath_nexthop));
		strlcat(xpath_nexthop, ab_xpath, sizeof(xpath_nexthop));
		nb_cli_enqueue_change(vty, xpath_nexthop, NB_OP_CREATE, NULL);

		if (type == STATIC_BLACKHOLE) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_BH_XPATH,
				sizeof(ab_xpath));

			/* Route flags */
			if (args->flag) {
				switch (args->flag[0]) {
				case 'r':
					bh_type = "reject";
					break;
				case 'b':
					bh_type = "unspec";
					break;
				case 'N':
					bh_type = "null";
					break;
				default:
					bh_type = NULL;
					break;
				}
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, bh_type);
			} else {
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "null");
			}
		}
		if (type == STATIC_IPV4_GATEWAY_IFNAME
		    || type == STATIC_IPV6_GATEWAY_IFNAME) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_ONLINK_XPATH,
				sizeof(ab_xpath));

			if (args->onlink)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "false");
		}
		if (type == STATIC_IPV4_GATEWAY ||
		    type == STATIC_IPV6_GATEWAY ||
		    type == STATIC_IPV4_GATEWAY_IFNAME ||
		    type == STATIC_IPV6_GATEWAY_IFNAME) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_COLOR_XPATH,
				sizeof(ab_xpath));
			if (args->color)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY,
						      args->color);

			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_PM_XPATH,
				sizeof(ab_xpath));

			if (args->pm)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "false");
		}
		if (args->label) {
			/* copy of label string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));

			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);

			orig_label = ostr = XSTRDUP(MTYPE_TMP, args->label);
			while ((nump = strsep(&ostr, "/")) != NULL) {
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_STATIC_ROUTE_NHLB_KEY_XPATH,
					 label_stack_id);
				strlcpy(xpath_label, xpath_mpls,
					sizeof(xpath_label));
				strlcat(xpath_label, ab_xpath,
					sizeof(xpath_label));
				nb_cli_enqueue_change(vty, xpath_label,
						      NB_OP_MODIFY, nump);
				label_stack_id++;
			}
		} else {
			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));
			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);
		}
		if (args->segs) {
			/* copy of seg string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			strlcpy(xpath_segs, xpath_nexthop, sizeof(xpath_segs));
			strlcat(xpath_segs, FRR_STATIC_ROUTE_NH_SRV6_SEGS_XPATH,
				sizeof(xpath_segs));

			nb_cli_enqueue_change(vty, xpath_segs, NB_OP_DESTROY,
					      NULL);

			orig_seg = ostr = XSTRDUP(MTYPE_TMP, args->segs);
			while ((nump = strsep(&ostr, "/")) != NULL) {
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_STATIC_ROUTE_NH_SRV6_KEY_SEG_XPATH,
					 segs_stack_id);
				strlcpy(xpath_seg, xpath_segs,
					sizeof(xpath_seg));
				strlcat(xpath_seg, ab_xpath, sizeof(xpath_seg));
				nb_cli_enqueue_change(vty, xpath_seg,
						      NB_OP_MODIFY, nump);
				segs_stack_id++;
			}
		} else {
			strlcpy(xpath_segs, xpath_nexthop, sizeof(xpath_segs));
			strlcat(xpath_segs, FRR_STATIC_ROUTE_NH_SRV6_SEGS_XPATH,
				sizeof(xpath_segs));
			nb_cli_enqueue_change(vty, xpath_segs, NB_OP_DESTROY,
					      NULL);
		}
		if (args->bfd) {
			char xpath_bfd[XPATH_MAXLEN];

			if (args->bfd_source) {
				strlcpy(xpath_bfd, xpath_nexthop,
					sizeof(xpath_bfd));
				strlcat(xpath_bfd,
					"/frr-staticd:bfd-monitoring/source",
					sizeof(xpath_bfd));
				nb_cli_enqueue_change(vty, xpath_bfd,
						      NB_OP_MODIFY,
						      args->bfd_source);
			}

			strlcpy(xpath_bfd, xpath_nexthop, sizeof(xpath_bfd));
			strlcat(xpath_bfd,
				"/frr-staticd:bfd-monitoring/multi-hop",
				sizeof(xpath_bfd));
			nb_cli_enqueue_change(vty, xpath_bfd, NB_OP_MODIFY,
					      args->bfd_multi_hop ? "true"
								  : "false");

			/* bfd auto-mode */
			strlcpy(xpath_bfd, xpath_nexthop, sizeof(xpath_bfd));
			strlcat(xpath_bfd,
				"/frr-staticd:bfd-monitoring/auto-hop",
				sizeof(xpath_bfd));
			nb_cli_enqueue_change(vty, xpath_bfd, NB_OP_MODIFY,
					      args->bfd_auto_hop ? "true" : "false");

			if (args->bfd_profile) {
				strlcpy(xpath_bfd, xpath_nexthop,
					sizeof(xpath_bfd));
				strlcat(xpath_bfd,
					"/frr-staticd:bfd-monitoring/profile",
					sizeof(xpath_bfd));
				nb_cli_enqueue_change(vty, xpath_bfd,
						      NB_OP_MODIFY,
						      args->bfd_profile);
			}
		}

		ret = nb_cli_apply_changes(vty, "%s", xpath_prefix);

		if (orig_label)
			XFREE(MTYPE_TMP, orig_label);
		if (orig_seg)
			XFREE(MTYPE_TMP, orig_seg);
	} else {
		if (args->source) {
			if (args->distance)
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_DEL_S_ROUTE_SRC_NH_KEY_XPATH,
					 "frr-staticd:staticd", "staticd",
					 args->vrf, buf_prefix,
					 yang_afi_safi_value2identity(
						 args->afi, args->safi),
					 buf_src_prefix, table_id, distance,
					 buf_nh_type, args->nexthop_vrf,
					 buf_gate_str, args->interface_name);
			else
				snprintf(
					ab_xpath, sizeof(ab_xpath),
					FRR_DEL_S_ROUTE_SRC_NH_KEY_NO_DISTANCE_XPATH,
					"frr-staticd:staticd", "staticd",
					args->vrf, buf_prefix,
					yang_afi_safi_value2identity(
						args->afi, args->safi),
					buf_src_prefix, table_id, buf_nh_type,
					args->nexthop_vrf, buf_gate_str,
					args->interface_name);
		} else {
			if (args->distance)
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_DEL_S_ROUTE_NH_KEY_XPATH,
					 "frr-staticd:staticd", "staticd",
					 args->vrf, buf_prefix,
					 yang_afi_safi_value2identity(
						 args->afi, args->safi),
					 table_id, distance, buf_nh_type,
					 args->nexthop_vrf, buf_gate_str,
					 args->interface_name);
			else
				snprintf(
					ab_xpath, sizeof(ab_xpath),
					FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH,
					"frr-staticd:staticd", "staticd",
					args->vrf, buf_prefix,
					yang_afi_safi_value2identity(
						args->afi, args->safi),
					table_id, buf_nh_type,
					args->nexthop_vrf, buf_gate_str,
					args->interface_name);
		}

		dnode = yang_dnode_get(vty->candidate_config->dnode, ab_xpath);
		if (!dnode) {
			vty_out(vty,
				"%% Refusing to remove a non-existent route\n");
			return CMD_SUCCESS;
		}

		dnode = yang_get_subtree_with_no_sibling(dnode);
		assert(dnode);
		yang_dnode_get_path(dnode, ab_xpath, XPATH_MAXLEN);

		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_DESTROY, NULL);
		ret = nb_cli_apply_changes(vty, "%s", ab_xpath);
	}

	return ret;
}
static int static_route_configure(struct vty *vty, struct static_route_args *args)
{
	return static_route_nb_run(vty, args);
}
#else
/* !HAVE_STATICD_NB */
static inline int static_route_args_cmp(const struct static_route_args *a,
					const struct static_route_args *b)
{
	const char *a_gw, *b_gw, *a_if, *b_if;
	int cmp;

	if (a->afi != b->afi)
		return (a->afi < b->afi) ? -1 : 1;

	if (a->safi != b->safi)
		return (a->safi < b->safi) ? -1 : 1;

	/* Compare based on AFI */
	if (a->afi == AFI_IP) {
		/* IPv4: Compare by prefix address (uint32_t) */
		if (a->p.u.prefix4.s_addr != b->p.u.prefix4.s_addr)
			return (a->p.u.prefix4.s_addr < b->p.u.prefix4.s_addr) ? -1 : 1;
	} else {
		/* IPv6: Compare by prefix (memcmp) */
		cmp = memcmp(&a->p.u.prefix6, &b->p.u.prefix6, IPV6_MAX_BYTELEN);
		if (cmp != 0)
			return cmp;
	}

	/* Same prefix address, compare prefix length */
	if (a->p.prefixlen != b->p.prefixlen)
		return (a->p.prefixlen < b->p.prefixlen) ? -1 : 1;

	/* Prefix and prefix length are identical, compare gateway strings */
	a_gw = a->gateway ? a->gateway : "";
	b_gw = b->gateway ? b->gateway : "";
	cmp = strcmp(a_gw, b_gw);
	if (cmp != 0)
		return cmp;

	/* Gateways are identical, compare interface names */
	a_if = a->interface_name ? a->interface_name : "";
	b_if = b->interface_name ? b->interface_name : "";
	cmp = strcmp(a_if, b_if);
	if (cmp != 0)
		return cmp;

	return 0;
}

static void static_route_args_add(struct static_route_args *args, struct static_vrf *svrf)
{
	struct static_route_args *run_args, *iter_args = NULL, *iter_args_prev = NULL;

	run_args = static_args_copy(args);

	/* Insert maintaining sorted order */
	frr_each (static_route_args_list, &svrf->route_args_list, iter_args) {
		/* If run_args should come before iter_args */
		if (static_route_args_cmp(run_args, iter_args) < 0)
			break;

		iter_args_prev = iter_args;
	}

	static_route_args_list_add_after(&svrf->route_args_list, iter_args_prev, run_args);
}

static void static_route_args_del(struct static_route_args *args, struct static_vrf *svrf)
{
	static_route_args_list_del(&svrf->route_args_list, args);
	static_args_free(args);
}

static int static_route_configure(struct vty *vty, struct static_route_args *args)
{
	struct static_route_args *run_args;
	struct prefix p = {};
	struct static_vrf *svrf;

	if (args->interface_name && (!strcasecmp(args->interface_name, "reject") ||
				     !strcasecmp(args->interface_name, "blackhole"))) {
		vty_out(vty,
			"Nexthop interface name can not be from reserved keywords (reject, blackhole)\n");
		return CMD_WARNING;
	}

	if (args->vrf == NULL)
		args->vrf = VRF_DEFAULT_NAME;

	svrf = static_vrf_lookup_by_name(args->vrf);
	if (!svrf)
		svrf = static_vrf_alloc(args->vrf);

	if (args->nexthop_vrf == NULL)
		args->nexthop_vrf = args->vrf;

	if (args->interface_name && !strcasecmp(args->interface_name, "Null0")) {
		args->flag = "Null0";
		args->interface_name = NULL;
	}

	/* set prefix from args */
	static_args_set_prefix(args, &p);

	prefix_copy(&args->p, &p);

	run_args = static_args_find(svrf, args);

	if (args->delete && !run_args)
		/* nothing to delete */
		return CMD_SUCCESS;

	if (args->delete) {
		/* delete the existing configuration */
		static_route_args_del(run_args, svrf);

		return CMD_SUCCESS;
	}

	if (run_args) {
		/* Update route an existing route */
		static_args_update(run_args, args);

		return CMD_SUCCESS;
	}

	/* Add a new route */
	static_route_args_add(args, svrf);

	return CMD_SUCCESS;
}
#endif /* !HAVE_STATICD_NB */

/* Static unicast routes for multicast RPF lookup. */
DEFPY_YANG (ip_mroute_dist,
       ip_mroute_dist_cmd,
       "[no] ip mroute A.B.C.D/M$prefix <A.B.C.D$gate|INTERFACE$ifname> [{"
       "(1-255)$distance"
       "|bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}]"
       "}]",
       NO_STR
       IP_STR
       "Configure static unicast route into MRIB for multicast RPF lookup\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Nexthop address\n"
       "Nexthop interface name\n"
       "Distance\n"
       BFD_INTEGRATION_STR
       BFD_INTEGRATION_MULTI_HOP_STR
       BFD_INTEGRATION_SOURCE_STR
       BFD_INTEGRATION_SOURCEV4_STR
       BFD_AUTOHOP_MODE_STR
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_MULTICAST,
		.prefix = prefix_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.distance = distance_str,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_configure(vty, &args);
}

/* Static route configuration.  */
DEFPY_YANG(ip_route_blackhole,
      ip_route_blackhole_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask>                        \
	<reject|blackhole>$flag                                               \
	[{                                                                    \
	  tag (1-4294967295)                                                  \
	  |(1-255)$distance                                                   \
	  |vrf NAME                                                           \
	  |label WORD                                                         \
          |table (1-4294967295)                                               \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.vrf = vrf,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ip_route_blackhole_vrf,
      ip_route_blackhole_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask>                        \
	<reject|blackhole>$flag                                               \
	[{                                                                    \
	  tag (1-4294967295)                                                  \
	  |(1-255)$distance                                                   \
	  |label WORD                                                         \
	  |table (1-4294967295)                                               \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
	};

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(args.prefix);

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ip_route_address_interface,
      ip_route_address_interface_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	<INTERFACE|Null0>$ifname                       \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |onlink$onlink                               \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	  |pm$pm                                       \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_AUTOHOP_MODE_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR
      "Enables Path Monitoring support\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ip_route_address_interface_vrf,
      ip_route_address_interface_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	<INTERFACE|Null0>$ifname                       \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |onlink$onlink                               \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	  |pm$pm                                       \
	  }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_AUTOHOP_MODE_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR
      "Enables Path Monitoring support\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_auto_hop = !!bfdauto,
		.bfd_profile = bfd_profile,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ip_route,
      ip_route_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|<INTERFACE|Null0>$ifname>        \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	  |pm$pm                                       \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_AUTOHOP_MODE_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR
      "Enables Path Monitoring support\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ip_route_vrf,
      ip_route_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|<INTERFACE|Null0>$ifname>        \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	  |pm$pm                                       \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_AUTOHOP_MODE_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR
      "Enables Path Monitoring support\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route_blackhole,
      ipv6_route_blackhole_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <reject|blackhole>$flag                          \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
            |table (1-4294967295)                          \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.vrf = vrf,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route_blackhole_vrf,
      ipv6_route_blackhole_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <reject|blackhole>$flag                          \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
            |table (1-4294967295)                          \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
	};

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(args.prefix);

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route_address_interface, ipv6_route_address_interface_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          <INTERFACE|Null0>$ifname                         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |onlink$onlink                                 \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	    |pm$pm                                         \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" VRF_CMD_HELP_STR MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR
	   "Treat the nexthop as directly attached to the interface\n"
	   "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_AUTOHOP_MODE_STR
				   BFD_PROFILE_STR BFD_PROFILE_NAME_STR
	   "Enables Path Monitoring support\n"
	   "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route_address_interface_vrf,
	   ipv6_route_address_interface_vrf_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          <INTERFACE|Null0>$ifname                         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |onlink$onlink                                 \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	    |pm$pm                                         \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR
	   "Treat the nexthop as directly attached to the interface\n"
	   "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_AUTOHOP_MODE_STR
				   BFD_PROFILE_STR BFD_PROFILE_NAME_STR
	   "Enables Path Monitoring support\n"
	   "Value of segs\n"
	   "Segs (SIDs)\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route, ipv6_route_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
            |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	    |pm$pm                                         \
			|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" VRF_CMD_HELP_STR MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_AUTOHOP_MODE_STR
				   BFD_PROFILE_STR BFD_PROFILE_NAME_STR
	   "Enables Path Monitoring support\n"
	   "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

DEFPY_YANG(ipv6_route_vrf, ipv6_route_vrf_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|auto-hop$bfdauto|profile BFDPROF$bfd_profile}] \
	    |pm$pm                                         \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_AUTOHOP_MODE_STR
				   BFD_PROFILE_STR BFD_PROFILE_NAME_STR
	   "Enables Path Monitoring support\n"
	   "Value of segs\n"
	   "Segs (SIDs)\n")
{
#ifndef HAVE_STATICD_NB
	VTY_DECLVAR_CONTEXT(vrf, vrf);
#endif /* !HAVE_STATICD_NB */
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
#ifdef HAVE_STATICD_NB
		.xpath_vrf = true,
#else
		.vrf = vrf->name,
#endif
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_auto_hop = !!bfdauto,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
		.pm = !!pm,
	};

	return static_route_configure(vty, &args);
}

#ifdef HAVE_STATICD_NB
#if defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD)

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	void
	static_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "../vrf");
	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, "vrf %s\n", vrf);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	void
	static_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "../vrf");
	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, "exit-vrf\n");
}

struct mpls_label_iter {
	struct vty *vty;
	bool first;
};

static int mpls_label_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct mpls_label_iter *iter = arg;

	if (yang_dnode_exists(dnode, "label")) {
		if (iter->first)
			vty_out(iter->vty, " label %s",
				yang_dnode_get_string(dnode, "label"));
		else
			vty_out(iter->vty, "/%s",
				yang_dnode_get_string(dnode, "label"));
		iter->first = false;
	}

	return YANG_ITER_CONTINUE;
}

struct srv6_seg_iter {
	struct vty *vty;
	bool first;
};

static int srv6_seg_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct srv6_seg_iter *iter = arg;
	char buffer[INET6_ADDRSTRLEN];
	struct in6_addr cli_seg;

	if (yang_dnode_exists(dnode, "seg")) {
		if (iter->first) {
			yang_dnode_get_ipv6(&cli_seg, dnode, "seg");
			if (inet_ntop(AF_INET6, &cli_seg, buffer,
				      INET6_ADDRSTRLEN) == NULL) {
				return 1;
			}
			vty_out(iter->vty, " segments %s", buffer);
		} else {
			yang_dnode_get_ipv6(&cli_seg, dnode, "seg");
			if (inet_ntop(AF_INET6, &cli_seg, buffer,
				      INET6_ADDRSTRLEN) == NULL) {
				return 1;
			}
			vty_out(iter->vty, "/%s", buffer);
		}
		iter->first = false;
	}

	return YANG_ITER_CONTINUE;
}

static void nexthop_cli_show(struct vty *vty, const struct lyd_node *route,
			     const struct lyd_node *src,
			     const struct lyd_node *path,
			     const struct lyd_node *nexthop, bool show_defaults)
{
	const char *vrf;
	const char *afi_safi;
	afi_t afi;
	safi_t safi;
	enum static_nh_type nh_type;
	enum static_blackhole_type bh_type;
	uint32_t tag;
	uint8_t distance;
	struct mpls_label_iter iter;
	struct srv6_seg_iter seg_iter;
	const char *nexthop_vrf;
	uint32_t table_id;
	bool onlink;

	vrf = yang_dnode_get_string(route, "../../vrf");

	afi_safi = yang_dnode_get_string(route, "afi-safi");
	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (afi == AFI_IP)
		vty_out(vty, "%sip",
			strmatch(vrf, VRF_DEFAULT_NAME) ? "" : " ");
	else
		vty_out(vty, "%sipv6",
			strmatch(vrf, VRF_DEFAULT_NAME) ? "" : " ");

	if (safi == SAFI_UNICAST)
		vty_out(vty, " route");
	else
		vty_out(vty, " mroute");

	vty_out(vty, " %s", yang_dnode_get_string(route, "prefix"));

	if (src)
		vty_out(vty, " from %s",
			yang_dnode_get_string(src, "src-prefix"));

	nh_type = yang_dnode_get_enum(nexthop, "nh-type");
	switch (nh_type) {
	case STATIC_IFNAME:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "interface"));
		break;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "gateway"));
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "gateway"));
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "interface"));
		break;
	case STATIC_BLACKHOLE:
		bh_type = yang_dnode_get_enum(nexthop, "bh-type");
		switch (bh_type) {
		case STATIC_BLACKHOLE_DROP:
			vty_out(vty, " blackhole");
			break;
		case STATIC_BLACKHOLE_NULL:
			vty_out(vty, " Null0");
			break;
		case STATIC_BLACKHOLE_REJECT:
			vty_out(vty, " reject");
			break;
		}
		break;
	}

	if (yang_dnode_exists(path, "tag")) {
		tag = yang_dnode_get_uint32(path, "tag");
		if (tag != 0 || show_defaults)
			vty_out(vty, " tag %" PRIu32, tag);
	}

	distance = yang_dnode_get_uint8(path, "distance");
	if (distance != ZEBRA_STATIC_DISTANCE_DEFAULT || show_defaults)
		vty_out(vty, " %" PRIu8, distance);

	iter.vty = vty;
	iter.first = true;
	yang_dnode_iterate(mpls_label_iter_cb, &iter, nexthop,
			   "./mpls-label-stack/entry");

	seg_iter.vty = vty;
	seg_iter.first = true;
	yang_dnode_iterate(srv6_seg_iter_cb, &seg_iter, nexthop,
			   "./srv6-segs-stack/entry");

	nexthop_vrf = yang_dnode_get_string(nexthop, "vrf");
	if (strcmp(vrf, nexthop_vrf))
		vty_out(vty, " nexthop-vrf %s", nexthop_vrf);

	table_id = yang_dnode_get_uint32(path, "table-id");
	if (table_id || show_defaults)
		vty_out(vty, " table %" PRIu32, table_id);

	if (yang_dnode_exists(nexthop, "onlink")) {
		onlink = yang_dnode_get_bool(nexthop, "onlink");
		if (onlink)
			vty_out(vty, " onlink");
	}

	if (yang_dnode_exists(nexthop, "pm")
			&& yang_dnode_get_bool(nexthop, "pm"))
		vty_out(vty, " pm");

	if (yang_dnode_exists(nexthop, "srte-color"))
		vty_out(vty, " color %s",
			yang_dnode_get_string(nexthop, "srte-color"));

	if (yang_dnode_exists(nexthop, "bfd-monitoring")) {
		const struct lyd_node *bfd_dnode =
			yang_dnode_get(nexthop, "bfd-monitoring");

		if (yang_dnode_get_bool(bfd_dnode, "multi-hop")) {
			vty_out(vty, " bfd multi-hop");

			if (yang_dnode_exists(bfd_dnode, "source"))
				vty_out(vty, " source %s",
					yang_dnode_get_string(bfd_dnode,
							      "./source"));
		} else if (yang_dnode_get_bool(bfd_dnode, "./auto-hop"))
			vty_out(vty, " bfd auto-hop");
		else
			vty_out(vty, " bfd");

		if (yang_dnode_exists(bfd_dnode, "profile"))
			vty_out(vty, " profile %s",
				yang_dnode_get_string(bfd_dnode, "profile"));
	}

	vty_out(vty, "\n");
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	void
	static_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *path = yang_dnode_get_parent(dnode, "path-list");
	const struct lyd_node *route =
		yang_dnode_get_parent(path, "route-list");

	nexthop_cli_show(vty, route, NULL, path, dnode, show_defaults);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	void
	static_src_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *path = yang_dnode_get_parent(dnode, "path-list");
	const struct lyd_node *src = yang_dnode_get_parent(path, "src-list");
	const struct lyd_node *route = yang_dnode_get_parent(src, "route-list");

	nexthop_cli_show(vty, route, src, path, dnode, show_defaults);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	int
	static_nexthop_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2)
{
	enum static_nh_type nh_type1, nh_type2;
	struct prefix prefix1, prefix2;
	const char *vrf1, *vrf2;
	int ret = 0;

	nh_type1 = yang_dnode_get_enum(dnode1, "nh-type");
	nh_type2 = yang_dnode_get_enum(dnode2, "nh-type");

	if (nh_type1 != nh_type2)
		return (int)nh_type1 - (int)nh_type2;

	switch (nh_type1) {
	case STATIC_IFNAME:
		ret = if_cmp_name_func(
			yang_dnode_get_string(dnode1, "interface"),
			yang_dnode_get_string(dnode2, "interface"));
		break;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		yang_dnode_get_prefix(&prefix1, dnode1, "gateway");
		yang_dnode_get_prefix(&prefix2, dnode2, "gateway");
		ret = prefix_cmp(&prefix1, &prefix2);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		yang_dnode_get_prefix(&prefix1, dnode1, "gateway");
		yang_dnode_get_prefix(&prefix2, dnode2, "gateway");
		ret = prefix_cmp(&prefix1, &prefix2);
		if (!ret)
			ret = if_cmp_name_func(
				yang_dnode_get_string(dnode1, "interface"),
				yang_dnode_get_string(dnode2, "interface"));
		break;
	case STATIC_BLACKHOLE:
		/* There's only one blackhole nexthop per route */
		ret = 0;
		break;
	}

	if (ret)
		return ret;

	vrf1 = yang_dnode_get_string(dnode1, "vrf");
	if (strmatch(vrf1, "default"))
		vrf1 = "";
	vrf2 = yang_dnode_get_string(dnode2, "vrf");
	if (strmatch(vrf2, "default"))
		vrf2 = "";

	return if_cmp_name_func(vrf1, vrf2);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	int
	static_route_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2)
{
	const char *afi_safi1, *afi_safi2;
	afi_t afi1, afi2;
	safi_t safi1, safi2;
	struct prefix prefix1, prefix2;

	afi_safi1 = yang_dnode_get_string(dnode1, "afi-safi");
	yang_afi_safi_identity2value(afi_safi1, &afi1, &safi1);

	afi_safi2 = yang_dnode_get_string(dnode2, "afi-safi");
	yang_afi_safi_identity2value(afi_safi2, &afi2, &safi2);

	if (afi1 != afi2)
		return (int)afi1 - (int)afi2;

	if (safi1 != safi2)
		return (int)safi1 - (int)safi2;

	yang_dnode_get_prefix(&prefix1, dnode1, "prefix");
	yang_dnode_get_prefix(&prefix2, dnode2, "prefix");

	return prefix_cmp(&prefix1, &prefix2);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	int
	static_src_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2)
{
	struct prefix prefix1, prefix2;

	yang_dnode_get_prefix(&prefix1, dnode1, "src-prefix");
	yang_dnode_get_prefix(&prefix2, dnode2, "src-prefix");

	return prefix_cmp(&prefix1, &prefix2);
}

#ifdef HAVE_STATICD_MGMTD
static
#endif /* HAVE_STATICD_MGMTD */
	int
	static_path_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2)
{
	uint32_t table_id1, table_id2;
	uint8_t distance1, distance2;

	table_id1 = yang_dnode_get_uint32(dnode1, "table-id");
	table_id2 = yang_dnode_get_uint32(dnode2, "table-id");

	if (table_id1 != table_id2)
		return (int)table_id1 - (int)table_id2;

	distance1 = yang_dnode_get_uint8(dnode1, "distance");
	distance2 = yang_dnode_get_uint8(dnode2, "distance");

	return (int)distance1 - (int)distance2;
}

const struct frr_yang_module_info frr_staticd_cli_info = {
	.name = "frr-staticd",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd",
			.cbs = {
				.cli_show = static_cli_show,
				.cli_show_end = static_cli_show_end,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list",
			.cbs = {
				.cli_cmp = static_route_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list",
			.cbs = {
				.cli_cmp = static_path_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.cli_show = static_nexthop_cli_show,
				.cli_cmp = static_nexthop_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list",
			.cbs = {
				.cli_cmp = static_src_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list",
			.cbs = {
				.cli_cmp = static_path_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.cli_show = static_src_nexthop_cli_show,
				.cli_cmp = static_nexthop_cli_cmp,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

#endif /* defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD) */
#endif /* HAVE_STATICD_NB */

#if !defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD)
DEFPY_YANG(debug_staticd, debug_staticd_cmd,
	   "[no] debug static [{events$events|route$route|bfd$bfd|pm$pm}]",
	   NO_STR DEBUG_STR STATICD_STR
	   "Debug events\n"
	   "Debug route\n"
	   "Debug bfd\n"
	   "Debug pm\n")
{
	/* If no specific category, change all */
	if (strmatch(argv[argc - 1]->text, "static"))
		static_debug_set(vty->node, !no, true, true, true, true);
	else
		static_debug_set(vty->node, !no, !!events, !!route, !!bfd, !!pm);

	return CMD_SUCCESS;
}

DEFPY(staticd_show_bfd_routes, staticd_show_bfd_routes_cmd,
      "show bfd static route [json]$isjson",
      SHOW_STR
      BFD_INTEGRATION_STR
      STATICD_STR
      ROUTE_STR
      JSON_STR)
{
	static_bfd_show(vty, !!isjson);
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_static,
	    show_debugging_static_cmd,
	    "show debugging [static]",
	    SHOW_STR
	    DEBUG_STR
	    "Static Information\n")
{
	vty_out(vty, "Staticd debugging status\n");

	static_debug_status_write(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = static_config_write_debug,
};

#endif /* !defined (INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD) */

void static_vty_init(void)
{
#if !defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD)
	install_node(&debug_node);
	install_element(ENABLE_NODE, &debug_staticd_cmd);
	install_element(CONFIG_NODE, &debug_staticd_cmd);
	install_element(ENABLE_NODE, &show_debugging_static_cmd);
	install_element(ENABLE_NODE, &staticd_show_bfd_routes_cmd);
#endif /* !defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD) */

#if defined(INCLUDE_MGMTD_CMDDEFS_ONLY) || !defined(HAVE_STATICD_MGMTD)
	install_element(CONFIG_NODE, &ip_mroute_dist_cmd);

	install_element(CONFIG_NODE, &ip_route_blackhole_cmd);
	install_element(VRF_NODE, &ip_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_address_interface_cmd);
	install_element(VRF_NODE, &ip_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_cmd);
	install_element(VRF_NODE, &ip_route_vrf_cmd);

	install_element(CONFIG_NODE, &ipv6_route_blackhole_cmd);
	install_element(VRF_NODE, &ipv6_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_address_interface_cmd);
	install_element(VRF_NODE, &ipv6_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_cmd);
	install_element(VRF_NODE, &ipv6_route_vrf_cmd);
#endif /* defined(INCLUDE_MGMTD_CMDDEFS_ONLY)  || !defined(HAVE_STATICD_MGMTD) */

#if !defined(INCLUDE_MGMTD_CMDDEFS_ONLY) && defined(HAVE_STATICD_MGMTD)
	mgmt_be_client_lib_vty_init();
#endif /* !defined(INCLUDE_MGMTD_CMDDEFS_ONLY) && defined(HAVE_STATICD_MGMTD) */
}
