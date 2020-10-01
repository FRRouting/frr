/*
 * STATICd - vty code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "vrf.h"
#include "prefix.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"
#include "mpls.h"
#include "northbound.h"
#include "libfrr.h"
#include "routing_nb.h"
#include "northbound_cli.h"

#include "static_vrf.h"
#include "static_memory.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_debug.h"
#ifndef VTYSH_EXTRACT_PL
#include "staticd/static_vty_clippy.c"
#endif
#include "static_nb.h"

#define STATICD_STR "Static route daemon\n"

static int static_route_leak(struct vty *vty, const char *svrf,
			     const char *nh_svrf, afi_t afi, safi_t safi,
			     const char *negate, const char *dest_str,
			     const char *mask_str, const char *src_str,
			     const char *gate_str, const char *ifname,
			     const char *flag_str, const char *tag_str,
			     const char *distance_str, const char *label_str,
			     const char *table_str, bool onlink,
			     const char *color_str)
{
	int ret;
	struct prefix p, src;
	struct in_addr mask;
	uint8_t type;
	const char *bh_type;
	char xpath_prefix[XPATH_MAXLEN];
	char xpath_nexthop[XPATH_MAXLEN];
	char xpath_mpls[XPATH_MAXLEN];
	char xpath_label[XPATH_MAXLEN];
	char ab_xpath[XPATH_MAXLEN];
	char buf_prefix[PREFIX_STRLEN];
	char buf_src_prefix[PREFIX_STRLEN];
	char buf_nh_type[PREFIX_STRLEN];
	char buf_tag[PREFIX_STRLEN];
	char buf_tableid[PREFIX_STRLEN];
	uint8_t label_stack_id = 0;
	const char *buf_gate_str;
	uint8_t distance = ZEBRA_STATIC_DISTANCE_DEFAULT;
	route_tag_t tag = 0;
	uint32_t table_id = 0;
	const struct lyd_node *dnode;

	memset(buf_src_prefix, 0, PREFIX_STRLEN);
	memset(buf_nh_type, 0, PREFIX_STRLEN);

	ret = str2prefix(dest_str, &p);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	switch (afi) {
	case AFI_IP:
		/* Cisco like mask notation. */
		if (mask_str) {
			ret = inet_aton(mask_str, &mask);
			if (ret == 0) {
				vty_out(vty, "%% Malformed address\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			p.prefixlen = ip_masklen(mask);
		}
		break;
	case AFI_IP6:
		/* srcdest routing */
		if (src_str) {
			ret = str2prefix(src_str, &src);
			if (ret <= 0 || src.family != AF_INET6) {
				vty_out(vty, "%% Malformed source address\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
		break;
	default:
		break;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	prefix2str(&p, buf_prefix, sizeof(buf_prefix));

	if (src_str)
		prefix2str(&src, buf_src_prefix, sizeof(buf_src_prefix));
	if (gate_str)
		buf_gate_str = gate_str;
	else
		buf_gate_str = "";

	if (gate_str == NULL && ifname == NULL)
		type = STATIC_BLACKHOLE;
	else if (gate_str && ifname) {
		if (afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY_IFNAME;
		else
			type = STATIC_IPV6_GATEWAY_IFNAME;
	} else if (ifname)
		type = STATIC_IFNAME;
	else {
		if (afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY;
		else
			type = STATIC_IPV6_GATEWAY;
	}

	/* Administrative distance. */
	if (distance_str)
		distance = atoi(distance_str);
	else
		distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

	/* tag */
	if (tag_str)
		tag = strtoul(tag_str, NULL, 10);

	/* TableID */
	if (table_str)
		table_id = atol(table_str);

	static_get_nh_type(type, buf_nh_type, PREFIX_STRLEN);
	if (!negate) {
		/* route + path procesing */
		if (src_str)
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_S_ROUTE_SRC_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", svrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(afi, safi),
				 buf_src_prefix, distance);
		else
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_STATIC_ROUTE_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", svrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(afi, safi),
				 distance);

		nb_cli_enqueue_change(vty, xpath_prefix, NB_OP_CREATE, NULL);

		/* Tag processing */
		snprintf(buf_tag, sizeof(buf_tag), "%u", tag);
		strlcpy(ab_xpath, xpath_prefix, sizeof(ab_xpath));
		strlcat(ab_xpath, FRR_STATIC_ROUTE_PATH_TAG_XPATH,
			sizeof(ab_xpath));
		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_MODIFY, buf_tag);

		/* Table-Id processing */
		snprintf(buf_tableid, sizeof(buf_tableid), "%u", table_id);
		strlcpy(ab_xpath, xpath_prefix, sizeof(ab_xpath));
		strlcat(ab_xpath, FRR_STATIC_ROUTE_PATH_TABLEID_XPATH,
			sizeof(ab_xpath));
		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_MODIFY, buf_tableid);
		/* nexthop processing */

		snprintf(ab_xpath, sizeof(ab_xpath),
			 FRR_STATIC_ROUTE_NH_KEY_XPATH, buf_nh_type, nh_svrf,
			 buf_gate_str, ifname);
		strlcpy(xpath_nexthop, xpath_prefix, sizeof(xpath_nexthop));
		strlcat(xpath_nexthop, ab_xpath, sizeof(xpath_nexthop));
		nb_cli_enqueue_change(vty, xpath_nexthop, NB_OP_CREATE, NULL);

		if (type == STATIC_BLACKHOLE) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_BH_XPATH,
				sizeof(ab_xpath));

			/* Route flags */
			if (flag_str) {
				switch (flag_str[0]) {
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

			if (onlink)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "false");
		}
		if (type == STATIC_IPV4_GATEWAY
		    || type == STATIC_IPV6_GATEWAY
		    || type == STATIC_IPV4_GATEWAY_IFNAME
		    || type == STATIC_IPV6_GATEWAY_IFNAME) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_COLOR_XPATH,
				sizeof(ab_xpath));
			if (color_str)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, color_str);
		}
		if (label_str) {
			/* copy of label string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));

			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);

			ostr = XSTRDUP(MTYPE_TMP, label_str);
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
			XFREE(MTYPE_TMP, ostr);
		} else {
			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));
			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);
		}
		ret = nb_cli_apply_changes(vty, xpath_prefix);
	} else {
		if (src_str)
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_SRC_NH_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", svrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(afi, safi),
				 buf_src_prefix, distance, buf_nh_type, nh_svrf,
				 buf_gate_str, ifname);
		else
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_NH_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", svrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(afi, safi),
				 distance, buf_nh_type, nh_svrf, buf_gate_str,
				 ifname);

		dnode = yang_dnode_get(vty->candidate_config->dnode, ab_xpath);
		if (!dnode)
			return ret;

		dnode = yang_get_subtree_with_no_sibling(dnode);
		assert(dnode);
		yang_dnode_get_path(dnode, ab_xpath, XPATH_MAXLEN);

		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_DESTROY, NULL);
		ret = nb_cli_apply_changes(vty, ab_xpath);
	}

	return ret;
}
static int static_route(struct vty *vty, afi_t afi, safi_t safi,
			const char *negate, const char *dest_str,
			const char *mask_str, const char *src_str,
			const char *gate_str, const char *ifname,
			const char *flag_str, const char *tag_str,
			const char *distance_str, const char *vrf_name,
			const char *label_str, const char *table_str)
{
	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	return static_route_leak(vty, vrf_name, vrf_name, afi, safi, negate,
				 dest_str, mask_str, src_str, gate_str, ifname,
				 flag_str, tag_str, distance_str, label_str,
				 table_str, false, NULL);
}

/* Write static route configuration. */
int static_config(struct vty *vty, struct static_vrf *svrf, afi_t afi,
		  safi_t safi, const char *cmd)
{
	char spacing[100];
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct route_table *stable;
	struct static_route_info *si;
	char buf[SRCDEST2STR_BUFFER];
	int write = 0;
	struct stable_info *info;

	stable = svrf->stable[afi][safi];
	if (stable == NULL)
		return write;

	snprintf(spacing, sizeof(spacing), "%s%s",
		 (svrf->vrf->vrf_id == VRF_DEFAULT) ? "" : " ", cmd);

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		info = static_get_stable_info(rn);
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				vty_out(vty, "%s %s", spacing,
					srcdest_rnode2str(rn, buf,
							  sizeof(buf)));

				switch (nh->type) {
				case STATIC_IPV4_GATEWAY:
					vty_out(vty, " %s",
						inet_ntoa(nh->addr.ipv4));
					break;
				case STATIC_IPV6_GATEWAY:
					vty_out(vty, " %s",
						inet_ntop(AF_INET6,
							  &nh->addr.ipv6, buf,
							  sizeof(buf)));
					break;
				case STATIC_IFNAME:
					vty_out(vty, " %s", nh->ifname);
					break;
				case STATIC_BLACKHOLE:
					switch (nh->bh_type) {
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
				case STATIC_IPV4_GATEWAY_IFNAME:
					vty_out(vty, " %s %s",
						inet_ntop(AF_INET,
							  &nh->addr.ipv4, buf,
							  sizeof(buf)),
						nh->ifname);
					break;
				case STATIC_IPV6_GATEWAY_IFNAME:
					vty_out(vty, " %s %s",
						inet_ntop(AF_INET6,
							  &nh->addr.ipv6, buf,
							  sizeof(buf)),
						nh->ifname);
					break;
				}

				if (pn->tag)
					vty_out(vty, " tag %" ROUTE_TAG_PRI,
						pn->tag);

				if (pn->distance
				    != ZEBRA_STATIC_DISTANCE_DEFAULT)
					vty_out(vty, " %u", pn->distance);

				/* Label information */
				if (nh->snh_label.num_labels)
					vty_out(vty, " label %s",
						mpls_label2str(
							nh->snh_label
								.num_labels,
							nh->snh_label.label,
							buf, sizeof(buf), 0));

				if (!strmatch(nh->nh_vrfname,
					      info->svrf->vrf->name))
					vty_out(vty, " nexthop-vrf %s",
						nh->nh_vrfname);

				/*
				 * table ID from VRF overrides
				 * configured
				 */
				if (pn->table_id
				    && svrf->vrf->data.l.table_id
					       == RT_TABLE_MAIN)
					vty_out(vty, " table %u", pn->table_id);

				if (nh->onlink)
					vty_out(vty, " onlink");

				/*
				 * SR-TE color
				 */
				if (nh->color != 0)
					vty_out(vty, " color %u", nh->color);

				vty_out(vty, "\n");

				write = 1;
			}
		}
	}
	return write;
}

/* Static unicast routes for multicast RPF lookup. */
DEFPY_YANG (ip_mroute_dist,
       ip_mroute_dist_cmd,
       "[no] ip mroute A.B.C.D/M$prefix <A.B.C.D$gate|INTERFACE$ifname> [(1-255)$distance]",
       NO_STR
       IP_STR
       "Configure static unicast route into MRIB for multicast RPF lookup\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Nexthop address\n"
       "Nexthop interface name\n"
       "Distance\n")
{
	return static_route(vty, AFI_IP, SAFI_MULTICAST, no, prefix_str,
			    NULL, NULL, gate_str, ifname, NULL, NULL,
			    distance_str, NULL, NULL, NULL);
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
	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route(vty, AFI_IP, SAFI_UNICAST, no, prefix,
			    mask_str, NULL, NULL, NULL, flag, tag_str,
			    distance_str, vrf, label, table_str);
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
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vrfname = yang_dnode_get_string(vrf_dnode, "./name");
	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);
	return static_route_leak(vty, vrfname, vrfname, AFI_IP, SAFI_UNICAST,
				 no, prefix, mask_str, NULL, NULL, NULL, flag,
				 tag_str, distance_str, label, table_str,
				 false, NULL);
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
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf;

	return static_route_leak(vty, vrf, nh_vrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, gate_str, ifname, flag,
				 tag_str, distance_str, label, table_str,
				 !!onlink, color_str);
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
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vrfname = yang_dnode_get_string(vrf_dnode, "./name");

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrfname;

	return static_route_leak(vty, vrfname, nh_vrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, gate_str, ifname, flag,
				 tag_str, distance_str, label, table_str,
				 !!onlink, color_str);
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
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (!vrf)
		vrf = VRF_DEFAULT_NAME;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf;

	return static_route_leak(vty, vrf, nh_vrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, gate_str, ifname, flag,
				 tag_str, distance_str, label, table_str,
				 false, color_str);
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
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	vrfname = yang_dnode_get_string(vrf_dnode, "./name");

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrfname;

	return static_route_leak(vty, vrfname, nh_vrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, gate_str, ifname, flag,
				 tag_str, distance_str, label, table_str,
				 false, color_str);
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
	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route(vty, AFI_IP6, SAFI_UNICAST, no, prefix_str,
			    NULL, from_str, NULL, NULL, flag, tag_str,
			    distance_str, vrf, label, table_str);
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
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vrfname = yang_dnode_get_string(vrf_dnode, "./name");

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);

	return static_route_leak(vty, vrfname, vrfname, AFI_IP6, SAFI_UNICAST,
				 no, prefix_str, NULL, from_str, NULL, NULL,
				 flag, tag_str, distance_str, label, table_str,
				 false, NULL);
}

DEFPY_YANG(ipv6_route_address_interface,
      ipv6_route_address_interface_cmd,
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
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "IPv6 gateway address\n"
      "IPv6 gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (!vrf)
		vrf = VRF_DEFAULT_NAME;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf;

	return static_route_leak(vty, vrf, nh_vrf, AFI_IP6, SAFI_UNICAST, no,
				 prefix_str, NULL, from_str, gate_str, ifname,
				 flag, tag_str, distance_str, label, table_str,
				 !!onlink, color_str);
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
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "IPv6 gateway address\n"
      "IPv6 gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vrfname = yang_dnode_get_string(vrf_dnode, "./name");

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrfname;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	return static_route_leak(vty, vrfname, nh_vrf, AFI_IP6, SAFI_UNICAST,
				 no, prefix_str, NULL, from_str, gate_str,
				 ifname, flag, tag_str, distance_str, label,
				 table_str, !!onlink, color_str);
}

DEFPY_YANG(ipv6_route,
      ipv6_route_cmd,
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
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "IPv6 gateway address\n"
      "IPv6 gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;

	if (!vrf)
		vrf = VRF_DEFAULT_NAME;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	return static_route_leak(vty, vrf, nh_vrf, AFI_IP6, SAFI_UNICAST, no,
				 prefix_str, NULL, from_str, gate_str, ifname,
				 flag, tag_str, distance_str, label, table_str,
				 false, color_str);
}

DEFPY_YANG(ipv6_route_vrf,
      ipv6_route_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |color (1-4294967295)                          \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "IPv6 gateway address\n"
      "IPv6 gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n")
{
	const char *nh_vrf;
	const char *flag = NULL;
	const struct lyd_node *vrf_dnode;
	const char *vrfname;

	vrf_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!vrf_dnode) {
		vty_out(vty, "%% Failed to get vrf dnode in candidate db\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vrfname = yang_dnode_get_string(vrf_dnode, "./name");

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrfname;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	return static_route_leak(vty, vrfname, nh_vrf, AFI_IP6, SAFI_UNICAST,
				 no, prefix_str, NULL, from_str, gate_str,
				 ifname, flag, tag_str, distance_str, label,
				 table_str, false, color_str);
}
DEFPY_YANG(debug_staticd,
      debug_staticd_cmd,
      "[no] debug static [{events$events}]",
      NO_STR
      DEBUG_STR
      STATICD_STR
      "Debug events\n")
{
	/* If no specific category, change all */
	if (strmatch(argv[argc - 1]->text, "static"))
		static_debug_set(vty->node, !no, true);
	else
		static_debug_set(vty->node, !no, !!events);

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

	return CMD_SUCCESS;
}

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = static_config_write_debug,
};

void static_vty_init(void)
{
	install_node(&debug_node);

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

	install_element(ENABLE_NODE, &show_debugging_static_cmd);
	install_element(ENABLE_NODE, &debug_staticd_cmd);
	install_element(CONFIG_NODE, &debug_staticd_cmd);
}
