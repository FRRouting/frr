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
			     const char *table_str, bool onlink)
{
	int ret;
	struct prefix p, src;
	struct prefix_ipv6 *src_p = NULL;
	struct in_addr mask;
	uint8_t type;
	const char *bh_type;
	char xpath_list[XPATH_MAXLEN];
	char buf_prefix[PREFIX_STRLEN];
	char buf_src_prefix[PREFIX_STRLEN];
	char buf_nh_type[PREFIX_STRLEN];
	uint8_t label_stack_id = 0;
	const char *buf_gate_str;
	uint8_t distance = ZEBRA_STATIC_DISTANCE_DEFAULT;
	route_tag_t tag = 0;
	uint32_t table_id = 0;

	memset(buf_src_prefix, 0, PREFIX_STRLEN);
	memset(buf_nh_type, 0, PREFIX_STRLEN);

	ret = str2prefix(dest_str, &p);
	if (ret <= 0) {
		if (vty)
			vty_out(vty, "%% Malformed address\n");
		else
			zlog_warn("%s: Malformed address: %s",
				  __PRETTY_FUNCTION__, dest_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	switch (afi) {
	case AFI_IP:
		/* Cisco like mask notation. */
		if (mask_str) {
			ret = inet_aton(mask_str, &mask);
			if (ret == 0) {
				if (vty)
					vty_out(vty, "%% Malformed address\n");
				else
					zlog_warn("%s: Malformed address: %s",
						  __PRETTY_FUNCTION__,
						  mask_str);
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
				if (vty)
					vty_out(vty,
						"%% Malformed source address\n");
				else
					zlog_warn(
						"%s: Malformed source address: %s",
						__func__, src_str);
				return CMD_WARNING_CONFIG_FAILED;
			}
			src_p = (struct prefix_ipv6 *)&src;
		}
		break;
	default:
		break;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	prefix2str(&p, buf_prefix, sizeof(buf_prefix));

	if (src_str)
		prefix2str(&src, buf_src_prefix, sizeof(buf_prefix));
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
		/* route processing */
		if (src_str)
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_S_ROUTE_SRC_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, buf_src_prefix);
		else

			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_STATIC_ROUTE_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix);

		nb_cli_enqueue_change(vty, xpath_list, NB_OP_CREATE, NULL);

		/* distance,tag,table-id processing */

		if (src_str)
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_S_ROUTE_SRC_INFO_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, buf_src_prefix, distance, tag,
				 table_id);
		else
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_STATIC_ROUTE_INFO_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, distance, tag, table_id);

		nb_cli_enqueue_change(vty, xpath_list, NB_OP_CREATE, NULL);

		/* nexthop processing */

		if (src_str) {
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_S_ROUTE_SRC_NH_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, buf_src_prefix, distance, tag,
				 table_id, buf_nh_type, buf_gate_str, ifname,
				 nh_svrf);
		} else {
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_STATIC_ROUTE_NH_KEY_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, distance, tag, table_id,
				 buf_nh_type, buf_gate_str, ifname, nh_svrf);
		}
		nb_cli_enqueue_change(vty, xpath_list, NB_OP_CREATE, NULL);

		if (src_str)
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_S_ROUTE_SRC_NH_BH_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, buf_src_prefix, distance, tag,
				 table_id, buf_nh_type, buf_gate_str, ifname,
				 nh_svrf);
		else
			snprintf(xpath_list, sizeof(xpath_list),
				 FRR_STATIC_ROUTE_NH_BH_XPATH,
				 "frr-staticd:static", "static", svrf,
				 buf_prefix, distance, tag, table_id,
				 buf_nh_type, buf_gate_str, ifname, nh_svrf);

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
			nb_cli_enqueue_change(vty, xpath_list, NB_OP_MODIFY,
					      bh_type);
		} else {
			nb_cli_enqueue_change(vty, xpath_list, NB_OP_DESTROY,
					      NULL);
		}

		if (type == STATIC_IPV4_GATEWAY_IFNAME
		    || type == STATIC_IPV6_GATEWAY_IFNAME) {

			if (src_str)
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_S_ROUTE_SRC_NH_ONLINK_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix, buf_src_prefix, distance,
					 tag, table_id, buf_nh_type,
					 buf_gate_str, ifname, nh_svrf);
			else
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_STATIC_ROUTE_NH_ONLINK_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix, distance, tag, table_id,
					 buf_nh_type, buf_gate_str, ifname,
					 nh_svrf);
			if (onlink)
				nb_cli_enqueue_change(vty, xpath_list,
						      NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(vty, xpath_list,
						      NB_OP_DESTROY, NULL);
		}

		if (label_str) {
			/* copy of label string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			ostr = XSTRDUP(MTYPE_TMP, label_str);
			while ((nump = strsep(&ostr, "/")) != NULL) {
				if (src_str)
					snprintf(
						xpath_list, sizeof(xpath_list),
						FRR_S_ROUTE_SRC_NHLB_KEY_XPATH,
						"frr-staticd:static", "static",
						svrf, buf_prefix,
						buf_src_prefix, distance, tag,
						table_id, buf_nh_type,
						buf_gate_str, ifname, nh_svrf,
						label_stack_id);
				else
					snprintf(
						xpath_list, sizeof(xpath_list),
						FRR_STATIC_ROUTE_NHLB_KEY_XPATH,
						"frr-staticd:static", "static",
						svrf, buf_prefix, distance, tag,
						table_id, buf_nh_type,
						buf_gate_str, ifname, nh_svrf,
						label_stack_id);

				nb_cli_enqueue_change(vty, xpath_list,
						      NB_OP_MODIFY, nump);
				label_stack_id++;
			}
			XFREE(MTYPE_TMP, ostr);
		} else {
			if (src_str)
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_S_ROUTE_SRC_NH_LABEL_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix, buf_src_prefix, distance,
					 tag, table_id, buf_nh_type,
					 buf_gate_str, ifname, nh_svrf);
			else
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_STATIC_ROUTE_NH_LABEL_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix, distance, tag, table_id,
					 buf_nh_type, buf_gate_str, ifname,
					 nh_svrf);
			nb_cli_enqueue_change(vty, xpath_list, NB_OP_DESTROY,
					      NULL);
		}

		ret = nb_cli_apply_changes(vty, xpath_list);
	} else {
		if (static_get_route_delete(afi, safi, type, &p, src_p, svrf)) {
			if (src_str)
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_S_ROUTE_SRC_KEY_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix, buf_src_prefix);
			else
				snprintf(xpath_list, sizeof(xpath_list),
					 FRR_STATIC_ROUTE_KEY_XPATH,
					 "frr-staticd:static", "static", svrf,
					 buf_prefix);
			nb_cli_enqueue_change(vty, xpath_list, NB_OP_DESTROY,
					      NULL);
			if (src_str) {
				if (static_get_src_route_delete(afi, safi, type,
								&p, svrf)) {
					ret = nb_cli_apply_changes(vty,
								   xpath_list);
					if (ret != CMD_SUCCESS)
						return ret;

					snprintf(xpath_list, sizeof(xpath_list),
						 FRR_STATIC_ROUTE_KEY_XPATH,
						 "frr-staticd:static", "static",
						 svrf, buf_prefix);
					nb_cli_enqueue_change(vty, xpath_list,
							      NB_OP_DESTROY,
							      NULL);
				}
			}

		} else {
			if (static_get_path_delete(afi, safi, type, &p, src_p,
						   svrf, distance, tag,
						   table_id)) {

				if (src_str)
					snprintf(
						xpath_list, sizeof(xpath_list),
						FRR_S_ROUTE_SRC_INFO_KEY_XPATH,
						"frr-staticd:static", "static",
						svrf, buf_prefix,
						buf_src_prefix, distance, tag,
						table_id);
				else
					snprintf(
						xpath_list, sizeof(xpath_list),
						FRR_STATIC_ROUTE_INFO_KEY_XPATH,
						"frr-staticd:static", "static",
						svrf, buf_prefix, distance, tag,
						table_id);
				nb_cli_enqueue_change(vty, xpath_list,
						      NB_OP_DESTROY, NULL);

			} else {
				if (src_str)
					snprintf(
						xpath_list, sizeof(xpath_list),
						FRR_S_ROUTE_SRC_NH_KEY_XPATH,
						"frr-staticd:static", "static",
						svrf, buf_prefix,
						buf_src_prefix, distance, tag,
						table_id, buf_nh_type,
						buf_gate_str, ifname, nh_svrf);
				else
					snprintf(xpath_list, sizeof(xpath_list),
						 FRR_STATIC_ROUTE_NH_KEY_XPATH,
						 "frr-staticd:static", "static",
						 svrf, buf_prefix, distance,
						 tag, table_id, buf_nh_type,
						 buf_gate_str, ifname, nh_svrf);
				nb_cli_enqueue_change(vty, xpath_list,
						      NB_OP_DESTROY, NULL);
			}
		}

		ret = nb_cli_apply_changes(vty, xpath_list);
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
				 table_str, false);
}

/* Write static route configuration. */
int static_config(struct vty *vty, struct static_vrf *svrf, afi_t afi,
		  safi_t safi, const char *cmd)
{
	char spacing[100];
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_route_info *ri;
	struct route_table *stable;
	char buf[SRCDEST2STR_BUFFER];
	int write = 0;

	stable = svrf->stable[afi][safi];
	if (stable == NULL)
		return write;

	snprintf(spacing, sizeof(spacing), "%s%s",
		 (svrf->vrf->vrf_id == VRF_DEFAULT) ? "" : " ", cmd);

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
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

				if (ri->tag)
					vty_out(vty, " tag %" ROUTE_TAG_PRI,
						ri->tag);

				if (ri->distance
				    != ZEBRA_STATIC_DISTANCE_DEFAULT)
					vty_out(vty, " %d", ri->distance);

				/* Label information */
				if (nh->snh_label.num_labels)
					vty_out(vty, " label %s",
						mpls_label2str(
							nh->snh_label
								.num_labels,
							nh->snh_label.label,
							buf, sizeof(buf), 0));

				if (nh->nh_vrf_id != nh->vrf_id)
					vty_out(vty, " nexthop-vrf %s",
						nh->nh_vrfname);

				/*
				 * table ID from VRF overrides configured
				 */
				if (ri->table_id
				    && svrf->vrf->data.l.table_id
					       == RT_TABLE_MAIN)
					vty_out(vty, " table %u", ri->table_id);

				if (nh->onlink)
					vty_out(vty, " onlink");

				vty_out(vty, "\n");

				write = 1;
			}
		}
	}
	return write;
}

/* Static unicast routes for multicast RPF lookup. */
DEFPY (ip_mroute_dist,
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
DEFPY(ip_route_blackhole,
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

	return static_route(vty, AFI_IP, SAFI_UNICAST, no, prefix, mask_str,
			    NULL, NULL, NULL, flag, tag_str, distance_str, vrf,
			    label, table_str);
}

DEFPY(ip_route_blackhole_vrf,
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
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);
	return static_route_leak(vty, vrf->name, vrf->name, AFI_IP,
				 SAFI_UNICAST, no, prefix, mask_str, NULL, NULL,
				 NULL, flag, tag_str, distance_str, label,
				 table_str, false);
}

DEFPY(ip_route_address_interface,
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
      "Treat the nexthop as directly attached to the interface\n")
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
				 !!onlink);
}

DEFPY(ip_route_address_interface_vrf,
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
      "Treat the nexthop as directly attached to the interface\n")
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *nh_vrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf->name;

	return static_route_leak(vty, vrf->name, nh_vrf, AFI_IP, SAFI_UNICAST,
				 no, prefix, mask_str, NULL, gate_str, ifname,
				 flag, tag_str, distance_str, label, table_str,
				 !!onlink);
}

DEFPY(ip_route,
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
      VRF_CMD_HELP_STR)
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
				 false);
}

DEFPY(ip_route_vrf,
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
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *nh_vrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf->name;

	return static_route_leak(vty, vrf->name, nh_vrf, AFI_IP, SAFI_UNICAST,
				 no, prefix, mask_str, NULL, gate_str, ifname,
				 flag, tag_str, distance_str, label, table_str,
				 false);
}

DEFPY(ipv6_route_blackhole,
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

	return static_route(vty, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
			    from_str, NULL, NULL, flag, tag_str, distance_str,
			    vrf, label, table_str);
}

DEFPY(ipv6_route_blackhole_vrf,
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
	VTY_DECLVAR_CONTEXT(vrf, vrf);

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);

	return static_route_leak(vty, vrf->name, vrf->name, AFI_IP6,
				 SAFI_UNICAST, no, prefix_str, NULL, from_str,
				 NULL, NULL, flag, tag_str, distance_str, label,
				 table_str, false);
}

DEFPY(ipv6_route_address_interface,
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
      "Treat the nexthop as directly attached to the interface\n")
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
				 !!onlink);
}

DEFPY(ipv6_route_address_interface_vrf,
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
      "Treat the nexthop as directly attached to the interface\n")
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *nh_vrf;
	const char *flag = NULL;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf->name;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	return static_route_leak(vty, vrf->name, nh_vrf, AFI_IP6, SAFI_UNICAST,
				 no, prefix_str, NULL, from_str, gate_str,
				 ifname, flag, tag_str, distance_str, label,
				 table_str, !!onlink);
}

DEFPY(ipv6_route,
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
      VRF_CMD_HELP_STR)
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
				 false);
}

DEFPY(ipv6_route_vrf,
      ipv6_route_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
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
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *nh_vrf;
	const char *flag = NULL;

	if (nexthop_vrf)
		nh_vrf = nexthop_vrf;
	else
		nh_vrf = vrf->name;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}
	return static_route_leak(vty, vrf->name, nh_vrf, AFI_IP6, SAFI_UNICAST,
				 no, prefix_str, NULL, from_str, gate_str,
				 ifname, flag, tag_str, distance_str, label,
				 table_str, false);
}
DEFPY(debug_staticd,
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

	install_element(VIEW_NODE, &show_debugging_static_cmd);
	install_element(VIEW_NODE, &debug_staticd_cmd);
	install_element(CONFIG_NODE, &debug_staticd_cmd);
}
