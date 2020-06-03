/* Zebra VTY functions
 * Copyright (C) 2002 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "zebra_memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "linklist.h"
#include "mpls.h"
#include "routemap.h"
#include "srcdest_table.h"
#include "vxlan.h"

#include "zebra/zebra_router.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "lib/json.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_vty_clippy.c"
#endif
#include "zebra/zserv.h"
#include "zebra/router-id.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_nhg.h"
#include "zebra/interface.h"
#include "northbound_cli.h"

extern int allow_delete;

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, bool use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    unsigned short ospf_instance_id, uint32_t tableid);
static void vty_show_ip_route_detail(struct vty *vty, struct route_node *rn,
				     int mcast, bool use_fib, bool show_ng);
static void vty_show_ip_route_summary(struct vty *vty,
				      struct route_table *table, bool use_json);
static void vty_show_ip_route_summary_prefix(struct vty *vty,
					     struct route_table *table,
					     bool use_json);

DEFUN (ip_multicast_mode,
       ip_multicast_mode_cmd,
       "ip multicast rpf-lookup-mode <urib-only|mrib-only|mrib-then-urib|lower-distance|longer-prefix>",
       IP_STR
       "Multicast options\n"
       "RPF lookup behavior\n"
       "Lookup in unicast RIB only\n"
       "Lookup in multicast RIB only\n"
       "Try multicast RIB first, fall back to unicast RIB\n"
       "Lookup both, use entry with lower distance\n"
       "Lookup both, use entry with longer prefix\n")
{
	char *mode = argv[3]->text;

	if (strmatch(mode, "urib-only"))
		multicast_mode_ipv4_set(MCAST_URIB_ONLY);
	else if (strmatch(mode, "mrib-only"))
		multicast_mode_ipv4_set(MCAST_MRIB_ONLY);
	else if (strmatch(mode, "mrib-then-urib"))
		multicast_mode_ipv4_set(MCAST_MIX_MRIB_FIRST);
	else if (strmatch(mode, "lower-distance"))
		multicast_mode_ipv4_set(MCAST_MIX_DISTANCE);
	else if (strmatch(mode, "longer-prefix"))
		multicast_mode_ipv4_set(MCAST_MIX_PFXLEN);
	else {
		vty_out(vty, "Invalid mode specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ip_multicast_mode,
       no_ip_multicast_mode_cmd,
       "no ip multicast rpf-lookup-mode [<urib-only|mrib-only|mrib-then-urib|lower-distance|longer-prefix>]",
       NO_STR
       IP_STR
       "Multicast options\n"
       "RPF lookup behavior\n"
       "Lookup in unicast RIB only\n"
       "Lookup in multicast RIB only\n"
       "Try multicast RIB first, fall back to unicast RIB\n"
       "Lookup both, use entry with lower distance\n"
       "Lookup both, use entry with longer prefix\n")
{
	multicast_mode_ipv4_set(MCAST_NO_CONFIG);
	return CMD_SUCCESS;
}


DEFUN (show_ip_rpf,
       show_ip_rpf_cmd,
       "show ip rpf [json]",
       SHOW_STR
       IP_STR
       "Display RPF information for multicast source\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	return do_show_ip_route(vty, VRF_DEFAULT_NAME, AFI_IP, SAFI_MULTICAST,
				false, uj, 0, NULL, false, 0, 0, 0);
}

DEFUN (show_ip_rpf_addr,
       show_ip_rpf_addr_cmd,
       "show ip rpf A.B.C.D",
       SHOW_STR
       IP_STR
       "Display RPF information for multicast source\n"
       "IP multicast source address (e.g. 10.0.0.0)\n")
{
	int idx_ipv4 = 3;
	struct in_addr addr;
	struct route_node *rn;
	struct route_entry *re;
	int ret;

	ret = inet_aton(argv[idx_ipv4]->arg, &addr);
	if (ret == 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING;
	}

	re = rib_match_ipv4_multicast(VRF_DEFAULT, addr, &rn);

	if (re)
		vty_show_ip_route_detail(vty, rn, 1, false, false);
	else
		vty_out(vty, "%% No match for RPF lookup\n");

	return CMD_SUCCESS;
}

static char re_status_output_char(const struct route_entry *re,
				  const struct nexthop *nhop)
{
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)) {
		if (!CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_DUPLICATE) &&
		    !CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_RECURSIVE))
			return '*';
		else
			return ' ';
	}

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_FAILED)) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED))
			return 'q';

		return 'r';
	}

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED))
		return 'q';

	return ' ';
}

/*
 * TODO -- Show backup nexthop info
 */
static void show_nh_backup_helper(struct vty *vty,
				  const struct nhg_hash_entry *nhe,
				  const struct nexthop *nexthop)
{
	/* Double-check that there _is_ a backup */
	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP))
		return;

	/* Locate the backup nexthop */

	/* Format the backup (indented) */

}

/*
 * Helper api to format output for a nexthop, used in the 'detailed'
 * output path.
 */
static void show_nexthop_detail_helper(struct vty *vty,
				       const struct route_entry *re,
				       const struct nexthop *nexthop)
{
	char addrstr[32];
	char buf[MPLS_LABEL_STRLEN];

	vty_out(vty, "  %c%s",
		re_status_output_char(re, nexthop),
		nexthop->rparent ? "  " : "");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, " %s",
			inet_ntoa(nexthop->gate.ipv4));
		if (nexthop->ifindex)
			vty_out(vty, ", via %s",
				ifindex2ifname(
					nexthop->ifindex,
					nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, " %s",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6,
				  buf, sizeof(buf)));
		if (nexthop->ifindex)
			vty_out(vty, ", via %s",
				ifindex2ifname(
					nexthop->ifindex,
					nexthop->vrf_id));
		break;

	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty, " directly connected, %s",
			ifindex2ifname(nexthop->ifindex,
				       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		vty_out(vty, " unreachable");
		switch (nexthop->bh_type) {
		case BLACKHOLE_REJECT:
			vty_out(vty, " (ICMP unreachable)");
			break;
		case BLACKHOLE_ADMINPROHIB:
			vty_out(vty,
				" (ICMP admin-prohibited)");
			break;
		case BLACKHOLE_NULL:
			vty_out(vty, " (blackhole)");
			break;
		case BLACKHOLE_UNSPEC:
			break;
		}
		break;
	default:
		break;
	}

	if ((re->vrf_id != nexthop->vrf_id)
	    && (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)) {
		struct vrf *vrf =
			vrf_lookup_by_id(nexthop->vrf_id);

		if (vrf)
			vty_out(vty, "(vrf %s)", vrf->name);
		else
			vty_out(vty, "(vrf UNKNOWN)");
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
		vty_out(vty, " (duplicate nexthop removed)");

	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		vty_out(vty, " inactive");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		vty_out(vty, " onlink");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
		vty_out(vty, " (recursive)");

	/* Source specified? */
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (nexthop->src.ipv4.s_addr) {
			if (inet_ntop(AF_INET, &nexthop->src.ipv4,
				      addrstr, sizeof(addrstr)))
				vty_out(vty, ", src %s",
					addrstr);
		}
		break;

	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (!IPV6_ADDR_SAME(&nexthop->src.ipv6,
				    &in6addr_any)) {
			if (inet_ntop(AF_INET6, &nexthop->src.ipv6,
				      addrstr, sizeof(addrstr)))
				vty_out(vty, ", src %s",
					addrstr);
		}
		break;

	default:
		break;
	}

	if (re->nexthop_mtu)
		vty_out(vty, ", mtu %u", re->nexthop_mtu);

	/* Label information */
	if (nexthop->nh_label && nexthop->nh_label->num_labels) {
		vty_out(vty, ", label %s",
			mpls_label2str(nexthop->nh_label->num_labels,
				       nexthop->nh_label->label, buf,
				       sizeof(buf), 1 /*pretty*/));
	}

	if (nexthop->weight)
		vty_out(vty, ", weight %u", nexthop->weight);
}

/* New RIB.  Detailed information for IPv4 route. */
static void vty_show_ip_route_detail(struct vty *vty, struct route_node *rn,
				     int mcast, bool use_fib, bool show_ng)
{
	struct route_entry *re;
	struct nexthop *nexthop;
	char buf[SRCDEST2STR_BUFFER];
	struct zebra_vrf *zvrf;
	rib_dest_t *dest;

	dest = rib_dest_from_rnode(rn);

	RNODE_FOREACH_RE (rn, re) {
		/*
		 * If re not selected for forwarding, skip re
		 * for "show ip/ipv6 fib <prefix>"
		 */
		if (use_fib && re != dest->selected_fib)
			continue;

		const char *mcast_info = "";
		if (mcast) {
			struct rib_table_info *info =
				srcdest_rnode_table_info(rn);
			mcast_info = (info->safi == SAFI_MULTICAST)
					     ? " using Multicast RIB"
					     : " using Unicast RIB";
		}

		vty_out(vty, "Routing entry for %s%s\n",
			srcdest_rnode2str(rn, buf, sizeof(buf)), mcast_info);
		vty_out(vty, "  Known via \"%s", zebra_route_string(re->type));
		if (re->instance)
			vty_out(vty, "[%d]", re->instance);
		vty_out(vty, "\"");
		vty_out(vty, ", distance %u, metric %u", re->distance,
			re->metric);
		if (re->tag) {
			vty_out(vty, ", tag %u", re->tag);
#if defined(SUPPORT_REALMS)
			if (re->tag > 0 && re->tag <= 255)
				vty_out(vty, "(realm)");
#endif
		}
		if (re->mtu)
			vty_out(vty, ", mtu %u", re->mtu);
		if (re->vrf_id != VRF_DEFAULT) {
			zvrf = vrf_info_lookup(re->vrf_id);
			vty_out(vty, ", vrf %s", zvrf_name(zvrf));
		}
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			vty_out(vty, ", best");
		vty_out(vty, "\n");

		time_t uptime;

		uptime = monotime(NULL);
		uptime -= re->uptime;

		frrtime_to_interval(uptime, buf, sizeof(buf));

		vty_out(vty, "  Last update %s ago\n", buf);

		if (show_ng)
			vty_out(vty, "  Nexthop Group ID: %u\n", re->nhe_id);

		for (ALL_NEXTHOPS(re->nhe->nhg, nexthop)) {
			/* Use helper to format each nexthop */
			show_nexthop_detail_helper(vty, re, nexthop);
			vty_out(vty, "\n");

			/* Include backup info, if present */
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP))
				show_nh_backup_helper(vty, re->nhe, nexthop);
		}
		vty_out(vty, "\n");
	}
}

/*
 * Helper for nexthop output, used in the 'show ip route' path
 */
static void show_route_nexthop_helper(struct vty *vty,
				      const struct route_entry *re,
				      const struct nexthop *nexthop)
{
	char buf[MPLS_LABEL_STRLEN];

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, " via %s", inet_ntoa(nexthop->gate.ipv4));
		if (nexthop->ifindex)
			vty_out(vty, ", %s",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, " via %s",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
				  sizeof(buf)));
		if (nexthop->ifindex)
			vty_out(vty, ", %s",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		break;

	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty, " is directly connected, %s",
			ifindex2ifname(nexthop->ifindex,
				       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		vty_out(vty, " unreachable");
		switch (nexthop->bh_type) {
		case BLACKHOLE_REJECT:
			vty_out(vty, " (ICMP unreachable)");
			break;
		case BLACKHOLE_ADMINPROHIB:
			vty_out(vty, " (ICMP admin-prohibited)");
			break;
		case BLACKHOLE_NULL:
			vty_out(vty, " (blackhole)");
			break;
		case BLACKHOLE_UNSPEC:
			break;
		}
		break;
	default:
		break;
	}

	if ((re == NULL || (nexthop->vrf_id != re->vrf_id)) &&
	    (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)) {
		struct vrf *vrf = vrf_lookup_by_id(nexthop->vrf_id);

		if (vrf)
			vty_out(vty, " (vrf %s)", vrf->name);
		else
			vty_out(vty, " (vrf UNKNOWN)");
	}

	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		vty_out(vty, " inactive");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		vty_out(vty, " onlink");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
		vty_out(vty, " (recursive)");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (nexthop->src.ipv4.s_addr) {
			if (inet_ntop(AF_INET, &nexthop->src.ipv4, buf,
				      sizeof(buf)))
				vty_out(vty, ", src %s", buf);
		}
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any)) {
			if (inet_ntop(AF_INET6, &nexthop->src.ipv6, buf,
				      sizeof(buf)))
				vty_out(vty, ", src %s", buf);
		}
		break;
	default:
		break;
	}

	/* Label information */
	if (nexthop->nh_label && nexthop->nh_label->num_labels) {
		vty_out(vty, ", label %s",
			mpls_label2str(nexthop->nh_label->num_labels,
				       nexthop->nh_label->label, buf,
				       sizeof(buf), 1));
	}

	if ((re == NULL) && nexthop->weight)
		vty_out(vty, ", weight %u", nexthop->weight);
}

static void vty_show_ip_route(struct vty *vty, struct route_node *rn,
			      struct route_entry *re, json_object *json,
			      bool is_fib)
{
	struct nexthop *nexthop;
	int len = 0;
	char buf[SRCDEST2STR_BUFFER];
	json_object *json_nexthops = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_route = NULL;
	json_object *json_labels = NULL;
	time_t uptime;
	struct vrf *vrf = NULL;
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct nexthop_group *nhg;
	char up_str[MONOTIME_STRLEN];

	uptime = monotime(NULL);
	uptime -= re->uptime;

	frrtime_to_interval(uptime, up_str, sizeof(up_str));

	/* If showing fib information, use the fib view of the
	 * nexthops.
	 */
	if (is_fib)
		nhg = rib_active_nhg(re);
	else
		nhg = &(re->nhe->nhg);

	if (json) {
		json_route = json_object_new_object();
		json_nexthops = json_object_new_array();

		json_object_string_add(json_route, "prefix",
				       srcdest_rnode2str(rn, buf, sizeof(buf)));
		json_object_string_add(json_route, "protocol",
				       zebra_route_string(re->type));

		if (re->instance)
			json_object_int_add(json_route, "instance",
					    re->instance);

		if (re->vrf_id) {
			json_object_int_add(json_route, "vrfId", re->vrf_id);
			vrf = vrf_lookup_by_id(re->vrf_id);
			json_object_string_add(json_route, "vrfName",
					       vrf->name);

		}
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			json_object_boolean_true_add(json_route, "selected");

		if (dest->selected_fib == re)
			json_object_boolean_true_add(json_route,
						     "destSelected");

		json_object_int_add(json_route, "distance",
				    re->distance);
		json_object_int_add(json_route, "metric", re->metric);

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
			json_object_boolean_true_add(json_route, "installed");

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_FAILED))
			json_object_boolean_true_add(json_route, "failed");

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED))
			json_object_boolean_true_add(json_route, "queued");

		if (re->tag)
			json_object_int_add(json_route, "tag", re->tag);

		if (re->table)
			json_object_int_add(json_route, "table", re->table);

		json_object_int_add(json_route, "internalStatus",
				    re->status);
		json_object_int_add(json_route, "internalFlags",
				    re->flags);
		json_object_int_add(json_route, "internalNextHopNum",
				    nexthop_group_nexthop_num(&(re->nhe->nhg)));
		json_object_int_add(json_route, "internalNextHopActiveNum",
				    nexthop_group_active_nexthop_num(
					    &(re->nhe->nhg)));

		json_object_string_add(json_route, "uptime", up_str);

		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			json_nexthop = json_object_new_object();

			json_object_int_add(json_nexthop, "flags",
					    nexthop->flags);

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
				json_object_boolean_true_add(json_nexthop,
							     "duplicate");

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				json_object_boolean_true_add(json_nexthop,
							     "fib");

			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				json_object_string_add(
					json_nexthop, "ip",
					inet_ntoa(nexthop->gate.ipv4));
				json_object_string_add(json_nexthop, "afi",
						       "ipv4");

				if (nexthop->ifindex) {
					json_object_int_add(json_nexthop,
							    "interfaceIndex",
							    nexthop->ifindex);
					json_object_string_add(
						json_nexthop, "interfaceName",
						ifindex2ifname(
							nexthop->ifindex,
							nexthop->vrf_id));
				}
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				json_object_string_add(
					json_nexthop, "ip",
					inet_ntop(AF_INET6, &nexthop->gate.ipv6,
						  buf, sizeof(buf)));
				json_object_string_add(json_nexthop, "afi",
						       "ipv6");

				if (nexthop->ifindex) {
					json_object_int_add(json_nexthop,
							    "interfaceIndex",
							    nexthop->ifindex);
					json_object_string_add(
						json_nexthop, "interfaceName",
						ifindex2ifname(
							nexthop->ifindex,
							nexthop->vrf_id));
				}
				break;

			case NEXTHOP_TYPE_IFINDEX:
				json_object_boolean_true_add(
					json_nexthop, "directlyConnected");
				json_object_int_add(json_nexthop,
						    "interfaceIndex",
						    nexthop->ifindex);
				json_object_string_add(
					json_nexthop, "interfaceName",
					ifindex2ifname(nexthop->ifindex,
						       nexthop->vrf_id));
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				json_object_boolean_true_add(json_nexthop,
							     "unreachable");
				switch (nexthop->bh_type) {
				case BLACKHOLE_REJECT:
					json_object_boolean_true_add(
						json_nexthop, "reject");
					break;
				case BLACKHOLE_ADMINPROHIB:
					json_object_boolean_true_add(
						json_nexthop,
						"admin-prohibited");
					break;
				case BLACKHOLE_NULL:
					json_object_boolean_true_add(
						json_nexthop, "blackhole");
					break;
				case BLACKHOLE_UNSPEC:
					break;
				}
				break;
			default:
				break;
			}

			if ((nexthop->vrf_id != re->vrf_id)
			     && (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)) {
				vrf = vrf_lookup_by_id(nexthop->vrf_id);
				json_object_string_add(json_nexthop, "vrf",
						       vrf->name);
			}
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
				json_object_boolean_true_add(json_nexthop,
							     "duplicate");

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				json_object_boolean_true_add(json_nexthop,
							     "active");

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
				json_object_boolean_true_add(json_nexthop,
							     "onLink");

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				json_object_boolean_true_add(json_nexthop,
							     "recursive");

			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				if (nexthop->src.ipv4.s_addr) {
					if (inet_ntop(AF_INET,
						      &nexthop->src.ipv4, buf,
						      sizeof(buf)))
						json_object_string_add(
							json_nexthop, "source",
							buf);
				}
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				if (!IPV6_ADDR_SAME(&nexthop->src.ipv6,
						    &in6addr_any)) {
					if (inet_ntop(AF_INET6,
						      &nexthop->src.ipv6, buf,
						      sizeof(buf)))
						json_object_string_add(
							json_nexthop, "source",
							buf);
				}
				break;
			default:
				break;
			}

			if (nexthop->nh_label
			    && nexthop->nh_label->num_labels) {
				json_labels = json_object_new_array();

				for (int label_index = 0;
				     label_index
				     < nexthop->nh_label->num_labels;
				     label_index++)
					json_object_array_add(
						json_labels,
						json_object_new_int(
							nexthop->nh_label->label
								[label_index]));

				json_object_object_add(json_nexthop, "labels",
						       json_labels);
			}

			if (nexthop->weight)
				json_object_int_add(json_nexthop, "weight",
						    nexthop->weight);

			json_object_array_add(json_nexthops, json_nexthop);
		}

		json_object_object_add(json_route, "nexthops", json_nexthops);
		json_object_array_add(json, json_route);
		return;
	}

	/* Nexthop information. */
	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		if (nexthop == nhg->nexthop) {
			/* Prefix information. */
			len = vty_out(vty, "%c", zebra_route_char(re->type));
			if (re->instance)
				len += vty_out(vty, "[%d]", re->instance);
			len += vty_out(
				vty, "%c%c %s",
				CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)
					? '>'
					: ' ',
				re_status_output_char(re, nexthop),
				srcdest_rnode2str(rn, buf, sizeof(buf)));

			/* Distance and metric display. */
			if (((re->type == ZEBRA_ROUTE_CONNECT) &&
			     (re->distance || re->metric)) ||
			    (re->type != ZEBRA_ROUTE_CONNECT))
				len += vty_out(vty, " [%u/%u]", re->distance,
					       re->metric);
		} else {
			vty_out(vty, "  %c%*c",
				re_status_output_char(re, nexthop),
				len - 3 + (2 * nexthop_level(nexthop)), ' ');
		}

		show_route_nexthop_helper(vty, re, nexthop);

		if (nexthop->weight)
			vty_out(vty, ", weight %u", nexthop->weight);

		vty_out(vty, ", %s\n", up_str);

		/* Check for backup info */
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
			struct nexthop *backup;
			int i;

			if (re->nhe->backup_info == NULL ||
			    re->nhe->backup_info->nhe == NULL)
				continue;

			i = 0;
			for (ALL_NEXTHOPS(re->nhe->backup_info->nhe->nhg,
					  backup)) {
				if (i == nexthop->backup_idx)
					break;
				i++;
			}

			/* Print useful backup info */
			if (backup) {
				/* TODO -- install state is not accurate */
				vty_out(vty, "   %*c [backup %d]",
					/*re_status_output_char(re, backup),*/
					len - 3 + (2 * nexthop_level(nexthop)),
					' ', nexthop->backup_idx);
				show_route_nexthop_helper(vty, re, backup);
				vty_out(vty, "\n");
			}
		}
	}
}

static void vty_show_ip_route_detail_json(struct vty *vty,
					  struct route_node *rn, bool use_fib)
{
	json_object *json = NULL;
	json_object *json_prefix = NULL;
	struct route_entry *re;
	char buf[BUFSIZ];
	rib_dest_t *dest;

	dest = rib_dest_from_rnode(rn);

	json = json_object_new_object();
	json_prefix = json_object_new_array();

	RNODE_FOREACH_RE (rn, re) {
		/*
		 * If re not selected for forwarding, skip re
		 * for "show ip/ipv6 fib <prefix> json"
		 */
		if (use_fib && re != dest->selected_fib)
			continue;
		vty_show_ip_route(vty, rn, re, json_prefix, use_fib);
	}

	prefix2str(&rn->p, buf, sizeof(buf));
	json_object_object_add(json, buf, json_prefix);
	vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
	json_object_free(json);
}

static void do_show_route_helper(struct vty *vty, struct zebra_vrf *zvrf,
				 struct route_table *table, afi_t afi,
				 bool use_fib, route_tag_t tag,
				 const struct prefix *longer_prefix_p,
				 bool supernets_only, int type,
				 unsigned short ospf_instance_id, bool use_json,
				 uint32_t tableid)
{
	struct route_node *rn;
	struct route_entry *re;
	int first = 1;
	rib_dest_t *dest;
	json_object *json = NULL;
	json_object *json_prefix = NULL;
	uint32_t addr;
	char buf[BUFSIZ];

	if (use_json)
		json = json_object_new_object();

	/* Show all routes. */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		dest = rib_dest_from_rnode(rn);

		RNODE_FOREACH_RE (rn, re) {
			if (use_fib && re != dest->selected_fib)
				continue;

			if (tag && re->tag != tag)
				continue;

			if (longer_prefix_p
			    && !prefix_match(longer_prefix_p, &rn->p))
				continue;

			/* This can only be true when the afi is IPv4 */
			if (supernets_only) {
				addr = ntohl(rn->p.u.prefix4.s_addr);

				if (IN_CLASSC(addr) && rn->p.prefixlen >= 24)
					continue;

				if (IN_CLASSB(addr) && rn->p.prefixlen >= 16)
					continue;

				if (IN_CLASSA(addr) && rn->p.prefixlen >= 8)
					continue;
			}

			if (type && re->type != type)
				continue;

			if (ospf_instance_id
			    && (re->type != ZEBRA_ROUTE_OSPF
				|| re->instance != ospf_instance_id))
				continue;

			if (use_json) {
				if (!json_prefix)
					json_prefix = json_object_new_array();
			} else {
				if (first) {
					if (afi == AFI_IP)
						vty_out(vty,
							SHOW_ROUTE_V4_HEADER);
					else
						vty_out(vty,
							SHOW_ROUTE_V6_HEADER);

					if (tableid && tableid != RT_TABLE_MAIN)
						vty_out(vty, "\nVRF %s table %u:\n",
							zvrf_name(zvrf), tableid);
					else if (zvrf_id(zvrf) != VRF_DEFAULT)
						vty_out(vty, "\nVRF %s:\n",
							zvrf_name(zvrf));
					first = 0;
				}
			}

			vty_show_ip_route(vty, rn, re, json_prefix, use_fib);
		}

		if (json_prefix) {
			prefix2str(&rn->p, buf, sizeof(buf));
			json_object_object_add(json, buf, json_prefix);
			json_prefix = NULL;
		}
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(json,
						JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

static void do_show_ip_route_all(struct vty *vty, struct zebra_vrf *zvrf,
				 afi_t afi, bool use_fib, bool use_json,
				 route_tag_t tag,
				 const struct prefix *longer_prefix_p,
				 bool supernets_only, int type,
				 unsigned short ospf_instance_id)
{
	struct zebra_router_table *zrt;
	struct rib_table_info *info;

	RB_FOREACH (zrt, zebra_router_table_head,
		    &zrouter.tables) {
		info = route_table_get_info(zrt->table);

		if (zvrf != info->zvrf)
			continue;
		if (zrt->afi != afi ||
		    zrt->safi != SAFI_UNICAST)
			continue;

		do_show_ip_route(vty, zvrf_name(zvrf), afi,
				 SAFI_UNICAST, use_fib, use_json,
				 tag, longer_prefix_p,
				 supernets_only, type,
				 ospf_instance_id, zrt->tableid);
	}
}

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, bool use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    unsigned short ospf_instance_id, uint32_t tableid)
{
	struct route_table *table;
	struct zebra_vrf *zvrf = NULL;

	if (!(zvrf = zebra_vrf_lookup_by_name(vrf_name))) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "vrf %s not defined\n", vrf_name);
		return CMD_SUCCESS;
	}

	if (zvrf_id(zvrf) == VRF_UNKNOWN) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "vrf %s inactive\n", vrf_name);
		return CMD_SUCCESS;
	}

	if (tableid)
		table = zebra_router_find_table(zvrf, tableid, afi, SAFI_UNICAST);
	else
		table = zebra_vrf_table(afi, safi, zvrf_id(zvrf));
	if (!table) {
		if (use_json)
			vty_out(vty, "{}\n");
		return CMD_SUCCESS;
	}

	do_show_route_helper(vty, zvrf, table, afi, use_fib, tag,
			     longer_prefix_p, supernets_only, type,
			     ospf_instance_id, use_json, tableid);

	return CMD_SUCCESS;
}

DEFPY (show_ip_nht,
       show_ip_nht_cmd,
       "show <ip$ipv4|ipv6$ipv6> <nht|import-check>$type [<A.B.C.D|X:X::X:X>$addr|vrf NAME$vrf_name [<A.B.C.D|X:X::X:X>$addr]|vrf all$vrf_all]",
       SHOW_STR
       IP_STR
       IP6_STR
       "IP nexthop tracking table\n"
       "IP import check tracking table\n"
       "IPv4 Address\n"
       "IPv6 Address\n"
       VRF_CMD_HELP_STR
       "IPv4 Address\n"
       "IPv6 Address\n"
       VRF_ALL_CMD_HELP_STR)
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct prefix prefix, *p = NULL;
	enum rnh_type rtype;

	if (strcmp(type, "nht") == 0)
		rtype = RNH_NEXTHOP_TYPE;
	else
		rtype = RNH_IMPORT_CHECK_TYPE;

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
			if ((zvrf = vrf->info) != NULL) {
				vty_out(vty, "\nVRF %s:\n", zvrf_name(zvrf));
				zebra_print_rnh_table(zvrf_id(zvrf), afi, vty,
						      rtype, NULL);
			}
		return CMD_SUCCESS;
	}
	if (vrf_name)
		VRF_GET_ID(vrf_id, vrf_name, false);

	memset(&prefix, 0, sizeof(prefix));
	if (addr)
		p = sockunion2hostprefix(addr, &prefix);

	zebra_print_rnh_table(vrf_id, afi, vty, rtype, p);
	return CMD_SUCCESS;
}

DEFUN (ip_nht_default_route,
       ip_nht_default_route_cmd,
       "ip nht resolve-via-default",
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	if (!zvrf)
		return CMD_WARNING;

	if (zvrf->zebra_rnh_ip_default_route)
		return CMD_SUCCESS;

	zvrf->zebra_rnh_ip_default_route = 1;

	zebra_evaluate_rnh(zvrf, AFI_IP, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

static void show_nexthop_group_out(struct vty *vty, struct nhg_hash_entry *nhe)
{
	struct nexthop *nexthop = NULL;
	struct nhg_connected *rb_node_dep = NULL;
	struct vrf *nhe_vrf = vrf_lookup_by_id(nhe->vrf_id);
	struct nexthop_group *backup_nhg;

	vty_out(vty, "ID: %u\n", nhe->id);
	vty_out(vty, "     RefCnt: %d\n", nhe->refcnt);

	if (nhe_vrf)
		vty_out(vty, "     VRF: %s AFI: %s\n", nhe_vrf->name,
			afi2str(nhe->afi));
	else
		vty_out(vty, "     VRF: UNKNOWN AFI: %s\n",
			afi2str(nhe->afi));

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_UNHASHABLE))
		vty_out(vty, "     Duplicate - from kernel not hashable\n");

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID)) {
		vty_out(vty, "     Valid");
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED))
			vty_out(vty, ", Installed");
		vty_out(vty, "\n");
	}
	if (nhe->ifp)
		vty_out(vty, "     Interface Index: %d\n", nhe->ifp->ifindex);

	if (!zebra_nhg_depends_is_empty(nhe)) {
		vty_out(vty, "     Depends:");
		frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
			vty_out(vty, " (%u)", rb_node_dep->nhe->id);
		}
		vty_out(vty, "\n");
	}

	/* Output nexthops */
	for (ALL_NEXTHOPS(nhe->nhg, nexthop)) {
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			vty_out(vty, "          ");
		else
			/* Make recursive nexthops a bit more clear */
			vty_out(vty, "       ");

		show_route_nexthop_helper(vty, NULL, nexthop);

		if (nhe->backup_info == NULL || nhe->backup_info->nhe == NULL) {
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_HAS_BACKUP))
				vty_out(vty, " [backup %d]",
					nexthop->backup_idx);

			vty_out(vty, "\n");
			continue;
		}

		/* TODO -- print more useful backup info */
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
			struct nexthop *backup;
			int i;

			i = 0;
			for (ALL_NEXTHOPS(nhe->backup_info->nhe->nhg, backup)) {
				if (i == nexthop->backup_idx)
					break;
				i++;
			}

			/* TODO */
			if (backup)
				vty_out(vty, " [backup %d]",
					nexthop->backup_idx);
			else
				vty_out(vty, " [backup INVALID]");
		}

		vty_out(vty, "\n");
	}

	/* Output backup nexthops (if any) */
	backup_nhg = zebra_nhg_get_backup_nhg(nhe);
	if (backup_nhg) {
		vty_out(vty, "     Backups:\n");

		for (ALL_NEXTHOPS_PTR(backup_nhg, nexthop)) {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				vty_out(vty, "          ");
			else
				/* Make recursive nexthops a bit more clear */
				vty_out(vty, "       ");

			show_route_nexthop_helper(vty, NULL, nexthop);
			vty_out(vty, "\n");
		}
	}

	if (!zebra_nhg_dependents_is_empty(nhe)) {
		vty_out(vty, "     Dependents:");
		frr_each(nhg_connected_tree, &nhe->nhg_dependents,
			  rb_node_dep) {
			vty_out(vty, " (%u)", rb_node_dep->nhe->id);
		}
		vty_out(vty, "\n");
	}

}

static int show_nexthop_group_id_cmd_helper(struct vty *vty, uint32_t id)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = zebra_nhg_lookup_id(id);

	if (nhe)
		show_nexthop_group_out(vty, nhe);
	else {
		vty_out(vty, "Nexthop Group ID: %u does not exist\n", id);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

/* Helper function for iteration through the hash of nexthop-groups/nhe-s */

struct nhe_show_context {
	struct vty *vty;
	vrf_id_t vrf_id;
	afi_t afi;
};

static int nhe_show_walker(struct hash_bucket *bucket, void *arg)
{
	struct nhe_show_context *ctx = arg;
	struct nhg_hash_entry *nhe;

	nhe = bucket->data; /* We won't be offered NULL buckets */

	if (ctx->afi && nhe->afi != ctx->afi)
		goto done;

	if (ctx->vrf_id && nhe->vrf_id != ctx->vrf_id)
		goto done;

	show_nexthop_group_out(ctx->vty, nhe);

done:
	return HASHWALK_CONTINUE;
}

static void show_nexthop_group_cmd_helper(struct vty *vty,
					  struct zebra_vrf *zvrf,
					  afi_t afi)
{
	struct nhe_show_context ctx;

	ctx.vty = vty;
	ctx.afi = afi;
	ctx.vrf_id = zvrf->vrf->vrf_id;

	hash_walk(zrouter.nhgs_id, nhe_show_walker, &ctx);
}

static void if_nexthop_group_dump_vty(struct vty *vty, struct interface *ifp)
{
	struct zebra_if *zebra_if = NULL;
	struct nhg_connected *rb_node_dep = NULL;

	zebra_if = ifp->info;

	if (!if_nhg_dependents_is_empty(ifp)) {
		vty_out(vty, "Interface %s:\n", ifp->name);

		frr_each(nhg_connected_tree, &zebra_if->nhg_dependents,
			  rb_node_dep) {
			vty_out(vty, "   ");
			show_nexthop_group_out(vty, rb_node_dep->nhe);
		}
	}
}

DEFPY (show_interface_nexthop_group,
       show_interface_nexthop_group_cmd,
       "show interface [IFNAME$if_name] nexthop-group",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface name\n"
       "Show Nexthop Groups\n")
{
	struct vrf *vrf = NULL;
	struct interface *ifp = NULL;
	bool found = false;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (if_name) {
			ifp = if_lookup_by_name(if_name, vrf->vrf_id);
			if (ifp) {
				if_nexthop_group_dump_vty(vty, ifp);
				found = true;
			}
		} else {
			FOR_ALL_INTERFACES (vrf, ifp)
				if_nexthop_group_dump_vty(vty, ifp);
			found = true;
		}
	}

	if (!found) {
		vty_out(vty, "%% Can't find interface %s\n", if_name);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY (show_nexthop_group,
       show_nexthop_group_cmd,
       "show nexthop-group rib <(0-4294967295)$id|[singleton <ip$v4|ipv6$v6>] [vrf <NAME$vrf_name|all$vrf_all>]>",
       SHOW_STR
       "Show Nexthop Groups\n"
       "RIB information\n"
       "Nexthop Group ID\n"
       "Show Singleton Nexthop-Groups\n"
       IP_STR
       IP6_STR
       VRF_FULL_CMD_HELP_STR)
{

	struct zebra_vrf *zvrf = NULL;
	afi_t afi = AFI_UNSPEC;

	if (id)
		return show_nexthop_group_id_cmd_helper(vty, id);

	if (v4)
		afi = AFI_IP;
	else if (v6)
		afi = AFI_IP6;

	if (!vrf_is_backend_netns() && (vrf_name || vrf_all)) {
		vty_out(vty,
			"VRF subcommand does not make any sense in l3mdev based vrf's\n");
		return CMD_WARNING;
	}

	if (vrf_all) {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			struct zebra_vrf *zvrf;

			zvrf = vrf->info;
			if (!zvrf)
				continue;

			vty_out(vty, "VRF: %s\n", vrf->name);
			show_nexthop_group_cmd_helper(vty, zvrf, afi);
		}

		return CMD_SUCCESS;
	}

	if (vrf_name)
		zvrf = zebra_vrf_lookup_by_name(vrf_name);
	else
		zvrf = zebra_vrf_lookup_by_name(VRF_DEFAULT_NAME);

	if (!zvrf) {
		vty_out(vty, "%% VRF '%s' specified does not exist\n",
			vrf_name);
		return CMD_WARNING;
	}

	show_nexthop_group_cmd_helper(vty, zvrf, afi);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(nexthop_group_use_enable,
	     nexthop_group_use_enable_cmd,
	     "[no] zebra nexthop kernel enable",
	     NO_STR
	     ZEBRA_STR
	     "Nexthop configuration \n"
	     "Configure use of kernel nexthops\n"
	     "Enable kernel nexthops\n")
{
	zebra_nhg_enable_kernel_nexthops(!no);
	return CMD_SUCCESS;
}

DEFUN (no_ip_nht_default_route,
       no_ip_nht_default_route_cmd,
       "no ip nht resolve-via-default",
       NO_STR
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	if (!zvrf)
		return CMD_WARNING;

	if (!zvrf->zebra_rnh_ip_default_route)
		return CMD_SUCCESS;

	zvrf->zebra_rnh_ip_default_route = 0;
	zebra_evaluate_rnh(zvrf, AFI_IP, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

DEFUN (ipv6_nht_default_route,
       ipv6_nht_default_route_cmd,
       "ipv6 nht resolve-via-default",
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	if (!zvrf)
		return CMD_WARNING;

	if (zvrf->zebra_rnh_ipv6_default_route)
		return CMD_SUCCESS;

	zvrf->zebra_rnh_ipv6_default_route = 1;
	zebra_evaluate_rnh(zvrf, AFI_IP6, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

DEFUN (no_ipv6_nht_default_route,
       no_ipv6_nht_default_route_cmd,
       "no ipv6 nht resolve-via-default",
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{

	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	if (!zvrf)
		return CMD_WARNING;

	if (!zvrf->zebra_rnh_ipv6_default_route)
		return CMD_SUCCESS;

	zvrf->zebra_rnh_ipv6_default_route = 0;
	zebra_evaluate_rnh(zvrf, AFI_IP6, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

DEFPY (show_route,
       show_route_cmd,
       "show\
         <\
	  ip$ipv4 <fib$fib|route> [table <(1-4294967295)$table|all$table_all>]\
	  [vrf <NAME$vrf_name|all$vrf_all>]\
	   [{\
	    tag (1-4294967295)\
	    |A.B.C.D/M$prefix longer-prefixes\
	    |supernets-only$supernets_only\
	   }]\
	   [<\
	    " FRR_IP_REDIST_STR_ZEBRA "$type_str\
	    |ospf$type_str (1-65535)$ospf_instance_id\
	   >]\
          |ipv6$ipv6 <fib$fib|route> [table <(1-4294967295)$table|all$table_all>]\
	  [vrf <NAME$vrf_name|all$vrf_all>]\
	   [{\
	    tag (1-4294967295)\
	    |X:X::X:X/M$prefix longer-prefixes\
	   }]\
	   [" FRR_IP6_REDIST_STR_ZEBRA "$type_str]\
	 >\
        [json$json]",
       SHOW_STR
       IP_STR
       "IP forwarding table\n"
       "IP routing table\n"
       "Table to display\n"
       "The table number to display\n"
       "All tables\n"
       VRF_FULL_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n"
       "Show supernet entries only\n"
       FRR_IP_REDIST_HELP_STR_ZEBRA
       "Open Shortest Path First (OSPFv2)\n"
       "Instance ID\n"
       IPV6_STR
       "IP forwarding table\n"
       "IP routing table\n"
       "Table to display\n"
       "The table number to display\n"
       "All tables\n"
       VRF_FULL_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n"
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n"
       FRR_IP6_REDIST_HELP_STR_ZEBRA
       JSON_STR)
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	struct vrf *vrf;
	int type = 0;
	struct zebra_vrf *zvrf;

	if (!vrf_is_backend_netns()) {
		if ((vrf_all || vrf_name) && (table || table_all)) {
			if (!!json)
				vty_out(vty, "{}\n");
			else {
				vty_out(vty, "Linux vrf backend already points to table id\n");
				vty_out(vty, "Either remove table parameter or vrf parameter\n");
			}
			return CMD_SUCCESS;
		}
	}
	if (type_str) {
		type = proto_redistnum(afi, type_str);
		if (type < 0) {
			vty_out(vty, "Unknown route type\n");
			return CMD_WARNING;
		}
	}

	if (vrf_all) {
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) == NULL
			    || (zvrf->table[afi][SAFI_UNICAST] == NULL))
				continue;

			if (table_all)
				do_show_ip_route_all(vty, zvrf, afi,
						     !!fib, !!json,
						     tag, prefix_str ? prefix : NULL,
						     !!supernets_only, type,
						     ospf_instance_id);
			else
				do_show_ip_route(vty, zvrf_name(zvrf), afi,
						 SAFI_UNICAST, !!fib, !!json, tag,
						 prefix_str ? prefix : NULL,
						 !!supernets_only, type,
						 ospf_instance_id, table);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, !!json);
		vrf = vrf_lookup_by_id(vrf_id);
		if (vrf)
			zvrf = vrf->info;
		if (!vrf || !zvrf)
			return CMD_SUCCESS;

		if (table_all)
			do_show_ip_route_all(vty, zvrf, afi,
					     !!fib, !!json,
					     tag, prefix_str ? prefix : NULL,
					     !!supernets_only, type,
					     ospf_instance_id);
		else
			do_show_ip_route(vty, vrf->name, afi, SAFI_UNICAST, !!fib,
					 !!json, tag, prefix_str ? prefix : NULL,
					 !!supernets_only, type, ospf_instance_id, table);
	}

	return CMD_SUCCESS;
}

DEFPY (show_route_detail,
       show_route_detail_cmd,
       "show\
         <\
          ip$ipv4 <fib$fib|route> [vrf <NAME$vrf_name|all$vrf_all>]\
          <\
	   A.B.C.D$address\
	   |A.B.C.D/M$prefix\
	  >\
          |ipv6$ipv6 <fib$fib|route> [vrf <NAME$vrf_name|all$vrf_all>]\
          <\
	   X:X::X:X$address\
	   |X:X::X:X/M$prefix\
	  >\
	 >\
	 [json$json] [nexthop-group$ng]",
       SHOW_STR
       IP_STR
       "IPv6 forwarding table\n"
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "Network in the IP routing table to display\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       IP6_STR
       "IPv6 forwarding table\n"
       "IPv6 routing table\n"
       VRF_FULL_CMD_HELP_STR
       "IPv6 Address\n"
       "IPv6 prefix\n"
       JSON_STR
       "Nexthop Group Information\n")
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	struct route_table *table;
	struct prefix p;
	struct route_node *rn;
	bool use_fib = !!fib;
	rib_dest_t *dest;
	bool network_found = false;
	bool show_ng = !!ng;

	if (address_str)
		prefix_str = address_str;
	if (str2prefix(prefix_str, &p) < 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING;
	}

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) == NULL
			    || (table = zvrf->table[afi][SAFI_UNICAST]) == NULL)
				continue;

			rn = route_node_match(table, &p);
			if (!rn)
				continue;
			if (!address_str && rn->p.prefixlen != p.prefixlen) {
				route_unlock_node(rn);
				continue;
			}

			dest = rib_dest_from_rnode(rn);
			if (use_fib && !dest->selected_fib) {
				route_unlock_node(rn);
				continue;
			}

			network_found = true;
			if (json)
				vty_show_ip_route_detail_json(vty, rn, use_fib);
			else
				vty_show_ip_route_detail(vty, rn, 0, use_fib,
							 show_ng);

			route_unlock_node(rn);
		}

		if (!network_found) {
			if (json)
				vty_out(vty, "{}\n");
			else {
				if (use_fib)
					vty_out(vty,
						"%% Network not in FIB\n");
				else
					vty_out(vty,
						"%% Network not in RIB\n");
			}
			return CMD_WARNING;
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, false);

		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		if (!table)
			return CMD_SUCCESS;

		rn = route_node_match(table, &p);
		if (rn)
			dest = rib_dest_from_rnode(rn);

		if (!rn || (!address_str && rn->p.prefixlen != p.prefixlen) ||
			(use_fib && dest && !dest->selected_fib)) {
			if (json)
				vty_out(vty, "{}\n");
			else {
				if (use_fib)
					vty_out(vty,
						"%% Network not in FIB\n");
				else
					vty_out(vty,
						"%% Network not in table\n");
			}
			if (rn)
				route_unlock_node(rn);
			return CMD_WARNING;
		}

		if (json)
			vty_show_ip_route_detail_json(vty, rn, use_fib);
		else
			vty_show_ip_route_detail(vty, rn, 0, use_fib, show_ng);

		route_unlock_node(rn);
	}

	return CMD_SUCCESS;
}

DEFPY (show_route_summary,
       show_route_summary_cmd,
       "show <ip$ipv4|ipv6$ipv6> route [vrf <NAME$vrf_name|all$vrf_all>] \
            summary [table (1-4294967295)$table_id] [prefix$prefix] [json]",
       SHOW_STR
       IP_STR
       IP6_STR
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "Summary of all routes\n"
       "Table to display summary for\n"
       "The table number\n"
       "Prefix routes\n"
       JSON_STR)
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	struct route_table *table;
	bool uj = use_json(argc, argv);

	if (table_id == 0)
		table_id = RT_TABLE_MAIN;

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) == NULL)
				continue;

			table = zebra_vrf_lookup_table_with_table_id(
				afi, SAFI_UNICAST, zvrf->vrf->vrf_id, table_id);

			if (!table)
				continue;

			if (prefix)
				vty_show_ip_route_summary_prefix(vty, table,
								 uj);
			else
				vty_show_ip_route_summary(vty, table, uj);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, false);

		table = zebra_vrf_lookup_table_with_table_id(afi, SAFI_UNICAST,
							     vrf_id, table_id);
		if (!table)
			return CMD_SUCCESS;

		if (prefix)
			vty_show_ip_route_summary_prefix(vty, table, uj);
		else
			vty_show_ip_route_summary(vty, table, uj);
	}

	return CMD_SUCCESS;
}

static void vty_show_ip_route_summary(struct vty *vty,
				      struct route_table *table, bool use_json)
{
	struct route_node *rn;
	struct route_entry *re;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
	uint32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t i;
	uint32_t is_ibgp;
	json_object *json_route_summary = NULL;
	json_object *json_route_routes = NULL;

	memset(&rib_cnt, 0, sizeof(rib_cnt));
	memset(&fib_cnt, 0, sizeof(fib_cnt));

	if (use_json) {
		json_route_summary = json_object_new_object();
		json_route_routes = json_object_new_array();
		json_object_object_add(json_route_summary, "routes",
				       json_route_routes);
	}

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, re) {
			is_ibgp = (re->type == ZEBRA_ROUTE_BGP
				   && CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP));

			rib_cnt[ZEBRA_ROUTE_TOTAL]++;
			if (is_ibgp)
				rib_cnt[ZEBRA_ROUTE_IBGP]++;
			else
				rib_cnt[re->type]++;

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)) {
				fib_cnt[ZEBRA_ROUTE_TOTAL]++;

				if (is_ibgp)
					fib_cnt[ZEBRA_ROUTE_IBGP]++;
				else
					fib_cnt[re->type]++;
			}
		}

	if (!use_json)
		vty_out(vty, "%-20s %-20s %s  (vrf %s)\n", "Route Source",
			"Routes", "FIB",
			zvrf_name(((struct rib_table_info *)
					   route_table_get_info(table))
					  ->zvrf));

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if ((rib_cnt[i] > 0) || (i == ZEBRA_ROUTE_BGP
					 && rib_cnt[ZEBRA_ROUTE_IBGP] > 0)) {
			if (i == ZEBRA_ROUTE_BGP) {
				if (use_json) {
					json_object *json_route_ebgp =
						json_object_new_object();

					json_object_int_add(
						json_route_ebgp, "fib",
						fib_cnt[ZEBRA_ROUTE_BGP]);
					json_object_int_add(
						json_route_ebgp, "rib",
						rib_cnt[ZEBRA_ROUTE_BGP]);
					json_object_string_add(json_route_ebgp,
							       "type", "ebgp");
					json_object_array_add(json_route_routes,
							      json_route_ebgp);

					json_object *json_route_ibgp =
						json_object_new_object();

					json_object_int_add(
						json_route_ibgp, "fib",
						fib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_int_add(
						json_route_ibgp, "rib",
						rib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_string_add(json_route_ibgp,
							       "type", "ibgp");
					json_object_array_add(json_route_routes,
							      json_route_ibgp);
				} else {
					vty_out(vty, "%-20s %-20d %-20d \n",
						"ebgp",
						rib_cnt[ZEBRA_ROUTE_BGP],
						fib_cnt[ZEBRA_ROUTE_BGP]);
					vty_out(vty, "%-20s %-20d %-20d \n",
						"ibgp",
						rib_cnt[ZEBRA_ROUTE_IBGP],
						fib_cnt[ZEBRA_ROUTE_IBGP]);
				}
			} else {
				if (use_json) {
					json_object *json_route_type =
						json_object_new_object();

					json_object_int_add(json_route_type,
							    "fib", fib_cnt[i]);
					json_object_int_add(json_route_type,
							    "rib", rib_cnt[i]);
					json_object_string_add(
						json_route_type, "type",
						zebra_route_string(i));
					json_object_array_add(json_route_routes,
							      json_route_type);
				} else
					vty_out(vty, "%-20s %-20d %-20d \n",
						zebra_route_string(i),
						rib_cnt[i], fib_cnt[i]);
			}
		}
	}

	if (use_json) {
		json_object_int_add(json_route_summary, "routesTotal",
				    rib_cnt[ZEBRA_ROUTE_TOTAL]);
		json_object_int_add(json_route_summary, "routesTotalFib",
				    fib_cnt[ZEBRA_ROUTE_TOTAL]);

		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json_route_summary, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_route_summary);
	} else {
		vty_out(vty, "------\n");
		vty_out(vty, "%-20s %-20d %-20d \n", "Totals",
			rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL]);
		vty_out(vty, "\n");
	}
}

/*
 * Implementation of the ip route summary prefix command.
 *
 * This command prints the primary prefixes that have been installed by various
 * protocols on the box.
 *
 */
static void vty_show_ip_route_summary_prefix(struct vty *vty,
					     struct route_table *table,
					     bool use_json)
{
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
	uint32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t i;
	int cnt;
	json_object *json_route_summary = NULL;
	json_object *json_route_routes = NULL;

	memset(&rib_cnt, 0, sizeof(rib_cnt));
	memset(&fib_cnt, 0, sizeof(fib_cnt));

	if (use_json) {
		json_route_summary = json_object_new_object();
		json_route_routes = json_object_new_array();
		json_object_object_add(json_route_summary, "prefixRoutes",
				       json_route_routes);
	}

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, re) {

			/*
			 * In case of ECMP, count only once.
			 */
			cnt = 0;
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)) {
				fib_cnt[ZEBRA_ROUTE_TOTAL]++;
				fib_cnt[re->type]++;
			}
			for (nexthop = re->nhe->nhg.nexthop; (!cnt && nexthop);
			     nexthop = nexthop->next) {
				cnt++;
				rib_cnt[ZEBRA_ROUTE_TOTAL]++;
				rib_cnt[re->type]++;
				if (re->type == ZEBRA_ROUTE_BGP
				    && CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP)) {
					rib_cnt[ZEBRA_ROUTE_IBGP]++;
					if (CHECK_FLAG(re->status,
						       ROUTE_ENTRY_INSTALLED))
						fib_cnt[ZEBRA_ROUTE_IBGP]++;
				}
			}
		}

	if (!use_json)
		vty_out(vty, "%-20s %-20s %s  (vrf %s)\n", "Route Source",
			"Prefix Routes", "FIB",
			zvrf_name(((struct rib_table_info *)
					   route_table_get_info(table))
					  ->zvrf));

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (rib_cnt[i] > 0) {
			if (i == ZEBRA_ROUTE_BGP) {
				if (use_json) {
					json_object *json_route_ebgp =
						json_object_new_object();

					json_object_int_add(
						json_route_ebgp, "fib",
						fib_cnt[ZEBRA_ROUTE_BGP]
							- fib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_int_add(
						json_route_ebgp, "rib",
						rib_cnt[ZEBRA_ROUTE_BGP]
							- rib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_string_add(json_route_ebgp,
							       "type", "ebgp");
					json_object_array_add(json_route_routes,
							      json_route_ebgp);

					json_object *json_route_ibgp =
						json_object_new_object();

					json_object_int_add(
						json_route_ibgp, "fib",
						fib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_int_add(
						json_route_ibgp, "rib",
						rib_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_string_add(json_route_ibgp,
							       "type", "ibgp");
					json_object_array_add(json_route_routes,
							      json_route_ibgp);
				} else {
					vty_out(vty, "%-20s %-20d %-20d \n",
						"ebgp",
						rib_cnt[ZEBRA_ROUTE_BGP]
							- rib_cnt[ZEBRA_ROUTE_IBGP],
						fib_cnt[ZEBRA_ROUTE_BGP]
							- fib_cnt[ZEBRA_ROUTE_IBGP]);
					vty_out(vty, "%-20s %-20d %-20d \n",
						"ibgp",
						rib_cnt[ZEBRA_ROUTE_IBGP],
						fib_cnt[ZEBRA_ROUTE_IBGP]);
				}
			} else {
				if (use_json) {
					json_object *json_route_type =
						json_object_new_object();

					json_object_int_add(json_route_type,
							    "fib", fib_cnt[i]);
					json_object_int_add(json_route_type,
							    "rib", rib_cnt[i]);
					json_object_string_add(
						json_route_type, "type",
						zebra_route_string(i));
					json_object_array_add(json_route_routes,
							      json_route_type);
				} else
					vty_out(vty, "%-20s %-20d %-20d \n",
						zebra_route_string(i),
						rib_cnt[i], fib_cnt[i]);
			}
		}
	}

	if (use_json) {
		json_object_int_add(json_route_summary, "prefixRoutesTotal",
				    rib_cnt[ZEBRA_ROUTE_TOTAL]);
		json_object_int_add(json_route_summary, "prefixRoutesTotalFib",
				    fib_cnt[ZEBRA_ROUTE_TOTAL]);

		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json_route_summary, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_route_summary);
	} else {
		vty_out(vty, "------\n");
		vty_out(vty, "%-20s %-20d %-20d \n", "Totals",
			rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL]);
		vty_out(vty, "\n");
	}
}

/*
 * Show IPv6 mroute command.Used to dump
 * the Multicast routing table.
 */
DEFUN (show_ipv6_mroute,
       show_ipv6_mroute_cmd,
       "show ipv6 mroute [vrf NAME]",
       SHOW_STR
       IP_STR
       "IPv6 Multicast routing table\n"
       VRF_CMD_HELP_STR)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	int first = 1;
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (argc == 5)
		VRF_GET_ID(vrf_id, argv[4]->arg, false);

	table = zebra_vrf_table(AFI_IP6, SAFI_MULTICAST, vrf_id);
	if (!table)
		return CMD_SUCCESS;

	/* Show all IPv6 route. */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, re) {
			if (first) {
				vty_out(vty, SHOW_ROUTE_V6_HEADER);
				first = 0;
			}
			vty_show_ip_route(vty, rn, re, NULL, false);
		}
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_mroute_vrf_all,
       show_ipv6_mroute_vrf_all_cmd,
       "show ipv6 mroute vrf all",
       SHOW_STR
       IP_STR
       "IPv6 Multicast routing table\n"
       VRF_ALL_CMD_HELP_STR)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	int first = 1;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if ((zvrf = vrf->info) == NULL
		    || (table = zvrf->table[AFI_IP6][SAFI_MULTICAST]) == NULL)
			continue;

		/* Show all IPv6 route. */
		for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
			RNODE_FOREACH_RE (rn, re) {
				if (first) {
					vty_out(vty, SHOW_ROUTE_V6_HEADER);
					first = 0;
				}
				vty_show_ip_route(vty, rn, re, NULL, false);
			}
	}
	return CMD_SUCCESS;
}

DEFUN (allow_external_route_update,
       allow_external_route_update_cmd,
       "allow-external-route-update",
       "Allow FRR routes to be overwritten by external processes\n")
{
	allow_delete = 1;

	return CMD_SUCCESS;
}

DEFUN (no_allow_external_route_update,
       no_allow_external_route_update_cmd,
       "no allow-external-route-update",
       NO_STR
       "Allow FRR routes to be overwritten by external processes\n")
{
	allow_delete = 0;

	return CMD_SUCCESS;
}

/* show vrf */
DEFUN (show_vrf,
       show_vrf_cmd,
       "show vrf",
       SHOW_STR
       "VRF\n")
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	if (vrf_is_backend_netns())
		vty_out(vty, "netns-based vrfs\n");

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!(zvrf = vrf->info))
			continue;
		if (zvrf_id(zvrf) == VRF_DEFAULT)
			continue;

		vty_out(vty, "vrf %s ", zvrf_name(zvrf));
		if (zvrf_id(zvrf) == VRF_UNKNOWN || !zvrf_is_active(zvrf))
			vty_out(vty, "inactive");
		else if (zvrf_ns_name(zvrf))
			vty_out(vty, "id %u netns %s", zvrf_id(zvrf),
				zvrf_ns_name(zvrf));
		else
			vty_out(vty, "id %u table %u", zvrf_id(zvrf),
				zvrf->table_id);
		if (vrf_is_user_cfged(vrf))
			vty_out(vty, " (configured)");
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN (default_vrf_vni_mapping,
       default_vrf_vni_mapping_cmd,
       "vni " CMD_VNI_RANGE "[prefix-routes-only]",
       "VNI corresponding to the DEFAULT VRF\n"
       "VNI-ID\n"
       "Prefix routes only \n")
{
	int ret = 0;
	char err[ERR_STR_SZ];
	struct zebra_vrf *zvrf = NULL;
	vni_t vni = strtoul(argv[1]->arg, NULL, 10);
	int filter = 0;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return CMD_WARNING;

	if (argc == 3)
		filter = 1;

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ,
					      filter, 1);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_default_vrf_vni_mapping,
       no_default_vrf_vni_mapping_cmd,
       "no vni " CMD_VNI_RANGE,
       NO_STR
       "VNI corresponding to DEFAULT VRF\n"
       "VNI-ID")
{
	int ret = 0;
	char err[ERR_STR_SZ];
	vni_t vni = strtoul(argv[2]->arg, NULL, 10);
	struct zebra_vrf *zvrf = NULL;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return CMD_WARNING;

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ, 0, 0);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (vrf_vni_mapping,
       vrf_vni_mapping_cmd,
       "vni " CMD_VNI_RANGE "[prefix-routes-only]",
       "VNI corresponding to tenant VRF\n"
       "VNI-ID\n"
       "prefix-routes-only\n")
{
	int ret = 0;
	int filter = 0;

	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);
	vni_t vni = strtoul(argv[1]->arg, NULL, 10);
	char err[ERR_STR_SZ];

	assert(vrf);
	assert(zvrf);

	if (argc == 3)
		filter = 1;

	/* Mark as having FRR configuration */
	vrf_set_user_cfged(vrf);
	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ,
					      filter, 1);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_vrf_vni_mapping,
       no_vrf_vni_mapping_cmd,
       "no vni " CMD_VNI_RANGE "[prefix-routes-only]",
       NO_STR
       "VNI corresponding to tenant VRF\n"
       "VNI-ID\n"
       "prefix-routes-only\n")
{
	int ret = 0;
	int filter = 0;
	char err[ERR_STR_SZ];
	vni_t vni = strtoul(argv[2]->arg, NULL, 10);

	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	assert(vrf);
	assert(zvrf);

	if (argc == 4)
		filter = 1;

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err,
					      ERR_STR_SZ, filter, 0);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	/* If no other FRR config for this VRF, mark accordingly. */
	if (!zebra_vrf_has_config(zvrf))
		vrf_reset_user_cfged(vrf);

	return CMD_SUCCESS;
}

/* show vrf */
DEFUN (show_vrf_vni,
       show_vrf_vni_cmd,
       "show vrf vni [json]",
       SHOW_STR
       "VRF\n"
       "VNI\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	bool uj = use_json(argc, argv);

	if (uj) {
		json = json_object_new_object();
		json_vrfs = json_object_new_array();
	}

	if (!uj)
		vty_out(vty, "%-37s %-10s %-20s %-20s %-5s %-18s\n", "VRF",
			"VNI", "VxLAN IF", "L3-SVI", "State", "Rmac");

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;

		zebra_vxlan_print_vrf_vni(vty, zvrf, json_vrfs);
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

DEFUN (show_evpn_global,
       show_evpn_global_cmd,
       "show evpn [json]",
       SHOW_STR
       "EVPN\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);

	zebra_vxlan_print_evpn(vty, uj);
	return CMD_SUCCESS;
}

DEFPY(show_evpn_es,
      show_evpn_es_cmd,
      "show evpn es [NAME$esi_str] [json$json] [detail$detail]",
      SHOW_STR
      "EVPN\n"
      "Ethernet Segment\n"
      "ES ID\n"
      JSON_STR
      "Detailed information\n")
{
	esi_t esi;
	bool uj = !!json;

	if (esi_str) {
		if (!str_to_esi(esi_str, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		zebra_evpn_es_show_esi(vty, uj, &esi);
	} else {
		if (detail)
			zebra_evpn_es_show_detail(vty, uj);
		else
			zebra_evpn_es_show(vty, uj);
	}

	return CMD_SUCCESS;
}

DEFPY(show_evpn_es_evi,
      show_evpn_es_evi_cmd,
      "show evpn es-evi [vni (1-16777215)$vni] [json$json] [detail$detail]",
      SHOW_STR
      "EVPN\n"
      "Ethernet Segment per EVI\n"
      "VxLAN Network Identifier\n"
      "VNI\n"
      JSON_STR
      "Detailed information\n")
{
	bool uj = !!json;
	bool ud = !!detail;

	if (vni)
		zebra_evpn_es_evi_show_vni(vty, uj, vni, ud);
	else
		zebra_evpn_es_evi_show(vty, uj, ud);

	return CMD_SUCCESS;
}

DEFPY(show_evpn_access_vlan,
      show_evpn_access_vlan_cmd,
      "show evpn access-vlan [(1-4094)$vid] [json$json] [detail$detail]",
      SHOW_STR
      "EVPN\n"
      "Access VLANs\n"
      "VLAN ID\n"
      JSON_STR
      "Detailed information\n")
{
	bool uj = !!json;

	if (vid) {
		zebra_evpn_acc_vl_show_vid(vty, uj, vid);
	} else {
		if (detail)
			zebra_evpn_acc_vl_show_detail(vty, uj);
		else
			zebra_evpn_acc_vl_show(vty, uj);
	}

	return CMD_SUCCESS;
}

DEFUN (show_evpn_vni,
       show_evpn_vni_cmd,
       "show evpn vni [json]",
       SHOW_STR
       "EVPN\n"
       "VxLAN Network Identifier\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_vnis(vty, zvrf, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_vni_detail, show_evpn_vni_detail_cmd,
       "show evpn vni detail [json]",
       SHOW_STR
       "EVPN\n"
       "VxLAN Network Identifier\n"
       "Detailed Information On Each VNI\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_vnis_detail(vty, zvrf, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_vni_vni,
       show_evpn_vni_vni_cmd,
       "show evpn vni " CMD_VNI_RANGE "[json]",
       SHOW_STR
       "EVPN\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[3]->arg, NULL, 10);
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_vni(vty, zvrf, vni, uj, NULL);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_rmac_vni_mac,
       show_evpn_rmac_vni_mac_cmd,
       "show evpn rmac vni " CMD_VNI_RANGE " mac WORD [json]",
       SHOW_STR
       "EVPN\n"
       "RMAC\n"
       "L3 VNI\n"
       "VNI number\n"
       "MAC\n"
       "mac-address (e.g. 0a:0a:0a:0a:0a:0a)\n"
       JSON_STR)
{
	vni_t l3vni = 0;
	struct ethaddr mac;
	bool uj = use_json(argc, argv);

	l3vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	zebra_vxlan_print_specific_rmac_l3vni(vty, l3vni, &mac, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_rmac_vni,
       show_evpn_rmac_vni_cmd,
       "show evpn rmac vni " CMD_VNI_RANGE "[json]",
       SHOW_STR
       "EVPN\n"
       "RMAC\n"
       "L3 VNI\n"
       "VNI number\n"
       JSON_STR)
{
	vni_t l3vni = 0;
	bool uj = use_json(argc, argv);

	l3vni = strtoul(argv[4]->arg, NULL, 10);
	zebra_vxlan_print_rmacs_l3vni(vty, l3vni, uj);

	return CMD_SUCCESS;
}

DEFUN (show_evpn_rmac_vni_all,
       show_evpn_rmac_vni_all_cmd,
       "show evpn rmac vni all [json]",
       SHOW_STR
       "EVPN\n"
       "RMAC addresses\n"
       "L3 VNI\n"
       "All VNIs\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);

	zebra_vxlan_print_rmacs_all_l3vni(vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_evpn_nh_vni_ip,
       show_evpn_nh_vni_ip_cmd,
       "show evpn next-hops vni " CMD_VNI_RANGE " ip WORD [json]",
       SHOW_STR
       "EVPN\n"
       "Remote Vteps\n"
       "L3 VNI\n"
       "VNI number\n"
       "Ip address\n"
       "Host address (ipv4 or ipv6)\n"
       JSON_STR)
{
	vni_t l3vni;
	struct ipaddr ip;
	bool uj = use_json(argc, argv);

	l3vni = strtoul(argv[4]->arg, NULL, 10);
	if (str2ipaddr(argv[6]->arg, &ip) != 0) {
		if (!uj)
			vty_out(vty, "%% Malformed Neighbor address\n");
		return CMD_WARNING;
	}
	zebra_vxlan_print_specific_nh_l3vni(vty, l3vni, &ip, uj);

	return CMD_SUCCESS;
}

DEFUN (show_evpn_nh_vni,
       show_evpn_nh_vni_cmd,
       "show evpn next-hops vni " CMD_VNI_RANGE "[json]",
       SHOW_STR
       "EVPN\n"
       "Remote Vteps\n"
       "L3 VNI\n"
       "VNI number\n"
       JSON_STR)
{
	vni_t l3vni;
	bool uj = use_json(argc, argv);

	l3vni = strtoul(argv[4]->arg, NULL, 10);
	zebra_vxlan_print_nh_l3vni(vty, l3vni, uj);

	return CMD_SUCCESS;
}

DEFUN (show_evpn_nh_vni_all,
       show_evpn_nh_vni_all_cmd,
       "show evpn next-hops vni all [json]",
       SHOW_STR
       "EVPN\n"
       "Remote VTEPs\n"
       "L3 VNI\n"
       "All VNIs\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);

	zebra_vxlan_print_nh_all_l3vni(vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_evpn_mac_vni,
       show_evpn_mac_vni_cmd,
       "show evpn mac vni " CMD_VNI_RANGE "[json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_vni(vty, zvrf, vni, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_mac_vni_all,
       show_evpn_mac_vni_all_cmd,
       "show evpn mac vni all [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_all_vni(vty, zvrf, false, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_mac_vni_all_detail, show_evpn_mac_vni_all_detail_cmd,
       "show evpn mac vni all detail [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       "Detailed Information On Each VNI MAC\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_all_vni_detail(vty, zvrf, false, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_mac_vni_all_vtep,
       show_evpn_mac_vni_all_vtep_cmd,
       "show evpn mac vni all vtep A.B.C.D [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       "Remote VTEP\n"
       "Remote VTEP IP address\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	struct in_addr vtep_ip;
	bool uj = use_json(argc, argv);

	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_all_vni_vtep(vty, zvrf, vtep_ip, uj);

	return CMD_SUCCESS;
}


DEFUN (show_evpn_mac_vni_mac,
       show_evpn_mac_vni_mac_cmd,
       "show evpn mac vni " CMD_VNI_RANGE " mac WORD [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "MAC\n"
       "MAC address (e.g., 00:e0:ec:20:12:62)\n"
       JSON_STR)

{
	struct zebra_vrf *zvrf;
	vni_t vni;
	struct ethaddr mac;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address");
		return CMD_WARNING;
	}
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_specific_mac_vni(vty, zvrf, vni, &mac, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_mac_vni_vtep,
       show_evpn_mac_vni_vtep_cmd,
       "show evpn mac vni " CMD_VNI_RANGE " vtep A.B.C.D" "[json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "Remote VTEP\n"
       "Remote VTEP IP address\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	struct in_addr vtep_ip;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_vni_vtep(vty, zvrf, vni, vtep_ip, uj);
	return CMD_SUCCESS;
}

DEFPY (show_evpn_mac_vni_all_dad,
       show_evpn_mac_vni_all_dad_cmd,
       "show evpn mac vni all duplicate [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       "Duplicate address list\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_all_vni(vty, zvrf, true, uj);
	return CMD_SUCCESS;
}


DEFPY (show_evpn_mac_vni_dad,
       show_evpn_mac_vni_dad_cmd,
       "show evpn mac vni " CMD_VNI_RANGE " duplicate [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "Duplicate address list\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();

	zebra_vxlan_print_macs_vni_dad(vty, zvrf, vni, uj);

	return CMD_SUCCESS;
}

DEFPY (show_evpn_neigh_vni_dad,
       show_evpn_neigh_vni_dad_cmd,
       "show evpn arp-cache vni " CMD_VNI_RANGE "duplicate [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "Duplicate address list\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_vni_dad(vty, zvrf, vni, uj);
	return CMD_SUCCESS;
}

DEFPY (show_evpn_neigh_vni_all_dad,
       show_evpn_neigh_vni_all_dad_cmd,
       "show evpn arp-cache vni all duplicate [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       "Duplicate address list\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_all_vni(vty, zvrf, true, uj);
	return CMD_SUCCESS;
}


DEFUN (show_evpn_neigh_vni,
       show_evpn_neigh_vni_cmd,
       "show evpn arp-cache vni " CMD_VNI_RANGE "[json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_vni(vty, zvrf, vni, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_neigh_vni_all,
       show_evpn_neigh_vni_all_cmd,
       "show evpn arp-cache vni all [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_all_vni(vty, zvrf, false, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_neigh_vni_all_detail, show_evpn_neigh_vni_all_detail_cmd,
       "show evpn arp-cache vni all detail [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "All VNIs\n"
       "Neighbor details for all vnis in detail\n" JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_all_vni_detail(vty, zvrf, false, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_neigh_vni_neigh,
       show_evpn_neigh_vni_neigh_cmd,
       "show evpn arp-cache vni " CMD_VNI_RANGE " ip WORD [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "Neighbor\n"
       "Neighbor address (IPv4 or IPv6 address)\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	struct ipaddr ip;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (str2ipaddr(argv[6]->arg, &ip) != 0) {
		if (!uj)
			vty_out(vty, "%% Malformed Neighbor address\n");
		return CMD_WARNING;
	}
	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_specific_neigh_vni(vty, zvrf, vni, &ip, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_neigh_vni_vtep,
       show_evpn_neigh_vni_vtep_cmd,
       "show evpn arp-cache vni " CMD_VNI_RANGE " vtep A.B.C.D [json]",
       SHOW_STR
       "EVPN\n"
       "ARP and ND cache\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "Remote VTEP\n"
       "Remote VTEP IP address\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	struct in_addr vtep_ip;
	bool uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_neigh_vni_vtep(vty, zvrf, vni, vtep_ip, uj);
	return CMD_SUCCESS;
}

/* policy routing contexts */
DEFUN (show_pbr_ipset,
       show_pbr_ipset_cmd,
       "show pbr ipset [WORD]",
       SHOW_STR
       "Policy-Based Routing\n"
       "IPset Context information\n"
       "IPset Name information\n")
{
	int idx = 0;
	int found = 0;
	found = argv_find(argv, argc, "WORD", &idx);
	if (!found)
		zebra_pbr_show_ipset_list(vty, NULL);
	else
		zebra_pbr_show_ipset_list(vty, argv[idx]->arg);
	return CMD_SUCCESS;
}

/* policy routing contexts */
DEFUN (show_pbr_iptable,
       show_pbr_iptable_cmd,
       "show pbr iptable [WORD]",
       SHOW_STR
       "Policy-Based Routing\n"
       "IPtable Context information\n"
       "IPtable Name information\n")
{
	int idx = 0;
	int found = 0;

	found = argv_find(argv, argc, "WORD", &idx);
	if (!found)
		zebra_pbr_show_iptable(vty, NULL);
	else
		zebra_pbr_show_iptable(vty, argv[idx]->arg);
	return CMD_SUCCESS;
}

DEFPY (clear_evpn_dup_addr,
       clear_evpn_dup_addr_cmd,
       "clear evpn dup-addr vni <all$vni_all |" CMD_VNI_RANGE"$vni [mac X:X:X:X:X:X | ip <A.B.C.D|X:X::X:X>]>",
       CLEAR_STR
       "EVPN\n"
       "Duplicate address \n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "All VNIs\n"
       "MAC\n"
       "MAC address (e.g., 00:e0:ec:20:12:62)\n"
       "IP\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	struct ipaddr host_ip = {.ipa_type = IPADDR_NONE };
	int ret = CMD_SUCCESS;
	struct list *input;
	struct yang_data *yang_dup = NULL, *yang_dup_ip = NULL,
			 *yang_dup_mac = NULL;

	input = list_new();

	if (!vni_str) {
		yang_dup = yang_data_new(
			"/frr-zebra:clear-evpn-dup-addr/input/clear-dup-choice",
			"all-case");
	} else {
		yang_dup = yang_data_new_uint32(
			"/frr-zebra:clear-evpn-dup-addr/input/clear-dup-choice/single-case/vni-id",
			vni);
		if (!is_zero_mac(&mac->eth_addr)) {
			yang_dup_mac = yang_data_new_mac(
				"/frr-zebra:clear-evpn-dup-addr/input/clear-dup-choice/single-case/vni-id/mac-addr",
				&mac->eth_addr);
			if (yang_dup_mac)
				listnode_add(input, yang_dup_mac);
		} else if (ip) {
			if (sockunion_family(ip) == AF_INET) {
				host_ip.ipa_type = IPADDR_V4;
				host_ip.ipaddr_v4.s_addr = sockunion2ip(ip);
			} else {
				host_ip.ipa_type = IPADDR_V6;
				memcpy(&host_ip.ipaddr_v6, &ip->sin6.sin6_addr,
				       sizeof(struct in6_addr));
			}

			yang_dup_ip = yang_data_new_ip(
				"/frr-zebra:clear-evpn-dup-addr/input/clear-dup-choice/single-case/vni-id/vni-ipaddr",
				&host_ip);

			if (yang_dup_ip)
				listnode_add(input, yang_dup_ip);
		}
	}

	if (yang_dup) {
		listnode_add(input, yang_dup);
		ret = nb_cli_rpc("/frr-zebra:clear-evpn-dup-addr", input, NULL);
	}

	list_delete(&input);

	return ret;
}

/* Static ip route configuration write function. */
static int zebra_ip_config(struct vty *vty)
{
	int write = 0;

	write += zebra_import_table_config(vty, VRF_DEFAULT);

	return write;
}

DEFUN (ip_zebra_import_table_distance,
       ip_zebra_import_table_distance_cmd,
       "ip import-table (1-252) [distance (1-255)] [route-map WORD]",
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n"
       "Distance for imported routes\n"
       "Default distance value\n"
       "route-map for filtering\n"
       "route-map name\n")
{
	uint32_t table_id = 0;

	table_id = strtoul(argv[2]->arg, NULL, 10);
	int distance = ZEBRA_TABLE_DISTANCE_DEFAULT;
	char *rmap =
		strmatch(argv[argc - 2]->text, "route-map")
			? XSTRDUP(MTYPE_ROUTE_MAP_NAME, argv[argc - 1]->arg)
			: NULL;
	int ret;

	if (argc == 7 || (argc == 5 && !rmap))
		distance = strtoul(argv[4]->arg, NULL, 10);

	if (!is_zebra_valid_kernel_table(table_id)) {
		vty_out(vty,
			"Invalid routing table ID, %d. Must be in range 1-252\n",
			table_id);
		if (rmap)
			XFREE(MTYPE_ROUTE_MAP_NAME, rmap);
		return CMD_WARNING;
	}

	if (is_zebra_main_routing_table(table_id)) {
		vty_out(vty,
			"Invalid routing table ID, %d. Must be non-default table\n",
			table_id);
		if (rmap)
			XFREE(MTYPE_ROUTE_MAP_NAME, rmap);
		return CMD_WARNING;
	}

	ret = zebra_import_table(AFI_IP, VRF_DEFAULT, table_id,
				 distance, rmap, 1);
	if (rmap)
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap);

	return ret;
}

DEFUN_HIDDEN (zebra_packet_process,
	      zebra_packet_process_cmd,
	      "zebra zapi-packets (1-10000)",
	      ZEBRA_STR
	      "Zapi Protocol\n"
	      "Number of packets to process before relinquishing thread\n")
{
	uint32_t packets = strtoul(argv[2]->arg, NULL, 10);

	atomic_store_explicit(&zrouter.packets_to_process, packets,
			      memory_order_relaxed);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_zebra_packet_process,
	      no_zebra_packet_process_cmd,
	      "no zebra zapi-packets [(1-10000)]",
	      NO_STR
	      ZEBRA_STR
	      "Zapi Protocol\n"
	      "Number of packets to process before relinquishing thread\n")
{
	atomic_store_explicit(&zrouter.packets_to_process,
			      ZEBRA_ZAPI_PACKETS_TO_PROCESS,
			      memory_order_relaxed);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (zebra_workqueue_timer,
	      zebra_workqueue_timer_cmd,
	      "zebra work-queue (0-10000)",
	      ZEBRA_STR
	      "Work Queue\n"
	      "Time in milliseconds\n")
{
	uint32_t timer = strtoul(argv[2]->arg, NULL, 10);
	zrouter.ribq->spec.hold = timer;

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_zebra_workqueue_timer,
	      no_zebra_workqueue_timer_cmd,
	      "no zebra work-queue [(0-10000)]",
	      NO_STR
	      ZEBRA_STR
	      "Work Queue\n"
	      "Time in milliseconds\n")
{
	zrouter.ribq->spec.hold = ZEBRA_RIB_PROCESS_HOLD_TIME;

	return CMD_SUCCESS;
}

DEFUN (no_ip_zebra_import_table,
       no_ip_zebra_import_table_cmd,
       "no ip import-table (1-252) [distance (1-255)] [route-map NAME]",
       NO_STR
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n"
       "Distance for imported routes\n"
       "Default distance value\n"
       "route-map for filtering\n"
       "route-map name\n")
{
	uint32_t table_id = 0;
	table_id = strtoul(argv[3]->arg, NULL, 10);

	if (!is_zebra_valid_kernel_table(table_id)) {
		vty_out(vty,
			"Invalid routing table ID. Must be in range 1-252\n");
		return CMD_WARNING;
	}

	if (is_zebra_main_routing_table(table_id)) {
		vty_out(vty,
			"Invalid routing table ID, %d. Must be non-default table\n",
			table_id);
		return CMD_WARNING;
	}

	if (!is_zebra_import_table_enabled(AFI_IP, VRF_DEFAULT, table_id))
		return CMD_SUCCESS;

	return (zebra_import_table(AFI_IP, VRF_DEFAULT, table_id, 0, NULL, 0));
}

static int config_write_protocol(struct vty *vty)
{
	if (allow_delete)
		vty_out(vty, "allow-external-route-update\n");

	if (zrouter.ribq->spec.hold != ZEBRA_RIB_PROCESS_HOLD_TIME)
		vty_out(vty, "zebra work-queue %u\n", zrouter.ribq->spec.hold);

	if (zrouter.packets_to_process != ZEBRA_ZAPI_PACKETS_TO_PROCESS)
		vty_out(vty, "zebra zapi-packets %u\n",
			zrouter.packets_to_process);

	enum multicast_mode ipv4_multicast_mode = multicast_mode_ipv4_get();

	if (ipv4_multicast_mode != MCAST_NO_CONFIG)
		vty_out(vty, "ip multicast rpf-lookup-mode %s\n",
			ipv4_multicast_mode == MCAST_URIB_ONLY
				? "urib-only"
				: ipv4_multicast_mode == MCAST_MRIB_ONLY
					  ? "mrib-only"
					  : ipv4_multicast_mode
							    == MCAST_MIX_MRIB_FIRST
						    ? "mrib-then-urib"
						    : ipv4_multicast_mode
								      == MCAST_MIX_DISTANCE
							      ? "lower-distance"
							      : "longer-prefix");

	/* Include dataplane info */
	dplane_config_write_helper(vty);

	/* Include nexthop-group config */
	if (!zebra_nhg_kernel_nexthops_enabled())
		vty_out(vty, "no zebra nexthop kernel enable\n");

	return 1;
}

DEFUN (show_zebra,
       show_zebra_cmd,
       "show zebra",
       SHOW_STR
       ZEBRA_STR)
{
	struct vrf *vrf;

	vty_out(vty,
		"                            Route      Route      Neighbor   LSP        LSP\n");
	vty_out(vty,
		"VRF                         Installs   Removals    Updates   Installs   Removals\n");

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct zebra_vrf *zvrf = vrf->info;

		vty_out(vty, "%-25s %10" PRIu64 " %10" PRIu64 " %10" PRIu64
			     " %10" PRIu64 " %10" PRIu64 "\n",
			vrf->name, zvrf->installs, zvrf->removals,
			zvrf->neigh_updates, zvrf->lsp_installs,
			zvrf->lsp_removals);
	}

	return CMD_SUCCESS;
}

DEFUN (ip_forwarding,
       ip_forwarding_cmd,
       "ip forwarding",
       IP_STR
       "Turn on IP forwarding\n")
{
	int ret;

	ret = ipforward();
	if (ret == 0)
		ret = ipforward_on();

	if (ret == 0) {
		vty_out(vty, "Can't turn on IP forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ip_forwarding,
       no_ip_forwarding_cmd,
       "no ip forwarding",
       NO_STR
       IP_STR
       "Turn off IP forwarding\n")
{
	int ret;

	ret = ipforward();
	if (ret != 0)
		ret = ipforward_off();

	if (ret != 0) {
		vty_out(vty, "Can't turn off IP forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* Only display ip forwarding is enabled or not. */
DEFUN (show_ip_forwarding,
       show_ip_forwarding_cmd,
       "show ip forwarding",
       SHOW_STR
       IP_STR
       "IP forwarding status\n")
{
	int ret;

	ret = ipforward();

	if (ret == 0)
		vty_out(vty, "IP forwarding is off\n");
	else
		vty_out(vty, "IP forwarding is on\n");
	return CMD_SUCCESS;
}

/* Only display ipv6 forwarding is enabled or not. */
DEFUN (show_ipv6_forwarding,
       show_ipv6_forwarding_cmd,
       "show ipv6 forwarding",
       SHOW_STR
       "IPv6 information\n"
       "Forwarding status\n")
{
	int ret;

	ret = ipforward_ipv6();

	switch (ret) {
	case -1:
		vty_out(vty, "ipv6 forwarding is unknown\n");
		break;
	case 0:
		vty_out(vty, "ipv6 forwarding is %s\n", "off");
		break;
	case 1:
		vty_out(vty, "ipv6 forwarding is %s\n", "on");
		break;
	default:
		vty_out(vty, "ipv6 forwarding is %s\n", "off");
		break;
	}
	return CMD_SUCCESS;
}

DEFUN (ipv6_forwarding,
       ipv6_forwarding_cmd,
       "ipv6 forwarding",
       IPV6_STR
       "Turn on IPv6 forwarding\n")
{
	int ret;

	ret = ipforward_ipv6();
	if (ret == 0)
		ret = ipforward_ipv6_on();

	if (ret == 0) {
		vty_out(vty, "Can't turn on IPv6 forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_forwarding,
       no_ipv6_forwarding_cmd,
       "no ipv6 forwarding",
       NO_STR
       IPV6_STR
       "Turn off IPv6 forwarding\n")
{
	int ret;

	ret = ipforward_ipv6();
	if (ret != 0)
		ret = ipforward_ipv6_off();

	if (ret != 0) {
		vty_out(vty, "Can't turn off IPv6 forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* Display dataplane info */
DEFUN (show_dataplane,
       show_dataplane_cmd,
       "show zebra dplane [detailed]",
       SHOW_STR
       ZEBRA_STR
       "Zebra dataplane information\n"
       "Detailed output\n")
{
	int idx = 0;
	bool detailed = false;

	if (argv_find(argv, argc, "detailed", &idx))
		detailed = true;

	return dplane_show_helper(vty, detailed);
}

/* Display dataplane providers info */
DEFUN (show_dataplane_providers,
       show_dataplane_providers_cmd,
       "show zebra dplane providers [detailed]",
       SHOW_STR
       ZEBRA_STR
       "Zebra dataplane information\n"
       "Zebra dataplane provider information\n"
       "Detailed output\n")
{
	int idx = 0;
	bool detailed = false;

	if (argv_find(argv, argc, "detailed", &idx))
		detailed = true;

	return dplane_show_provs_helper(vty, detailed);
}

/* Configure dataplane incoming queue limit */
DEFUN (zebra_dplane_queue_limit,
       zebra_dplane_queue_limit_cmd,
       "zebra dplane limit (0-10000)",
       ZEBRA_STR
       "Zebra dataplane\n"
       "Limit incoming queued updates\n"
       "Number of queued updates\n")
{
	uint32_t limit = 0;

	limit = strtoul(argv[3]->arg, NULL, 10);

	dplane_set_in_queue_limit(limit, true);

	return CMD_SUCCESS;
}

/* Reset dataplane queue limit to default value */
DEFUN (no_zebra_dplane_queue_limit,
       no_zebra_dplane_queue_limit_cmd,
       "no zebra dplane limit [(0-10000)]",
       NO_STR
       ZEBRA_STR
       "Zebra dataplane\n"
       "Limit incoming queued updates\n"
       "Number of queued updates\n")
{
	dplane_set_in_queue_limit(0, false);

	return CMD_SUCCESS;
}

DEFUN (zebra_show_routing_tables_summary,
       zebra_show_routing_tables_summary_cmd,
       "show zebra router table summary",
       SHOW_STR
       ZEBRA_STR
       "The Zebra Router Information\n"
       "Table Information about this Zebra Router\n"
       "Summary Information\n")
{
	zebra_router_show_table_summary(vty);

	return CMD_SUCCESS;
}

/* Table configuration write function. */
static int config_write_table(struct vty *vty)
{
	return 0;
}

/* IPForwarding configuration write function. */
static int config_write_forwarding(struct vty *vty)
{
	/* FIXME: Find better place for that. */
	router_id_write(vty);

	if (!ipforward())
		vty_out(vty, "no ip forwarding\n");
	if (!ipforward_ipv6())
		vty_out(vty, "no ipv6 forwarding\n");
	vty_out(vty, "!\n");
	return 0;
}

DEFUN_HIDDEN (show_frr,
	      show_frr_cmd,
	      "show frr",
	      SHOW_STR
	      "FRR\n")
{
	vty_out(vty, "........ .. .  .. . ..... ...77:................................................\n");
	vty_out(vty, ".............................7777:..............................................\n");
	vty_out(vty, ".............................777777,............................................\n");
	vty_out(vty, "... .........................77777777,..........................................\n");
	vty_out(vty, "............................=7777777777:........................................\n");
	vty_out(vty, "........................:7777777777777777,......................................\n");
	vty_out(vty, ".................... ~7777777777777?~,..........................................\n");
	vty_out(vty, "...................I7777777777+.................................................\n");
	vty_out(vty, "................,777777777?............  .......................................\n");
	vty_out(vty, "..............:77777777?..........~?77777.......................................\n");
	vty_out(vty, ".............77777777~........=7777777777.......................................\n");
	vty_out(vty, ".......... +7777777,.......?7777777777777.......................................\n");
	vty_out(vty, "..........7777777~......:7777777777777777......77?,.............................\n");
	vty_out(vty, "........:777777?......+777777777777777777......777777I,.........................\n");
	vty_out(vty, ".......?777777,.....+77777777777777777777......777777777?.......................\n");
	vty_out(vty, "......?777777......7777777777777777777777......,?777777777?.....................\n");
	vty_out(vty, ".....?77777?.....=7777777777777777777I~............,I7777777~...................\n");
	vty_out(vty, "....+77777+.....I77777777777777777:...................+777777I..................\n");
	vty_out(vty, "...~77777+.....7777777777777777=........................?777777......    .......\n");
	vty_out(vty, "...77777I.....I77777777777777~.........:?................,777777.....I777.......\n");
	vty_out(vty, "..777777.....I7777777777777I .......?7777..................777777.....777?......\n");
	vty_out(vty, ".~77777,....=7777777777777:......,7777777..................,77777+....+777......\n");
	vty_out(vty, ".77777I.....7777777777777,......777777777.......ONNNN.......=77777.....777~.....\n");
	vty_out(vty, ",77777.....I777777777777,.....:7777777777......DNNNNNN.......77777+ ...7777.....\n");
	vty_out(vty, "I7777I.....777777777777=.....~77777777777......NNNNNNN~......=7777I....=777.....\n");
	vty_out(vty, "77777:....=777777777777.....,777777777777......$NNNNND ......:77777....:777.....\n");
	vty_out(vty, "77777. ...777777777777~.....7777777777777........7DZ,........:77777.....777.....\n");
	vty_out(vty, "????? . ..777777777777.....,7777777777777....................:77777I....777.....\n");
	vty_out(vty, "....... ..777777777777.....+7777777777777....................=7777777+...?7.....\n");
	vty_out(vty, "..........77777777777I.....I7777777777777....................7777777777:........\n");
	vty_out(vty, "..........77777777777I.....?7777777777777...................~777777777777.......\n");
	vty_out(vty, "..........777777777777.....~7777777777777..................,77777777777777+.....\n");
	vty_out(vty, "..........777777777777......7777777777777..................77777777777777777,...\n");
	vty_out(vty, "..... ....?77777777777I.....~777777777777................,777777.....,:+77777I..\n");
	vty_out(vty, "........ .:777777777777,.....?77777777777...............?777777..............,:=\n");
	vty_out(vty, ".......... 7777777777777..... ?7777777777.............=7777777.....~777I........\n");
	vty_out(vty, "...........:777777777777I......~777777777...........I7777777~.....+777I.........\n");
	vty_out(vty, "..... ......7777777777777I.......I7777777.......+777777777I......7777I..........\n");
	vty_out(vty, ".............77777777777777........?77777......777777777?......=7777=...........\n");
	vty_out(vty, ".............,77777777777777+.........~77......777777I,......:77777.............\n");
	vty_out(vty, "..............~777777777777777~................777777......:77777=..............\n");
	vty_out(vty, "...............:7777777777777777?..............:777777,.....=77=................\n");
	vty_out(vty, "................,777777777777777777?,...........,777777:.....,..................\n");
	vty_out(vty, "........... ......I777777777777777777777I.........777777~.......................\n");
	vty_out(vty, "...................,777777777777777777777..........777777+......................\n");
	vty_out(vty, ".....................+7777777777777777777...........777777?.....................\n");
	vty_out(vty, ".......................=77777777777777777............777777I....................\n");
	vty_out(vty, ".........................:777777777777777.............I77777I...................\n");
	vty_out(vty, "............................~777777777777..............+777777..................\n");
	vty_out(vty, "................................~77777777...............=777777.................\n");
	vty_out(vty, ".....................................:=?I................~777777................\n");
	vty_out(vty, "..........................................................:777777,..............\n");
	vty_out(vty, ".... ... ... .  . .... ....... ....... ....................:777777..............\n");

	return CMD_SUCCESS;
}

/* IP node for static routes. */
static int zebra_ip_config(struct vty *vty);
static struct cmd_node ip_node = {
	.name = "static ip",
	.node = IP_NODE,
	.prompt = "",
	.config_write = zebra_ip_config,
};
static int config_write_protocol(struct vty *vty);
static struct cmd_node protocol_node = {
	.name = "protocol",
	.node = PROTOCOL_NODE,
	.prompt = "",
	.config_write = config_write_protocol,
};
/* table node for routing tables. */
static int config_write_table(struct vty *vty);
static struct cmd_node table_node = {
	.name = "table",
	.node = TABLE_NODE,
	.prompt = "",
	.config_write = config_write_table,
};
static int config_write_forwarding(struct vty *vty);
static struct cmd_node forwarding_node = {
	.name = "forwarding",
	.node = FORWARDING_NODE,
	.prompt = "",
	.config_write = config_write_forwarding,
};

/* Route VTY.  */
void zebra_vty_init(void)
{
	/* Install configuration write function. */
	install_node(&table_node);
	install_node(&forwarding_node);

	install_element(VIEW_NODE, &show_ip_forwarding_cmd);
	install_element(CONFIG_NODE, &ip_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ip_forwarding_cmd);
	install_element(ENABLE_NODE, &show_zebra_cmd);

	install_element(VIEW_NODE, &show_ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ipv6_forwarding_cmd);

	/* Route-map */
	zebra_route_map_init();

	install_node(&ip_node);
	install_node(&protocol_node);

	install_element(CONFIG_NODE, &allow_external_route_update_cmd);
	install_element(CONFIG_NODE, &no_allow_external_route_update_cmd);

	install_element(CONFIG_NODE, &ip_multicast_mode_cmd);
	install_element(CONFIG_NODE, &no_ip_multicast_mode_cmd);

	install_element(CONFIG_NODE, &ip_zebra_import_table_distance_cmd);
	install_element(CONFIG_NODE, &no_ip_zebra_import_table_cmd);
	install_element(CONFIG_NODE, &zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &no_zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &zebra_packet_process_cmd);
	install_element(CONFIG_NODE, &no_zebra_packet_process_cmd);
	install_element(CONFIG_NODE, &nexthop_group_use_enable_cmd);

	install_element(VIEW_NODE, &show_nexthop_group_cmd);
	install_element(VIEW_NODE, &show_interface_nexthop_group_cmd);

	install_element(VIEW_NODE, &show_vrf_cmd);
	install_element(VIEW_NODE, &show_vrf_vni_cmd);
	install_element(VIEW_NODE, &show_route_cmd);
	install_element(VIEW_NODE, &show_route_detail_cmd);
	install_element(VIEW_NODE, &show_route_summary_cmd);
	install_element(VIEW_NODE, &show_ip_nht_cmd);

	install_element(VIEW_NODE, &show_ip_rpf_cmd);
	install_element(VIEW_NODE, &show_ip_rpf_addr_cmd);

	install_element(CONFIG_NODE, &ip_nht_default_route_cmd);
	install_element(CONFIG_NODE, &no_ip_nht_default_route_cmd);
	install_element(CONFIG_NODE, &ipv6_nht_default_route_cmd);
	install_element(CONFIG_NODE, &no_ipv6_nht_default_route_cmd);
	install_element(VRF_NODE, &ip_nht_default_route_cmd);
	install_element(VRF_NODE, &no_ip_nht_default_route_cmd);
	install_element(VRF_NODE, &ipv6_nht_default_route_cmd);
	install_element(VRF_NODE, &no_ipv6_nht_default_route_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_cmd);

	/* Commands for VRF */
	install_element(VIEW_NODE, &show_ipv6_mroute_vrf_all_cmd);

	install_element(VIEW_NODE, &show_frr_cmd);
	install_element(VIEW_NODE, &show_evpn_global_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_detail_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_es_cmd);
	install_element(VIEW_NODE, &show_evpn_es_evi_cmd);
	install_element(VIEW_NODE, &show_evpn_access_vlan_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_mac_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_ip_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_detail_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_vtep_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_mac_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_vtep_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_dad_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_dad_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_all_detail_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_neigh_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_vtep_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_dad_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_all_dad_cmd);
	install_element(ENABLE_NODE, &clear_evpn_dup_addr_cmd);

	install_element(VIEW_NODE, &show_pbr_ipset_cmd);
	install_element(VIEW_NODE, &show_pbr_iptable_cmd);

	install_element(CONFIG_NODE, &default_vrf_vni_mapping_cmd);
	install_element(CONFIG_NODE, &no_default_vrf_vni_mapping_cmd);
	install_element(VRF_NODE, &vrf_vni_mapping_cmd);
	install_element(VRF_NODE, &no_vrf_vni_mapping_cmd);

	install_element(VIEW_NODE, &show_dataplane_cmd);
	install_element(VIEW_NODE, &show_dataplane_providers_cmd);
	install_element(CONFIG_NODE, &zebra_dplane_queue_limit_cmd);
	install_element(CONFIG_NODE, &no_zebra_dplane_queue_limit_cmd);

	install_element(VIEW_NODE, &zebra_show_routing_tables_summary_cmd);
}
