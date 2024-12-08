// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra VTY functions
 * Copyright (C) 2002 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "memory.h"
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
#include "termtable.h"
#include "affinitymap.h"
#include "frrdistance.h"

#include "zebra/zebra_router.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_affinitymap.h"
#include "zebra/zebra_routemap.h"
#include "lib/json.h"
#include "lib/route_opaque.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_vty_clippy.c"
#include "zebra/zserv.h"
#include "zebra/router-id.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/interface.h"
#include "northbound_cli.h"
#include "zebra/zebra_nb.h"
#include "zebra/kernel_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/table_manager.h"
#include "zebra/zebra_script.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_ptm.h"

/* context to manage dumps in multiple tables or vrfs */
struct route_show_ctx {
	bool multi;       /* dump multiple tables or vrf */
	bool header_done; /* common header already displayed */
};

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, bool use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    unsigned short ospf_instance_id, uint32_t tableid,
			    bool show_ng, struct route_show_ctx *ctx);
static void vty_show_ip_route_detail(struct vty *vty, struct route_node *rn,
				     int mcast, bool use_fib, bool show_ng);
static void vty_show_ip_route_summary(struct vty *vty, struct route_table *table,
				      json_object *vrf_json, bool use_json);
static void vty_show_ip_route_summary_prefix(struct vty *vty,
					     struct route_table *table,
					     json_object *vrf_json,
					     bool use_json);
/* Helper api to format a nexthop in the 'detailed' output path. */
static void show_nexthop_detail_helper(struct vty *vty,
				       const struct route_node *rn,
				       const struct route_entry *re,
				       const struct nexthop *nexthop,
				       bool is_backup);

static void show_ip_route_dump_vty(struct vty *vty, struct route_table *table);
static void show_ip_route_nht_dump(struct vty *vty,
				   const struct nexthop *nexthop,
				   const struct route_node *rn,
				   const struct route_entry *re,
				   unsigned int num);

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


DEFPY (show_ip_rpf,
       show_ip_rpf_cmd,
       "show [ip$ip|ipv6$ipv6] rpf [json]",
       SHOW_STR
       IP_STR
       IPV6_STR
       "Display RPF information for multicast source\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct route_show_ctx ctx = {
		.multi = false,
	};

	return do_show_ip_route(vty, VRF_DEFAULT_NAME, ip ? AFI_IP : AFI_IP6,
				SAFI_MULTICAST, false, uj, 0, NULL, false, 0, 0,
				0, false, &ctx);
}

DEFPY (show_ip_rpf_addr,
       show_ip_rpf_addr_cmd,
       "show ip rpf A.B.C.D$address",
       SHOW_STR
       IP_STR
       "Display RPF information for multicast source\n"
       "IP multicast source address (e.g. 10.0.0.0)\n")
{
	struct route_node *rn;
	struct route_entry *re;

	re = rib_match_multicast(AFI_IP, VRF_DEFAULT, (union g_addr *)&address,
				 &rn);

	if (re)
		vty_show_ip_route_detail(vty, rn, 1, false, false);
	else
		vty_out(vty, "%% No match for RPF lookup\n");

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_rpf_addr,
       show_ipv6_rpf_addr_cmd,
       "show ipv6 rpf X:X::X:X$address",
       SHOW_STR
       IPV6_STR
       "Display RPF information for multicast source\n"
       "IPv6 multicast source address\n")
{
	struct route_node *rn;
	struct route_entry *re;

	re = rib_match_multicast(AFI_IP6, VRF_DEFAULT, (union g_addr *)&address,
				 &rn);

	if (re)
		vty_show_ip_route_detail(vty, rn, 1, false, false);
	else
		vty_out(vty, "%% No match for RPF lookup\n");

	return CMD_SUCCESS;
}

static char re_status_output_char(const struct route_entry *re,
				  const struct nexthop *nhop,
				  bool is_fib)
{
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)) {
		bool star_p = false;

		if (nhop &&
		    !CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_DUPLICATE) &&
		    !CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_RECURSIVE)) {
			/* More-specific test for 'fib' output */
			if (is_fib) {
				star_p = !!CHECK_FLAG(nhop->flags,
						      NEXTHOP_FLAG_FIB);
			} else if (CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_ACTIVE))
				star_p = true;
		}

		if (zrouter.asic_offloaded &&
		    CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED))
			return 'q';

		if (zrouter.asic_offloaded
		    && CHECK_FLAG(re->flags, ZEBRA_FLAG_TRAPPED))
			return 't';

		if (zrouter.asic_offloaded
		    && CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOAD_FAILED))
			return 'o';

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OUTOFSYNC))
			return 'd';

		if (star_p)
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
 * Show backup nexthop info, in the 'detailed' output path
 */
static void show_nh_backup_helper(struct vty *vty, const struct route_node *rn,
				  const struct route_entry *re,
				  const struct nexthop *nexthop)
{
	const struct nexthop *start, *backup, *temp;
	int i, idx;

	/* Double-check that there _is_ a backup */
	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP) ||
	    re->nhe->backup_info == NULL || re->nhe->backup_info->nhe == NULL ||
	    re->nhe->backup_info->nhe->nhg.nexthop == NULL)
		return;

	/* Locate the backup nexthop(s) */
	start = re->nhe->backup_info->nhe->nhg.nexthop;
	for (i = 0; i < nexthop->backup_num; i++) {
		/* Format the backup(s) (indented) */
		backup = start;
		for (idx = 0; idx < nexthop->backup_idx[i]; idx++) {
			backup = backup->next;
			if (backup == NULL)
				break;
		}

		/* It's possible for backups to be recursive too,
		 * so walk the recursive resolution list if present.
		 */
		temp = backup;
		while (backup) {
			vty_out(vty, "  ");
			show_nexthop_detail_helper(vty, rn, re, backup,
						   true /*backup*/);
			vty_out(vty, "\n");

			if (backup->resolved && temp == backup)
				backup = backup->resolved;
			else
				backup = nexthop_next(backup);

			if (backup == temp->next)
				break;
		}
	}

}

/*
 * Helper api to format output for a nexthop, used in the 'detailed'
 * output path.
 */
static void show_nexthop_detail_helper(struct vty *vty,
				       const struct route_node *rn,
				       const struct route_entry *re,
				       const struct nexthop *nexthop,
				       bool is_backup)
{
	char buf[MPLS_LABEL_STRLEN];
	int i;

	if (is_backup)
		vty_out(vty, "    b%s",
			nexthop->rparent ? "  " : "");
	else
		vty_out(vty, "  %c%s",
			re_status_output_char(re, nexthop, false),
			nexthop->rparent ? "  " : "");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, " %pI4",
			&nexthop->gate.ipv4);
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
	}

	if (re->vrf_id != nexthop->vrf_id && nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
		struct vrf *vrf = vrf_lookup_by_id(nexthop->vrf_id);

		vty_out(vty, "(vrf %s)", VRF_LOGNAME(vrf));
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
		vty_out(vty, " (duplicate nexthop removed)");

	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		vty_out(vty, " inactive");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		vty_out(vty, " onlink");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_LINKDOWN))
		vty_out(vty, " linkdown");

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
		vty_out(vty, " (recursive)");

	/* Source specified? */
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (nexthop->rmap_src.ipv4.s_addr)
			vty_out(vty, ", rmapsrc %pI4", &nexthop->rmap_src.ipv4);
		else if (nexthop->src.ipv4.s_addr)
			vty_out(vty, ", src %pI4", &nexthop->src.ipv4);
		break;

	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* Allow for 5549 ipv4 prefix with ipv6 nexthop */
		if (rn->p.family == AF_INET && nexthop->rmap_src.ipv4.s_addr)
			vty_out(vty, ", rmapsrc %pI4", &nexthop->rmap_src.ipv4);
		else if (!IPV6_ADDR_SAME(&nexthop->rmap_src.ipv6, &in6addr_any))
			vty_out(vty, ", rmapsrc %pI6", &nexthop->rmap_src.ipv6);
		else if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
			vty_out(vty, ", src %pI6", &nexthop->src.ipv6);
		break;

	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	if (re->nexthop_mtu)
		vty_out(vty, ", mtu %u", re->nexthop_mtu);

	/* Label information */
	if (nexthop->nh_label && nexthop->nh_label->num_labels) {
		vty_out(vty, ", label %s",
			mpls_label2str(nexthop->nh_label->num_labels,
				       nexthop->nh_label->label, buf,
				       sizeof(buf), nexthop->nh_label_type,
				       1 /*pretty*/));
	}

	if (nexthop->weight)
		vty_out(vty, ", weight %u", nexthop->weight);

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		vty_out(vty, ", backup %d", nexthop->backup_idx[0]);

		for (i = 1; i < nexthop->backup_num; i++)
			vty_out(vty, ",%d", nexthop->backup_idx[i]);
	}
}

static void zebra_show_ip_route_opaque(struct vty *vty, struct route_entry *re,
				       struct json_object *json)
{
	struct bgp_zebra_opaque bzo = {};
	struct ospf_zebra_opaque ozo = {};

	if (!re->opaque)
		return;

	switch (re->type) {
	case ZEBRA_ROUTE_SHARP:
		if (json)
			json_object_string_add(json, "opaque",
					       (char *)re->opaque->data);
		else
			vty_out(vty, "    Opaque Data: %s",
				(char *)re->opaque->data);
		break;

	case ZEBRA_ROUTE_BGP:
		memcpy(&bzo, re->opaque->data, re->opaque->length);

		if (json) {
			json_object_string_add(json, "asPath", bzo.aspath);
			json_object_string_add(json, "communities",
					       bzo.community);
			json_object_string_add(json, "largeCommunities",
					       bzo.lcommunity);
			json_object_string_add(json, "selectionReason",
					       bzo.selection_reason);
		} else {
			vty_out(vty, "    AS-Path          : %s\n", bzo.aspath);

			if (bzo.community[0] != '\0')
				vty_out(vty, "    Communities      : %s\n",
					bzo.community);

			if (bzo.lcommunity[0] != '\0')
				vty_out(vty, "    Large-Communities: %s\n",
					bzo.lcommunity);

			vty_out(vty, "    Selection reason : %s\n",
				bzo.selection_reason);
		}
		break;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		memcpy(&ozo, re->opaque->data, re->opaque->length);

		if (json) {
			json_object_string_add(json, "ospfPathType",
					       ozo.path_type);
			if (ozo.area_id[0] != '\0')
				json_object_string_add(json, "ospfAreaId",
						       ozo.area_id);
			if (ozo.tag[0] != '\0')
				json_object_string_add(json, "ospfTag",
						       ozo.tag);
		} else {
			vty_out(vty, "    OSPF path type        : %s\n",
				ozo.path_type);
			if (ozo.area_id[0] != '\0')
				vty_out(vty, "    OSPF area ID          : %s\n",
					ozo.area_id);
			if (ozo.tag[0] != '\0')
				vty_out(vty, "    OSPF tag              : %s\n",
					ozo.tag);
		}
		break;
	default:
		break;
	}
}

static void uptime2str(time_t uptime, char *buf, size_t bufsize)
{
	time_t cur;

	cur = monotime(NULL);
	cur -= uptime;

	frrtime_to_interval(cur, buf, bufsize);
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
			zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
			vty_out(vty, ", vrf %s", zvrf_name(zvrf));
		}
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			vty_out(vty, ", best");
		vty_out(vty, "\n");

		uptime2str(re->uptime, buf, sizeof(buf));

		vty_out(vty, "  Last update %s ago\n", buf);

		if (show_ng) {
			if (fpm_pic_nexthop) {
				if (re->pic_nhe_id != 0) {
					vty_out(vty, "  Nexthop Group ID: %u\n", re->pic_nhe_id);
					vty_out(vty, "  PIC Context ID: %u\n", re->nhe_id);
					if (re->pic_nhe_installed_id != 0 &&
					    re->pic_nhe_installed_id != re->pic_nhe_id)
						vty_out(vty, "  Installed Nexthop Group ID: %u\n",
							re->pic_nhe_installed_id);
					if (re->nhe_installed_id != 0 &&
					    re->nhe_installed_id != re->nhe_id)
						vty_out(vty, "  Installed PIC Context ID: %u\n",
							re->pic_nhe_installed_id);
				} else {
					vty_out(vty, "  Nexthop Group ID: %u\n", re->nhe_id);
					if (re->nhe_installed_id != 0 &&
					    re->nhe_installed_id != re->nhe_id)
						vty_out(vty, "  Installed Nexthop Group ID: %u\n",
							re->pic_nhe_installed_id);
				}
			} else {
				vty_out(vty, "  Nexthop Group ID: %u\n", re->nhe_id);
				if (re->nhe_installed_id != 0 && re->nhe_id != re->nhe_installed_id)
					vty_out(vty, "  Installed Nexthop Group ID: %u\n",
						re->nhe_installed_id);
			}
		}

		for (ALL_NEXTHOPS(re->nhe->nhg, nexthop)) {
			/* Use helper to format each nexthop */
			show_nexthop_detail_helper(vty, rn, re, nexthop,
						   false /*not backup*/);
			vty_out(vty, "\n");

			/* Include backup(s), if present */
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP))
				show_nh_backup_helper(vty, rn, re, nexthop);
		}
		zebra_show_ip_route_opaque(vty, re, NULL);

		vty_out(vty, "\n");
	}
}

static void vty_show_ip_route(struct vty *vty, struct route_node *rn,
			      struct route_entry *re, json_object *json,
			      bool is_fib, bool show_ng)
{
	const struct nexthop *nexthop;
	int len = 0;
	char buf[SRCDEST2STR_BUFFER];
	json_object *json_nexthops = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_route = NULL;
	const rib_dest_t *dest = rib_dest_from_rnode(rn);
	const struct nexthop_group *nhg;
	char up_str[MONOTIME_STRLEN];
	bool first_p = true;
	bool nhg_from_backup = false;

	uptime2str(re->uptime, up_str, sizeof(up_str));

	/* If showing fib information, use the fib view of the
	 * nexthops.
	 */
	if (is_fib)
		nhg = rib_get_fib_nhg(re);
	else
		nhg = &(re->nhe->nhg);

	if (json) {
		json_route = json_object_new_object();
		json_nexthops = json_object_new_array();

		json_object_string_add(json_route, "prefix",
				       srcdest_rnode2str(rn, buf, sizeof(buf)));
		json_object_int_add(json_route, "prefixLen", rn->p.prefixlen);
		json_object_string_add(json_route, "protocol",
				       zebra_route_string(re->type));

		if (re->instance)
			json_object_int_add(json_route, "instance",
					    re->instance);

		json_object_int_add(json_route, "vrfId", re->vrf_id);
		json_object_string_add(json_route, "vrfName",
				       vrf_id_to_name(re->vrf_id));

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

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_TRAPPED))
			json_object_boolean_true_add(json_route, "trapped");

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED))
			json_object_boolean_true_add(json_route, "offloaded");

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOAD_FAILED))
			json_object_boolean_false_add(json_route, "offloaded");

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
		json_object_int_add(json_route, "nexthopGroupId", re->nhe_id);
		if (re->pic_nhe_id != 0)
			json_object_int_add(json_route, "picNexthopId", re->pic_nhe_id);

		if (re->nhe_installed_id != 0)
			json_object_int_add(json_route,
					    "installedNexthopGroupId",
					    re->nhe_installed_id);
		if (re->pic_nhe_installed_id != 0)
			json_object_int_add(json_route, "installedPicNexthopGroupId",
					    re->pic_nhe_installed_id);

		json_object_string_add(json_route, "uptime", up_str);

		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			json_nexthop = json_object_new_object();
			show_nexthop_json_helper(json_nexthop, nexthop, rn, re);

			json_object_array_add(json_nexthops,
					      json_nexthop);
		}

		json_object_object_add(json_route, "nexthops", json_nexthops);

		/* If there are backup nexthops, include them */
		if (is_fib)
			nhg = rib_get_fib_backup_nhg(re);
		else
			nhg = zebra_nhg_get_backup_nhg(re->nhe);

		if (nhg && nhg->nexthop) {
			json_nexthops = json_object_new_array();

			for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
				json_nexthop = json_object_new_object();

				show_nexthop_json_helper(json_nexthop, nexthop,
							 rn, re);
				json_object_array_add(json_nexthops,
						      json_nexthop);
			}

			json_object_object_add(json_route, "backupNexthops",
					       json_nexthops);
		}
		zebra_show_ip_route_opaque(NULL, re, json_route);

		json_object_array_add(json, json_route);
		return;
	}

	/* Prefix information, and first nexthop. If we're showing 'fib',
	 * and there are no installed primary nexthops, see if there are any
	 * backup nexthops and start with those.
	 */
	if (is_fib && nhg->nexthop == NULL) {
		nhg = rib_get_fib_backup_nhg(re);
		nhg_from_backup = true;
	}

	len = vty_out(vty, "%c", zebra_route_char(re->type));
	if (re->instance)
		len += vty_out(vty, "[%d]", re->instance);
	if (nhg_from_backup && nhg->nexthop) {
		len += vty_out(
			vty, "%cb%c %s",
			CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED) ? '>' : ' ',
			re_status_output_char(re, nhg->nexthop, is_fib),
			srcdest_rnode2str(rn, buf, sizeof(buf)));
	} else {
		len += vty_out(
			vty, "%c%c %s",
			CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED) ? '>' : ' ',
			re_status_output_char(re, nhg->nexthop, is_fib),
			srcdest_rnode2str(rn, buf, sizeof(buf)));
	}

	/* Distance and metric display. */
	if (((re->type == ZEBRA_ROUTE_CONNECT ||
	      re->type == ZEBRA_ROUTE_LOCAL) &&
	     (re->distance || re->metric)) ||
	    (re->type != ZEBRA_ROUTE_CONNECT && re->type != ZEBRA_ROUTE_LOCAL))
		len += vty_out(vty, " [%u/%u]", re->distance,
			       re->metric);

	if (show_ng) {
		len += vty_out(vty, " (%u)", re->nhe_id);
		len += vty_out(vty, " (pic_nh %u)", re->pic_nhe_id);
	}

	/* Nexthop information. */
	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		if (first_p) {
			first_p = false;
		} else if (nhg_from_backup) {
			vty_out(vty, "  b%c%*c",
				re_status_output_char(re, nexthop, is_fib),
				len - 3 + (2 * nexthop_level(nexthop)), ' ');
		} else {
			vty_out(vty, "  %c%*c",
				re_status_output_char(re, nexthop, is_fib),
				len - 3 + (2 * nexthop_level(nexthop)), ' ');
		}

		show_route_nexthop_helper(vty, rn, re, nexthop);
		vty_out(vty, ", %s\n", up_str);
	}

	/* If we only had backup nexthops, we're done */
	if (nhg_from_backup)
		return;

	/* Check for backup nexthop info if present */
	if (is_fib)
		nhg = rib_get_fib_backup_nhg(re);
	else
		nhg = zebra_nhg_get_backup_nhg(re->nhe);

	if (nhg == NULL)
		return;

	/* Print backup info */
	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		bool star_p = false;

		if (is_fib)
			star_p = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

		/* TODO -- it'd be nice to be able to include
		 * the entire list of backups, *and* include the
		 * real installation state.
		 */
		vty_out(vty, "  b%c %*c",
			(star_p ? '*' : ' '),
			len - 3 + (2 * nexthop_level(nexthop)),	' ');
		show_route_nexthop_helper(vty, rn, re, nexthop);
		vty_out(vty, "\n");
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
		vty_show_ip_route(vty, rn, re, json_prefix, use_fib, false);
	}

	prefix2str(&rn->p, buf, sizeof(buf));
	json_object_object_add(json, buf, json_prefix);
	vty_json(vty, json);
}

static void zebra_vty_display_vrf_header(struct vty *vty, struct zebra_vrf *zvrf, uint32_t tableid)
{
	if (!tableid)
		vty_out(vty, "VRF %s:\n", zvrf_name(zvrf));
	else {
		if (vrf_is_backend_netns())
			vty_out(vty, "VRF %s table %u:\n", zvrf_name(zvrf), tableid);
		else {
			vrf_id_t vrf = zebra_vrf_lookup_by_table(tableid, zvrf->zns->ns_id);

			if (vrf == VRF_DEFAULT && tableid != RT_TABLE_ID_MAIN)
				vty_out(vty, "table %u:\n", tableid);
			else {
				struct zebra_vrf *zvrf2 = zebra_vrf_lookup_by_id(vrf);

				vty_out(vty, "VRF %s table %u:\n", zvrf_name(zvrf2), tableid);
			}
		}
	}
}

static void do_show_route_helper(struct vty *vty, struct zebra_vrf *zvrf,
				 struct route_table *table, afi_t afi,
				 bool use_fib, route_tag_t tag,
				 const struct prefix *longer_prefix_p,
				 bool supernets_only, int type,
				 unsigned short ospf_instance_id, bool use_json,
				 uint32_t tableid, bool show_ng,
				 struct route_show_ctx *ctx)
{
	struct route_node *rn;
	struct route_entry *re;
	bool first_json = true;
	int first = 1;
	rib_dest_t *dest;
	json_object *json_prefix = NULL;
	uint32_t addr;
	char buf[BUFSIZ];

	/*
	 * ctx->multi indicates if we are dumping multiple tables or vrfs.
	 * if set:
	 *   => display the common header at most once
	 *   => add newline at each call except first
	 *   => always display the VRF and table
	 * else:
	 *   => display the common header if at least one entry is found
	 *   => display the VRF and table if specific
	 */

	/* Show all routes. */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		dest = rib_dest_from_rnode(rn);

		if (longer_prefix_p && !prefix_match(longer_prefix_p, &rn->p))
			continue;

		RNODE_FOREACH_RE (rn, re) {
			if (use_fib && re != dest->selected_fib)
				continue;

			if (tag && re->tag != tag)
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
			} else if (first) {
				if (!ctx->header_done) {
					if (afi == AFI_IP)
						vty_out(vty,
							SHOW_ROUTE_V4_HEADER);
					else
						vty_out(vty,
							SHOW_ROUTE_V6_HEADER);
				}
				if (ctx->multi && ctx->header_done)
					vty_out(vty, "\n");
				if (ctx->multi || zvrf_id(zvrf) != VRF_DEFAULT || tableid)
					zebra_vty_display_vrf_header(vty, zvrf, tableid);

				ctx->header_done = true;
				first = 0;
			}

			vty_show_ip_route(vty, rn, re, json_prefix, use_fib,
					  show_ng);
		}

		if (json_prefix) {
			prefix2str(&rn->p, buf, sizeof(buf));
			vty_json_key(vty, buf, &first_json);
			vty_json_no_pretty(vty, json_prefix);

			json_prefix = NULL;
		}
	}

	if (use_json)
		vty_json_close(vty, first_json);
}

static void do_show_ip_route_all(struct vty *vty, struct zebra_vrf *zvrf,
				 afi_t afi, bool use_fib, bool use_json,
				 route_tag_t tag,
				 const struct prefix *longer_prefix_p,
				 bool supernets_only, int type,
				 unsigned short ospf_instance_id, bool show_ng,
				 struct route_show_ctx *ctx)
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

		do_show_ip_route(vty, zvrf_name(zvrf), afi, SAFI_UNICAST,
				 use_fib, use_json, tag, longer_prefix_p,
				 supernets_only, type, ospf_instance_id,
				 zrt->tableid, show_ng, ctx);
	}
}

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, bool use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    unsigned short ospf_instance_id, uint32_t tableid,
			    bool show_ng, struct route_show_ctx *ctx)
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
			     ospf_instance_id, use_json, tableid, show_ng, ctx);

	return CMD_SUCCESS;
}

DEFPY (show_ip_nht,
       show_ip_nht_cmd,
       "show <ip$ipv4|ipv6$ipv6> <nht|import-check>$type [<A.B.C.D|X:X::X:X>$addr|vrf NAME$vrf_name [<A.B.C.D|X:X::X:X>$addr]|vrf all$vrf_all] [mrib$mrib] [json]",
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
       VRF_ALL_CMD_HELP_STR
       "Show Multicast (MRIB) NHT state\n"
       JSON_STR)
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct prefix prefix, *p = NULL;
	safi_t safi = mrib ? SAFI_MULTICAST : SAFI_UNICAST;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrf = NULL;
	json_object *json_nexthop = NULL;
	struct zebra_vrf *zvrf;
	bool resolve_via_default = false;

	if (uj)
		json = json_object_new_object();

	if (vrf_all) {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) != NULL) {
				resolve_via_default =
					(afi == AFI_IP)
						? zvrf->zebra_rnh_ip_default_route
						: zvrf->zebra_rnh_ipv6_default_route;

				if (uj) {
					json_vrf = json_object_new_object();
					json_nexthop = json_object_new_object();
					json_object_object_add(json,
							       zvrf_name(zvrf),
							       json_vrf);
					json_object_object_add(json_vrf,
							       (afi == AFI_IP)
								       ? "ipv4"
								       : "ipv6",
							       json_nexthop);
					json_object_boolean_add(json_nexthop,
								"resolveViaDefault",
								resolve_via_default);
				} else {
					vty_out(vty, "\nVRF %s:\n",
						zvrf_name(zvrf));
					vty_out(vty,
						" Resolve via default: %s\n",
						resolve_via_default ? "on"
								    : "off");
				}
				zebra_print_rnh_table(zvrf_id(zvrf), afi, safi,
						      vty, NULL, json_nexthop);
			}
		}

		if (uj)
			vty_json(vty, json);

		return CMD_SUCCESS;
	}
	if (vrf_name)
		VRF_GET_ID(vrf_id, vrf_name, false);

	memset(&prefix, 0, sizeof(prefix));
	if (addr) {
		p = sockunion2hostprefix(addr, &prefix);
		if (!p) {
			if (uj)
				json_object_free(json);
			return CMD_WARNING;
		}
	}

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	resolve_via_default = (afi == AFI_IP)
				      ? zvrf->zebra_rnh_ip_default_route
				      : zvrf->zebra_rnh_ipv6_default_route;

	if (uj) {
		json_vrf = json_object_new_object();
		json_nexthop = json_object_new_object();
		if (vrf_name)
			json_object_object_add(json, vrf_name, json_vrf);
		else
			json_object_object_add(json, "default", json_vrf);

		json_object_object_add(json_vrf,
				       (afi == AFI_IP) ? "ipv4" : "ipv6",
				       json_nexthop);

		json_object_boolean_add(json_nexthop, "resolveViaDefault",
					resolve_via_default);
	} else {
		vty_out(vty, "VRF %s:\n", zvrf_name(zvrf));
		vty_out(vty, " Resolve via default: %s\n",
			resolve_via_default ? "on" : "off");
	}

	zebra_print_rnh_table(vrf_id, afi, safi, vty, p, json_nexthop);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

static void show_nexthop_group_out(struct vty *vty, struct nhg_hash_entry *nhe,
				   json_object *json_nhe_hdr)
{
	struct nexthop *nexthop = NULL;
	struct nhg_connected *rb_node_dep = NULL;
	struct nexthop_group *backup_nhg;
	char up_str[MONOTIME_STRLEN];
	char time_left[MONOTIME_STRLEN];
	json_object *json_dependants = NULL;
	json_object *json_depends = NULL;
	json_object *json_nexthop_array = NULL;
	json_object *json_nexthops = NULL;
	json_object *json = NULL;
	json_object *json_backup_nexthop_array = NULL;
	json_object *json_backup_nexthops = NULL;


	uptime2str(nhe->uptime, up_str, sizeof(up_str));

	if (json_nhe_hdr)
		json = json_object_new_object();

	if (json) {
		json_object_string_add(json, "type",
				       zebra_route_string(nhe->type));
		json_object_int_add(json, "refCount", nhe->refcnt);
		if (event_is_scheduled(nhe->timer))
			json_object_string_add(
				json, "timeToDeletion",
				event_timer_to_hhmmss(time_left,
						      sizeof(time_left),
						      nhe->timer));
		json_object_string_add(json, "uptime", up_str);
		json_object_string_add(json, "vrf",
				       vrf_id_to_name(nhe->vrf_id));
		json_object_string_add(json, "afi", afi2str(nhe->afi));

	} else {
		vty_out(vty, "ID: %u (%s)\n", nhe->id,
			zebra_route_string(nhe->type));
		vty_out(vty, "     RefCnt: %u", nhe->refcnt);
		if (event_is_scheduled(nhe->timer))
			vty_out(vty, " Time to Deletion: %s",
				event_timer_to_hhmmss(time_left,
						      sizeof(time_left),
						      nhe->timer));
		vty_out(vty, "\n");

		vty_out(vty, "     Uptime: %s\n", up_str);
		vty_out(vty, "     VRF: %s(%s)\n", vrf_id_to_name(nhe->vrf_id),
			afi2str(nhe->afi));
	}

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID)) {
		if (json)
			json_object_boolean_true_add(json, "valid");
		else
			vty_out(vty, "     Valid");
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL)) {
			if (json)
				json_object_boolean_true_add(json, "reInstall");
			else
				vty_out(vty, ", Reinstall");
		}
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)) {
			if (json)
				json_object_boolean_true_add(json, "installed");
			else
				vty_out(vty, ", Installed");
		}
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL)) {
			if (json)
				json_object_boolean_true_add(json,
							     "initialDelay");
			else
				vty_out(vty, ", Initial Delay");
		}
		if (!json)
			vty_out(vty, "\n");
	}
	if (nhe->ifp) {
		if (json)
			json_object_int_add(json, "interfaceIndex",
					    nhe->ifp->ifindex);
		else
			vty_out(vty, "     Interface Index: %d\n",
				nhe->ifp->ifindex);
	}

	if (!zebra_nhg_depends_is_empty(nhe)) {
		if (json)
			json_depends = json_object_new_array();
		else
			vty_out(vty, "     Depends:");
		frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
			if (json_depends)
				json_object_array_add(
					json_depends,
					json_object_new_int(
						rb_node_dep->nhe->id));
			else
				vty_out(vty, " (%u)", rb_node_dep->nhe->id);
		}
		if (!json_depends)
			vty_out(vty, "\n");
		else
			json_object_object_add(json, "depends", json_depends);
	}

	/* Output nexthops */
	if (json)
		json_nexthop_array = json_object_new_array();


	for (ALL_NEXTHOPS(nhe->nhg, nexthop)) {
		if (json_nexthop_array) {
			json_nexthops = json_object_new_object();
			show_nexthop_json_helper(json_nexthops, nexthop, NULL,
						 NULL);
		} else {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				vty_out(vty, "          ");
			else
				/* Make recursive nexthops a bit more clear */
				vty_out(vty, "       ");
			show_route_nexthop_helper(vty, NULL, NULL, nexthop);
		}

		if (nhe->backup_info == NULL || nhe->backup_info->nhe == NULL) {
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_HAS_BACKUP)) {
				if (json)
					json_object_int_add(
						json_nexthops, "backup",
						nexthop->backup_idx[0]);
				else
					vty_out(vty, " [backup %d]",
						nexthop->backup_idx[0]);
			}

			if (!json)
				vty_out(vty, "\n");
			else
				json_object_array_add(json_nexthop_array,
						      json_nexthops);

			continue;
		}

		if (!json) {
			/* TODO -- print more useful backup info */
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_HAS_BACKUP)) {
				int i;

				vty_out(vty, "[backup");
				for (i = 0; i < nexthop->backup_num; i++)
					vty_out(vty, " %d",
						nexthop->backup_idx[i]);
				vty_out(vty, "]");
			}
			vty_out(vty, "\n");
		} else {
			json_object_array_add(json_nexthop_array,
					      json_nexthops);
		}
	}

	if (json)
		json_object_object_add(json, "nexthops", json_nexthop_array);

	/* Output backup nexthops (if any) */
	backup_nhg = zebra_nhg_get_backup_nhg(nhe);
	if (backup_nhg) {
		if (json)
			json_backup_nexthop_array = json_object_new_array();
		else
			vty_out(vty, "     Backups:\n");

		for (ALL_NEXTHOPS_PTR(backup_nhg, nexthop)) {
			if (json_backup_nexthop_array) {
				json_backup_nexthops = json_object_new_object();
				show_nexthop_json_helper(json_backup_nexthops,
							 nexthop, NULL, NULL);
				json_object_array_add(json_backup_nexthop_array,
						      json_backup_nexthops);
			} else {

				if (!CHECK_FLAG(nexthop->flags,
						NEXTHOP_FLAG_RECURSIVE))
					vty_out(vty, "          ");
				else
					/* Make recursive nexthops a bit more
					 * clear
					 */
					vty_out(vty, "       ");
				show_route_nexthop_helper(vty, NULL, NULL,
							  nexthop);
				vty_out(vty, "\n");
			}
		}

		if (json)
			json_object_object_add(json, "backupNexthops",
					       json_backup_nexthop_array);
	}

	if (!zebra_nhg_dependents_is_empty(nhe)) {
		if (json)
			json_dependants = json_object_new_array();
		else
			vty_out(vty, "     Dependents:");
		frr_each(nhg_connected_tree, &nhe->nhg_dependents,
			  rb_node_dep) {
			if (json)
				json_object_array_add(
					json_dependants,
					json_object_new_int(
						rb_node_dep->nhe->id));
			else
				vty_out(vty, " (%u)", rb_node_dep->nhe->id);
		}
		if (json)
			json_object_object_add(json, "dependents",
					       json_dependants);
		else
			vty_out(vty, "\n");
	}

	if (nhe->pic_nhe)
		vty_out(vty, "     pic nhe:%d \n", nhe->pic_nhe->id);

	if (nhe->nhg.nhgr.buckets) {
		if (json) {
			json_object_int_add(json, "buckets",
					    nhe->nhg.nhgr.buckets);
			json_object_int_add(json, "idleTimer",
					    nhe->nhg.nhgr.idle_timer);
			json_object_int_add(json, "unbalancedTimer",
					    nhe->nhg.nhgr.unbalanced_timer);
			json_object_int_add(json, "unbalancedTime",
					    nhe->nhg.nhgr.unbalanced_time);
		} else {
			vty_out(vty,
				"     Buckets: %u Idle Timer: %u Unbalanced Timer: %u Unbalanced time: %" PRIu64
				"\n",
				nhe->nhg.nhgr.buckets, nhe->nhg.nhgr.idle_timer,
				nhe->nhg.nhgr.unbalanced_timer,
				nhe->nhg.nhgr.unbalanced_time);
		}
	}

	if (json_nhe_hdr)
		json_object_object_addf(json_nhe_hdr, json, "%u", nhe->id);
}

static int show_nexthop_group_id_cmd_helper(struct vty *vty, uint32_t id,
					    json_object *json)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = zebra_nhg_lookup_id(id);

	if (nhe)
		show_nexthop_group_out(vty, nhe, json);
	else {
		if (json)
			vty_json(vty, json);
		else
			vty_out(vty, "Nexthop Group ID: %u does not exist\n",
				id);
		return CMD_WARNING;
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* Helper function for iteration through the hash of nexthop-groups/nhe-s */

struct nhe_show_context {
	struct vty *vty;
	vrf_id_t vrf_id;
	afi_t afi;
	int type;
	json_object *json;
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

	if (ctx->type && nhe->type != ctx->type)
		goto done;

	show_nexthop_group_out(ctx->vty, nhe, ctx->json);

done:
	return HASHWALK_CONTINUE;
}

static void show_nexthop_group_cmd_helper(struct vty *vty,
					  struct zebra_vrf *zvrf, afi_t afi,
					  int type, json_object *json)
{
	struct nhe_show_context ctx;

	ctx.vty = vty;
	ctx.afi = afi;
	ctx.vrf_id = zvrf->vrf->vrf_id;
	ctx.type = type;
	ctx.json = json;

	hash_walk(zrouter.nhgs_id, nhe_show_walker, &ctx);
}

static void if_nexthop_group_dump_vty(struct vty *vty, struct interface *ifp)
{
	struct zebra_if *zebra_if = NULL;
	struct nhg_connected *rb_node_dep = NULL;
	bool first = true;

	zebra_if = ifp->info;

	frr_each (nhg_connected_tree, &zebra_if->nhg_dependents, rb_node_dep) {
		if (first) {
			vty_out(vty, "Interface %s:\n", ifp->name);
			first = false;
		}

		vty_out(vty, "   ");
		show_nexthop_group_out(vty, rb_node_dep->nhe, NULL);
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

DEFPY(show_nexthop_group,
      show_nexthop_group_cmd,
      "show nexthop-group rib <(0-4294967295)$id|[singleton <ip$v4|ipv6$v6>] [<kernel|zebra|bgp|sharp>$type_str] [vrf <NAME$vrf_name|all$vrf_all>]> [json]",
      SHOW_STR
      "Show Nexthop Groups\n"
      "RIB information\n"
      "Nexthop Group ID\n"
      "Show Singleton Nexthop-Groups\n"
      IP_STR
      IP6_STR
      "Kernel (not installed via the zebra RIB)\n"
      "Zebra (implicitly created by zebra)\n"
      "Border Gateway Protocol (BGP)\n"
      "Super Happy Advanced Routing Protocol (SHARP)\n"
      VRF_FULL_CMD_HELP_STR
      JSON_STR)
{

	struct zebra_vrf *zvrf = NULL;
	afi_t afi = AFI_UNSPEC;
	int type = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrf = NULL;

	if (uj)
		json = json_object_new_object();

	if (id)
		return show_nexthop_group_id_cmd_helper(vty, id, json);

	if (v4)
		afi = AFI_IP;
	else if (v6)
		afi = AFI_IP6;

	if (type_str) {
		type = proto_redistnum((afi ? afi : AFI_IP), type_str);
		if (type < 0) {
			/* assume zebra */
			type = ZEBRA_ROUTE_NHG;
		}
	}

	if (!vrf_is_backend_netns() && (vrf_name || vrf_all)) {
		if (uj)
			vty_json(vty, json);
		else
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
			if (uj)
				json_vrf = json_object_new_object();
			else
				vty_out(vty, "VRF: %s\n", vrf->name);

			show_nexthop_group_cmd_helper(vty, zvrf, afi, type,
						      json_vrf);
			if (uj)
				json_object_object_add(json, vrf->name,
						       json_vrf);
		}

		if (uj)
			vty_json(vty, json);

		return CMD_SUCCESS;
	}

	if (vrf_name)
		zvrf = zebra_vrf_lookup_by_name(vrf_name);
	else
		zvrf = zebra_vrf_lookup_by_name(VRF_DEFAULT_NAME);

	if (!zvrf) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% VRF '%s' specified does not exist\n",
				vrf_name);
		return CMD_WARNING;
	}

	show_nexthop_group_cmd_helper(vty, zvrf, afi, type, json);

	if (uj)
		vty_json(vty, json);

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

DEFPY_HIDDEN(proto_nexthop_group_only, proto_nexthop_group_only_cmd,
	     "[no] zebra nexthop proto only",
	     NO_STR ZEBRA_STR
	     "Nexthop configuration\n"
	     "Configure exclusive use of proto nexthops\n"
	     "Only use proto nexthops\n")
{
	zebra_nhg_set_proto_nexthops_only(!no);
	return CMD_SUCCESS;
}

DEFPY_HIDDEN(backup_nexthop_recursive_use_enable,
	     backup_nexthop_recursive_use_enable_cmd,
	     "[no] zebra nexthop resolve-via-backup",
	     NO_STR
	     ZEBRA_STR
	     "Nexthop configuration \n"
	     "Configure use of backup nexthops in recursive resolution\n")
{
	zebra_nhg_set_recursive_use_backups(!no);
	return CMD_SUCCESS;
}

DEFPY_HIDDEN(rnh_hide_backups, rnh_hide_backups_cmd,
	     "[no] ip nht hide-backup-events",
	     NO_STR
	     IP_STR
	     "Nexthop-tracking configuration\n"
	     "Hide notification about backup nexthops\n")
{
	rnh_set_hide_backups(!no);
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
        [<json$json|nexthop-group$ng>]",
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
       JSON_STR
       "Nexthop Group Information\n")
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	bool first_vrf_json = true;
	struct vrf *vrf;
	int type = 0;
	struct zebra_vrf *zvrf;
	struct route_show_ctx ctx = {
		.multi = vrf_all || table_all,
	};

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
			if (json)
				vty_json_key(vty, zvrf_name(zvrf),
					     &first_vrf_json);
			if (table_all)
				do_show_ip_route_all(vty, zvrf, afi, !!fib,
						     !!json, tag,
						     prefix_str ? prefix : NULL,
						     !!supernets_only, type,
						     ospf_instance_id, !!ng,
						     &ctx);
			else
				do_show_ip_route(vty, zvrf_name(zvrf), afi,
						 SAFI_UNICAST, !!fib, !!json,
						 tag, prefix_str ? prefix : NULL,
						 !!supernets_only, type,
						 ospf_instance_id, table, !!ng,
						 &ctx);
		}
		if (json)
			vty_json_close(vty, first_vrf_json);
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, !!json);
		vrf = vrf_lookup_by_id(vrf_id);
		if (!vrf)
			return CMD_SUCCESS;

		zvrf = vrf->info;
		if (!zvrf)
			return CMD_SUCCESS;

		if (table_all)
			do_show_ip_route_all(vty, zvrf, afi, !!fib, !!json, tag,
					     prefix_str ? prefix : NULL,
					     !!supernets_only, type,
					     ospf_instance_id, !!ng, &ctx);
		else
			do_show_ip_route(vty, vrf->name, afi, SAFI_UNICAST,
					 !!fib, !!json, tag,
					 prefix_str ? prefix : NULL,
					 !!supernets_only, type,
					 ospf_instance_id, table, !!ng, &ctx);
	}

	return CMD_SUCCESS;
}

ALIAS_HIDDEN (show_route,
              show_ro_cmd,
              "show <ip$ipv4|ipv6$ipv6> ro",
              SHOW_STR
              IP_STR
              IPV6_STR
              "IP routing table\n");


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
       "IP forwarding table\n"
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
	json_object *vrf_json = NULL;

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		if (uj && !vrf_json)
			vrf_json = json_object_new_object();

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) == NULL)
				continue;

			if (table_id == 0)
				table = zebra_vrf_table(afi, SAFI_UNICAST,
							zvrf->vrf->vrf_id);
			else
				table = zebra_vrf_lookup_table_with_table_id(
					afi, SAFI_UNICAST, zvrf->vrf->vrf_id,
					table_id);

			if (!table)
				continue;

			if (prefix)
				vty_show_ip_route_summary_prefix(vty, table,
								 vrf_json, uj);
			else
				vty_show_ip_route_summary(vty, table, vrf_json,
							  uj);
		}

		if (uj)
			vty_json(vty, vrf_json);
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, false);

		if (table_id == 0)
			table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		else
			table = zebra_vrf_lookup_table_with_table_id(
				afi, SAFI_UNICAST, vrf_id, table_id);
		if (!table)
			return CMD_SUCCESS;

		if (prefix)
			vty_show_ip_route_summary_prefix(vty, table, NULL, uj);
		else
			vty_show_ip_route_summary(vty, table, NULL, uj);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (show_route_zebra_dump,
              show_route_zebra_dump_cmd,
              "show <ip|ipv6> zebra route dump [vrf VRFNAME]",
              SHOW_STR
              IP_STR
              IP6_STR
              "Zebra daemon\n"
              "Routing table\n"
              "All information\n"
              VRF_CMD_HELP_STR)
{
	afi_t afi = AFI_IP;
	struct route_table *table;
	const char *vrf_name = NULL;
	int idx = 0;

	afi = strmatch(argv[1]->text, "ipv6") ? AFI_IP6 : AFI_IP;

	if (argv_find(argv, argc, "vrf", &idx))
		vrf_name = argv[++idx]->arg;

	if (!vrf_name) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if ((zvrf == NULL)
			    || (zvrf->table[afi][SAFI_UNICAST] == NULL))
				continue;

			table = zvrf->table[afi][SAFI_UNICAST];
			show_ip_route_dump_vty(vty, table);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		VRF_GET_ID(vrf_id, vrf_name, true);

		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		if (!table)
			return CMD_SUCCESS;

		show_ip_route_dump_vty(vty, table);
	}

	return CMD_SUCCESS;
}

static void show_ip_route_nht_dump(struct vty *vty,
				   const struct nexthop *nexthop,
				   const struct route_node *rn,
				   const struct route_entry *re,
				   unsigned int num)
{

	char buf[SRCDEST2STR_BUFFER];

	vty_out(vty, "   Nexthop %u:\n", num);
	vty_out(vty, "      type: %u\n", nexthop->type);
	vty_out(vty, "      flags: %u\n", nexthop->flags);
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, "      ip address: %s\n",
			inet_ntop(AF_INET, &nexthop->gate.ipv4, buf,
				  sizeof(buf)));
		vty_out(vty, "      afi: ipv4\n");

		if (nexthop->ifindex) {
			vty_out(vty, "      interface index: %d\n",
				nexthop->ifindex);
			vty_out(vty, "      interface name: %s\n",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		}

		if (nexthop->rmap_src.ipv4.s_addr)
			vty_out(vty, "      rmapsrc: %pI4\n",
				&nexthop->rmap_src.ipv4);
		else if (nexthop->src.ipv4.s_addr)
			vty_out(vty, "      source: %pI4\n",
				&nexthop->src.ipv4.s_addr);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, "      ip: %s\n",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
				  sizeof(buf)));
		vty_out(vty, "      afi: ipv6\n");

		if (nexthop->ifindex) {
			vty_out(vty, "      interface index: %d\n",
				nexthop->ifindex);
			vty_out(vty, "      interface name: %s\n",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		}

		/* Allow for 5549 ipv4 prefix with ipv6 nexthop */
		if (rn->p.family == AF_INET && nexthop->rmap_src.ipv4.s_addr)
			vty_out(vty, "      rmapsrc: %pI4\n",
				&nexthop->rmap_src.ipv4);
		else if (!IPV6_ADDR_SAME(&nexthop->rmap_src.ipv6, &in6addr_any))
			vty_out(vty, "      rmapsrc: %pI6\n",
				&nexthop->rmap_src.ipv6);
		else if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
			vty_out(vty, "      source: %pI6\n", &nexthop->src.ipv6);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty,
			"      Nexthop is an interface (directly connected).\n");
		vty_out(vty, "      interface index: %d\n", nexthop->ifindex);
		vty_out(vty, "      interface name: %s\n",
			ifindex2ifname(nexthop->ifindex, nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		vty_out(vty, "      Nexthop type is blackhole.\n");

		switch (nexthop->bh_type) {
		case BLACKHOLE_REJECT:
			vty_out(vty, "      Blackhole type: reject\n");
			break;
		case BLACKHOLE_ADMINPROHIB:
			vty_out(vty,
				"      Blackhole type: admin-prohibited\n");
			break;
		case BLACKHOLE_NULL:
			vty_out(vty, "      Blackhole type: NULL0\n");
			break;
		case BLACKHOLE_UNSPEC:
			break;
		}
		break;
	}
}

static void show_ip_route_dump_vty(struct vty *vty, struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	char buf[SRCDEST2STR_BUFFER];
	char time[20];
	time_t uptime;
	struct tm tm;
	struct timeval tv;
	struct nexthop *nexthop = NULL;
	int nexthop_num = 0;

	vty_out(vty, "\nIPv4/IPv6 Routing table dump\n");
	vty_out(vty, "----------------------------\n");

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		RNODE_FOREACH_RE (rn, re) {
			vty_out(vty, "Route: %s\n",
				srcdest_rnode2str(rn, buf, sizeof(buf)));
			vty_out(vty, "   protocol: %s\n",
				zebra_route_string(re->type));
			vty_out(vty, "   instance: %u\n", re->instance);
			vty_out(vty, "   VRF ID: %u\n", re->vrf_id);
			vty_out(vty, "   VRF name: %s\n",
				vrf_id_to_name(re->vrf_id));
			vty_out(vty, "   flags: %u\n", re->flags);

			if (re->type != ZEBRA_ROUTE_CONNECT &&
			    re->type != ZEBRA_ROUTE_LOCAL) {
				vty_out(vty, "   distance: %u\n", re->distance);
				vty_out(vty, "   metric: %u\n", re->metric);
			}

			vty_out(vty, "   tag: %u\n", re->tag);

			uptime = monotime(&tv);
			uptime -= re->uptime;
			gmtime_r(&uptime, &tm);

			if (uptime < ONE_DAY_SECOND)
				snprintf(time, sizeof(time), "%02d:%02d:%02d",
					 tm.tm_hour, tm.tm_min, tm.tm_sec);
			else if (uptime < ONE_WEEK_SECOND)
				snprintf(time, sizeof(time), "%dd%02dh%02dm",
					 tm.tm_yday, tm.tm_hour, tm.tm_min);
			else
				snprintf(time, sizeof(time), "%02dw%dd%02dh",
					 tm.tm_yday / 7,
					 tm.tm_yday - ((tm.tm_yday / 7) * 7),
					 tm.tm_hour);

			vty_out(vty, "   status: %u\n", re->status);
			vty_out(vty, "   nexthop_num: %u\n",
				nexthop_group_nexthop_num(&(re->nhe->nhg)));
			vty_out(vty, "   nexthop_active_num: %u\n",
				nexthop_group_active_nexthop_num(
					&(re->nhe->nhg)));
			vty_out(vty, "   table: %u\n", re->table);
			vty_out(vty, "   uptime: %s\n", time);

			for (ALL_NEXTHOPS_PTR(&(re->nhe->nhg), nexthop)) {
				nexthop_num++;
				show_ip_route_nht_dump(vty, nexthop, rn, re,
						       nexthop_num);
			}

			nexthop_num = 0;
			vty_out(vty, "\n");
		}
	}
}

static void vty_show_ip_route_summary(struct vty *vty, struct route_table *table,
				      json_object *vrf_json, bool use_json)
{
	struct route_node *rn;
	struct route_entry *re;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
	uint32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t offload_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t trap_cnt[ZEBRA_ROUTE_TOTAL + 1];
	uint32_t i;
	uint32_t is_ibgp;
	json_object *json_route_summary = NULL;
	json_object *json_route_routes = NULL;
	const char *vrf_name = zvrf_name(
		((struct rib_table_info *)route_table_get_info(table))->zvrf);

	memset(&rib_cnt, 0, sizeof(rib_cnt));
	memset(&fib_cnt, 0, sizeof(fib_cnt));
	memset(&offload_cnt, 0, sizeof(offload_cnt));
	memset(&trap_cnt, 0, sizeof(trap_cnt));

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

			if (CHECK_FLAG(re->flags, ZEBRA_FLAG_TRAPPED)) {
				if (is_ibgp)
					trap_cnt[ZEBRA_ROUTE_IBGP]++;
				else
					trap_cnt[re->type]++;
			}

			if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED)) {
				if (is_ibgp)
					offload_cnt[ZEBRA_ROUTE_IBGP]++;
				else
					offload_cnt[re->type]++;
			}
		}

	if (!use_json)
		vty_out(vty, "%-20s %-20s %s  (vrf %s)\n", "Route Source",
			"Routes", "FIB", vrf_name);

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
					json_object_int_add(
						json_route_ebgp, "fibOffLoaded",
						offload_cnt[ZEBRA_ROUTE_BGP]);
					json_object_int_add(
						json_route_ebgp, "fibTrapped",
						trap_cnt[ZEBRA_ROUTE_BGP]);

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
					json_object_int_add(
						json_route_ibgp, "fibOffLoaded",
						offload_cnt[ZEBRA_ROUTE_IBGP]);
					json_object_int_add(
						json_route_ibgp, "fibTrapped",
						trap_cnt[ZEBRA_ROUTE_IBGP]);
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

					json_object_int_add(json_route_type,
							    "fibOffLoaded",
							    offload_cnt[i]);
					json_object_int_add(json_route_type,
							    "fibTrapped",
							    trap_cnt[i]);
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

		if (!vrf_json)
			vty_json(vty, json_route_summary);
		else
			json_object_object_add(vrf_json, vrf_name,
					       json_route_summary);
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
					     json_object *vrf_json,
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
	const char *vrf_name = zvrf_name(
		((struct rib_table_info *)route_table_get_info(table))->zvrf);

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
			"Prefix Routes", "FIB", vrf_name);

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

		if (!vrf_json)
			vty_json(vty, json_route_summary);
		else
			json_object_object_add(vrf_json, vrf_name,
					       json_route_summary);
	} else {
		vty_out(vty, "------\n");
		vty_out(vty, "%-20s %-20d %-20d \n", "Totals",
			rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL]);
		vty_out(vty, "\n");
	}
}

DEFUN (allow_external_route_update,
       allow_external_route_update_cmd,
       "allow-external-route-update",
       "Allow FRR routes to be overwritten by external processes\n")
{
	zrouter.allow_delete = true;

	return CMD_SUCCESS;
}

DEFUN (no_allow_external_route_update,
       no_allow_external_route_update_cmd,
       "no allow-external-route-update",
       NO_STR
       "Allow FRR routes to be overwritten by external processes\n")
{
	zrouter.allow_delete = false;

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

DEFPY (evpn_mh_mac_holdtime,
       evpn_mh_mac_holdtime_cmd,
       "[no$no] evpn mh mac-holdtime (0-86400)$duration",
       NO_STR
       "EVPN\n"
       "Multihoming\n"
       "MAC hold time\n"
       "Duration in seconds\n")
{
	return zebra_evpn_mh_mac_holdtime_update(vty, duration,
			no ? true : false);
}

DEFPY (evpn_mh_neigh_holdtime,
       evpn_mh_neigh_holdtime_cmd,
       "[no$no] evpn mh neigh-holdtime (0-86400)$duration",
       NO_STR
       "EVPN\n"
       "Multihoming\n"
       "Neighbor entry hold time\n"
       "Duration in seconds\n")
{

	return zebra_evpn_mh_neigh_holdtime_update(vty, duration,
						   no ? true : false);
}

DEFPY (evpn_mh_startup_delay,
       evpn_mh_startup_delay_cmd,
       "[no] evpn mh startup-delay(0-3600)$duration",
       NO_STR
       "EVPN\n"
       "Multihoming\n"
       "Startup delay\n"
       "duration in seconds\n")
{

	return zebra_evpn_mh_startup_delay_update(vty, duration,
			no ? true : false);
}

DEFPY(evpn_mh_redirect_off, evpn_mh_redirect_off_cmd,
      "[no$no] evpn mh redirect-off",
      NO_STR
      "EVPN\n"
      "Multihoming\n"
      "ES bond redirect for fast-failover off\n")
{
	bool redirect_off;

	redirect_off = no ? false : true;

	return zebra_evpn_mh_redirect_off(vty, redirect_off);
}

/* show vrf */
DEFPY (show_vrf_vni,
       show_vrf_vni_cmd,
       "show vrf [<NAME$vrf_name|all$vrf_all>] vni [json]",
       SHOW_STR
       VRF_FULL_CMD_HELP_STR
       "VNI\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	bool uj = use_json(argc, argv);
	bool use_vrf = false;

	if (uj)
		json = json_object_new_object();

	/* show vrf vni used to display across all vrfs
	 * This is enhanced to support only for specific
	 * vrf based output.
	 */
	if (vrf_all || !vrf_name) {
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if (!zvrf)
				continue;

			use_vrf = true;
			break;
		}
		if (use_vrf) {
			if (!uj)
				vty_out(vty,
					"%-37s %-10s %-20s %-20s %-5s %-18s\n",
					"VRF", "VNI", "VxLAN IF", "L3-SVI",
					"State", "Rmac");
			else
				json_vrfs = json_object_new_array();
		} else {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty, "%% VRF does not exist\n");

			return CMD_WARNING;
		}
	}

	if (use_vrf) {
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if (!zvrf)
				continue;

			zebra_vxlan_print_vrf_vni(vty, zvrf, json_vrfs);
		}
	} else if (vrf_name) {
		zvrf = zebra_vrf_lookup_by_name(vrf_name);
		if (!zvrf) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% VRF '%s' specified does not exist\n",
					vrf_name);

			return CMD_WARNING;
		}

		if (!uj)
			vty_out(vty, "%-37s %-10s %-20s %-20s %-5s %-18s\n",
				"VRF", "VNI", "VxLAN IF", "L3-SVI", "State",
				"Rmac");
		else
			json_vrfs = json_object_new_array();

		zebra_vxlan_print_vrf_vni(vty, zvrf, json_vrfs);
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		vty_json(vty, json);
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

DEFPY(show_evpn_neigh, show_neigh_cmd, "show ip neigh",
      SHOW_STR IP_STR "neighbors\n")

{
	zebra_neigh_show(vty);

	return CMD_SUCCESS;
}

DEFPY(show_evpn_l2_nh,
      show_evpn_l2_nh_cmd,
      "show evpn l2-nh [json$json]",
      SHOW_STR
      "EVPN\n"
      "Layer2 nexthops\n"
      JSON_STR)
{
	bool uj = !!json;

	zebra_evpn_l2_nh_show(vty, uj);

	return CMD_SUCCESS;
}

DEFPY(show_evpn_es,
      show_evpn_es_cmd,
      "show evpn es [NAME$esi_str|detail$detail] [json$json]",
      SHOW_STR
      "EVPN\n"
      "Ethernet Segment\n"
      "ES ID\n"
      "Detailed information\n"
      JSON_STR)
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
      "show evpn es-evi [vni (1-16777215)$vni] [detail$detail] [json$json]",
      SHOW_STR
      "EVPN\n"
      "Ethernet Segment per EVI\n"
      "VxLAN Network Identifier\n"
      "VNI\n"
      "Detailed information\n"
      JSON_STR)
{
	bool uj = !!json;
	bool ud = !!detail;

	if (vni)
		zebra_evpn_es_evi_show_vni(vty, uj, vni, ud);
	else
		zebra_evpn_es_evi_show(vty, uj, ud);

	return CMD_SUCCESS;
}

DEFPY(show_evpn_access_vlan, show_evpn_access_vlan_cmd,
      "show evpn access-vlan [IFNAME$if_name (1-4094)$vid | detail$detail] [json$json]",
      SHOW_STR
      "EVPN\n"
      "Access VLANs\n"
      "Interface Name\n"
      "VLAN ID\n"
      "Detailed information\n" JSON_STR)
{
	bool uj = !!json;

	if (if_name && vid) {
		bool found = false;
		struct vrf *vrf;
		struct interface *ifp;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if (if_name) {
				ifp = if_lookup_by_name(if_name, vrf->vrf_id);
				if (ifp) {
					zebra_evpn_acc_vl_show_vid(vty, uj, vid,
								   ifp);
					found = true;
					break;
				}
			}
		}
		if (!found) {
			vty_out(vty, "%% Can't find interface %s\n", if_name);
			return CMD_WARNING;
		}
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

DEFUN_HIDDEN (show_evpn_nh_svd_ip,
              show_evpn_nh_svd_ip_cmd,
              "show evpn next-hops svd ip WORD [json]",
              SHOW_STR
              "EVPN\n"
              "Remote Vteps\n"
              "Single Vxlan Device\n"
              "Ip address\n"
              "Host address (ipv4 or ipv6)\n"
              JSON_STR)
{
	struct ipaddr ip;
	bool uj = use_json(argc, argv);

	if (str2ipaddr(argv[5]->arg, &ip) != 0) {
		if (!uj)
			vty_out(vty, "%% Malformed Neighbor address\n");
		return CMD_WARNING;
	}
	zebra_vxlan_print_specific_nh_l3vni(vty, 0, &ip, uj);

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

DEFUN_HIDDEN (show_evpn_nh_svd,
              show_evpn_nh_svd_cmd,
              "show evpn next-hops svd [json]",
              SHOW_STR
              "EVPN\n"
              "Remote VTEPs\n"
              "Single Vxlan Device\n"
              JSON_STR)
{
	bool uj = use_json(argc, argv);

	zebra_vxlan_print_nh_svd(vty, uj);

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
	zebra_vxlan_print_macs_vni(vty, zvrf, vni, uj, false);
	return CMD_SUCCESS;
}

DEFPY (show_evpn_mac_vni_detail,
       show_evpn_mac_vni_detail_cmd,
       "show evpn mac vni " CMD_VNI_RANGE " detail [json]",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VXLAN Network Identifier\n"
       "VNI number\n"
       "Detailed Information On Each VNI MAC\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	bool uj = use_json(argc, argv);

	zvrf = zebra_vrf_get_evpn();
	zebra_vxlan_print_macs_vni(vty, zvrf, vni, uj, true);
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
		vty_out(vty, "%% Malformed MAC address\n");
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

/* policy routing contexts */
DEFPY (show_pbr_rule,
       show_pbr_rule_cmd,
       "show pbr rule",
       SHOW_STR
       "Policy-Based Routing\n"
       "Rule\n")
{
	zebra_pbr_show_rule(vty);
	return CMD_SUCCESS;
}

DEFPY (pbr_nexthop_resolve,
       pbr_nexthop_resolve_cmd,
       "[no$no] pbr nexthop-resolve",
       NO_STR
       "Policy Based Routing\n"
       "Resolve nexthop for dataplane programming\n")
{
	zebra_pbr_expand_action_update(!no);
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
	if (!vni_str) {
		nb_cli_rpc_enqueue(vty, "all-vnis", NULL);
	} else {
		nb_cli_rpc_enqueue(vty, "vni-id", vni_str);
		if (mac_str)
			nb_cli_rpc_enqueue(vty, "mac-addr", mac_str);
		else if (ip_str)
			nb_cli_rpc_enqueue(vty, "vni-ipaddr", ip_str);
	}

	return nb_cli_rpc(vty, "/frr-zebra:clear-evpn-dup-addr", NULL);
}

DEFPY_HIDDEN (evpn_accept_bgp_seq,
              evpn_accept_bgp_seq_cmd,
              "evpn accept-bgp-seq",
              "EVPN\n"
	      "Accept all sequence numbers from BGP\n")
{
	zebra_vxlan_set_accept_bgp_seq(true);
	return CMD_SUCCESS;
}

DEFPY_HIDDEN (no_evpn_accept_bgp_seq,
              no_evpn_accept_bgp_seq_cmd,
              "no evpn accept-bgp-seq",
              NO_STR
              "EVPN\n"
	      "Accept all sequence numbers from BGP\n")
{
	zebra_vxlan_set_accept_bgp_seq(false);
	return CMD_SUCCESS;
}

/* Static ip route configuration write function. */
static int zebra_ip_config(struct vty *vty)
{
	int write = 0;

	write += zebra_import_table_config(vty, VRF_DEFAULT);

	return write;
}

DEFPY (ip_zebra_import_table_distance,
       ip_zebra_import_table_distance_cmd,
       "ip import-table (1-252)$table_id [mrib]$mrib [distance (1-255)$distance] [route-map RMAP_NAME$rmap]",
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n"
	   "Import into the MRIB instead of the URIB\n"
       "Distance for imported routes\n"
       "Default distance value\n"
       "route-map for filtering\n"
       "route-map name\n")
{
	safi_t safi = mrib ? SAFI_MULTICAST : SAFI_UNICAST;

	if (distance_str == NULL)
		distance = ZEBRA_TABLE_DISTANCE_DEFAULT;

	if (!is_zebra_valid_kernel_table(table_id)) {
		vty_out(vty, "Invalid routing table ID, %ld. Must be in range 1-252\n", table_id);
		return CMD_WARNING;
	}

	if (is_zebra_main_routing_table(table_id)) {
		vty_out(vty, "Invalid routing table ID, %ld. Must be non-default table\n", table_id);
		return CMD_WARNING;
	}

	return zebra_import_table(AFI_IP, safi, VRF_DEFAULT, table_id, distance, rmap, true);
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

DEFPY (no_ip_zebra_import_table,
       no_ip_zebra_import_table_cmd,
       "no ip import-table (1-252)$table_id [mrib]$mrib [distance (1-255)] [route-map NAME]",
       NO_STR
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n"
	   "Import into the MRIB instead of the URIB\n"
       "Distance for imported routes\n"
       "Default distance value\n"
       "route-map for filtering\n"
       "route-map name\n")
{
	safi_t safi = mrib ? SAFI_MULTICAST : SAFI_UNICAST;

	if (!is_zebra_valid_kernel_table(table_id)) {
		vty_out(vty,
			"Invalid routing table ID. Must be in range 1-252\n");
		return CMD_WARNING;
	}

	if (is_zebra_main_routing_table(table_id)) {
		vty_out(vty, "Invalid routing table ID, %ld. Must be non-default table\n", table_id);
		return CMD_WARNING;
	}

	if (!is_zebra_import_table_enabled(AFI_IP, safi, VRF_DEFAULT, table_id))
		return CMD_SUCCESS;

	return (zebra_import_table(AFI_IP, safi, VRF_DEFAULT, table_id, 0, NULL, false));
}

DEFPY (zebra_nexthop_group_keep,
       zebra_nexthop_group_keep_cmd,
       "[no] zebra nexthop-group keep (1-3600)",
       NO_STR
       ZEBRA_STR
       "Nexthop-Group\n"
       "How long to keep\n"
       "Time in seconds from 1-3600\n")
{
	if (no)
		zrouter.nhg_keep = ZEBRA_DEFAULT_NHG_KEEP_TIMER;
	else
		zrouter.nhg_keep = keep;

	return CMD_SUCCESS;
}

static int config_write_protocol(struct vty *vty)
{
	if (zrouter.allow_delete)
		vty_out(vty, "allow-external-route-update\n");

	if (zrouter.nhg_keep != ZEBRA_DEFAULT_NHG_KEEP_TIMER)
		vty_out(vty, "zebra nexthop-group keep %u\n", zrouter.nhg_keep);

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

	zebra_evpn_mh_config_write(vty);

	zebra_pbr_config_write(vty);

	if (!zebra_vxlan_get_accept_bgp_seq())
		vty_out(vty, "no evpn accept-bgp-seq\n");

	/* Include nexthop-group config */
	if (!zebra_nhg_kernel_nexthops_enabled())
		vty_out(vty, "no zebra nexthop kernel enable\n");

	if (zebra_nhg_proto_nexthops_only())
		vty_out(vty, "zebra nexthop proto only\n");

	if (!zebra_nhg_recursive_use_backups())
		vty_out(vty, "no zebra nexthop resolve-via-backup\n");

#ifdef HAVE_SCRIPTING
	frrscript_names_config_write(vty);
#endif

	if (rnh_get_hide_backups())
		vty_out(vty, "ip nht hide-backup-events\n");

#ifdef HAVE_NETLINK
	/* Include netlink info */
	netlink_config_write_helper(vty);
#endif /* HAVE_NETLINK */

	return 1;
}

static inline bool zebra_vty_v6_rr_semantics_used(void)
{
	if (zebra_nhg_kernel_nexthops_enabled())
		return true;

	if (zrouter.v6_rr_semantics)
		return true;

	return false;
}

DEFUN (show_zebra,
       show_zebra_cmd,
       "show zebra",
       SHOW_STR
       ZEBRA_STR)
{
	struct vrf *vrf;
	struct ttable *table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	char *out;
	char timebuf[MONOTIME_STRLEN];

	time_to_string(zrouter.startup_time, timebuf);
	vty_out(vty, "Zebra started%s at time %s",
		zrouter.graceful_restart ? " gracefully" : "", timebuf);

	if (zrouter.t_rib_sweep)
		vty_out(vty,
			"Zebra RIB sweep timer running, remaining time %lds\n",
			event_timer_remain_second(zrouter.t_rib_sweep));
	else {
		time_to_string(zrouter.rib_sweep_time, timebuf);
		vty_out(vty, "Zebra RIB sweep happened at %s", timebuf);
	}

	ttable_rowseps(table, 0, BOTTOM, true, '-');
	ttable_add_row(table, "OS|%s(%s)", cmd_system_get(), cmd_release_get());
	ttable_add_row(table, "ECMP Maximum|%d", zrouter.multipath_num);
	ttable_add_row(table, "v4 Forwarding|%s", ipforward() ? "On" : "Off");
	ttable_add_row(table, "v6 Forwarding|%s",
		       ipforward_ipv6() ? "On" : "Off");
	ttable_add_row(table, "MPLS|%s", mpls_enabled ? "On" : "Off");
	ttable_add_row(table, "EVPN|%s", is_evpn_enabled() ? "On" : "Off");
	ttable_add_row(table, "Kernel socket buffer size|%d", rcvbufsize);
	ttable_add_row(table, "v6 Route Replace Semantics|%s",
		       zebra_vty_v6_rr_semantics_used() ? "Replace"
							: "Delete then Add");

#ifdef GNU_LINUX
	if (!vrf_is_backend_netns())
		ttable_add_row(table, "VRF|l3mdev Available");
	else
		ttable_add_row(table, "VRF|Namespaces");
#else
	ttable_add_row(table, "VRF|Not Available");
#endif

	ttable_add_row(table, "v6 with v4 nexthop|%s",
		       zrouter.v6_with_v4_nexthop ? "Used" : "Unavaliable");

	ttable_add_row(table, "ASIC offload|%s",
		       zrouter.asic_offloaded ? "Used" : "Unavailable");

	/*
	 * Do not display this unless someone is actually using it
	 *
	 * Why this distinction?  I think this is effectively dead code
	 * and should not be exposed.  Maybe someone proves me wrong.
	 */
	if (zrouter.asic_notification_nexthop_control)
		ttable_add_row(table, "ASIC offload and nexthop control|Used");

	ttable_add_row(table, "RA|%s",
		       rtadv_compiled_in() ? "Compiled in" : "Not Compiled in");
	ttable_add_row(table, "RFC 5549|%s",
		       rtadv_get_interfaces_configured_from_bgp()
			       ? "BGP is using"
			       : "BGP is not using");

	ttable_add_row(table, "Kernel NHG|%s",
		       zrouter.supports_nhgs ? "Available" : "Unavailable");

	ttable_add_row(table, "Allow Non FRR route deletion|%s",
		       zrouter.allow_delete ? "Yes" : "No");
	ttable_add_row(table, "v4 All LinkDown Routes|%s",
		       zrouter.all_linkdownv4 ? "On" : "Off");
	ttable_add_row(table, "v4 Default LinkDown Routes|%s",
		       zrouter.default_linkdownv4 ? "On" : "Off");
	ttable_add_row(table, "v6 All LinkDown Routes|%s",
		       zrouter.all_linkdownv6 ? "On" : "Off");
	ttable_add_row(table, "v6 Default LinkDown Routes|%s",
		       zrouter.default_linkdownv6 ? "On" : "Off");

	ttable_add_row(table, "v4 All MC Forwarding|%s",
		       zrouter.all_mc_forwardingv4 ? "On" : "Off");
	ttable_add_row(table, "v4 Default MC Forwarding|%s",
		       zrouter.default_mc_forwardingv4 ? "On" : "Off");
	ttable_add_row(table, "v6 All MC Forwarding|%s",
		       zrouter.all_mc_forwardingv6 ? "On" : "Off");
	ttable_add_row(table, "v6 Default MC Forwarding|%s",
		       zrouter.default_mc_forwardingv6 ? "On" : "Off");

	out = ttable_dump(table, "\n");
	vty_out(vty, "%s\n", out);
	XFREE(MTYPE_TMP_TTABLE, out);

	ttable_del(table);
	vty_out(vty,
		"                            Route      Route      Neighbor   LSP        LSP\n");
	vty_out(vty,
		"VRF                         Installs   Removals    Updates   Installs   Removals\n");

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct zebra_vrf *zvrf = vrf->info;

		vty_out(vty, "%-25s %10" PRIu64 " %10" PRIu64 " %10" PRIu64" %10" PRIu64 " %10" PRIu64 "\n",
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

/* IPForwarding configuration write function. */
static int config_write_forwarding(struct vty *vty)
{
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

#ifdef HAVE_NETLINK
DEFUN_HIDDEN(zebra_kernel_netlink_batch_tx_buf,
	     zebra_kernel_netlink_batch_tx_buf_cmd,
	     "zebra kernel netlink batch-tx-buf (1-1048576) (1-1048576)",
	     ZEBRA_STR
	     "Zebra kernel interface\n"
	     "Set Netlink parameters\n"
	     "Set batch buffer size and send threshold\n"
	     "Size of the buffer\n"
	     "Send threshold\n")
{
	uint32_t bufsize = 0, threshold = 0;

	bufsize = strtoul(argv[4]->arg, NULL, 10);
	threshold = strtoul(argv[5]->arg, NULL, 10);

	netlink_set_batch_buffer_size(bufsize, threshold, true);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN(no_zebra_kernel_netlink_batch_tx_buf,
	     no_zebra_kernel_netlink_batch_tx_buf_cmd,
	     "no zebra kernel netlink batch-tx-buf [(0-1048576)] [(0-1048576)]",
	     NO_STR ZEBRA_STR
	     "Zebra kernel interface\n"
	     "Set Netlink parameters\n"
	     "Set batch buffer size and send threshold\n"
	     "Size of the buffer\n"
	     "Send threshold\n")
{
	netlink_set_batch_buffer_size(0, 0, false);

	return CMD_SUCCESS;
}

DEFPY (zebra_protodown_bit,
       zebra_protodown_bit_cmd,
       "zebra protodown reason-bit (0-31)$bit",
       ZEBRA_STR
       "Protodown Configuration\n"
       "Reason Bit used in the kernel for application\n"
       "Reason Bit range\n")
{
	if_netlink_set_frr_protodown_r_bit(bit);
	return CMD_SUCCESS;
}

DEFPY (no_zebra_protodown_bit,
       no_zebra_protodown_bit_cmd,
       "no zebra protodown reason-bit [(0-31)$bit]",
       NO_STR
       ZEBRA_STR
       "Protodown Configuration\n"
       "Reason Bit used in the kernel for setting protodown\n"
       "Reason Bit Range\n")
{
	if_netlink_unset_frr_protodown_r_bit();
	return CMD_SUCCESS;
}

#endif /* HAVE_NETLINK */

#ifdef HAVE_SCRIPTING

DEFUN(zebra_on_rib_process_script, zebra_on_rib_process_script_cmd,
      "zebra on-rib-process script SCRIPT",
      ZEBRA_STR
      "on_rib_process_dplane_results hook call\n"
      "Set a script\n"
      "Script name (same as filename in /etc/frr/scripts/, without .lua)\n")
{

	if (frrscript_names_set_script_name(ZEBRA_ON_RIB_PROCESS_HOOK_CALL,
					    argv[3]->arg)
	    == 0) {
		vty_out(vty, "Successfully added script %s for hook call %s\n",
			argv[3]->arg, ZEBRA_ON_RIB_PROCESS_HOOK_CALL);
	} else {
		vty_out(vty, "Failed to add script %s for hook call %s\n",
			argv[3]->arg, ZEBRA_ON_RIB_PROCESS_HOOK_CALL);
	}
	return CMD_SUCCESS;
}

#endif /* HAVE_SCRIPTING */

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

	zebra_affinity_map_init();

	install_node(&ip_node);
	install_node(&protocol_node);

	install_element(CONFIG_NODE, &allow_external_route_update_cmd);
	install_element(CONFIG_NODE, &no_allow_external_route_update_cmd);

	install_element(CONFIG_NODE, &ip_multicast_mode_cmd);
	install_element(CONFIG_NODE, &no_ip_multicast_mode_cmd);

	install_element(CONFIG_NODE, &zebra_nexthop_group_keep_cmd);
	install_element(CONFIG_NODE, &ip_zebra_import_table_distance_cmd);
	install_element(CONFIG_NODE, &no_ip_zebra_import_table_cmd);
	install_element(CONFIG_NODE, &zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &no_zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &zebra_packet_process_cmd);
	install_element(CONFIG_NODE, &no_zebra_packet_process_cmd);
	install_element(CONFIG_NODE, &nexthop_group_use_enable_cmd);
	install_element(CONFIG_NODE, &proto_nexthop_group_only_cmd);
	install_element(CONFIG_NODE, &backup_nexthop_recursive_use_enable_cmd);

	install_element(VIEW_NODE, &show_nexthop_group_cmd);
	install_element(VIEW_NODE, &show_interface_nexthop_group_cmd);

	install_element(VIEW_NODE, &show_vrf_cmd);
	install_element(VIEW_NODE, &show_vrf_vni_cmd);
	install_element(VIEW_NODE, &show_route_cmd);
	install_element(VIEW_NODE, &show_ro_cmd);
	install_element(VIEW_NODE, &show_route_detail_cmd);
	install_element(VIEW_NODE, &show_route_summary_cmd);
	install_element(VIEW_NODE, &show_ip_nht_cmd);

	install_element(VIEW_NODE, &show_ip_rpf_cmd);
	install_element(VIEW_NODE, &show_ip_rpf_addr_cmd);
	install_element(VIEW_NODE, &show_ipv6_rpf_addr_cmd);

	install_element(CONFIG_NODE, &rnh_hide_backups_cmd);

	install_element(VIEW_NODE, &show_frr_cmd);
	install_element(VIEW_NODE, &show_evpn_global_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_detail_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_l2_nh_cmd);
	install_element(VIEW_NODE, &show_evpn_es_cmd);
	install_element(VIEW_NODE, &show_evpn_es_evi_cmd);
	install_element(VIEW_NODE, &show_evpn_access_vlan_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_mac_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_ip_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_svd_ip_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_svd_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_detail_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_detail_cmd);
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
	install_element(CONFIG_NODE, &evpn_accept_bgp_seq_cmd);
	install_element(CONFIG_NODE, &no_evpn_accept_bgp_seq_cmd);

	install_element(VIEW_NODE, &show_neigh_cmd);

	install_element(VIEW_NODE, &show_pbr_ipset_cmd);
	install_element(VIEW_NODE, &show_pbr_iptable_cmd);
	install_element(VIEW_NODE, &show_pbr_rule_cmd);
	install_element(CONFIG_NODE, &pbr_nexthop_resolve_cmd);
	install_element(VIEW_NODE, &show_route_zebra_dump_cmd);

	install_element(CONFIG_NODE, &evpn_mh_mac_holdtime_cmd);
	install_element(CONFIG_NODE, &evpn_mh_neigh_holdtime_cmd);
	install_element(CONFIG_NODE, &evpn_mh_startup_delay_cmd);
	install_element(CONFIG_NODE, &evpn_mh_redirect_off_cmd);

	install_element(VIEW_NODE, &show_dataplane_cmd);
	install_element(VIEW_NODE, &show_dataplane_providers_cmd);
	install_element(CONFIG_NODE, &zebra_dplane_queue_limit_cmd);
	install_element(CONFIG_NODE, &no_zebra_dplane_queue_limit_cmd);

#ifdef HAVE_NETLINK
	install_element(CONFIG_NODE, &zebra_kernel_netlink_batch_tx_buf_cmd);
	install_element(CONFIG_NODE, &no_zebra_kernel_netlink_batch_tx_buf_cmd);
	install_element(CONFIG_NODE, &zebra_protodown_bit_cmd);
	install_element(CONFIG_NODE, &no_zebra_protodown_bit_cmd);
#endif /* HAVE_NETLINK */

#ifdef HAVE_SCRIPTING
	install_element(CONFIG_NODE, &zebra_on_rib_process_script_cmd);
#endif /* HAVE_SCRIPTING */

	install_element(VIEW_NODE, &zebra_show_routing_tables_summary_cmd);
}
