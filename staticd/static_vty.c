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

#include "static_vrf.h"
#include "static_memory.h"
#include "static_vty.h"
#include "static_routes.h"
#ifndef VTYSH_EXTRACT_PL
#include "staticd/static_vty_clippy.c"
#endif
static struct static_vrf *static_vty_get_unknown_vrf(struct vty *vty,
						     const char *vrf_name)
{
	struct static_vrf *svrf;
	struct vrf *vrf;

	svrf = static_vrf_lookup_by_name(vrf_name);

	if (svrf)
		return svrf;

	vrf = vrf_get(VRF_UNKNOWN, vrf_name);
	if (!vrf) {
		vty_out(vty, "%% Could not create vrf %s\n", vrf_name);
		return NULL;
	}
	svrf = vrf->info;
	if (!svrf) {
		vty_out(vty, "%% Could not create vrf-info %s\n",
			vrf_name);
		return NULL;
	}
	/* Mark as having FRR configuration */
	vrf_set_user_cfged(vrf);

	return svrf;
}

struct static_hold_route {
	char *vrf_name;
	char *nhvrf_name;
	afi_t afi;
	safi_t safi;
	char *dest_str;
	char *mask_str;
	char *src_str;
	char *gate_str;
	char *ifname;
	char *flag_str;
	char *tag_str;
	char *distance_str;
	char *label_str;
	char *table_str;
	bool onlink;

	/* processed & masked destination, used for config display */
	struct prefix dest;
};

static struct list *static_list;

static int static_list_compare_helper(const char *s1, const char *s2)
{
	/* extra (!s1 && !s2) to keep SA happy */
	if (s1 == s2 || (!s1 && !s2))
		return 0;

	if (!s1 && s2)
		return -1;

	if (s1 && !s2)
		return 1;

	return strcmp(s1, s2);
}

static void static_list_delete(struct static_hold_route *shr)
{
	XFREE(MTYPE_STATIC_ROUTE, shr->vrf_name);
	XFREE(MTYPE_STATIC_ROUTE, shr->nhvrf_name);
	XFREE(MTYPE_STATIC_ROUTE, shr->dest_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->mask_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->src_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->gate_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->ifname);
	XFREE(MTYPE_STATIC_ROUTE, shr->flag_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->tag_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->distance_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->label_str);
	XFREE(MTYPE_STATIC_ROUTE, shr->table_str);

	XFREE(MTYPE_STATIC_ROUTE, shr);
}

static int static_list_compare(void *arg1, void *arg2)
{
	struct static_hold_route *shr1 = arg1;
	struct static_hold_route *shr2 = arg2;
	int ret;

	ret = strcmp(shr1->vrf_name, shr2->vrf_name);
	if (ret)
		return ret;

	ret = strcmp(shr1->nhvrf_name, shr2->nhvrf_name);
	if (ret)
		return ret;

	ret = shr1->afi - shr2->afi;
	if (ret)
		return ret;

	ret = shr1->safi - shr2->safi;
	if (ret)
		return ret;

	ret = prefix_cmp(&shr1->dest, &shr2->dest);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->src_str, shr2->src_str);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->gate_str, shr2->gate_str);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->ifname, shr2->ifname);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->flag_str, shr2->flag_str);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->tag_str, shr2->tag_str);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->distance_str,
					 shr2->distance_str);
	if (ret)
		return ret;

	ret = static_list_compare_helper(shr1->table_str,
					 shr2->table_str);
	if (ret)
		return ret;

	return static_list_compare_helper(shr1->label_str, shr2->label_str);
}


/* General function for static route. */
static int zebra_static_route_holdem(
	struct static_vrf *svrf, struct static_vrf *nh_svrf, afi_t afi,
	safi_t safi, const char *negate, struct prefix *dest,
	const char *dest_str, const char *mask_str, const char *src_str,
	const char *gate_str, const char *ifname, const char *flag_str,
	const char *tag_str, const char *distance_str, const char *label_str,
	const char *table_str, bool onlink)
{
	struct static_hold_route *shr, *lookup;
	struct listnode *node;

	zlog_warn("Static Route to %s not installed currently because dependent config not fully available",
		  dest_str);

	shr = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(*shr));
	shr->vrf_name = XSTRDUP(MTYPE_STATIC_ROUTE, svrf->vrf->name);
	shr->nhvrf_name = XSTRDUP(MTYPE_STATIC_ROUTE, nh_svrf->vrf->name);
	shr->afi = afi;
	shr->safi = safi;
	shr->onlink = onlink;
	if (dest)
		prefix_copy(&shr->dest, dest);
	if (dest_str)
		shr->dest_str = XSTRDUP(MTYPE_STATIC_ROUTE, dest_str);
	if (mask_str)
		shr->mask_str = XSTRDUP(MTYPE_STATIC_ROUTE, mask_str);
	if (src_str)
		shr->src_str = XSTRDUP(MTYPE_STATIC_ROUTE, src_str);
	if (gate_str)
		shr->gate_str = XSTRDUP(MTYPE_STATIC_ROUTE, gate_str);
	if (ifname)
		shr->ifname = XSTRDUP(MTYPE_STATIC_ROUTE, ifname);
	if (flag_str)
		shr->flag_str = XSTRDUP(MTYPE_STATIC_ROUTE, flag_str);
	if (tag_str)
		shr->tag_str = XSTRDUP(MTYPE_STATIC_ROUTE, tag_str);
	if (distance_str)
		shr->distance_str = XSTRDUP(MTYPE_STATIC_ROUTE, distance_str);
	if (label_str)
		shr->label_str = XSTRDUP(MTYPE_STATIC_ROUTE, label_str);
	if (table_str)
		shr->table_str = XSTRDUP(MTYPE_STATIC_ROUTE, table_str);

	for (ALL_LIST_ELEMENTS_RO(static_list, node, lookup)) {
		if (static_list_compare(shr, lookup) == 0)
			break;
	}

	if (lookup) {
		if (negate) {
			listnode_delete(static_list, lookup);
			static_list_delete(shr);
			static_list_delete(lookup);

			return CMD_SUCCESS;
		}

		/*
		 * If a person enters the same line again
		 * we need to silently accept it
		 */
		goto shr_cleanup;
	}

	if (!negate) {
		listnode_add_sort(static_list, shr);
		return CMD_SUCCESS;
	}

 shr_cleanup:
	XFREE(MTYPE_STATIC_ROUTE, shr->nhvrf_name);
	XFREE(MTYPE_STATIC_ROUTE, shr->vrf_name);
	XFREE(MTYPE_STATIC_ROUTE, shr);

	return CMD_SUCCESS;
}

static int static_route_leak(
	struct vty *vty, struct static_vrf *svrf, struct static_vrf *nh_svrf,
	afi_t afi, safi_t safi, const char *negate, const char *dest_str,
	const char *mask_str, const char *src_str, const char *gate_str,
	const char *ifname, const char *flag_str, const char *tag_str,
	const char *distance_str, const char *label_str, const char *table_str,
	bool onlink)
{
	int ret;
	uint8_t distance;
	struct prefix p, src;
	struct prefix_ipv6 *src_p = NULL;
	union g_addr gate;
	union g_addr *gatep = NULL;
	struct in_addr mask;
	enum static_blackhole_type bh_type = 0;
	route_tag_t tag = 0;
	uint8_t type;
	struct static_nh_label snh_label;
	uint32_t table_id = 0;

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
						__PRETTY_FUNCTION__, src_str);
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

	if (svrf->vrf->vrf_id == VRF_UNKNOWN
	    || nh_svrf->vrf->vrf_id == VRF_UNKNOWN) {
		vrf_set_user_cfged(svrf->vrf);
		return zebra_static_route_holdem(
			svrf, nh_svrf, afi, safi, negate, &p, dest_str,
			mask_str, src_str, gate_str, ifname, flag_str, tag_str,
			distance_str, label_str, table_str, onlink);
	}

	if (table_str) {
		/* table configured. check consistent with vrf config
		 */
		if (svrf->vrf->data.l.table_id != RT_TABLE_MAIN) {
			if (vty)
				vty_out(vty,
				    "%% Table %s overlaps vrf table %u\n",
				    table_str, svrf->vrf->data.l.table_id);
			else
				zlog_warn(
				    "%s: Table %s overlaps vrf table %u",
				    __PRETTY_FUNCTION__,
				    table_str, svrf->vrf->data.l.table_id);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Administrative distance. */
	if (distance_str)
		distance = atoi(distance_str);
	else
		distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

	/* tag */
	if (tag_str)
		tag = strtoul(tag_str, NULL, 10);

	/* Labels */
	memset(&snh_label, 0, sizeof(struct static_nh_label));
	if (label_str) {
		if (!mpls_enabled) {
			if (vty)
				vty_out(vty,
					"%% MPLS not turned on in kernel, ignoring command\n");
			else
				zlog_warn(
					"%s: MPLS not turned on in kernel ignoring static route to %s",
					__PRETTY_FUNCTION__, dest_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		int rc = mpls_str2label(label_str, &snh_label.num_labels,
					snh_label.label);
		if (rc < 0) {
			switch (rc) {
			case -1:
				if (vty)
					vty_out(vty, "%% Malformed label(s)\n");
				else
					zlog_warn(
						"%s: Malformed labels specified for route %s",
						__PRETTY_FUNCTION__, dest_str);
				break;
			case -2:
				if (vty)
					vty_out(vty,
						"%% Cannot use reserved label(s) (%d-%d)\n",
						MPLS_LABEL_RESERVED_MIN,
						MPLS_LABEL_RESERVED_MAX);
				else
					zlog_warn(
						"%s: Cannot use reserved labels (%d-%d) for %s",
						__PRETTY_FUNCTION__,
						MPLS_LABEL_RESERVED_MIN,
						MPLS_LABEL_RESERVED_MAX,
						dest_str);
				break;
			case -3:
				if (vty)
					vty_out(vty,
						"%% Too many labels. Enter %d or fewer\n",
						MPLS_MAX_LABELS);
				else
					zlog_warn(
						"%s: Too many labels, Enter %d or fewer for %s",
						__PRETTY_FUNCTION__,
						MPLS_MAX_LABELS, dest_str);
				break;
			}
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* TableID */
	if (table_str)
		table_id = atol(table_str);

	/* Null0 static route.  */
	if (ifname != NULL) {
		if (strcasecmp(ifname, "Null0") == 0
		    || strcasecmp(ifname, "reject") == 0
		    || strcasecmp(ifname, "blackhole") == 0) {
			if (vty)
				vty_out(vty,
					"%% Nexthop interface name can not be from reserved keywords (Null0, reject, blackhole)\n");
			else
				zlog_warn(
					"%s: %s: Nexthop interface name can not be from reserved keywords (Null0, reject, blackhole)",
					__PRETTY_FUNCTION__, dest_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Route flags */
	if (flag_str) {
		switch (flag_str[0]) {
		case 'r':
			bh_type = STATIC_BLACKHOLE_REJECT;
			break;
		case 'b':
			bh_type = STATIC_BLACKHOLE_DROP;
			break;
		case 'N':
			bh_type = STATIC_BLACKHOLE_NULL;
			break;
		default:
			if (vty)
				vty_out(vty, "%% Malformed flag %s \n",
					flag_str);
			else
				zlog_warn("%s: Malformed flag %s for %s",
					  __PRETTY_FUNCTION__, flag_str,
					  dest_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (gate_str) {
		if (inet_pton(afi2family(afi), gate_str, &gate) != 1) {
			if (vty)
				vty_out(vty,
					"%% Malformed nexthop address %s\n",
					gate_str);
			else
				zlog_warn(
					"%s: Malformed nexthop address %s for %s",
					__PRETTY_FUNCTION__, gate_str,
					dest_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		gatep = &gate;

		if (afi == AFI_IP && !negate) {
			if (if_lookup_exact_address(&gatep->ipv4, AF_INET,
							svrf->vrf->vrf_id))
				if (vty)
					vty_out(vty,
						"%% Warning!! Local connected address is configured as Gateway IP(%s)\n",
						gate_str);
		} else if (afi == AFI_IP6 && !negate) {
			if (if_lookup_exact_address(&gatep->ipv6, AF_INET6,
							svrf->vrf->vrf_id))
				if (vty)
					vty_out(vty,
						"%% Warning!! Local connected address is configured as Gateway IPv6(%s)\n",
						gate_str);
		}

	}

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

	if (!negate) {
		static_add_route(afi, safi, type, &p, src_p, gatep, ifname,
				 bh_type, tag, distance, svrf, nh_svrf,
				 &snh_label, table_id, onlink);
		/* Mark as having FRR configuration */
		vrf_set_user_cfged(svrf->vrf);
	} else {
		static_delete_route(afi, safi, type, &p, src_p, gatep, ifname,
				    tag, distance, svrf, &snh_label, table_id);
		/* If no other FRR config for this VRF, mark accordingly. */
		if (!static_vrf_has_config(svrf))
			vrf_reset_user_cfged(svrf->vrf);
	}

	return CMD_SUCCESS;
}

static int static_route(struct vty *vty, afi_t afi, safi_t safi,
			const char *negate, const char *dest_str,
			const char *mask_str, const char *src_str,
			const char *gate_str, const char *ifname,
			const char *flag_str, const char *tag_str,
			const char *distance_str, const char *vrf_name,
			const char *label_str, const char *table_str)
{
	struct static_vrf *svrf;

	/* VRF id */
	svrf = static_vrf_lookup_by_name(vrf_name);

	/* When trying to delete, the VRF must exist. */
	if (negate && !svrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf_name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* When trying to create, create the VRF if it doesn't exist.
	 * Note: The VRF isn't active until we hear about it from the kernel.
	 */
	if (!svrf) {
		svrf = static_vty_get_unknown_vrf(vty, vrf_name);
		if (!svrf)
			return CMD_WARNING_CONFIG_FAILED;
	}
	return static_route_leak(vty, svrf, svrf, afi, safi, negate, dest_str,
				 mask_str, src_str, gate_str, ifname, flag_str,
				 tag_str, distance_str, label_str, table_str,
				 false);
}

void static_config_install_delayed_routes(struct static_vrf *svrf)
{
	struct listnode *node, *nnode;
	struct static_hold_route *shr;
	struct static_vrf *osvrf, *nh_svrf;
	int installed;

	for (ALL_LIST_ELEMENTS(static_list, node, nnode, shr)) {
		osvrf = static_vrf_lookup_by_name(shr->vrf_name);
		nh_svrf = static_vrf_lookup_by_name(shr->nhvrf_name);

		if (osvrf != svrf && nh_svrf != svrf)
			continue;

		if (osvrf->vrf->vrf_id == VRF_UNKNOWN
		    || nh_svrf->vrf->vrf_id == VRF_UNKNOWN)
			continue;

		installed = static_route_leak(
			NULL, osvrf, nh_svrf, shr->afi, shr->safi, NULL,
			shr->dest_str, shr->mask_str, shr->src_str,
			shr->gate_str, shr->ifname, shr->flag_str, shr->tag_str,
			shr->distance_str, shr->label_str, shr->table_str,
			shr->onlink);

		if (installed != CMD_SUCCESS)
			zlog_debug(
				"%s: Attempt to install %s as a route and it was rejected",
				__PRETTY_FUNCTION__, shr->dest_str);
		listnode_delete(static_list, shr);
		static_list_delete(shr);
	}
}

/* Write static route configuration. */
int static_config(struct vty *vty, struct static_vrf *svrf, afi_t afi,
		  safi_t safi, const char *cmd)
{
	struct static_hold_route *shr;
	struct listnode *node;
	char spacing[100];
	struct route_node *rn;
	struct static_route *si;
	struct route_table *stable;
	char buf[SRCDEST2STR_BUFFER];
	int write = 0;

	stable = svrf->stable[afi][safi];
	if (stable == NULL)
		return write;

	sprintf(spacing, "%s%s", (svrf->vrf->vrf_id == VRF_DEFAULT) ? "" : " ",
		cmd);

	/*
	 * Static routes for vrfs not fully inited
	 */
	for (ALL_LIST_ELEMENTS_RO(static_list, node, shr)) {
		if (shr->afi != afi || shr->safi != safi)
			continue;

		if (strcmp(svrf->vrf->name, shr->vrf_name) != 0)
			continue;

		char dest_str[PREFIX_STRLEN];

		prefix2str(&shr->dest, dest_str, sizeof(dest_str));

		vty_out(vty, "%s ", spacing);
		if (shr->dest_str)
			vty_out(vty, "%s ", dest_str);
		if (shr->src_str)
			vty_out(vty, "from %s ", shr->src_str);
		if (shr->gate_str)
			vty_out(vty, "%s ", shr->gate_str);
		if (shr->ifname)
			vty_out(vty, "%s ", shr->ifname);
		if (shr->flag_str)
			vty_out(vty, "%s ", shr->flag_str);
		if (shr->tag_str)
			vty_out(vty, "tag %s ", shr->tag_str);
		if (shr->distance_str)
			vty_out(vty, "%s ", shr->distance_str);
		if (shr->label_str)
			vty_out(vty, "label %s ", shr->label_str);
		if (shr->table_str)
			vty_out(vty, "table %s", shr->table_str);
		if (strcmp(shr->vrf_name, shr->nhvrf_name) != 0)
			vty_out(vty, "nexthop-vrf %s ", shr->nhvrf_name);
		if (shr->onlink)
			vty_out(vty, "onlink");
		vty_out(vty, "\n");
	}

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn))
		for (si = rn->info; si; si = si->next) {
			vty_out(vty, "%s %s", spacing,
				srcdest_rnode2str(rn, buf, sizeof(buf)));

			switch (si->type) {
			case STATIC_IPV4_GATEWAY:
				vty_out(vty, " %s", inet_ntoa(si->addr.ipv4));
				break;
			case STATIC_IPV6_GATEWAY:
				vty_out(vty, " %s",
					inet_ntop(AF_INET6, &si->addr.ipv6, buf,
						  sizeof(buf)));
				break;
			case STATIC_IFNAME:
				vty_out(vty, " %s", si->ifname);
				break;
			case STATIC_BLACKHOLE:
				switch (si->bh_type) {
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
					inet_ntop(AF_INET, &si->addr.ipv4, buf,
						  sizeof(buf)),
					si->ifname);
				break;
			case STATIC_IPV6_GATEWAY_IFNAME:
				vty_out(vty, " %s %s",
					inet_ntop(AF_INET6, &si->addr.ipv6, buf,
						  sizeof(buf)),
					si->ifname);
				break;
			}

			if (si->tag)
				vty_out(vty, " tag %" ROUTE_TAG_PRI, si->tag);

			if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
				vty_out(vty, " %d", si->distance);

			/* Label information */
			if (si->snh_label.num_labels)
				vty_out(vty, " label %s",
					mpls_label2str(si->snh_label.num_labels,
						       si->snh_label.label, buf,
						       sizeof(buf), 0));

			if (si->nh_vrf_id != si->vrf_id)
				vty_out(vty, " nexthop-vrf %s", si->nh_vrfname);

			/*
			 * table ID from VRF overrides configured
			 */
			if (si->table_id &&
			    svrf->vrf->data.l.table_id == RT_TABLE_MAIN)
				vty_out(vty, " table %u", si->table_id);

			if (si->onlink)
				vty_out(vty, " onlink");

			vty_out(vty, "\n");

			write = 1;
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

	return static_route(vty, AFI_IP, SAFI_UNICAST, no, prefix,
			    mask_str, NULL, NULL, NULL, flag, tag_str,
			    distance_str, vrf, label, table_str);
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
	struct static_vrf *svrf = vrf->info;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);
	return static_route_leak(vty, svrf, svrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, NULL, NULL, flag,
				 tag_str, distance_str, label, table_str,
				 false);
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
      "Treat the nexthop as directly attached to the interface")
{
	struct static_vrf *svrf;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	svrf = static_vty_get_unknown_vrf(vty, vrf);
	if (!svrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route_leak(vty, svrf, nh_svrf, AFI_IP, SAFI_UNICAST, no,
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
      "Treat the nexthop as directly attached to the interface")
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *flag = NULL;
	struct static_vrf *svrf = vrf->info;
	struct static_vrf *nh_svrf;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route_leak(vty, svrf, nh_svrf, AFI_IP, SAFI_UNICAST, no,
				 prefix, mask_str, NULL, gate_str, ifname, flag,
				 tag_str, distance_str, label, table_str,
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
	struct static_vrf *svrf;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	svrf = static_vty_get_unknown_vrf(vty, vrf);
	if (!svrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP, SAFI_UNICAST, no, prefix, mask_str,
		NULL, gate_str, ifname, flag, tag_str, distance_str, label,
		table_str, false);
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
	struct static_vrf *svrf = vrf->info;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP, SAFI_UNICAST, no, prefix, mask_str,
		NULL, gate_str, ifname, flag, tag_str, distance_str, label,
		table_str, false);
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

	return static_route(vty, AFI_IP6, SAFI_UNICAST, no, prefix_str,
			    NULL, from_str, NULL, NULL, flag, tag_str,
			    distance_str, vrf, label, table_str);
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
	struct static_vrf *svrf = vrf->info;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(prefix);
	return static_route_leak(
		vty, svrf, svrf, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
		from_str, NULL, NULL, flag, tag_str, distance_str, label,
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
      "Treat the nexthop as directly attached to the interface")
{
	struct static_vrf *svrf;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	svrf = static_vty_get_unknown_vrf(vty, vrf);
	if (!svrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
		from_str, gate_str, ifname, flag, tag_str, distance_str, label,
		table_str, !!onlink);
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
      "Treat the nexthop as directly attached to the interface")
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct static_vrf *svrf = vrf->info;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
		from_str, gate_str, ifname, flag, tag_str, distance_str, label,
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
	struct static_vrf *svrf;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && vrf && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	svrf = static_vty_get_unknown_vrf(vty, vrf);
	if (!svrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
		from_str, gate_str, ifname, flag, tag_str, distance_str, label,
		table_str, false);
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
	struct static_vrf *svrf = vrf->info;
	struct static_vrf *nh_svrf;
	const char *flag = NULL;

	if (table_str && !vrf_is_backend_netns()) {
		vty_out(vty,
			"%% table param only available when running on netns-based vrfs\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_svrf = static_vty_get_unknown_vrf(vty, nexthop_vrf);
	else
		nh_svrf = svrf;

	if (!nh_svrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n", nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	return static_route_leak(
		vty, svrf, nh_svrf, AFI_IP6, SAFI_UNICAST, no, prefix_str, NULL,
		from_str, gate_str, ifname, flag, tag_str, distance_str, label,
		table_str, false);
}

DEFUN_NOSH (show_debugging_staticd,
	    show_debugging_staticd_cmd,
	    "show debugging [static]",
	    SHOW_STR
	    DEBUG_STR
	    "Static Information\n")
{
	vty_out(vty, "Static debugging status\n");

	return CMD_SUCCESS;
}

void static_vty_init(void)
{
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

	install_element(VIEW_NODE, &show_debugging_staticd_cmd);

	static_list = list_new();
	static_list->cmp = (int (*)(void *, void *))static_list_compare;
	static_list->del = (void (*)(void *))static_list_delete;
}
