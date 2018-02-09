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
#include "mpls.h"
#include "routemap.h"
#include "srcdest_table.h"
#include "vxlan.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_static.h"
#include "lib/json.h"
#include "zebra/zebra_vxlan.h"
#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_vty_clippy.c"
#endif
#include "zebra/zserv.h"
#include "zebra/router-id.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_vxlan_private.h"

extern int allow_delete;

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, u_char use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    u_short ospf_instance_id);
static void vty_show_ip_route_detail(struct vty *vty, struct route_node *rn,
				     int mcast);
static void vty_show_ip_route_summary(struct vty *vty,
				      struct route_table *table);
static void vty_show_ip_route_summary_prefix(struct vty *vty,
					     struct route_table *table);

/*
 * special macro to allow us to get the correct zebra_vrf
 */
#define ZEBRA_DECLVAR_CONTEXT(A, B)			\
	struct vrf *A = VTY_GET_CONTEXT(vrf);		\
	struct zebra_vrf *B =				\
		(vrf) ? vrf->info : NULL;		\

/* VNI range as per RFC 7432 */
#define CMD_VNI_RANGE "(1-16777215)"

/* General function for static route. */
static int zebra_static_route_leak(struct vty *vty,
				   struct zebra_vrf *zvrf,
				   struct zebra_vrf *nh_zvrf,
				   afi_t afi, safi_t safi,
				   const char *negate, const char *dest_str,
				   const char *mask_str, const char *src_str,
				   const char *gate_str, const char *ifname,
				   const char *flag_str, const char *tag_str,
				   const char *distance_str,
				   const char *label_str)
{
	int ret;
	u_char distance;
	struct prefix p, src;
	struct prefix_ipv6 *src_p = NULL;
	union g_addr gate;
	union g_addr *gatep = NULL;
	struct in_addr mask;
	enum static_blackhole_type bh_type = 0;
	route_tag_t tag = 0;
	u_char type;
	struct static_nh_label snh_label;

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
			src_p = (struct prefix_ipv6 *)&src;
		}
		break;
	default:
		break;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

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
			vty_out(vty,
				"%% MPLS not turned on in kernel, ignoring command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		int rc = mpls_str2label(label_str, &snh_label.num_labels,
					snh_label.label);
		if (rc < 0) {
			switch (rc) {
			case -1:
				vty_out(vty, "%% Malformed label(s)\n");
				break;
			case -2:
				vty_out(vty,
					"%% Cannot use reserved label(s) (%d-%d)\n",
					MPLS_MIN_RESERVED_LABEL,
					MPLS_MAX_RESERVED_LABEL);
				break;
			case -3:
				vty_out(vty,
					"%% Too many labels. Enter %d or fewer\n",
					MPLS_MAX_LABELS);
				break;
			}
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Null0 static route.  */
	if (ifname != NULL) {
		if (strncasecmp(ifname, "Null0", strlen(ifname)) == 0 ||
		    strncasecmp(ifname, "reject", strlen(ifname)) == 0 ||
		    strncasecmp(ifname, "blackhole", strlen(ifname)) == 0) {
			vty_out(vty, "%% Nexthop interface cannot be Null0, reject or blackhole\n");
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
			vty_out(vty, "%% Malformed flag %s \n", flag_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (gate_str) {
		if (inet_pton(afi2family(afi), gate_str, &gate) != 1) {
			vty_out(vty, "%% Malformed nexthop address %s\n",
				gate_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		gatep = &gate;
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
				 bh_type, tag, distance, zvrf, nh_zvrf,
				 &snh_label);
		/* Mark as having FRR configuration */
		vrf_set_user_cfged(zvrf->vrf);
	} else {
		static_delete_route(afi, safi, type, &p, src_p, gatep, ifname,
				    tag, distance, zvrf, &snh_label);
		/* If no other FRR config for this VRF, mark accordingly. */
		if (!zebra_vrf_has_config(zvrf))
			vrf_reset_user_cfged(zvrf->vrf);
	}

	return CMD_SUCCESS;
}

static int zebra_static_route(struct vty *vty, afi_t afi, safi_t safi,
                             const char *negate, const char *dest_str,
                             const char *mask_str, const char *src_str,
                             const char *gate_str, const char *ifname,
                             const char *flag_str, const char *tag_str,
                             const char *distance_str, const char *vrf_name,
                             const char *label_str)
{
	struct zebra_vrf *zvrf;
	struct vrf *vrf;

	/* VRF id */
	zvrf = zebra_vrf_lookup_by_name(vrf_name);

	/* When trying to delete, the VRF must exist. */
	if (negate && !zvrf) {
		vty_out(vty, "%% vrf %s is not defined\n", vrf_name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* When trying to create, create the VRF if it doesn't exist.
	 * Note: The VRF isn't active until we hear about it from the kernel.
	 */
	if (!zvrf) {
		vrf = vrf_get(VRF_UNKNOWN, vrf_name);
		if (!vrf) {
			vty_out(vty, "%% Could not create vrf %s\n", vrf_name);
			return CMD_WARNING_CONFIG_FAILED;
		}
		zvrf = vrf->info;
		if (!zvrf) {
			vty_out(vty, "%% Could not create vrf-info %s\n",
				vrf_name);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* Mark as having FRR configuration */
		vrf_set_user_cfged(vrf);
	}
	return zebra_static_route_leak(vty, zvrf, zvrf, afi, safi,
				       negate, dest_str, mask_str, src_str,
				       gate_str, ifname, flag_str, tag_str,
				       distance_str, label_str);
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
	return zebra_static_route(vty, AFI_IP, SAFI_MULTICAST, no, prefix_str,
				  NULL, NULL, gate_str, ifname, NULL, NULL,
				  distance_str, NULL, NULL);
}

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
	int uj = use_json(argc, argv);
	return do_show_ip_route(vty, VRF_DEFAULT_NAME, AFI_IP, SAFI_MULTICAST,
				false, uj, 0, NULL, false, 0, 0);
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
		vty_show_ip_route_detail(vty, rn, 1);
	else
		vty_out(vty, "%% No match for RPF lookup\n");

	return CMD_SUCCESS;
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
      MPLS_LABEL_HELPSTR)
{
	return zebra_static_route(vty, AFI_IP, SAFI_UNICAST, no, prefix,
				  mask_str, NULL, NULL, NULL, flag,
				  tag_str, distance_str, vrf, label);
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
      MPLS_LABEL_HELPSTR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct zebra_vrf *zvrf = vrf->info;

	return zebra_static_route_leak(vty, zvrf, zvrf,
				       AFI_IP, SAFI_UNICAST, no, prefix,
				       mask_str, NULL, NULL, NULL, flag,
				       tag_str, distance_str, label);
}

DEFPY(ip_route_address_interface,
      ip_route_address_interface_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	INTERFACE$ifname                               \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |nexthop-vrf NAME                            \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name. Specify 'Null0' (case-insensitive) for a \
      null route.\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	struct zebra_vrf *zvrf;
	struct zebra_vrf *nh_zvrf;

	const char *flag = NULL;
	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	zvrf = zebra_vrf_lookup_by_name(vrf);
	if (!zvrf) {
		vty_out(vty, "%% vrf %s is not defined\n",
			vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP, SAFI_UNICAST, no, prefix,
				       mask_str, NULL, gate_str, ifname, flag,
				       tag_str, distance_str, label);
}

DEFPY(ip_route_address_interface_vrf,
      ip_route_address_interface_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	INTERFACE$ifname                               \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |nexthop-vrf NAME                            \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name. Specify 'Null0' (case-insensitive) for a \
      null route.\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	const char *flag = NULL;
	struct zebra_vrf *zvrf = vrf->info;
	struct zebra_vrf *nh_zvrf;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP, SAFI_UNICAST, no, prefix,
				       mask_str, NULL, gate_str, ifname, flag,
				       tag_str, distance_str, label);
}

DEFPY(ip_route,
      ip_route_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|INTERFACE$ifname>                \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |nexthop-vrf NAME                            \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	struct zebra_vrf *zvrf;
	struct zebra_vrf *nh_zvrf;
	const char *flag = NULL;

	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	zvrf = zebra_vrf_lookup_by_name(vrf);
	if (!zvrf) {
		vty_out(vty, "%% vrf %s is not defined\n",
			vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}


	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP, SAFI_UNICAST, no, prefix,
				       mask_str, NULL, gate_str, ifname, flag,
				       tag_str, distance_str, label);
}

DEFPY(ip_route_vrf,
      ip_route_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|INTERFACE$ifname>                \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |nexthop-vrf NAME                            \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct zebra_vrf *zvrf = vrf->info;
	struct zebra_vrf *nh_zvrf;

	const char *flag = NULL;
	if (ifname && !strncasecmp(ifname, "Null0", 5)) {
		flag = "Null0";
		ifname = NULL;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP, SAFI_UNICAST, no, prefix,
				       mask_str, NULL, gate_str, ifname, flag,
				       tag_str, distance_str, label);
}

/* New RIB.  Detailed information for IPv4 route. */
static void vty_show_ip_route_detail(struct vty *vty, struct route_node *rn,
				     int mcast)
{
	struct route_entry *re;
	struct nexthop *nexthop;
	char buf[SRCDEST2STR_BUFFER];
	struct zebra_vrf *zvrf;

	RNODE_FOREACH_RE (rn, re) {
		const char *mcast_info = "";
		if (mcast) {
			rib_table_info_t *info = srcdest_rnode_table_info(rn);
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
		struct tm *tm;

		uptime = time(NULL);
		uptime -= re->uptime;
		tm = gmtime(&uptime);

		vty_out(vty, "  Last update ");

		if (uptime < ONE_DAY_SECOND)
			vty_out(vty, "%02d:%02d:%02d", tm->tm_hour,
				tm->tm_min, tm->tm_sec);
		else if (uptime < ONE_WEEK_SECOND)
			vty_out(vty, "%dd%02dh%02dm", tm->tm_yday,
				tm->tm_hour, tm->tm_min);
		else
			vty_out(vty, "%02dw%dd%02dh", tm->tm_yday / 7,
				tm->tm_yday - ((tm->tm_yday / 7) * 7),
				tm->tm_hour);
		vty_out(vty, " ago\n");

		for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
			char addrstr[32];

			vty_out(vty, "  %c%s",
				CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)
					? CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE)
						? ' ' : '*'
					: ' ',
				nexthop->rparent ? "  " : "");

			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				vty_out(vty, " %s",
					inet_ntoa(nexthop->gate.ipv4));
				if (nexthop->ifindex)
					vty_out(vty, ", via %s",
						ifindex2ifname(nexthop->ifindex,
							       re->nh_vrf_id));
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				vty_out(vty, " %s",
					inet_ntop(AF_INET6, &nexthop->gate.ipv6,
						  buf, sizeof buf));
				if (nexthop->ifindex)
					vty_out(vty, ", via %s",
						ifindex2ifname(nexthop->ifindex,
							       re->nh_vrf_id));
				break;
			case NEXTHOP_TYPE_IFINDEX:
				vty_out(vty, " directly connected, %s",
					ifindex2ifname(nexthop->ifindex,
						       re->nh_vrf_id));
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

			if (re->vrf_id != re->nh_vrf_id) {
				struct vrf *vrf =
					vrf_lookup_by_id(re->nh_vrf_id);

				vty_out(vty, "(vrf %s)", vrf->name);
			}

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
				vty_out(vty, " (duplicate nexthop removed)");

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
					if (inet_ntop(AF_INET,
						      &nexthop->src.ipv4,
						      addrstr, sizeof addrstr))
						vty_out(vty, ", src %s",
							addrstr);
				}
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				if (!IPV6_ADDR_SAME(&nexthop->src.ipv6,
						    &in6addr_any)) {
					if (inet_ntop(AF_INET6,
						      &nexthop->src.ipv6,
						      addrstr, sizeof addrstr))
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
			if (nexthop->nh_label
			    && nexthop->nh_label->num_labels) {
				vty_out(vty, ", label %s",
					mpls_label2str(
						nexthop->nh_label->num_labels,
						nexthop->nh_label->label, buf,
						sizeof buf, 1));
			}

			vty_out(vty, "\n");
		}
		vty_out(vty, "\n");
	}
}

static void vty_show_ip_route(struct vty *vty, struct route_node *rn,
			      struct route_entry *re, json_object *json)
{
	struct nexthop *nexthop;
	int len = 0;
	char buf[SRCDEST2STR_BUFFER];
	json_object *json_nexthops = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_route = NULL;
	json_object *json_labels = NULL;
	time_t uptime;
	struct tm *tm;

	uptime = time(NULL);
	uptime -= re->uptime;
	tm = gmtime(&uptime);

	if (json) {
		json_route = json_object_new_object();
		json_nexthops = json_object_new_array();

		json_object_string_add(json_route, "prefix",
				       srcdest_rnode2str(rn, buf, sizeof buf));
		json_object_string_add(json_route, "protocol",
				       zebra_route_string(re->type));

		if (re->instance)
			json_object_int_add(json_route, "instance",
					    re->instance);

		if (re->vrf_id)
			json_object_int_add(json_route, "vrfId", re->vrf_id);

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			json_object_boolean_true_add(json_route, "selected");

		if (re->type != ZEBRA_ROUTE_CONNECT) {
			json_object_int_add(json_route, "distance",
					    re->distance);
			json_object_int_add(json_route, "metric", re->metric);
		}

		if (uptime < ONE_DAY_SECOND)
			sprintf(buf, "%02d:%02d:%02d", tm->tm_hour,
				tm->tm_min, tm->tm_sec);
		else if (uptime < ONE_WEEK_SECOND)
			sprintf(buf, "%dd%02dh%02dm", tm->tm_yday,
				tm->tm_hour, tm->tm_min);
		else
			sprintf(buf, "%02dw%dd%02dh", tm->tm_yday / 7,
				tm->tm_yday - ((tm->tm_yday / 7) * 7),
				tm->tm_hour);

		json_object_string_add(json_route, "uptime", buf);

		for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
			json_nexthop = json_object_new_object();

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
						ifindex2ifname(nexthop->ifindex,
							       re->nh_vrf_id));
				}
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				json_object_string_add(
					json_nexthop, "ip",
					inet_ntop(AF_INET6, &nexthop->gate.ipv6,
						  buf, sizeof buf));
				json_object_string_add(json_nexthop, "afi",
						       "ipv6");

				if (nexthop->ifindex) {
					json_object_int_add(json_nexthop,
							    "interfaceIndex",
							    nexthop->ifindex);
					json_object_string_add(
						json_nexthop, "interfaceName",
						ifindex2ifname(nexthop->ifindex,
							       re->nh_vrf_id));
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
						       re->nh_vrf_id));
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

			if (re->nh_vrf_id != re->vrf_id) {
				struct vrf *vrf =
					vrf_lookup_by_id(re->nh_vrf_id);

				json_object_string_add(json_nexthop,
						       "vrf",
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
						      sizeof buf))
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
						      sizeof buf))
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

			json_object_array_add(json_nexthops, json_nexthop);
		}

		json_object_object_add(json_route, "nexthops", json_nexthops);
		json_object_array_add(json, json_route);
		return;
	}

	/* Nexthop information. */
	for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
		if (nexthop == re->nexthop) {
			/* Prefix information. */
			len = vty_out(vty, "%c", zebra_route_char(re->type));
			if (re->instance)
				len += vty_out(vty, "[%d]", re->instance);
			len += vty_out(
				vty, "%c%c %s",
				CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)
					? '>'
					: ' ',
				CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)
					? '*'
					: ' ',
				srcdest_rnode2str(rn, buf, sizeof buf));

			/* Distance and metric display. */
			if (re->type != ZEBRA_ROUTE_CONNECT)
				len += vty_out(vty, " [%u/%u]", re->distance,
					       re->metric);
		} else {
			vty_out(vty, "  %c%*c",
				CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)
					? CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE)
						? ' ' : '*'
					: ' ',
				len - 3 + (2 * nexthop_level(nexthop)), ' ');
		}

		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			vty_out(vty, " via %s", inet_ntoa(nexthop->gate.ipv4));
			if (nexthop->ifindex)
				vty_out(vty, ", %s",
					ifindex2ifname(nexthop->ifindex,
						       re->nh_vrf_id));
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			vty_out(vty, " via %s",
				inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
					  sizeof buf));
			if (nexthop->ifindex)
				vty_out(vty, ", %s",
					ifindex2ifname(nexthop->ifindex,
						       re->nh_vrf_id));
			break;

		case NEXTHOP_TYPE_IFINDEX:
			vty_out(vty, " is directly connected, %s",
				ifindex2ifname(nexthop->ifindex,
					       re->nh_vrf_id));
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

		if (re->nh_vrf_id != re->vrf_id) {
			struct vrf *vrf =
				vrf_lookup_by_id(re->nh_vrf_id);

			vty_out(vty, "(vrf %s)", vrf->name);
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
					      sizeof buf))
					vty_out(vty, ", src %s", buf);
			}
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any)) {
				if (inet_ntop(AF_INET6, &nexthop->src.ipv6, buf,
					      sizeof buf))
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
					       sizeof buf, 1));
		}

		if (uptime < ONE_DAY_SECOND)
			vty_out(vty, ", %02d:%02d:%02d", tm->tm_hour,
				tm->tm_min, tm->tm_sec);
		else if (uptime < ONE_WEEK_SECOND)
			vty_out(vty, ", %dd%02dh%02dm", tm->tm_yday,
				tm->tm_hour, tm->tm_min);
		else
			vty_out(vty, ", %02dw%dd%02dh", tm->tm_yday / 7,
				tm->tm_yday - ((tm->tm_yday / 7) * 7),
				tm->tm_hour);
		vty_out(vty, "\n");
	}
}

static int do_show_ip_route(struct vty *vty, const char *vrf_name, afi_t afi,
			    safi_t safi, bool use_fib, u_char use_json,
			    route_tag_t tag,
			    const struct prefix *longer_prefix_p,
			    bool supernets_only, int type,
			    u_short ospf_instance_id)
{
	struct route_table *table;
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_entry *re;
	int first = 1;
	struct zebra_vrf *zvrf = NULL;
	char buf[BUFSIZ];
	json_object *json = NULL;
	json_object *json_prefix = NULL;
	u_int32_t addr;

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

	table = zebra_vrf_table(afi, safi, zvrf_id(zvrf));
	if (!table) {
		if (use_json)
			vty_out(vty, "{}\n");
		return CMD_SUCCESS;
	}

	if (use_json)
		json = json_object_new_object();

	/* Show all routes. */
	for (rn = route_top(table); rn; rn = route_next(rn)) {
		dest = rib_dest_from_rnode(rn);

		RNODE_FOREACH_RE (rn, re) {
			if (use_fib
			    && re != dest->selected_fib)
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

					if (zvrf_id(zvrf) != VRF_DEFAULT)
						vty_out(vty, "\nVRF %s:\n",
							zvrf_name(zvrf));

					first = 0;
				}
			}

			vty_show_ip_route(vty, rn, re, json_prefix);
		}

		if (json_prefix) {
			prefix2str(&rn->p, buf, sizeof buf);
			json_object_object_add(json, buf, json_prefix);
			json_prefix = NULL;
		}
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_nht,
       show_ip_nht_cmd,
       "show ip nht [vrf NAME]",
       SHOW_STR
       IP_STR
       "IP nexthop tracking table\n"
       VRF_CMD_HELP_STR)
{
	int idx_vrf = 4;
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (argc == 5)
		VRF_GET_ID(vrf_id, argv[idx_vrf]->arg);

	zebra_print_rnh_table(vrf_id, AF_INET, vty, RNH_NEXTHOP_TYPE);
	return CMD_SUCCESS;
}


DEFUN (show_ip_nht_vrf_all,
       show_ip_nht_vrf_all_cmd,
       "show ip nht vrf all",
       SHOW_STR
       IP_STR
       "IP nexthop tracking table\n"
       VRF_ALL_CMD_HELP_STR)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		if ((zvrf = vrf->info) != NULL) {
			vty_out(vty, "\nVRF %s:\n", zvrf_name(zvrf));
			zebra_print_rnh_table(zvrf_id(zvrf), AF_INET, vty,
					      RNH_NEXTHOP_TYPE);
		}

	return CMD_SUCCESS;
}

DEFUN (show_ipv6_nht,
       show_ipv6_nht_cmd,
       "show ipv6 nht [vrf NAME]",
       SHOW_STR
       IPV6_STR
       "IPv6 nexthop tracking table\n"
       VRF_CMD_HELP_STR)
{
	int idx_vrf = 4;
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (argc == 5)
		VRF_GET_ID(vrf_id, argv[idx_vrf]->arg);

	zebra_print_rnh_table(vrf_id, AF_INET6, vty, RNH_NEXTHOP_TYPE);
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_nht_vrf_all,
       show_ipv6_nht_vrf_all_cmd,
       "show ipv6 nht vrf all",
       SHOW_STR
       IP_STR
       "IPv6 nexthop tracking table\n"
       VRF_ALL_CMD_HELP_STR)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		if ((zvrf = vrf->info) != NULL) {
			vty_out(vty, "\nVRF %s:\n", zvrf_name(zvrf));
			zebra_print_rnh_table(zvrf_id(zvrf), AF_INET6, vty,
					      RNH_NEXTHOP_TYPE);
		}

	return CMD_SUCCESS;
}

DEFUN (ip_nht_default_route,
       ip_nht_default_route_cmd,
       "ip nht resolve-via-default",
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	if (zebra_rnh_ip_default_route)
		return CMD_SUCCESS;

	zebra_rnh_ip_default_route = 1;
	zebra_evaluate_rnh(VRF_DEFAULT, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
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
	if (!zebra_rnh_ip_default_route)
		return CMD_SUCCESS;

	zebra_rnh_ip_default_route = 0;
	zebra_evaluate_rnh(VRF_DEFAULT, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

DEFUN (ipv6_nht_default_route,
       ipv6_nht_default_route_cmd,
       "ipv6 nht resolve-via-default",
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	if (zebra_rnh_ipv6_default_route)
		return CMD_SUCCESS;

	zebra_rnh_ipv6_default_route = 1;
	zebra_evaluate_rnh(VRF_DEFAULT, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);
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
	if (!zebra_rnh_ipv6_default_route)
		return CMD_SUCCESS;

	zebra_rnh_ipv6_default_route = 0;
	zebra_evaluate_rnh(VRF_DEFAULT, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);
	return CMD_SUCCESS;
}

DEFPY (show_route,
       show_route_cmd,
       "show\
         <\
	  ip$ipv4 <fib$fib|route> [vrf <NAME$vrf_name|all$vrf_all>]\
	   [{\
	    tag (1-4294967295)\
	    |A.B.C.D/M$prefix longer-prefixes\
	    |supernets-only$supernets_only\
	   }]\
	   [<\
	    " FRR_IP_REDIST_STR_ZEBRA "$type_str\
	    |ospf$type_str (1-65535)$ospf_instance_id\
	   >]\
          |ipv6$ipv6 <fib$fib|route> [vrf <NAME$vrf_name|all$vrf_all>]\
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

	if (type_str) {
		type = proto_redistnum(afi, type_str);
		if (type < 0) {
			vty_out(vty, "Unknown route type\n");
			return CMD_WARNING;
		}
	}

	if (vrf_all) {
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			struct zebra_vrf *zvrf;
			struct route_table *table;

			if ((zvrf = vrf->info) == NULL
			    || (table = zvrf->table[afi][SAFI_UNICAST]) == NULL)
				continue;

			do_show_ip_route(
				vty, zvrf_name(zvrf), afi, SAFI_UNICAST, !!fib,
				!!json, tag, prefix_str ? prefix : NULL,
				!!supernets_only, type, ospf_instance_id);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name);
		vrf = vrf_lookup_by_id(vrf_id);
		do_show_ip_route(vty, vrf->name, afi, SAFI_UNICAST, !!fib,
				 !!json, tag, prefix_str ? prefix : NULL,
				 !!supernets_only, type, ospf_instance_id);
	}

	return CMD_SUCCESS;
}

DEFPY (show_route_detail,
       show_route_detail_cmd,
       "show\
         <\
          ip$ipv4 route [vrf <NAME$vrf_name|all$vrf_all>]\
          <\
	   A.B.C.D$address\
	   |A.B.C.D/M$prefix\
	  >\
          |ipv6$ipv6 route [vrf <NAME$vrf_name|all$vrf_all>]\
          <\
	   X:X::X:X$address\
	   |X:X::X:X/M$prefix\
	  >\
	 >",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "Network in the IP routing table to display\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       IP6_STR
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "IPv6 Address\n"
       "IPv6 prefix\n")
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	struct route_table *table;
	struct prefix p;
	struct route_node *rn;

	if (address_str)
		prefix_str = address_str;
	if (str2prefix(prefix_str, &p) < 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING;
	}

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
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

			vty_show_ip_route_detail(vty, rn, 0);

			route_unlock_node(rn);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name);

		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		if (!table)
			return CMD_SUCCESS;

		rn = route_node_match(table, &p);
		if (!rn) {
			vty_out(vty, "%% Network not in table\n");
			return CMD_WARNING;
		}
		if (!address_str && rn->p.prefixlen != p.prefixlen) {
			vty_out(vty, "%% Network not in table\n");
			route_unlock_node(rn);
			return CMD_WARNING;
		}

		vty_show_ip_route_detail(vty, rn, 0);

		route_unlock_node(rn);
	}

	return CMD_SUCCESS;
}

DEFPY (show_route_summary,
       show_route_summary_cmd,
       "show\
         <\
          ip$ipv4 route [vrf <NAME$vrf_name|all$vrf_all>]\
            summary [prefix$prefix]\
          |ipv6$ipv6 route [vrf <NAME$vrf_name|all$vrf_all>]\
	    summary [prefix$prefix]\
	 >",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "Summary of all routes\n"
       "Prefix routes\n"
       IP6_STR
       "IP routing table\n"
       VRF_FULL_CMD_HELP_STR
       "Summary of all routes\n"
       "Prefix routes\n")
{
	afi_t afi = ipv4 ? AFI_IP : AFI_IP6;
	struct route_table *table;

	if (vrf_all) {
		struct vrf *vrf;
		struct zebra_vrf *zvrf;

		RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
			if ((zvrf = vrf->info) == NULL
			    || (table = zvrf->table[afi][SAFI_UNICAST]) == NULL)
				continue;

			if (prefix)
				vty_show_ip_route_summary_prefix(vty, table);
			else
				vty_show_ip_route_summary(vty, table);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name);

		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		if (!table)
			return CMD_SUCCESS;

		if (prefix)
			vty_show_ip_route_summary_prefix(vty, table);
		else
			vty_show_ip_route_summary(vty, table);
	}

	return CMD_SUCCESS;
}

static void vty_show_ip_route_summary(struct vty *vty,
				      struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
	u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	u_int32_t i;
	u_int32_t is_ibgp;

	memset(&rib_cnt, 0, sizeof(rib_cnt));
	memset(&fib_cnt, 0, sizeof(fib_cnt));
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, re) {
			is_ibgp = (re->type == ZEBRA_ROUTE_BGP
				   && CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP));

			rib_cnt[ZEBRA_ROUTE_TOTAL]++;
			if (is_ibgp)
				rib_cnt[ZEBRA_ROUTE_IBGP]++;
			else
				rib_cnt[re->type]++;

			if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
				fib_cnt[ZEBRA_ROUTE_TOTAL]++;

				if (is_ibgp)
					fib_cnt[ZEBRA_ROUTE_IBGP]++;
				else
					fib_cnt[re->type]++;
			}
		}

	vty_out(vty, "%-20s %-20s %s  (vrf %s)\n", "Route Source", "Routes",
		"FIB", zvrf_name(((rib_table_info_t *)table->info)->zvrf));

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if ((rib_cnt[i] > 0) || (i == ZEBRA_ROUTE_BGP
					 && rib_cnt[ZEBRA_ROUTE_IBGP] > 0)) {
			if (i == ZEBRA_ROUTE_BGP) {
				vty_out(vty, "%-20s %-20d %-20d \n", "ebgp",
					rib_cnt[ZEBRA_ROUTE_BGP],
					fib_cnt[ZEBRA_ROUTE_BGP]);
				vty_out(vty, "%-20s %-20d %-20d \n", "ibgp",
					rib_cnt[ZEBRA_ROUTE_IBGP],
					fib_cnt[ZEBRA_ROUTE_IBGP]);
			} else
				vty_out(vty, "%-20s %-20d %-20d \n",
					zebra_route_string(i), rib_cnt[i],
					fib_cnt[i]);
		}
	}

	vty_out(vty, "------\n");
	vty_out(vty, "%-20s %-20d %-20d \n", "Totals",
		rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL]);
	vty_out(vty, "\n");
}

/*
 * Implementation of the ip route summary prefix command.
 *
 * This command prints the primary prefixes that have been installed by various
 * protocols on the box.
 *
 */
static void vty_show_ip_route_summary_prefix(struct vty *vty,
					     struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
	u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
	u_int32_t i;
	int cnt;

	memset(&rib_cnt, 0, sizeof(rib_cnt));
	memset(&fib_cnt, 0, sizeof(fib_cnt));
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, re) {

			/*
			 * In case of ECMP, count only once.
			 */
			cnt = 0;
			for (nexthop = re->nexthop; (!cnt && nexthop);
			     nexthop = nexthop->next) {
				cnt++;
				rib_cnt[ZEBRA_ROUTE_TOTAL]++;
				rib_cnt[re->type]++;
				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_FIB)) {
					fib_cnt[ZEBRA_ROUTE_TOTAL]++;
					fib_cnt[re->type]++;
				}
				if (re->type == ZEBRA_ROUTE_BGP
				    && CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP)) {
					rib_cnt[ZEBRA_ROUTE_IBGP]++;
					if (CHECK_FLAG(nexthop->flags,
						       NEXTHOP_FLAG_FIB))
						fib_cnt[ZEBRA_ROUTE_IBGP]++;
				}
			}
		}

	vty_out(vty, "%-20s %-20s %s  (vrf %s)\n", "Route Source",
		"Prefix Routes", "FIB",
		zvrf_name(((rib_table_info_t *)table->info)->zvrf));

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (rib_cnt[i] > 0) {
			if (i == ZEBRA_ROUTE_BGP) {
				vty_out(vty, "%-20s %-20d %-20d \n", "ebgp",
					rib_cnt[ZEBRA_ROUTE_BGP]
						- rib_cnt[ZEBRA_ROUTE_IBGP],
					fib_cnt[ZEBRA_ROUTE_BGP]
						- fib_cnt[ZEBRA_ROUTE_IBGP]);
				vty_out(vty, "%-20s %-20d %-20d \n", "ibgp",
					rib_cnt[ZEBRA_ROUTE_IBGP],
					fib_cnt[ZEBRA_ROUTE_IBGP]);
			} else
				vty_out(vty, "%-20s %-20d %-20d \n",
					zebra_route_string(i), rib_cnt[i],
					fib_cnt[i]);
		}
	}

	vty_out(vty, "------\n");
	vty_out(vty, "%-20s %-20d %-20d \n", "Totals",
		rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL]);
	vty_out(vty, "\n");
}

/* Write static route configuration. */
int static_config(struct vty *vty, struct zebra_vrf *zvrf,
		  afi_t afi, safi_t safi, const char *cmd)
{
	char spacing[100];
	struct route_node *rn;
	struct static_route *si;
	struct route_table *stable;
	char buf[SRCDEST2STR_BUFFER];
	int write = 0;

	if ((stable = zvrf->stable[afi][safi]) == NULL)
		return write;

	sprintf(spacing, "%s%s",
		(zvrf->vrf->vrf_id == VRF_DEFAULT) ? "" : " ",
		cmd);

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn))
		for (si = rn->info; si; si = si->next) {
			vty_out(vty, "%s %s", spacing,
				srcdest_rnode2str(rn, buf, sizeof buf));

			switch (si->type) {
			case STATIC_IPV4_GATEWAY:
				vty_out(vty, " %s",
					inet_ntoa(si->addr.ipv4));
				break;
			case STATIC_IPV6_GATEWAY:
				vty_out(vty, " %s",
					inet_ntop(AF_INET6,
						  &si->addr.ipv6, buf,
						  sizeof buf));
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
					inet_ntop(AF_INET,
						  &si->addr.ipv4, buf,
						  sizeof buf),
					si->ifname);
				break;
			case STATIC_IPV6_GATEWAY_IFNAME:
				vty_out(vty, " %s %s",
					inet_ntop(AF_INET6,
						  &si->addr.ipv6, buf,
						  sizeof buf),
					si->ifname);
				break;
			}

			if (si->tag)
				vty_out(vty, " tag %" ROUTE_TAG_PRI,
					si->tag);

			if (si->distance
			    != ZEBRA_STATIC_DISTANCE_DEFAULT)
				vty_out(vty, " %d", si->distance);

			if (si->nh_vrf_id != si->vrf_id) {
				struct vrf *vrf;

				vrf = vrf_lookup_by_id(si->nh_vrf_id);
				vty_out(vty, " nexthop-vrf %s",
					(vrf) ? vrf->name : "Unknown");
			}

			/* Label information */
			if (si->snh_label.num_labels)
				vty_out(vty, " label %s",
					mpls_label2str(si->snh_label.num_labels,
						       si->snh_label.label,
						       buf, sizeof buf, 0));

			vty_out(vty, "\n");

			write = 1;
		}
	return write;
}

DEFPY(ipv6_route_blackhole,
      ipv6_route_blackhole_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <Null0|reject|blackhole>$flag                    \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Null interface\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR)
{
	return zebra_static_route(vty, AFI_IP6, SAFI_UNICAST, no, prefix_str,
				  NULL, from_str, NULL, NULL, flag,
				  tag_str, distance_str, vrf, label);
}

DEFPY(ipv6_route_blackhole_vrf,
      ipv6_route_blackhole_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <Null0|reject|blackhole>$flag                    \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Null interface\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct zebra_vrf *zvrf = vrf->info;

	return zebra_static_route_leak(vty, zvrf, zvrf,
				       AFI_IP6, SAFI_UNICAST, no, prefix_str,
				       NULL, from_str, NULL, NULL, flag,
				       tag_str, distance_str, label);
}

DEFPY(ipv6_route_address_interface,
      ipv6_route_address_interface_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          INTERFACE$ifname                                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
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
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	struct zebra_vrf *zvrf;
	struct zebra_vrf *nh_zvrf;

	zvrf = zebra_vrf_lookup_by_name(vrf);
	if (!zvrf) {
		vty_out(vty, "%% vrf %s is not defined\n",
			vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP6, SAFI_UNICAST, no, prefix_str,
				       NULL, from_str, gate_str, ifname, NULL,
				       tag_str, distance_str, label);
}

DEFPY(ipv6_route_address_interface_vrf,
      ipv6_route_address_interface_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          INTERFACE$ifname                                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
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
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct zebra_vrf *zvrf = vrf->info;
	struct zebra_vrf *nh_zvrf;

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP6, SAFI_UNICAST, no, prefix_str,
				       NULL, from_str, gate_str, ifname, NULL,
				       tag_str, distance_str, label);
}

DEFPY(ipv6_route,
      ipv6_route_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|INTERFACE$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
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
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	struct zebra_vrf *zvrf;
	struct zebra_vrf *nh_zvrf;

	zvrf = zebra_vrf_lookup_by_name(vrf);
	if (!zvrf) {
		vty_out(vty, "%% vrf %s is not defined\n",
			vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP6, SAFI_UNICAST, no, prefix_str,
				       NULL, from_str, gate_str, ifname, NULL,
				       tag_str, distance_str, label);
}

DEFPY(ipv6_route_vrf,
      ipv6_route_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|INTERFACE$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
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
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      VRF_CMD_HELP_STR)
{
	VTY_DECLVAR_CONTEXT(vrf, vrf);
	struct zebra_vrf *zvrf = vrf->info;
	struct zebra_vrf *nh_zvrf;

	if (nexthop_vrf)
		nh_zvrf = zebra_vrf_lookup_by_name(nexthop_vrf);
	else
		nh_zvrf = zvrf;

	if (!nh_zvrf) {
		vty_out(vty, "%% nexthop vrf %s is not defined\n",
			nexthop_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return zebra_static_route_leak(vty, zvrf, nh_zvrf,
				       AFI_IP6, SAFI_UNICAST, no, prefix_str,
				       NULL, from_str, gate_str, ifname, NULL,
				       tag_str, distance_str, label);
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
		VRF_GET_ID(vrf_id, argv[4]->arg);

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
			vty_show_ip_route(vty, rn, re, NULL);
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
				vty_show_ip_route(vty, rn, re, NULL);
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

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!(zvrf = vrf->info))
			continue;
		if (zvrf_id(zvrf) == VRF_DEFAULT)
			continue;

		vty_out(vty, "vrf %s ", zvrf_name(zvrf));
		if (zvrf_id(zvrf) == VRF_UNKNOWN)
			vty_out(vty, "inactive");
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
       "vni " CMD_VNI_RANGE,
       "VNI corresponding to the DEFAULT VRF\n"
       "VNI-ID\n")
{
	int ret = 0;
	char err[ERR_STR_SZ];
	struct zebra_vrf *zvrf = NULL;
	vni_t vni = strtoul(argv[1]->arg, NULL, 10);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return CMD_WARNING;

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ, 1);
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

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ, 0);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (vrf_vni_mapping,
       vrf_vni_mapping_cmd,
       "vni " CMD_VNI_RANGE,
       "VNI corresponding to tenant VRF\n"
       "VNI-ID\n")
{
	int ret = 0;

	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);
	vni_t vni = strtoul(argv[1]->arg, NULL, 10);
	char err[ERR_STR_SZ];

	assert(vrf);
	assert(zvrf);

	/* Mark as having FRR configuration */
	vrf_set_user_cfged(vrf);
	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ, 1);
	if (ret != 0) {
		vty_out(vty, "%s\n", err);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_vrf_vni_mapping,
       no_vrf_vni_mapping_cmd,
       "no vni " CMD_VNI_RANGE,
       NO_STR
       "VNI corresponding to tenant VRF\n"
       "VNI-ID")
{
	int ret = 0;
	char err[ERR_STR_SZ];
	vni_t vni = strtoul(argv[2]->arg, NULL, 10);

	ZEBRA_DECLVAR_CONTEXT(vrf, zvrf);

	assert(vrf);
	assert(zvrf);

	ret = zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ, 0);
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
	u_char uj = use_json(argc, argv);

	if (uj) {
		json = json_object_new_object();
		json_vrfs = json_object_new_array();
	}

	if (!uj)
		vty_out(vty, "%-37s %-10s %-20s %-20s %-5s %-18s\n",
			"VRF", "VNI", "VxLAN IF", "L3-SVI", "State", "Rmac");

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
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
	u_char uj = use_json(argc, argv);

	zebra_vxlan_print_evpn(vty, uj);
	return CMD_SUCCESS;
}

DEFUN (show_evpn_vni,
       show_evpn_vni_cmd,
       "show evpn vni [json]",
       SHOW_STR
       "EVPN\n"
       "VxLAN information\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	u_char uj = use_json(argc, argv);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_vnis(vty, zvrf, uj);
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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[3]->arg, NULL, 10);
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_vni(vty, zvrf, vni, uj);
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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	zvrf = vrf_info_lookup(VRF_DEFAULT);
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
	u_char uj = use_json(argc, argv);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_macs_all_vni(vty, zvrf, uj);
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
	u_char uj = use_json(argc, argv);

	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_macs_all_vni_vtep(vty, zvrf, vtep_ip, uj);

	return CMD_SUCCESS;
}


DEFUN (show_evpn_mac_vni_mac,
       show_evpn_mac_vni_mac_cmd,
       "show evpn mac vni " CMD_VNI_RANGE " mac WORD",
       SHOW_STR
       "EVPN\n"
       "MAC addresses\n"
       "VxLAN Network Identifier\n"
       "VNI number\n"
       "MAC\n"
       "MAC address (e.g., 00:e0:ec:20:12:62)\n")
{
	struct zebra_vrf *zvrf;
	vni_t vni;
	struct ethaddr mac;

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address");
		return CMD_WARNING;
	}
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_specific_mac_vni(vty, zvrf, vni, &mac);
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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_macs_vni_vtep(vty, zvrf, vni, vtep_ip, uj);
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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	zvrf = vrf_info_lookup(VRF_DEFAULT);
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
	u_char uj = use_json(argc, argv);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_neigh_all_vni(vty, zvrf, uj);
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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (str2ipaddr(argv[6]->arg, &ip) != 0) {
		if (!uj)
			vty_out(vty, "%% Malformed Neighbor address\n");
		return CMD_WARNING;
	}
	zvrf = vrf_info_lookup(VRF_DEFAULT);
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
	u_char uj = use_json(argc, argv);

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!inet_aton(argv[6]->arg, &vtep_ip)) {
		if (!uj)
			vty_out(vty, "%% Malformed VTEP IP address\n");
		return CMD_WARNING;
	}

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_vxlan_print_neigh_vni_vtep(vty, zvrf, vni, vtep_ip, uj);
	return CMD_SUCCESS;
}

/* Static ip route configuration write function. */
static int zebra_ip_config(struct vty *vty)
{
	int write = 0;

	write += zebra_import_table_config(vty);

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
	u_int32_t table_id = 0;

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

	ret = zebra_import_table(AFI_IP, table_id, distance, rmap, 1);
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

	zebrad.packets_to_process = packets;

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
	zebrad.packets_to_process = ZEBRA_ZAPI_PACKETS_TO_PROCESS;

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
       zebrad.ribq->spec.hold = timer;

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
       zebrad.ribq->spec.hold = ZEBRA_RIB_PROCESS_HOLD_TIME;

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
	u_int32_t table_id = 0;
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

	if (!is_zebra_import_table_enabled(AFI_IP, table_id))
		return CMD_SUCCESS;

	return (zebra_import_table(AFI_IP, table_id, 0, NULL, 0));
}

static int config_write_protocol(struct vty *vty)
{
	if (allow_delete)
		vty_out(vty, "allow-external-route-update\n");

	if (zebra_rnh_ip_default_route)
		vty_out(vty, "ip nht resolve-via-default\n");

	if (zebra_rnh_ipv6_default_route)
		vty_out(vty, "ipv6 nht resolve-via-default\n");

	if (zebrad.ribq->spec.hold != ZEBRA_RIB_PROCESS_HOLD_TIME)
		vty_out(vty, "zebra work-queue %u\n", zebrad.ribq->spec.hold);

	if (zebrad.packets_to_process != ZEBRA_ZAPI_PACKETS_TO_PROCESS)
		vty_out(vty,
			"zebra zapi-packets %u\n", zebrad.packets_to_process);

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

	zebra_routemap_config_write_protocol(vty);

	return 1;
}

#ifdef HAVE_NETLINK
/* Display default rtm_table for all clients. */
DEFUN (show_table,
       show_table_cmd,
       "show table",
       SHOW_STR
       "default routing table to use for all clients\n")
{
	vty_out(vty, "table %d\n", zebrad.rtm_table_default);
	return CMD_SUCCESS;
}

DEFUN (config_table,
       config_table_cmd,
       "table TABLENO",
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
	zebrad.rtm_table_default = strtol(argv[1]->arg, (char **)0, 10);
	return CMD_SUCCESS;
}

DEFUN (no_config_table,
       no_config_table_cmd,
       "no table [TABLENO]",
       NO_STR
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
	zebrad.rtm_table_default = 0;
	return CMD_SUCCESS;
}
#endif

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

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
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

/* Table configuration write function. */
static int config_write_table(struct vty *vty)
{
	if (zebrad.rtm_table_default)
		vty_out(vty, "table %d\n", zebrad.rtm_table_default);
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

/* IP node for static routes. */
static struct cmd_node ip_node = {IP_NODE, "", 1};
static struct cmd_node protocol_node = {PROTOCOL_NODE, "", 1};
/* table node for routing tables. */
static struct cmd_node table_node = {TABLE_NODE,
				     "", /* This node has no interface. */
				     1};
static struct cmd_node forwarding_node = {FORWARDING_NODE,
					  "", /* This node has no interface. */
					  1};

/* Route VTY.  */
void zebra_vty_init(void)
{
	/* Install configuration write function. */
	install_node(&table_node, config_write_table);
	install_node(&forwarding_node, config_write_forwarding);

	install_element(VIEW_NODE, &show_ip_forwarding_cmd);
	install_element(CONFIG_NODE, &ip_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ip_forwarding_cmd);
	install_element(ENABLE_NODE, &show_zebra_cmd);

#ifdef HAVE_NETLINK
	install_element(VIEW_NODE, &show_table_cmd);
	install_element(CONFIG_NODE, &config_table_cmd);
	install_element(CONFIG_NODE, &no_config_table_cmd);
#endif /* HAVE_NETLINK */

	install_element(VIEW_NODE, &show_ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ipv6_forwarding_cmd);

	/* Route-map */
	zebra_route_map_init();

	install_node(&ip_node, zebra_ip_config);
	install_node(&protocol_node, config_write_protocol);

	install_element(CONFIG_NODE, &allow_external_route_update_cmd);
	install_element(CONFIG_NODE, &no_allow_external_route_update_cmd);
	install_element(CONFIG_NODE, &ip_mroute_dist_cmd);
	install_element(CONFIG_NODE, &ip_multicast_mode_cmd);
	install_element(CONFIG_NODE, &no_ip_multicast_mode_cmd);
	install_element(CONFIG_NODE, &ip_route_blackhole_cmd);
	install_element(VRF_NODE, &ip_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_address_interface_cmd);
	install_element(VRF_NODE, &ip_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_cmd);
	install_element(VRF_NODE, &ip_route_vrf_cmd);
	install_element(CONFIG_NODE, &ip_zebra_import_table_distance_cmd);
	install_element(CONFIG_NODE, &no_ip_zebra_import_table_cmd);
	install_element(CONFIG_NODE, &zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &no_zebra_workqueue_timer_cmd);
	install_element(CONFIG_NODE, &zebra_packet_process_cmd);
	install_element(CONFIG_NODE, &no_zebra_packet_process_cmd);

	install_element(VIEW_NODE, &show_vrf_cmd);
	install_element(VIEW_NODE, &show_vrf_vni_cmd);
	install_element(VIEW_NODE, &show_route_cmd);
	install_element(VIEW_NODE, &show_route_detail_cmd);
	install_element(VIEW_NODE, &show_route_summary_cmd);
	install_element(VIEW_NODE, &show_ip_nht_cmd);
	install_element(VIEW_NODE, &show_ip_nht_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_nht_cmd);
	install_element(VIEW_NODE, &show_ipv6_nht_vrf_all_cmd);

	install_element(VIEW_NODE, &show_ip_rpf_cmd);
	install_element(VIEW_NODE, &show_ip_rpf_addr_cmd);

	install_element(CONFIG_NODE, &ipv6_route_blackhole_cmd);
	install_element(VRF_NODE, &ipv6_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_address_interface_cmd);
	install_element(VRF_NODE, &ipv6_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_cmd);
	install_element(VRF_NODE, &ipv6_route_vrf_cmd);
	install_element(CONFIG_NODE, &ip_nht_default_route_cmd);
	install_element(CONFIG_NODE, &no_ip_nht_default_route_cmd);
	install_element(CONFIG_NODE, &ipv6_nht_default_route_cmd);
	install_element(CONFIG_NODE, &no_ipv6_nht_default_route_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_cmd);

	/* Commands for VRF */
	install_element(VIEW_NODE, &show_ipv6_mroute_vrf_all_cmd);

	install_element(VIEW_NODE, &show_evpn_global_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_vni_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_mac_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_rmac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_ip_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_nh_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_all_vtep_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_mac_cmd);
	install_element(VIEW_NODE, &show_evpn_mac_vni_vtep_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_all_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_neigh_cmd);
	install_element(VIEW_NODE, &show_evpn_neigh_vni_vtep_cmd);

	install_element(CONFIG_NODE, &default_vrf_vni_mapping_cmd);
	install_element(CONFIG_NODE, &no_default_vrf_vni_mapping_cmd);
	install_element(VRF_NODE, &vrf_vni_mapping_cmd);
	install_element(VRF_NODE, &no_vrf_vni_mapping_cmd);

}
