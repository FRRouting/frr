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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
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
#include "lib/json.h"
#include "routemap.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_static.h"

extern int allow_delete;

static int do_show_ip_route(struct vty *vty, const char *vrf_name,
                            safi_t safi, u_char use_json);
static void vty_show_ip_route_detail (struct vty *vty, struct route_node *rn,
                                      int mcast);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

/* General function for static route. */
static int
zebra_static_ipv4 (struct vty *vty, safi_t safi, int add_cmd,
		   const char *dest_str, const char *mask_str,
		   const char *gate_str, const char *flag_str,
		   const char *tag_str, const char *distance_str,
		   const char *vrf_id_str)
{
  int ret;
  u_char distance;
  struct prefix p;
  struct in_addr gate;
  struct in_addr mask;
  u_char flag = 0;
  u_short tag = 0;
  struct zebra_vrf *zvrf = NULL;
  unsigned int ifindex = 0;
  const char *ifname = NULL;
  u_char type = STATIC_IPV4_BLACKHOLE;

  ret = str2prefix (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Cisco like mask notation. */
  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (ret == 0)
        {
          vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      p.prefixlen = ip_masklen (mask);
    }

  /* Apply mask for given prefix. */
  apply_mask (&p);

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* tag */
  if (tag_str)
    tag = atoi(tag_str);

  /* VRF id */
  zvrf = zebra_vrf_list_lookup_by_name (vrf_id_str);

  if (!zvrf)
    {
      vty_out (vty, "%% vrf %s is not defined%s", vrf_id_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Null0 static route.  */
  if ((gate_str != NULL) && (strncasecmp (gate_str, "Null0", strlen (gate_str)) == 0))
    {
      if (flag_str)
        {
          vty_out (vty, "%% can not have flag %s with Null0%s", flag_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
      if (add_cmd)
        static_add_route (AFI_IP, safi, type, &p, NULL, ifindex, ifname, ZEBRA_FLAG_BLACKHOLE, tag, distance, zvrf);
      else
        static_delete_route (AFI_IP, safi, type, &p, NULL, ifindex, tag, distance, zvrf);
      return CMD_SUCCESS;
    }

  /* Route flags */
  if (flag_str) {
    switch(flag_str[0]) {
      case 'r':
      case 'R': /* XXX */
        SET_FLAG (flag, ZEBRA_FLAG_REJECT);
        break;
      case 'b':
      case 'B': /* XXX */
        SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
        break;
      default:
        vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
        return CMD_WARNING;
    }
  }

  if (gate_str == NULL)
  {
    if (add_cmd)
      static_add_route (AFI_IP, safi, type, &p, NULL, ifindex, ifname, flag, tag, distance, zvrf);
    else
      static_delete_route (AFI_IP, safi, type, &p, NULL, ifindex, tag, distance, zvrf);

    return CMD_SUCCESS;
  }
  
  /* When gateway is A.B.C.D format, gate is treated as nexthop
     address other case gate is treated as interface name. */
  ret = inet_aton (gate_str, &gate);
  if (!ret)
    {
      struct interface *ifp = if_lookup_by_name_vrf (gate_str, zvrf->vrf_id);
      if (!ifp)
        {
	  vty_out (vty, "%% Unknown interface: %s%s", gate_str, VTY_NEWLINE);
          ifindex = IFINDEX_DELETED;
        }
      else
        ifindex = ifp->ifindex;
      ifname = gate_str;
      type = STATIC_IFINDEX;
    }
  else
    type = STATIC_IPV4_GATEWAY;

  if (add_cmd)
    static_add_route (AFI_IP, safi, type, &p, ifindex ? NULL : (union g_addr *)&gate, ifindex, ifname, flag, tag, distance, zvrf);
  else
    static_delete_route (AFI_IP, safi, type, &p, ifindex ? NULL : (union g_addr *)&gate, ifindex, tag, distance, zvrf);

  return CMD_SUCCESS;
}

/* Static unicast routes for multicast RPF lookup. */
DEFUN (ip_mroute_dist,
       ip_mroute_dist_cmd,
       "ip mroute A.B.C.D/M <A.B.C.D|INTERFACE> [(1-255)]",
       IP_STR
       "Configure static unicast route into MRIB for multicast RPF lookup\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Nexthop address\n"
       "Nexthop interface name\n"
       "Distance\n")
{
  char *destprefix = argv[2]->arg;
  char *nexthop = argv[3]->arg;
  char *distance = (argc == 5) ? argv[4]->arg : NULL;

  return zebra_static_ipv4 (vty, SAFI_MULTICAST, 1, destprefix, NULL, nexthop, NULL, NULL, distance, NULL);
}

DEFUN (no_ip_mroute_dist,
       no_ip_mroute_dist_cmd,
       "no ip mroute A.B.C.D/M <A.B.C.D|INTERFACE> [(1-255)]",
       IP_STR
       "Configure static unicast route into MRIB for multicast RPF lookup\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Nexthop address\n"
       "Nexthop interface name\n"
       "Distance\n")
{
  char *destprefix = argv[2]->arg;
  char *nexthop = argv[3]->arg;
  char *distance = (argc == 5) ? argv[4]->arg : NULL;

  return zebra_static_ipv4 (vty, SAFI_MULTICAST, 0, destprefix, NULL, nexthop, NULL, NULL, distance, NULL);
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

  if (strmatch (mode, "urib-only"))
    multicast_mode_ipv4_set (MCAST_URIB_ONLY);
  else if (strmatch (mode, "mrib-only"))
    multicast_mode_ipv4_set (MCAST_MRIB_ONLY);
  else if (strmatch (mode, "mrib-then-urib"))
    multicast_mode_ipv4_set (MCAST_MIX_MRIB_FIRST);
  else if (strmatch (mode, "lower-distance"))
    multicast_mode_ipv4_set (MCAST_MIX_DISTANCE);
  else if (strmatch (mode, "longer-prefix"))
    multicast_mode_ipv4_set (MCAST_MIX_PFXLEN);
  else
    {
      vty_out (vty, "Invalid mode specified%s", VTY_NEWLINE);
      return CMD_WARNING;
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
  multicast_mode_ipv4_set (MCAST_NO_CONFIG);
  return CMD_SUCCESS;
}


DEFUN (show_ip_rpf,
       show_ip_rpf_cmd,
       "show ip rpf",
       SHOW_STR
       IP_STR
       "Display RPF information for multicast source\n")
{
  return do_show_ip_route(vty, VRF_DEFAULT_NAME, SAFI_MULTICAST, 0);
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
  struct rib *rib;
  int ret;

  ret = inet_aton (argv[idx_ipv4]->arg, &addr);
  if (ret == 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rib = rib_match_ipv4_multicast (VRF_DEFAULT, addr, &rn);

  if (rib)
    vty_show_ip_route_detail (vty, rn, 1);
  else
    vty_out (vty, "%% No match for RPF lookup%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

static void
zebra_vty_ip_route_tdv_helper (int argc, struct cmd_token *argv[],
			       int idx_curr, char **tag,
			       char **distance, char **vrf)
{
  if (argc > idx_curr)
    {
      if (strmatch (argv[idx_curr]->text, "tag"))
	{
	  *tag = argv[idx_curr]->arg;
	  idx_curr++;
	}

      if (strmatch (argv[idx_curr]->text, "vrf"))
	{
	  *distance = NULL;
	  *vrf = argv[idx_curr]->arg;
	}
      else
	{
	  *distance = argv[idx_curr]->arg;
	  *vrf = argv[++idx_curr]->arg;
	}
    }

  return;
}


/* Static route configuration.  */
DEFUN (ip_route,
       ip_route_cmd,
       "ip route A.B.C.D/M <A.B.C.D|INTERFACE|null0> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 2;
  int idx_ipv4_ifname_null = 3;
  int idx_curr = 4;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL,
			    argv[idx_ipv4_ifname_null]->arg,
			    NULL,
			    tag, distance, vrf);
}

DEFUN (ip_route_flags,
       ip_route_flags_cmd,
       "ip route A.B.C.D/M <A.B.C.D|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 2;
  int idx_ipv4_ifname = 3;
  int idx_reject_blackhole = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL,
			    argv[idx_ipv4_ifname]->arg,
			    argv[idx_reject_blackhole]->arg,
                            tag, distance, vrf);
}

DEFUN (ip_route_flags2,
       ip_route_flags2_cmd,
       "ip route A.B.C.D/M <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 2;
  int idx_reject_blackhole = 3;
  int idx_curr = 4;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL,
			    NULL,
			    argv[idx_reject_blackhole]->arg,
			    tag, distance, vrf);
}

/* Mask as A.B.C.D format.  */
DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D <A.B.C.D|INTERFACE|null0> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 2;
  int idx_ipv4_2 = 3;
  int idx_ipv4_ifname_null = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    argv[idx_ipv4_ifname_null]->arg,
			    NULL, tag, distance, vrf);
}

DEFUN (ip_route_mask_flags,
       ip_route_mask_flags_cmd,
       "ip route A.B.C.D A.B.C.D <A.B.C.D|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 2;
  int idx_ipv4_2 = 3;
  int idx_ipv4_ifname = 4;
  int idx_reject_blackhole = 5;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    argv[idx_ipv4_ifname]->arg,
			    argv[idx_reject_blackhole]->arg,
			    tag, distance, vrf);
}


DEFUN (ip_route_mask_flags2,
       ip_route_mask_flags2_cmd,
       "ip route A.B.C.D A.B.C.D <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 2;
  int idx_ipv4_2 = 3;
  int idx_reject_blackhole = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    NULL,
			    argv[idx_reject_blackhole]->arg,
			    tag, distance, vrf);
}

DEFUN (no_ip_route,
       no_ip_route_cmd,
       "no ip route A.B.C.D/M <A.B.C.D|INTERFACE|null0> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 3;
  int idx_ipv4_ifname_null = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL,
			    argv[idx_ipv4_ifname_null]->arg,
			    NULL,
			    tag, distance, vrf);
}

DEFUN (no_ip_route_flags2,
       no_ip_route_flags2_cmd,
       "no ip route A.B.C.D/M <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 3;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL, NULL, NULL,
			    tag, distance, vrf);
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D <A.B.C.D|INTERFACE|null0> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 3;
  int idx_ipv4_2 = 4;
  int idx_ipv4_ifname_null = 5;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    argv[idx_ipv4_ifname_null]->arg,
			    NULL,
			    tag, distance, vrf);
}

DEFUN (no_ip_route_mask_flags2,
       no_ip_route_mask_flags2_cmd,
       "no ip route A.B.C.D A.B.C.D <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 3;
  int idx_ipv4_2 = 4;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    NULL, NULL,
			    tag, distance, vrf);
}

DEFUN (no_ip_route_flags,
       no_ip_route_flags_cmd,
       "no ip route A.B.C.D/M <A.B.C.D|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4_prefixlen = 3;
  int idx_ipv4_ifname = 4;
  int idx_reject_blackhole = 5;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4_prefixlen]->arg,
			    NULL,
			    argv[idx_ipv4_ifname]->arg,
			    argv[idx_reject_blackhole]->arg,
			    tag, distance, vrf);
}

DEFUN (no_ip_route_mask_flags,
       no_ip_route_mask_flags_cmd,
       "no ip route A.B.C.D A.B.C.D <A.B.C.D|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Tag of this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv4 = 3;
  int idx_ipv4_2 = 4;
  int idx_ipv4_ifname = 5;
  int idx_reject_blackhole = 6;
  int idx_curr = 7;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf); 

  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0,
			    argv[idx_ipv4]->arg,
			    argv[idx_ipv4_2]->arg,
			    argv[idx_ipv4_ifname]->arg,
			    argv[idx_reject_blackhole]->arg,
			    tag, distance, vrf);
}


/* New RIB.  Detailed information for IPv4 route. */
static void
vty_show_ip_route_detail (struct vty *vty, struct route_node *rn, int mcast)
{
  struct rib *rib;
  struct nexthop *nexthop, *tnexthop;
  int recursing;
  char buf[PREFIX_STRLEN];
  struct zebra_vrf *zvrf;

  RNODE_FOREACH_RIB (rn, rib)
    {
      const char *mcast_info = "";
      if (mcast)
        {
          rib_table_info_t *info = rn->table->info;
          mcast_info = (info->safi == SAFI_MULTICAST)
                       ? " using Multicast RIB"
                       : " using Unicast RIB";
        }
      
      vty_out (vty, "Routing entry for %s%s%s",
	       prefix2str (&rn->p, buf, sizeof(buf)), mcast_info,
	       VTY_NEWLINE);
      vty_out (vty, "  Known via \"%s", zebra_route_string (rib->type));
      if (rib->instance)
        vty_out (vty, "[%d]", rib->instance);
      vty_out (vty, "\"");
      vty_out (vty, ", distance %u, metric %u", rib->distance, rib->metric);
      if (rib->tag)
	vty_out (vty, ", tag %d", rib->tag);
       if (rib->mtu)
        vty_out (vty, ", mtu %u", rib->mtu);
      if (rib->vrf_id != VRF_DEFAULT)
        {
          zvrf = vrf_info_lookup(rib->vrf_id);
          vty_out (vty, ", vrf %s", zvrf->name);
        }
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	vty_out (vty, ", best");
      if (rib->refcnt)
	vty_out (vty, ", refcnt %ld", rib->refcnt);
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
       vty_out (vty, ", blackhole");
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
       vty_out (vty, ", reject");
      vty_out (vty, "%s", VTY_NEWLINE);

      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_TABLE
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

	  vty_out (vty, "  Last update ");

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  "%02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, "%dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, "%02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	  vty_out (vty, " ago%s", VTY_NEWLINE);
	}

      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
	{
          char addrstr[32];

	  vty_out (vty, "  %c%s",
		   CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ',
		   recursing ? "  " : "");

	  switch (nexthop->type)
	    {
	    case NEXTHOP_TYPE_IPV4:
	    case NEXTHOP_TYPE_IPV4_IFINDEX:
	      vty_out (vty, " %s", inet_ntoa (nexthop->gate.ipv4));
	      if (nexthop->ifindex)
		vty_out (vty, ", via %s",
                         ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	      break;
	    case NEXTHOP_TYPE_IPV6:
	    case NEXTHOP_TYPE_IPV6_IFINDEX:
	      vty_out (vty, " %s",
		       inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
	      if (nexthop->ifindex)
		vty_out (vty, ", via %s",
                         ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	      vty_out (vty, " directly connected, %s",
		       ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	      break;
	    case NEXTHOP_TYPE_BLACKHOLE:
	      vty_out (vty, " directly connected, Null0");
	      break;
	    default:
	      break;
	    }
	  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	    vty_out (vty, " inactive");

	  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ONLINK))
	    vty_out (vty, " onlink");

	  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	    vty_out (vty, " (recursive)");

	  switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
              if (nexthop->src.ipv4.s_addr)
                {
		  if (inet_ntop(AF_INET, &nexthop->src.ipv4, addrstr,
		      sizeof addrstr))
                    vty_out (vty, ", src %s", addrstr);
                }
              break;
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
              if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
                {
		  if (inet_ntop(AF_INET6, &nexthop->src.ipv6, addrstr,
		      sizeof addrstr))
                    vty_out (vty, ", src %s", addrstr);
                }
              break;
            default:
	       break;
            }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

static void
vty_show_ip_route (struct vty *vty, struct route_node *rn, struct rib *rib,
                   json_object *json)
{
  struct nexthop *nexthop, *tnexthop;
  int recursing;
  int len = 0;
  char buf[BUFSIZ];
  json_object *json_nexthops = NULL;
  json_object *json_nexthop = NULL;
  json_object *json_route = NULL;

  if (json)
    {
      json_route = json_object_new_object();
      json_nexthops = json_object_new_array();

      json_object_string_add(json_route, "prefix", prefix2str (&rn->p, buf, sizeof buf));
      json_object_string_add(json_route, "protocol", zebra_route_string(rib->type));

      if (rib->instance)
        json_object_int_add(json_route, "instance", rib->instance);

      if (rib->vrf_id)
        json_object_int_add(json_route, "vrfId", rib->vrf_id);

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        json_object_boolean_true_add(json_route, "selected");

      if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
        {
          json_object_int_add(json_route, "distance", rib->distance);
          json_object_int_add(json_route, "metric", rib->metric);
        }

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
        json_object_boolean_true_add(json_route, "blackhole");

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
        json_object_boolean_true_add(json_route, "reject");

      if (rib->type == ZEBRA_ROUTE_RIP
          || rib->type == ZEBRA_ROUTE_OSPF
          || rib->type == ZEBRA_ROUTE_ISIS
          || rib->type == ZEBRA_ROUTE_TABLE
          || rib->type == ZEBRA_ROUTE_BGP)
        {
          time_t uptime;
          struct tm *tm;

          uptime = time (NULL);
          uptime -= rib->uptime;
          tm = gmtime (&uptime);

          if (uptime < ONE_DAY_SECOND)
            sprintf(buf, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
          else if (uptime < ONE_WEEK_SECOND)
            sprintf(buf, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
          else
            sprintf(buf, "%02dw%dd%02dh", tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);

          json_object_string_add(json_route, "uptime", buf);
        }

      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        {
          json_nexthop = json_object_new_object();

          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            json_object_boolean_true_add(json_nexthop, "fib");

          switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
              json_object_string_add(json_nexthop, "ip", inet_ntoa (nexthop->gate.ipv4));
              json_object_string_add(json_nexthop, "afi", "ipv4");

              if (nexthop->ifindex)
                {
                  json_object_int_add(json_nexthop, "interfaceIndex", nexthop->ifindex);
                  json_object_string_add(json_nexthop, "interfaceName", ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
                }
              break;
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
              json_object_string_add(json_nexthop, "ip", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
              json_object_string_add(json_nexthop, "afi", "ipv6");

              if (nexthop->ifindex)
                {
                  json_object_int_add(json_nexthop, "interfaceIndex", nexthop->ifindex);
                  json_object_string_add(json_nexthop, "interfaceName", ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
                }
              break;

            case NEXTHOP_TYPE_IFINDEX:
              json_object_boolean_true_add(json_nexthop, "directlyConnected");
              json_object_int_add(json_nexthop, "interfaceIndex", nexthop->ifindex);
              json_object_string_add(json_nexthop, "interfaceName", ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
              break;
            case NEXTHOP_TYPE_BLACKHOLE:
              json_object_boolean_true_add(json_nexthop, "blackhole");
              break;
            default:
              break;
            }

          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
            json_object_boolean_true_add(json_nexthop, "active");

          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ONLINK))
            json_object_boolean_true_add(json_nexthop, "onLink");

          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            json_object_boolean_true_add(json_nexthop, "recursive");

          switch (nexthop->type)
            {
              case NEXTHOP_TYPE_IPV4:
              case NEXTHOP_TYPE_IPV4_IFINDEX:
                if (nexthop->src.ipv4.s_addr)
                  {
                    if (inet_ntop(AF_INET, &nexthop->src.ipv4, buf, sizeof buf))
                      json_object_string_add(json_nexthop, "source", buf);
                  }
                break;
              case NEXTHOP_TYPE_IPV6:
              case NEXTHOP_TYPE_IPV6_IFINDEX:
                if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
                  {
                    if (inet_ntop(AF_INET6, &nexthop->src.ipv6, buf, sizeof buf))
                      json_object_string_add(json_nexthop, "source", buf);
                  }
                break;
              default:
                break;
            }

          json_object_array_add(json_nexthops, json_nexthop);
        }

      json_object_object_add(json_route, "nexthops", json_nexthops);
      json_object_array_add(json, json_route);
      return;
    }

  /* Nexthop information. */
  for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
    {
      if (nexthop == rib->nexthop)
	{
	  /* Prefix information. */
	  len = vty_out (vty, "%c", zebra_route_char (rib->type));
          if (rib->instance)
	    len += vty_out (vty, "[%d]", rib->instance);
          len += vty_out (vty, "%c%c %s",
			  CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
			  ? '>' : ' ',
			  CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
			  ? '*' : ' ',
			  prefix2str (&rn->p, buf, sizeof buf));

	  /* Distance and metric display. */
	  if (rib->type != ZEBRA_ROUTE_CONNECT 
	      && rib->type != ZEBRA_ROUTE_KERNEL)
	    len += vty_out (vty, " [%d/%d]", rib->distance,
			    rib->metric);
	}
      else
	vty_out (vty, "  %c%*c",
		 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
		 ? '*' : ' ',
		 len - 3 + (2 * recursing), ' ');

      switch (nexthop->type)
	{
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	  vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
	  if (nexthop->ifindex)
	    vty_out (vty, ", %s",
                     ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	  break;
        case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	  vty_out (vty, " via %s",
		   inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
	  if (nexthop->ifindex)
	    vty_out (vty, ", %s",
                     ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	  break;

	case NEXTHOP_TYPE_IFINDEX:
	  vty_out (vty, " is directly connected, %s",
		   ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	  break;
	case NEXTHOP_TYPE_BLACKHOLE:
	  vty_out (vty, " is directly connected, Null0");
	  break;
	default:
	  break;
	}
      if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	vty_out (vty, " inactive");

      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ONLINK))
	vty_out (vty, " onlink");

      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	vty_out (vty, " (recursive)");

      switch (nexthop->type)
        {
          case NEXTHOP_TYPE_IPV4:
          case NEXTHOP_TYPE_IPV4_IFINDEX:
            if (nexthop->src.ipv4.s_addr)
              {
		if (inet_ntop(AF_INET, &nexthop->src.ipv4, buf, sizeof buf))
                  vty_out (vty, ", src %s", buf);
              }
            break;
          case NEXTHOP_TYPE_IPV6:
          case NEXTHOP_TYPE_IPV6_IFINDEX:
            if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
              {
		if (inet_ntop(AF_INET6, &nexthop->src.ipv6, buf, sizeof buf))
                  vty_out (vty, ", src %s", buf);
              }
            break;
          default:
	    break;
        }

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
               vty_out (vty, ", bh");
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
               vty_out (vty, ", rej");

      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_TABLE
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  ", %02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, ", %dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, ", %02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

DEFUN (show_ip_route,
       show_ip_route_cmd,
       "show ip route [json]",
       SHOW_STR
       IP_STR
       "IP routing table\n")
{
  return do_show_ip_route (vty, VRF_DEFAULT_NAME, SAFI_UNICAST, use_json(argc, argv));
}

static int
do_show_ip_route (struct vty *vty, const char *vrf_name, safi_t safi,
                  u_char use_json)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  struct zebra_vrf *zvrf = NULL;
  char buf[BUFSIZ];
  json_object *json = NULL;
  json_object *json_prefix = NULL;

  if (!(zvrf = zebra_vrf_list_lookup_by_name (vrf_name)))
    {
      if (use_json)
        vty_out (vty, "{}%s", VTY_NEWLINE);
      else
        vty_out (vty, "vrf %s not defined%s", vrf_name, VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (zvrf->vrf_id == VRF_UNKNOWN)
    {
      if (use_json)
        vty_out (vty, "{}%s", VTY_NEWLINE);
      else
        vty_out (vty, "vrf %s inactive%s", vrf_name, VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  table = zebra_vrf_table (AFI_IP, safi, zvrf->vrf_id);
  if (! table)
    {
      if (use_json)
        vty_out (vty, "{}%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (use_json)
    {
      json = json_object_new_object();

      /* Show all IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        {
          RNODE_FOREACH_RIB (rn, rib)
            {
              if (!json_prefix)
                json_prefix = json_object_new_array();
              vty_show_ip_route (vty, rn, rib, json_prefix);
            }

          if (json_prefix)
            {
              prefix2str (&rn->p, buf, sizeof buf);
              json_object_object_add(json, buf, json_prefix);
              json_prefix = NULL;
            }
        }

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      /* Show all IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        {
          RNODE_FOREACH_RIB (rn, rib)
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V4_HEADER);
                  first = 0;
                }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf,
       show_ip_route_vrf_cmd,
       "show ip route vrf NAME [json]",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR)
{
  int idx_json = 5;
  u_char uj = use_json(argc, argv);

  if (argc == 1 && uj)
    return do_show_ip_route (vty, NULL, SAFI_UNICAST, uj);
  else
    return do_show_ip_route (vty, argv[idx_json]->arg, SAFI_UNICAST, uj);
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
    VRF_GET_ID (vrf_id, argv[idx_vrf]->arg);

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
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      {
        vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
        zebra_print_rnh_table(zvrf->vrf_id, AF_INET, vty, RNH_NEXTHOP_TYPE);
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
    VRF_GET_ID (vrf_id, argv[idx_vrf]->arg);

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
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      {
        vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
        zebra_print_rnh_table(zvrf->vrf_id, AF_INET6, vty, RNH_NEXTHOP_TYPE);
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
  zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
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
  zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
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
  zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);
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
  zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_tag,
       show_ip_route_tag_cmd,
       "show ip route [vrf NAME] tag (1-65535)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  u_short tag = 0;
  vrf_id_t vrf_id = VRF_DEFAULT;
 
  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      tag = atoi(argv[6]->arg);
    }
  else
    {
      tag = atoi(argv[4]->arg);
    }

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show all IPv4 routes with matching tag value. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {
        if (rib->tag != tag)
          continue;

        if (first)
          {
            vty_out (vty, SHOW_ROUTE_V4_HEADER);
            first = 0;
          }
        vty_show_ip_route (vty, rn, rib, NULL);
      }
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix_longer,
       show_ip_route_prefix_longer_cmd,
       "show ip route [vrf NAME] A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  int ret;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix (argv[5]->arg, &p);
    }
  else
    {
      ret = str2prefix (argv[3]->arg, &p);
    }

  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv4 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      if (prefix_match (&p, &rn->p))
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V4_HEADER);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib, NULL);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_supernets,
       show_ip_route_supernets_cmd,
       "show ip route [vrf NAME] supernets-only",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "Show supernet entries only\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  u_int32_t addr;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv4 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {
	addr = ntohl (rn->p.u.prefix4.s_addr);

	if ((IN_CLASSC (addr) && rn->p.prefixlen < 24)
	   || (IN_CLASSB (addr) && rn->p.prefixlen < 16)
	   || (IN_CLASSA (addr) && rn->p.prefixlen < 8))
	  {
	    if (first)
	      {
		vty_out (vty, SHOW_ROUTE_V4_HEADER);
		first = 0;
	      }
	    vty_show_ip_route (vty, rn, rib, NULL);
	  }
      }
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_protocol,
       show_ip_route_protocol_cmd,
       "show ip route [vrf NAME] <kernel|connected|static|rip|ospf|isis|bgp|pim|table>",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       QUAGGA_IP_REDIST_HELP_STR_ZEBRA)
{
  int type;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      type = proto_redistnum (AFI_IP, argv[5]->arg);
      VRF_GET_ID (vrf_id, argv[4]->arg);
    }
  else
    {
      type = proto_redistnum (AFI_IP, argv[3]->arg);
    }

  if (type < 0)
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv4 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      if (rib->type == type)
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V4_HEADER);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib, NULL);
	}
  return CMD_SUCCESS;
}


DEFUN (show_ip_route_ospf_instance,
       show_ip_route_ospf_instance_cmd,
       "show ip route ospf (1-65535)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Instance ID\n")
{
  int idx_number = 4;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[idx_number]->arg);

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv4 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      if (rib->type == ZEBRA_ROUTE_OSPF && rib->instance == instance)
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V4_HEADER);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib, NULL);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_addr,
       show_ip_route_addr_cmd,
       "show ip route [vrf NAME] A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "Network in the IP routing table to display\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix_ipv4 (argv[5]->arg, &p);
    }
  else
    {
      ret = str2prefix_ipv4 (argv[3]->arg, &p);
    }

  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  rn = route_node_match (table, (struct prefix *) &p);
  if (! rn)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn, 0);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix,
       show_ip_route_prefix_cmd,
       "show ip route [vrf NAME] A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix_ipv4 (argv[5]->arg, &p);
    }
  else
    {
      ret = str2prefix_ipv4 (argv[3]->arg, &p);
    }

  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  rn = route_node_match (table, (struct prefix *) &p);
  if (! rn || rn->p.prefixlen != p.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn, 0);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}


static void
vty_show_ip_route_summary (struct vty *vty, struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
  u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
  u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
  u_int32_t i;
  u_int32_t is_ibgp;

  memset (&rib_cnt, 0, sizeof(rib_cnt));
  memset (&fib_cnt, 0, sizeof(fib_cnt));
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {
        is_ibgp = (rib->type == ZEBRA_ROUTE_BGP &&
                   CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP));

        rib_cnt[ZEBRA_ROUTE_TOTAL]++;
        if (is_ibgp)
          rib_cnt[ZEBRA_ROUTE_IBGP]++;
        else
          rib_cnt[rib->type]++;

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
          {
            fib_cnt[ZEBRA_ROUTE_TOTAL]++;

            if (is_ibgp)
              fib_cnt[ZEBRA_ROUTE_IBGP]++;
            else
              fib_cnt[rib->type]++;
          }
      }

  vty_out (vty, "%-20s %-20s %s  (vrf %s)%s",
           "Route Source", "Routes", "FIB",
           ((rib_table_info_t *)table->info)->zvrf->name,
           VTY_NEWLINE);

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if ((rib_cnt[i] > 0) ||
	  (i == ZEBRA_ROUTE_BGP && rib_cnt[ZEBRA_ROUTE_IBGP] > 0))
        {
          if (i == ZEBRA_ROUTE_BGP)
            {
              vty_out (vty, "%-20s %-20d %-20d %s", "ebgp",
                       rib_cnt[ZEBRA_ROUTE_BGP], fib_cnt[ZEBRA_ROUTE_BGP],
                       VTY_NEWLINE);
              vty_out (vty, "%-20s %-20d %-20d %s", "ibgp",
                       rib_cnt[ZEBRA_ROUTE_IBGP], fib_cnt[ZEBRA_ROUTE_IBGP],
                       VTY_NEWLINE);
            }
          else
            vty_out (vty, "%-20s %-20d %-20d %s", zebra_route_string(i),
                     rib_cnt[i], fib_cnt[i], VTY_NEWLINE);
        }
    }

  vty_out (vty, "------%s", VTY_NEWLINE);
  vty_out (vty, "%-20s %-20d %-20d %s", "Totals", rib_cnt[ZEBRA_ROUTE_TOTAL],
           fib_cnt[ZEBRA_ROUTE_TOTAL], VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);
}

/*
 * Implementation of the ip route summary prefix command.
 *
 * This command prints the primary prefixes that have been installed by various
 * protocols on the box.
 *
 */
static void
vty_show_ip_route_summary_prefix (struct vty *vty, struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
  u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
  u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
  u_int32_t i;
  int       cnt;

  memset (&rib_cnt, 0, sizeof(rib_cnt));
  memset (&fib_cnt, 0, sizeof(fib_cnt));
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {

       /*
        * In case of ECMP, count only once.
        */
       cnt = 0;
       for (nexthop = rib->nexthop; (!cnt && nexthop); nexthop = nexthop->next)
         {
          cnt++;
          rib_cnt[ZEBRA_ROUTE_TOTAL]++;
          rib_cnt[rib->type]++;
          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
	        {
	         fib_cnt[ZEBRA_ROUTE_TOTAL]++;
             fib_cnt[rib->type]++;
            }
	      if (rib->type == ZEBRA_ROUTE_BGP &&
	          CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
            {
	         rib_cnt[ZEBRA_ROUTE_IBGP]++;
		     if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
		        fib_cnt[ZEBRA_ROUTE_IBGP]++;
            }
	     }
      }

  vty_out (vty, "%-20s %-20s %s  (vrf %s)%s",
           "Route Source", "Prefix Routes", "FIB",
           ((rib_table_info_t *)table->info)->zvrf->name,
           VTY_NEWLINE);

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if (rib_cnt[i] > 0)
	{
	  if (i == ZEBRA_ROUTE_BGP)
	    {
	      vty_out (vty, "%-20s %-20d %-20d %s", "ebgp",
		       rib_cnt[ZEBRA_ROUTE_BGP] - rib_cnt[ZEBRA_ROUTE_IBGP],
		       fib_cnt[ZEBRA_ROUTE_BGP] - fib_cnt[ZEBRA_ROUTE_IBGP],
		       VTY_NEWLINE);
	      vty_out (vty, "%-20s %-20d %-20d %s", "ibgp",
		       rib_cnt[ZEBRA_ROUTE_IBGP], fib_cnt[ZEBRA_ROUTE_IBGP],
		       VTY_NEWLINE);
	    }
	  else
	    vty_out (vty, "%-20s %-20d %-20d %s", zebra_route_string(i),
		     rib_cnt[i], fib_cnt[i], VTY_NEWLINE);
	}
    }

  vty_out (vty, "------%s", VTY_NEWLINE);
  vty_out (vty, "%-20s %-20d %-20d %s", "Totals", rib_cnt[ZEBRA_ROUTE_TOTAL],
	   fib_cnt[ZEBRA_ROUTE_TOTAL], VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* Show route summary.  */
DEFUN (show_ip_route_summary,
       show_ip_route_summary_cmd,
       "show ip route [vrf NAME] summary",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "Summary of all routes\n")
{
  struct route_table *table;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  vty_show_ip_route_summary (vty, table);

  return CMD_SUCCESS;
}


/* Show route summary prefix.  */
DEFUN (show_ip_route_summary_prefix,
       show_ip_route_summary_prefix_cmd,
       "show ip route [vrf NAME] summary prefix",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       "Summary of all routes\n"
       "Prefix routes\n")
{
  struct route_table *table;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  vty_show_ip_route_summary_prefix (vty, table);

  return CMD_SUCCESS;
}


DEFUN (show_ip_route_vrf_all,
       show_ip_route_vrf_all_cmd,
       "show ip route vrf all",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show all IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
            if (first)
              {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
              }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
            vty_show_ip_route (vty, rn, rib, NULL);
          }
      vrf_header  = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_tag,
       show_ip_route_vrf_all_tag_cmd,
       "show ip route vrf all tag (1-65535)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n")
{
  int idx_number = 6;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;
  u_short tag = 0;

  if (argv[idx_number]->arg)
    tag = atoi(argv[idx_number]->arg);

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show all IPv4 routes with matching tag value. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
            if (rib->tag != tag)
              continue;

            if (first)
              {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
              }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
            vty_show_ip_route (vty, rn, rib, NULL);
          }
      vrf_header = 1;
    }
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_prefix_longer,
       show_ip_route_vrf_all_prefix_longer_cmd,
       "show ip route vrf all A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  int idx_ipv4_prefixlen = 5;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int ret;
  int first = 1;
  int vrf_header = 1;

  ret = str2prefix (argv[idx_ipv4_prefixlen]->arg, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show matched type IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          if (prefix_match (&p, &rn->p))
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V4_HEADER);
                  first = 0;
                }

              if (vrf_header)
                {
                  vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                  vrf_header = 0;
                }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_supernets,
       show_ip_route_vrf_all_supernets_cmd,
       "show ip route vrf all supernets-only",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Show supernet entries only\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  u_int32_t addr;
  int first = 1;
  int vrf_header = 1;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show matched type IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
            addr = ntohl (rn->p.u.prefix4.s_addr);

            if ((IN_CLASSC (addr) && rn->p.prefixlen < 24)
               || (IN_CLASSB (addr) && rn->p.prefixlen < 16)
               || (IN_CLASSA (addr) && rn->p.prefixlen < 8))
              {
                if (first)
                  {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                  }

                if (vrf_header)
                  {
                    vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                    vrf_header = 0;
                  }
                vty_show_ip_route (vty, rn, rib, NULL);
              }
          }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_protocol,
       show_ip_route_vrf_all_protocol_cmd,
       "show ip route vrf all <kernel|connected|static|rip|ospf|isis|bgp|pim|table>",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       QUAGGA_IP_REDIST_HELP_STR_ZEBRA"\n")
{
  int type;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;

  type = proto_redistnum (AFI_IP, argv[6]->arg);
  if (type < 0)
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show matched type IPv4 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          if (rib->type == type)
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V4_HEADER);
                  first = 0;
                }

              if (vrf_header)
                {
                  vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                  vrf_header = 0;
                }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_addr,
       show_ip_route_vrf_all_addr_cmd,
       "show ip route vrf all A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Network in the IP routing table to display\n")
{
  int idx_ipv4 = 5;
  int ret;
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  ret = str2prefix_ipv4 (argv[idx_ipv4]->arg, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      rn = route_node_match (table, (struct prefix *) &p);
      if (! rn)
        continue;

      vty_show_ip_route_detail (vty, rn, 0);

      route_unlock_node (rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_prefix,
       show_ip_route_vrf_all_prefix_cmd,
       "show ip route vrf all A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int idx_ipv4_prefixlen = 5;
  int ret;
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  ret = str2prefix_ipv4 (argv[idx_ipv4_prefixlen]->arg, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      rn = route_node_match (table, (struct prefix *) &p);
      if (! rn)
        continue;
      if (rn->p.prefixlen != p.prefixlen)
        {
          route_unlock_node (rn);
          continue;
        }

      vty_show_ip_route_detail (vty, rn, 0);

      route_unlock_node (rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_summary,
       show_ip_route_vrf_all_summary_cmd,
       "show ip route vrf all summary ",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Summary of all routes\n")
{
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      vty_show_ip_route_summary (vty, zvrf->table[AFI_IP][SAFI_UNICAST]);

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_vrf_all_summary_prefix,
       show_ip_route_vrf_all_summary_prefix_cmd,
       "show ip route vrf all summary prefix",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Summary of all routes\n"
       "Prefix routes\n")
{
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      vty_show_ip_route_summary_prefix (vty, zvrf->table[AFI_IP][SAFI_UNICAST]);

  return CMD_SUCCESS;
}

/* Write IPv4 static route configuration. */
static int
static_config_ipv4 (struct vty *vty, safi_t safi, const char *cmd)
{
  struct route_node *rn;
  struct static_route *si;
  struct route_table *stable;
  struct zebra_vrf *zvrf;
  char buf[PREFIX_STRLEN];
  int write =0;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (zvrf_list, node, zvrf))
    {
      if ((stable = zvrf->stable[AFI_IP][safi]) == NULL)
        continue;

      for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
          {
            vty_out (vty, "%s %s", cmd, prefix2str (&rn->p, buf, sizeof buf));

            switch (si->type)
              {
              case STATIC_IPV4_GATEWAY:
                vty_out (vty, " %s", inet_ntoa (si->addr.ipv4));
                break;
              case STATIC_IFINDEX:
                vty_out (vty, " %s", si->ifname);
                break;
              case STATIC_IPV4_BLACKHOLE:
                vty_out (vty, " Null0");
                break;
              }

            /* flags are incompatible with STATIC_IPV4_BLACKHOLE */
            if (si->type != STATIC_IPV4_BLACKHOLE)
              {
                if (CHECK_FLAG(si->flags, ZEBRA_FLAG_REJECT))
                  vty_out (vty, " %s", "reject");

                if (CHECK_FLAG(si->flags, ZEBRA_FLAG_BLACKHOLE))
                  vty_out (vty, " %s", "blackhole");
              }

            if (si->tag)
              vty_out (vty, " tag %d", si->tag);

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
              vty_out (vty, " %d", si->distance);

            if (si->vrf_id != VRF_DEFAULT)
                vty_out (vty, " vrf %s", zvrf ? zvrf->name : "");

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
          }
    }
  return write;
}

/* General fucntion for IPv6 static route. */
static int
static_ipv6_func (struct vty *vty, int add_cmd, const char *dest_str,
		  const char *gate_str, const char *ifname,
		  const char *flag_str, const char *tag_str,
                  const char *distance_str, const char *vrf_id_str)
{
  int ret;
  u_char distance;
  struct prefix p;
  struct in6_addr *gate = NULL;
  struct in6_addr gate_addr;
  u_char type = 0;
  u_char flag = 0;
  u_short tag = 0;
  unsigned int ifindex = 0;
  struct interface *ifp = NULL;
  struct zebra_vrf *zvrf;
  
  ret = str2prefix (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Apply mask for given prefix. */
  apply_mask (&p);

  /* Route flags */
  if (flag_str) {
    switch(flag_str[0]) {
      case 'r':
      case 'R': /* XXX */
        SET_FLAG (flag, ZEBRA_FLAG_REJECT);
        break;
      case 'b':
      case 'B': /* XXX */
        SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
        break;
      default:
        vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
        return CMD_WARNING;
    }
  }

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* tag */
  if (tag_str)
    tag = atoi(tag_str);

  /* When gateway is valid IPv6 addrees, then gate is treated as
     nexthop address other case gate is treated as interface name. */
  ret = inet_pton (AF_INET6, gate_str, &gate_addr);

  /* VRF id */
  zvrf = zebra_vrf_list_lookup_by_name (vrf_id_str);

  if (!zvrf)
    {
      vty_out (vty, "%% vrf %s is not defined%s", vrf_id_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ifname)
    {
      /* When ifname is specified.  It must be come with gateway
         address. */
      if (ret != 1)
	{
	  vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      type = STATIC_IPV6_GATEWAY_IFINDEX;
      gate = &gate_addr;
      ifp = if_lookup_by_name_vrf (ifname, zvrf->vrf_id);
      if (!ifp)
	{
	  vty_out (vty, "%% Malformed Interface name %s%s", ifname, VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ifindex = ifp->ifindex;
    }
  else
    {
      if (ret == 1)
	{
	  type = STATIC_IPV6_GATEWAY;
	  gate = &gate_addr;
	}
      else
	{
	  type = STATIC_IFINDEX;
	  ifp = if_lookup_by_name_vrf (gate_str, zvrf->vrf_id);
	  if (!ifp)
	    {
	      vty_out (vty, "%% Malformed Interface name %s%s", gate_str, VTY_NEWLINE);
              ifindex = IFINDEX_DELETED;
	    }
          else
	    ifindex = ifp->ifindex;
	  ifname = gate_str;
	}
    }

  if (add_cmd)
    static_add_route (AFI_IP6, SAFI_UNICAST, type, &p, (union g_addr *)gate, ifindex, ifname, flag, tag, distance, zvrf);
  else
    static_delete_route (AFI_IP6, SAFI_UNICAST, type, &p, (union g_addr *)gate, ifindex, tag, distance, zvrf);

  return CMD_SUCCESS;
}

DEFUN (ipv6_route,
       ipv6_route_cmd,
       "ipv6 route X:X::X:X/M <X:X::X:X|INTERFACE> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 2;
  int idx_ipv6_ifname = 3;
  int idx_curr = 4;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 1,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6_ifname]->arg,
			   NULL, NULL,
			   tag, distance, vrf);
}


DEFUN (ipv6_route_flags,
       ipv6_route_flags_cmd,
       "ipv6 route X:X::X:X/M <X:X::X:X|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 2;
  int idx_ipv6_ifname = 3;
  int idx_reject_blackhole = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 1,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6_ifname]->arg,
			   NULL,
			   argv[idx_reject_blackhole]->arg,
			   tag, distance, vrf);
}

DEFUN (ipv6_route_ifname,
       ipv6_route_ifname_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 2;
  int idx_ipv6 = 3;
  int idx_interface = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 1,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6]->arg,
			   argv[idx_interface]->arg,
			   NULL,
			   tag, distance, vrf);
}

DEFUN (ipv6_route_ifname_flags,
       ipv6_route_ifname_flags_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 2;
  int idx_ipv6 = 3;
  int idx_interface = 4;
  int idx_reject_blackhole = 5;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 1,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6]->arg,
			   argv[idx_interface]->arg,
			   argv[idx_reject_blackhole]->arg,
			   tag, distance, vrf);
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route X:X::X:X/M <X:X::X:X|INTERFACE> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 3;
  int idx_ipv6_ifname = 4;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 0,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6_ifname]->arg,
			   NULL, NULL,
			   tag, distance, vrf);
}

DEFUN (no_ipv6_route_flags,
       no_ipv6_route_flags_cmd,
       "no ipv6 route X:X::X:X/M <X:X::X:X|INTERFACE> <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 3;
  int idx_ipv6_ifname = 4;
  int idx_reject_blackhole = 5;
  int idx_curr = 5;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 0,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6_ifname]->arg,
			   NULL,
			   argv[idx_reject_blackhole]->arg,
			   tag, distance, vrf);
}

DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 3;
  int idx_ipv6 = 4;
  int idx_interface = 5;
  int idx_curr = 6;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 0,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6]->arg,
			   argv[idx_interface]->arg,
			   NULL,
			   tag, distance, vrf);
}

DEFUN (no_ipv6_route_ifname_flags,
       no_ipv6_route_ifname_flags_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <reject|blackhole> [tag (1-65535)] [(1-255)] [vrf NAME]",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       VRF_CMD_HELP_STR)
{
  int idx_ipv6_prefixlen = 3;
  int idx_ipv6 = 4;
  int idx_interface = 5;
  int idx_reject_blackhole = 6;
  int idx_curr = 7;
  char *tag, *distance, *vrf;

  tag = distance = vrf = NULL;
  zebra_vty_ip_route_tdv_helper (argc, argv, idx_curr, &tag, &distance, &vrf);

  return static_ipv6_func (vty, 0,
			   argv[idx_ipv6_prefixlen]->arg,
			   argv[idx_ipv6]->arg,
			   argv[idx_interface]->arg,
			   argv[idx_reject_blackhole]->arg,
			   tag, distance, vrf);
}

DEFUN (show_ipv6_route,
       show_ipv6_route_cmd,
       "show ipv6 route [vrf NAME] [json]",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "Output JSON\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;
  struct zebra_vrf *zvrf = NULL;
  char buf[BUFSIZ];
  json_object *json = NULL;
  json_object *json_prefix = NULL;

  int vrf = (argc > 3 && strmatch (argv[3]->text, "vrf"));
  int uj = vrf ? argc == 6 : argc == 4;
  char *vrfname = vrf ? argv[4]->arg : NULL;

  if (vrf)
  {
    if (!(zvrf = zebra_vrf_list_lookup_by_name (vrfname)))
       {
         if (uj)
           vty_out (vty, "{}%s", VTY_NEWLINE);
         else
           vty_out (vty, "vrf %s not defined%s", vrfname, VTY_NEWLINE);
         return CMD_SUCCESS;
       }

     if (zvrf->vrf_id == VRF_UNKNOWN)
       {
         if (uj)
           vty_out (vty, "{}%s", VTY_NEWLINE);
         else
           vty_out (vty, "vrf %s inactive%s", vrfname, VTY_NEWLINE);
         return CMD_SUCCESS;
       }
     else
       vrf_id = zvrf->vrf_id;
  }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (!table)
    {
      if (uj)
        vty_out (vty, "{}%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (uj)
    {
      json = json_object_new_object();

      /* Show all IPv6 route. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        {
          RNODE_FOREACH_RIB (rn, rib)
            {
              if (!json_prefix)
                json_prefix = json_object_new_array();
              vty_show_ip_route (vty, rn, rib, json_prefix);
            }

          if (json_prefix)
            {
              prefix2str (&rn->p, buf, sizeof buf);
              json_object_object_add(json, buf, json_prefix);
              json_prefix = NULL;
            }
        }

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      /* Show all IPv6 route. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        {
          RNODE_FOREACH_RIB (rn, rib)
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V6_HEADER);
                  first = 0;
                }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_tag,
       show_ipv6_route_tag_cmd,
       "show ipv6 route [vrf NAME] tag (1-65535)",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  u_short tag = 0;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      tag = atoi(argv[6]->arg);
    }
  else
    {
      tag = atoi(argv[4]->arg);
    }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show all IPv6 routes with matching tag value. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {
        if (rib->tag != tag)
          continue;

	if (first)
	  {
	    vty_out (vty, SHOW_ROUTE_V6_HEADER);
	    first = 0;
	  }
	vty_show_ip_route (vty, rn, rib, NULL);
      }
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix_longer,
       show_ipv6_route_prefix_longer_cmd,
       "show ipv6 route [vrf NAME] X:X::X:X/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  int ret;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix (argv[5]->arg, &p);
    }
  else
    {
      ret = str2prefix (argv[3]->arg, &p);
    }

  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv6 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      if (prefix_match (&p, &rn->p))
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V6_HEADER);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib, NULL);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_protocol,
       show_ipv6_route_protocol_cmd,
       "show ipv6 route [vrf NAME] <kernel|connected|static|ripng|ospf6|isis|bgp|table>",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_CMD_HELP_STR
       QUAGGA_IP6_REDIST_HELP_STR_ZEBRA)
{
  int type;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  char *vrfname = (argc == 6) ? argv[4]->arg : NULL;
  char *proto = argv[argc - 1]->text;

  if (vrfname)
    {
      VRF_GET_ID (vrf_id, vrfname);
      type = proto_redistnum (AFI_IP6, proto);
    }
  else
    type = proto_redistnum (AFI_IP6, proto);

  if (type < 0)
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show matched type IPv6 routes. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      if (rib->type == type)
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V6_HEADER);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib, NULL);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_addr,
       show_ipv6_route_addr_cmd,
       "show ipv6 route [vrf NAME] X:X::X:X",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "IPv6 Address\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_table *table;
  struct route_node *rn;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix_ipv6 (argv[5]->arg, &p);
    }
  else
    {
      ret = str2prefix_ipv6 (argv[3]->arg, &p);
    }

  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  rn = route_node_match (table, (struct prefix *) &p);
  if (! rn)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn, 0);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix,
       show_ipv6_route_prefix_cmd,
       "show ipv6 route [vrf NAME] X:X::X:X/M",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "IPv6 prefix\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_table *table;
  struct route_node *rn;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    {
      VRF_GET_ID (vrf_id, argv[4]->arg);
      ret = str2prefix_ipv6 (argv[5]->arg, &p);
    }
  else
    ret = str2prefix_ipv6 (argv[3]->arg, &p);

  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  rn = route_node_match (table, (struct prefix *) &p);
  if (! rn || rn->p.prefixlen != p.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn, 0);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}


/* Show route summary.  */
DEFUN (show_ipv6_route_summary,
       show_ipv6_route_summary_cmd,
       "show ipv6 route [vrf NAME] summary",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "Summary of all IPv6 routes\n")
{
  struct route_table *table;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  vty_show_ip_route_summary (vty, table);

  return CMD_SUCCESS;
}


/* Show ipv6 route summary prefix.  */
DEFUN (show_ipv6_route_summary_prefix,
       show_ipv6_route_summary_prefix_cmd,
       "show ipv6 route [vrf NAME] summary prefix",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_CMD_HELP_STR
       "Summary of all IPv6 routes\n"
       "Prefix routes\n")
{
  struct route_table *table;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  vty_show_ip_route_summary_prefix (vty, table);

  return CMD_SUCCESS;
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
  struct rib *rib;
  int first = 1;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (strmatch(argv[3]->text, "vrf"))
    VRF_GET_ID (vrf_id, argv[4]->arg);

  table = zebra_vrf_table (AFI_IP6, SAFI_MULTICAST, vrf_id);
  if (! table)
    return CMD_SUCCESS;

  /* Show all IPv6 route. */
  for (rn = route_top (table); rn; rn = route_next (rn))
    RNODE_FOREACH_RIB (rn, rib)
      {
       if (first)
         {
	   vty_out (vty, SHOW_ROUTE_V6_HEADER);
           first = 0;
         }
       vty_show_ip_route (vty, rn, rib, NULL);
      }
  return CMD_SUCCESS;
}


DEFUN (show_ipv6_route_vrf_all,
       show_ipv6_route_vrf_all_cmd,
       "show ipv6 route vrf all",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      /* Show all IPv6 route. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
            if (first)
              {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
              }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
            vty_show_ip_route (vty, rn, rib, NULL);
          }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_tag,
       show_ipv6_route_vrf_all_tag_cmd,
       "show ipv6 route vrf all tag (1-65535)",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Show only routes with tag\n"
       "Tag value\n")
{
  int idx_number = 6;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;
  u_short tag = 0;

  if (argv[idx_number]->arg)
    tag = atoi(argv[idx_number]->arg);

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP][SAFI_UNICAST]) == NULL)
        continue;

      /* Show all IPv6 routes with matching tag value. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
            if (rib->tag != tag)
              continue;

            if (first)
              {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
              }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
            vty_show_ip_route (vty, rn, rib, NULL);
          }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_prefix_longer,
       show_ipv6_route_vrf_all_prefix_longer_cmd,
       "show ipv6 route vrf all X:X::X:X/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  int idx_ipv6_prefixlen = 5;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int ret;
  int first = 1;
  int vrf_header = 1;

  ret = str2prefix (argv[idx_ipv6_prefixlen]->arg, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      /* Show matched type IPv6 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          if (prefix_match (&p, &rn->p))
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V6_HEADER);
                  first = 0;
                }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_protocol,
       show_ipv6_route_vrf_all_protocol_cmd,
       "show ipv6 route vrf all <kernel|connected|static|ripng|ospf6|isis|bgp|table>",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       VRF_ALL_CMD_HELP_STR
       QUAGGA_IP6_REDIST_HELP_STR_ZEBRA)
{
  int type;
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;
  int vrf_header = 1;

  type = proto_redistnum (AFI_IP6, argv[4]->arg);
  if (type < 0)
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      /* Show matched type IPv6 routes. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          if (rib->type == type)
            {
              if (first)
                {
                  vty_out (vty, SHOW_ROUTE_V6_HEADER);
                  first = 0;
                }

            if (vrf_header)
              {
                vty_out (vty, "%sVRF %s:%s", VTY_NEWLINE, zvrf->name, VTY_NEWLINE);
                vrf_header = 0;
              }
              vty_show_ip_route (vty, rn, rib, NULL);
            }
      vrf_header = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_addr,
       show_ipv6_route_vrf_all_addr_cmd,
       "show ipv6 route vrf all X:X::X:X",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "IPv6 Address\n")
{
  int idx_ipv6 = 5;
  int ret;
  struct prefix_ipv6 p;
  struct route_table *table;
  struct route_node *rn;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  ret = str2prefix_ipv6 (argv[idx_ipv6]->arg, &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      rn = route_node_match (table, (struct prefix *) &p);
      if (! rn)
        continue;

      vty_show_ip_route_detail (vty, rn, 0);

      route_unlock_node (rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_prefix,
       show_ipv6_route_vrf_all_prefix_cmd,
       "show ipv6 route vrf all X:X::X:X/M",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "IPv6 prefix\n")
{
  int idx_ipv6_prefixlen = 5;
  int ret;
  struct prefix_ipv6 p;
  struct route_table *table;
  struct route_node *rn;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  ret = str2prefix_ipv6 (argv[idx_ipv6_prefixlen]->arg, &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      rn = route_node_match (table, (struct prefix *) &p);
      if (! rn)
        continue;
      if (rn->p.prefixlen != p.prefixlen)
        {
          route_unlock_node (rn);
          continue;
        }

      vty_show_ip_route_detail (vty, rn, 0);

      route_unlock_node (rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_summary,
       show_ipv6_route_vrf_all_summary_cmd,
       "show ipv6 route vrf all summary",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Summary of all IPv6 routes\n")
{
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      vty_show_ip_route_summary (vty, zvrf->table[AFI_IP6][SAFI_UNICAST]);

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
  struct rib *rib;
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;
  int first = 1;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (table = zvrf->table[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      /* Show all IPv6 route. */
      for (rn = route_top (table); rn; rn = route_next (rn))
        RNODE_FOREACH_RIB (rn, rib)
          {
           if (first)
             {
               vty_out (vty, SHOW_ROUTE_V6_HEADER);
               first = 0;
             }
           vty_show_ip_route (vty, rn, rib, NULL);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_vrf_all_summary_prefix,
       show_ipv6_route_vrf_all_summary_prefix_cmd,
       "show ipv6 route vrf all summary prefix",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       VRF_ALL_CMD_HELP_STR
       "Summary of all IPv6 routes\n"
       "Prefix routes\n")
{
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      vty_show_ip_route_summary_prefix (vty, zvrf->table[AFI_IP6][SAFI_UNICAST]);

  return CMD_SUCCESS;
}

/* Write IPv6 static route configuration. */
static int
static_config_ipv6 (struct vty *vty)
{
  struct route_node *rn;
  struct static_route *si;
  int write = 0;
  char buf[PREFIX_STRLEN];
  struct route_table *stable;
  struct zebra_vrf *zvrf;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (zvrf_list, node, zvrf))
    {
      if ((stable = zvrf->stable[AFI_IP6][SAFI_UNICAST]) == NULL)
        continue;

      for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
          {
            vty_out (vty, "ipv6 route %s", prefix2str (&rn->p, buf, sizeof buf));

	    switch (si->type)
	      {
	      case STATIC_IPV6_GATEWAY:
		vty_out (vty, " %s", inet_ntop (AF_INET6, &si->addr.ipv6, buf, BUFSIZ));
		break;
	      case STATIC_IFINDEX:
		vty_out (vty, " %s", si->ifname);
		break;
	      case STATIC_IPV6_GATEWAY_IFINDEX:
		vty_out (vty, " %s %s",
			 inet_ntop (AF_INET6, &si->addr.ipv6, buf, BUFSIZ),
			 ifindex2ifname_vrf (si->ifindex, si->vrf_id));
		break;
	      }

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_REJECT))
              vty_out (vty, " %s", "reject");

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_BLACKHOLE))
              vty_out (vty, " %s", "blackhole");

            if (si->tag)
              vty_out (vty, " tag %d", si->tag);

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
              vty_out (vty, " %d", si->distance);

            if (si->vrf_id != VRF_DEFAULT)
              {
                vty_out (vty, " vrf %s", zvrf->name);
              }

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
          }
    }
  return write;
}

DEFUN (allow_external_route_update,
       allow_external_route_update_cmd,
       "allow-external-route-update",
       "Allow Quagga routes to be overwritten by external processes")
{
  allow_delete = 1;

  return CMD_SUCCESS;
}

DEFUN (no_allow_external_route_update,
       no_allow_external_route_update_cmd,
       "no allow-external-route-update",
       "Allow Quagga routes to be overwritten by external processes")
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
  struct zebra_vrf *zvrf;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (zvrf_list, node, zvrf))
    {
      if (!zvrf->vrf_id)
        continue;

     vty_out (vty, "vrf %s ", zvrf->name);
     if (zvrf->vrf_id == VRF_UNKNOWN)
       vty_out (vty, "inactive");
     else
       vty_out (vty, "id %u table %u", zvrf->vrf_id, zvrf->table_id);
     vty_out (vty, "%s", VTY_NEWLINE);

    }

  return CMD_SUCCESS;
}

/* Static ip route configuration write function. */
static int
zebra_ip_config (struct vty *vty)
{
  int write = 0;

  write += static_config_ipv4 (vty, SAFI_UNICAST, "ip route");
  write += static_config_ipv4 (vty, SAFI_MULTICAST, "ip mroute");
  write += static_config_ipv6 (vty);

  write += zebra_import_table_config (vty);
  return write;
}

DEFUN (ip_zebra_import_table_distance,
       ip_zebra_import_table_distance_cmd,
       "ip import-table (1-252) [distance (1-255)] [route-map WORD>]",
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n"
       "Distance for imported routes\n"
       "Default distance value\n"
       "route-map for filtering\n"
       "route-map name\n")
{
  u_int32_t table_id = 0;

  VTY_GET_INTEGER("table", table_id, argv[2]->arg);
  int distance = ZEBRA_TABLE_DISTANCE_DEFAULT;
  char *rmap = strmatch (argv[argc - 2]->text, "route-map") ?
               XSTRDUP(MTYPE_ROUTE_MAP_NAME, argv[argc - 1]->arg) : NULL;
  if (argc == 7 || (argc == 5 && !rmap))
    VTY_GET_INTEGER_RANGE("distance", distance, argv[4]->arg, 1, 255);

  if (!is_zebra_valid_kernel_table(table_id))
    {
      vty_out(vty, "Invalid routing table ID, %d. Must be in range 1-252%s",
	      table_id, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (is_zebra_main_routing_table(table_id))
    {
      vty_out(vty, "Invalid routing table ID, %d. Must be non-default table%s",
              table_id, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return (zebra_import_table(AFI_IP, table_id, distance, rmap, 1));
}

DEFUN (no_ip_zebra_import_table,
       no_ip_zebra_import_table_cmd,
       "no ip import-table (1-252) [distance (1-255)] [route-map NAME]",
       NO_STR
       IP_STR
       "import routes from non-main kernel table\n"
       "kernel routing table id\n")
{
  u_int32_t table_id = 0;
  VTY_GET_INTEGER("table", table_id, argv[3]->arg);

  if (!is_zebra_valid_kernel_table(table_id))
    {
      vty_out(vty, "Invalid routing table ID. Must be in range 1-252%s",
	      VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (is_zebra_main_routing_table(table_id))
    {
      vty_out(vty, "Invalid routing table ID, %d. Must be non-default table%s",
	      table_id, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!is_zebra_import_table_enabled(AFI_IP, table_id))
    return CMD_SUCCESS;

  return (zebra_import_table(AFI_IP, table_id, 0, NULL, 0));
}

static int
config_write_protocol (struct vty *vty)
{
  if (allow_delete)
    vty_out(vty, "allow-external-route-update%s", VTY_NEWLINE);

  if (zebra_rnh_ip_default_route)
    vty_out(vty, "ip nht resolve-via-default%s", VTY_NEWLINE);

  if (zebra_rnh_ipv6_default_route)
    vty_out(vty, "ipv6 nht resolve-via-default%s", VTY_NEWLINE);

  enum multicast_mode ipv4_multicast_mode = multicast_mode_ipv4_get ();

  if (ipv4_multicast_mode != MCAST_NO_CONFIG)
    vty_out (vty, "ip multicast rpf-lookup-mode %s%s",
             ipv4_multicast_mode == MCAST_URIB_ONLY ? "urib-only" :
             ipv4_multicast_mode == MCAST_MRIB_ONLY ? "mrib-only" :
             ipv4_multicast_mode == MCAST_MIX_MRIB_FIRST ? "mrib-then-urib" :
             ipv4_multicast_mode == MCAST_MIX_DISTANCE ? "lower-distance" :
             "longer-prefix",
             VTY_NEWLINE);

  zebra_routemap_config_write_protocol(vty);

  return 1;
}

/* IP node for static routes. */
static struct cmd_node ip_node = { IP_NODE,  "",  1 };
static struct cmd_node protocol_node = { PROTOCOL_NODE, "", 1 };

/* Route VTY.  */
void
zebra_vty_init (void)
{
  install_node (&ip_node, zebra_ip_config);
  install_node (&protocol_node, config_write_protocol);

  install_element (CONFIG_NODE, &allow_external_route_update_cmd);
  install_element (CONFIG_NODE, &no_allow_external_route_update_cmd);
  install_element (CONFIG_NODE, &ip_mroute_dist_cmd);
  install_element (CONFIG_NODE, &no_ip_mroute_dist_cmd);
  install_element (CONFIG_NODE, &ip_multicast_mode_cmd);
  install_element (CONFIG_NODE, &no_ip_multicast_mode_cmd);
  install_element (CONFIG_NODE, &ip_route_cmd);
  install_element (CONFIG_NODE, &ip_route_flags_cmd);
  install_element (CONFIG_NODE, &ip_route_flags2_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_flags_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_flags2_cmd);
  install_element (CONFIG_NODE, &no_ip_route_cmd);
  install_element (CONFIG_NODE, &no_ip_route_flags2_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_flags2_cmd);
  install_element (CONFIG_NODE, &ip_zebra_import_table_distance_cmd);
  install_element (CONFIG_NODE, &no_ip_zebra_import_table_cmd);

  install_element (VIEW_NODE, &show_vrf_cmd);
  install_element (VIEW_NODE, &show_ip_route_cmd);
  install_element (VIEW_NODE, &show_ip_route_ospf_instance_cmd);
  install_element (VIEW_NODE, &show_ip_route_tag_cmd);
  install_element (VIEW_NODE, &show_ip_nht_cmd);
  install_element (VIEW_NODE, &show_ip_nht_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_nht_cmd);
  install_element (VIEW_NODE, &show_ipv6_nht_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ip_route_addr_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
  install_element (VIEW_NODE, &show_ip_route_supernets_cmd);
  install_element (VIEW_NODE, &show_ip_route_summary_cmd);
  install_element (VIEW_NODE, &show_ip_route_summary_prefix_cmd);
  install_element (ENABLE_NODE, &show_vrf_cmd);
  install_element (ENABLE_NODE, &show_ip_route_cmd);
  install_element (ENABLE_NODE, &show_ip_route_ospf_instance_cmd);
  install_element (ENABLE_NODE, &show_ip_route_tag_cmd);
  install_element (ENABLE_NODE, &show_ip_nht_cmd);
  install_element (ENABLE_NODE, &show_ip_nht_vrf_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_nht_cmd);
  install_element (ENABLE_NODE, &show_ipv6_nht_vrf_all_cmd);
  install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_route_supernets_cmd);
  install_element (ENABLE_NODE, &show_ip_route_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_route_summary_prefix_cmd);

  install_element (VIEW_NODE, &show_ip_rpf_cmd);
  install_element (ENABLE_NODE, &show_ip_rpf_cmd);
  install_element (VIEW_NODE, &show_ip_rpf_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_rpf_addr_cmd);

  /* Commands for VRF */

  install_element (CONFIG_NODE, &no_ip_route_flags_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_flags_cmd);

  install_element (VIEW_NODE, &show_ip_route_vrf_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_cmd);

  install_element (VIEW_NODE, &show_ip_route_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_tag_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_addr_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_protocol_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_supernets_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_summary_cmd);
  install_element (VIEW_NODE, &show_ip_route_vrf_all_summary_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_tag_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_supernets_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_route_vrf_all_summary_prefix_cmd);

  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &ipv6_route_flags_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_flags_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_flags_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_flags_cmd);
  install_element (CONFIG_NODE, &ip_nht_default_route_cmd);
  install_element (CONFIG_NODE, &no_ip_nht_default_route_cmd);
  install_element (CONFIG_NODE, &ipv6_nht_default_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_nht_default_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_tag_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_summary_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_protocol_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_addr_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_tag_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_summary_prefix_cmd);

  install_element (VIEW_NODE, &show_ipv6_mroute_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mroute_cmd);

  /* Commands for VRF */
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_tag_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_summary_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_protocol_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_addr_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_vrf_all_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_tag_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_protocol_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_addr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_vrf_all_summary_prefix_cmd);

  install_element (VIEW_NODE, &show_ipv6_mroute_vrf_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mroute_vrf_all_cmd);
}
