/* Zebra MPLS VTY functions
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
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "lib/json.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_static.h"

static int
zebra_mpls_transit_lsp (struct vty *vty, int add_cmd, const char *inlabel_str,
		        const char *gate_str, const char *outlabel_str,
                        const char *flag_str)
{
  struct zebra_vrf *zvrf;
  int ret;
  enum nexthop_types_t gtype;
  union g_addr gate;
  mpls_label_t label;
  mpls_label_t in_label, out_label;

  zvrf = vrf_info_lookup(VRF_DEFAULT);
  if (!zvrf)
    {
      vty_out (vty, "%% Default VRF does not exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!inlabel_str)
    {
      vty_out (vty, "%% No Label Information%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  out_label = MPLS_IMP_NULL_LABEL; /* as initialization */
  label = atoi(inlabel_str);
  if (!IS_MPLS_UNRESERVED_LABEL(label))
    {
      vty_out (vty, "%% Invalid label%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (add_cmd)
    {
      if (!gate_str)
        {
          vty_out (vty, "%% No Nexthop Information%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if (!outlabel_str)
        {
          vty_out (vty, "%% No Outgoing label Information%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  in_label = label;
  gtype = NEXTHOP_TYPE_BLACKHOLE; /* as initialization */

  if (gate_str)
    {
      /* Gateway is a IPv4 or IPv6 nexthop. */
      ret = inet_pton (AF_INET6, gate_str, &gate.ipv6);
      if (ret)
        gtype = NEXTHOP_TYPE_IPV6;
      else
        {
          ret = inet_pton (AF_INET, gate_str, &gate.ipv4);
          if (ret)
            gtype = NEXTHOP_TYPE_IPV4;
          else
            {
              vty_out (vty, "%% Invalid nexthop%s", VTY_NEWLINE);
              return CMD_WARNING;
            }
        }
    }

  if (outlabel_str)
    {
      if (outlabel_str[0] == 'i')
        out_label = MPLS_IMP_NULL_LABEL;
      else if (outlabel_str[0] == 'e' && gtype == NEXTHOP_TYPE_IPV4)
        out_label = MPLS_V4_EXP_NULL_LABEL;
      else if (outlabel_str[0] == 'e' && gtype == NEXTHOP_TYPE_IPV6)
        out_label = MPLS_V6_EXP_NULL_LABEL;
      else
        out_label = atoi(outlabel_str);
    }

  if (add_cmd)
    {
#if defined(HAVE_CUMULUS)
      /* Check that label value is consistent. */
      if (!zebra_mpls_lsp_label_consistent (zvrf, in_label, out_label, gtype,
                                            &gate, NULL, 0))
        {
          vty_out (vty, "%% Label value not consistent%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        }
#endif /* HAVE_CUMULUS */

      ret = zebra_mpls_static_lsp_add (zvrf, in_label, out_label, gtype,
                                       &gate, NULL, 0);
    }
  else
    ret = zebra_mpls_static_lsp_del (zvrf, in_label, gtype, &gate, NULL, 0);

  if (ret)
    {
      vty_out (vty, "%% LSP cannot be %s%s",
               add_cmd ? "added" : "deleted", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (mpls_transit_lsp,
       mpls_transit_lsp_cmd,
       "mpls lsp <16-1048575> (A.B.C.D|X:X::X:X) (<16-1048575>|explicit-null|implicit-null)",
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n"
       "IPv4 gateway address\n"
       "IPv6 gateway address\n"
       "Outgoing MPLS label\n"
       "Use Explicit-Null label\n"
       "Use Implicit-Null label\n")
{
  return zebra_mpls_transit_lsp (vty, 1, argv[0], argv[1], argv[2], NULL);
}

DEFUN (no_mpls_transit_lsp,
       no_mpls_transit_lsp_cmd,
       "no mpls lsp <16-1048575> (A.B.C.D|X:X::X:X)",
       NO_STR
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n"
       "IPv4 gateway address\n"
       "IPv6 gateway address\n")
{
  return zebra_mpls_transit_lsp (vty, 0, argv[0], argv[1], NULL, NULL);
}

ALIAS (no_mpls_transit_lsp,
       no_mpls_transit_lsp_out_label_cmd,
       "no mpls lsp <16-1048575> (A.B.C.D|X:X::X:X) (<16-1048575>|explicit-null|implicit-null)",
       NO_STR
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n"
       "IPv4 gateway address\n"
       "IPv6 gateway address\n"
       "Outgoing MPLS label\n"
       "Use Explicit-Null label\n"
       "Use Implicit-Null label\n")
 
DEFUN (no_mpls_transit_lsp_all,
       no_mpls_transit_lsp_all_cmd,
       "no mpls lsp <16-1048575>",
       NO_STR
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n")
{
  return zebra_mpls_transit_lsp (vty, 0, argv[0], NULL, NULL, NULL);
}

/* Static route configuration.  */
DEFUN (ip_route_label,
       ip_route_label_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], NULL, argv[1], NULL, NULL,
                            NULL, NULL, argv[2]);
}

DEFUN (ip_route_tag_label,
       ip_route_tag_label_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) tag <1-65535> label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], NULL, argv[1], NULL, argv[2],
                            NULL, NULL, argv[3]);
}

/* Mask as A.B.C.D format.  */
DEFUN (ip_route_mask_label,
       ip_route_mask_label_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], argv[1], argv[2], NULL, NULL,
                            NULL, NULL, argv[3]);
}

DEFUN (ip_route_mask_tag_label,
       ip_route_mask_tag_label_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) tag <1-65535> label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")

{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], argv[1], argv[2], NULL, argv[3],
                            NULL, NULL, argv[4]);
}

/* Distance option value.  */
DEFUN (ip_route_distance_label,
       ip_route_distance_label_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], NULL, argv[1], NULL, NULL,
                            argv[2], NULL, argv[3]);
}

DEFUN (ip_route_tag_distance_label,
       ip_route_tag_distance_label_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) tag <1-65535> <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this route\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")

{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], NULL, argv[1], NULL, argv[2],
                            argv[3], NULL, argv[4]);
}

DEFUN (ip_route_mask_distance_label,
       ip_route_mask_distance_label_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], argv[1], argv[2], NULL, NULL,
                            argv[3], NULL, argv[4]);
}

DEFUN (ip_route_mask_tag_distance_label,
       ip_route_mask_tag_distance_label_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) tag <1-65535> <1-255> label WORD",
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
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 1, argv[0], argv[1], argv[2], NULL, argv[3],
                            argv[4], NULL, argv[5]);
}

DEFUN (no_ip_route_label,
       no_ip_route_label_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], NULL, argv[1], NULL, NULL,
                            NULL, NULL, argv[2]);
}

DEFUN (no_ip_route_tag_label,
       no_ip_route_tag_label_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) tag <1-65535> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Tag of this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], NULL, argv[1], NULL, argv[2],
                            NULL, NULL, argv[3]);
}

DEFUN (no_ip_route_mask_label,
       no_ip_route_mask_label_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], argv[1], argv[2], NULL, NULL,
                            NULL, NULL, argv[3]);
}

DEFUN (no_ip_route_mask_tag_label,
       no_ip_route_mask_tag_label_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) tag <1-65535> label WORD",
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
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], argv[1], argv[2], NULL, argv[3],
                            NULL, NULL, argv[4]);
}

DEFUN (no_ip_route_distance_label,
       no_ip_route_distance_label_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], NULL, argv[1], NULL, NULL,
                            argv[2], NULL, argv[3]);
}

DEFUN (no_ip_route_tag_distance_label,
       no_ip_route_tag_distance_label_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) tag <1-65535> <1-255> label WORD",
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
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], NULL, argv[1], NULL, argv[2],
                            argv[3], NULL, argv[4]);
}

DEFUN (no_ip_route_mask_distance_label,
       no_ip_route_mask_distance_label_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], argv[1], argv[2], NULL, NULL,
                            argv[3], NULL, argv[5]);
}

DEFUN (no_ip_route_mask_tag_distance_label,
       no_ip_route_mask_tag_distance_label_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) tag <1-65535> <1-255> label WORD",
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
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return zebra_static_ipv4 (vty, SAFI_UNICAST, 0, argv[0], argv[1], argv[2], NULL, argv[3],
                            argv[4], NULL, argv[5]);
}

DEFUN (ipv6_route_label,
       ipv6_route_label_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, NULL, NULL, NULL, argv[2]);
}

DEFUN (ipv6_route_tag_label,
       ipv6_route_tag_label_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) tag <1-65535> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, argv[2], NULL, NULL, argv[3]);
}

DEFUN (ipv6_route_ifname_label,
       ipv6_route_ifname_label_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, NULL, NULL, NULL, argv[3]);
}
DEFUN (ipv6_route_ifname_tag_label,
       ipv6_route_ifname_tag_label_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE tag <1-65535> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3], NULL, NULL, argv[4]);
}

DEFUN (ipv6_route_pref_label,
       ipv6_route_pref_label_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, NULL, argv[2], NULL, argv[3]);
}

DEFUN (ipv6_route_pref_tag_label,
       ipv6_route_pref_tag_label_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) tag <1-65535> <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, argv[2], argv[3], NULL, argv[4]);
}

DEFUN (ipv6_route_ifname_pref_label,
       ipv6_route_ifname_pref_label_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, NULL, argv[3], NULL, argv[4]);
}

DEFUN (ipv6_route_ifname_pref_tag_label,
       ipv6_route_ifname_pref_tag_label_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE tag <1-65535> <1-255> label WORD",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3], argv[4], NULL, argv[5]);
}

DEFUN (no_ipv6_route_label,
       no_ipv6_route_label_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, NULL, NULL, NULL, argv[2]);
}

DEFUN (no_ipv6_route_tag_label,
       no_ipv6_route_tag_label_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) tag <1-65535> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, argv[2], NULL, NULL, argv[3]);
}

DEFUN (no_ipv6_route_ifname_label,
       no_ipv6_route_ifname_label_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, NULL, NULL, NULL, argv[3]);
}

DEFUN (no_ipv6_route_ifname_tag_label,
       no_ipv6_route_ifname_tag_label_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE tag <1-65535> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3], NULL, NULL, argv[4]);
}

DEFUN (no_ipv6_route_pref_label,
       no_ipv6_route_pref_label_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, NULL, argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_route_pref_tag_label,
       no_ipv6_route_pref_tag_label_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) tag <1-65535> <1-255> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, argv[2], argv[3], NULL, argv[4]);
}

DEFUN (no_ipv6_route_ifname_pref_label,
       no_ipv6_route_ifname_pref_label_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, NULL, argv[3], NULL, argv[4]);
}

DEFUN (no_ipv6_route_ifname_pref_tag_label,
       no_ipv6_route_ifname_pref_tag_label_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE tag <1-65535> <1-255> label WORD",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Set tag for this route\n"
       "Tag value\n"
       "Distance value for this prefix\n"
       "Specify label(s) for this route\n"
       "One or more labels separated by '/'\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3], argv[4], NULL, argv[5]);
}

/* MPLS LSP configuration write function. */
static int
zebra_mpls_config (struct vty *vty)
{
  int write = 0;
  struct zebra_vrf *zvrf;

  zvrf = vrf_info_lookup(VRF_DEFAULT);
  if (!zvrf)
    return 0;

  write += zebra_mpls_write_lsp_config(vty, zvrf);
  return write;
}

DEFUN (show_mpls_table,
       show_mpls_table_cmd,
       "show mpls table {json}",
       SHOW_STR
       MPLS_STR
       "MPLS table\n"
       "JavaScript Object Notation\n")
{
  struct zebra_vrf *zvrf;
  u_char use_json = (argv[0] != NULL);

  zvrf = vrf_info_lookup(VRF_DEFAULT);
  zebra_mpls_print_lsp_table(vty, zvrf, use_json);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_table_lsp,
       show_mpls_table_lsp_cmd,
       "show mpls table <16-1048575> {json}",
       SHOW_STR
       MPLS_STR
       "MPLS table\n"
       "LSP to display information about\n"
       "JavaScript Object Notation\n")
{
  u_int32_t label;
  struct zebra_vrf *zvrf;
  u_char use_json = (argv[1] != NULL);

  zvrf = vrf_info_lookup(VRF_DEFAULT);
  label = atoi(argv[0]);
  zebra_mpls_print_lsp (vty, zvrf, label, use_json);
  return CMD_SUCCESS;
}

DEFUN (show_mpls_status,
       show_mpls_status_cmd,
       "show mpls status",
       SHOW_STR
       "MPLS information\n"
       "MPLS status\n")
{
  vty_out (vty, "MPLS support enabled: %s%s", (mpls_enabled) ? "yes" :
	   "no (mpls kernel extensions not detected)", VTY_NEWLINE);
  return CMD_SUCCESS;
}

/* MPLS node for MPLS LSP. */
static struct cmd_node mpls_node = { MPLS_NODE,  "",  1 };

/* MPLS VTY.  */
void
zebra_mpls_vty_init (void)
{
  install_element (VIEW_NODE, &show_mpls_status_cmd);
  install_element (ENABLE_NODE, &show_mpls_status_cmd);

  if (! mpls_enabled)
    return;

  install_node (&mpls_node, zebra_mpls_config);

  install_element (CONFIG_NODE, &ip_route_label_cmd);
  install_element (CONFIG_NODE, &ip_route_tag_label_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_label_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_tag_label_cmd);
  install_element (CONFIG_NODE, &ip_route_distance_label_cmd);
  install_element (CONFIG_NODE, &ip_route_tag_distance_label_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_distance_label_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_tag_distance_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_distance_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_tag_distance_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_distance_label_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_tag_distance_label_cmd);

  install_element (CONFIG_NODE, &ipv6_route_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_pref_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_pref_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_pref_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_tag_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_tag_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_pref_tag_label_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_pref_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_pref_tag_label_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_tag_label_cmd);

  install_element (CONFIG_NODE, &mpls_transit_lsp_cmd);
  install_element (CONFIG_NODE, &no_mpls_transit_lsp_cmd);
  install_element (CONFIG_NODE, &no_mpls_transit_lsp_out_label_cmd);
  install_element (CONFIG_NODE, &no_mpls_transit_lsp_all_cmd);

  install_element (VIEW_NODE, &show_mpls_table_cmd);
  install_element (ENABLE_NODE, &show_mpls_table_cmd);
  install_element (VIEW_NODE, &show_mpls_table_lsp_cmd);
  install_element (ENABLE_NODE, &show_mpls_table_lsp_cmd);
}
