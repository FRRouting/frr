/* BGP VTY interface.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "stream.h"
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "hash.h"
#include "queue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"

static struct peer_group *
listen_range_exists (struct bgp *bgp, struct prefix *range, int exact);

/* Utility function to get address family from current node.  */
afi_t
bgp_node_afi (struct vty *vty)
{
  if (vty->node == BGP_IPV6_NODE || vty->node == BGP_IPV6M_NODE)
    return AFI_IP6;
  return AFI_IP;
}

/* Utility function to get subsequent address family from current
   node.  */
safi_t
bgp_node_safi (struct vty *vty)
{
  if (vty->node == BGP_VPNV4_NODE)
    return SAFI_MPLS_VPN;
  if (vty->node == BGP_IPV4M_NODE || vty->node == BGP_IPV6M_NODE)
    return SAFI_MULTICAST;
  return SAFI_UNICAST;
}

static int
peer_address_self_check (struct bgp *bgp, union sockunion *su)
{
  struct interface *ifp = NULL;

  if (su->sa.sa_family == AF_INET)
    ifp = if_lookup_by_ipv4_exact (&su->sin.sin_addr, bgp->vrf_id);
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    ifp = if_lookup_by_ipv6_exact (&su->sin6.sin6_addr,
				   su->sin6.sin6_scope_id, bgp->vrf_id);
#endif /* HAVE IPV6 */

  if (ifp)
    return 1;

  return 0;
}

/* Utility function for looking up peer from VTY.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
static struct peer *
peer_lookup_vty (struct vty *vty, const char *ip_str)
{
  int ret;
  struct bgp *bgp;
  union sockunion su;
  struct peer *peer;

  bgp = vty->index;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (bgp, ip_str);
      if (!peer)
        {
	  if ((peer = peer_lookup_by_hostname(bgp, ip_str)) == NULL)
	    {
	      vty_out (vty, "%% Malformed address or name: %s%s", ip_str, VTY_NEWLINE);
	      return NULL;
	    }
        }
    }
  else
    {
      peer = peer_lookup (bgp, &su);
      if (! peer)
        {
          vty_out (vty, "%% Specify remote-as or peer-group commands first%s",
                   VTY_NEWLINE);
          return NULL;
        }
      if (peer_dynamic_neighbor (peer))
        {
          vty_out (vty, "%% Operation not allowed on a dynamic neighbor%s",
	           VTY_NEWLINE);
          return NULL;
        }

    }
  return peer;
}

/* Utility function for looking up peer or peer group.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
struct peer *
peer_and_group_lookup_vty (struct vty *vty, const char *peer_str)
{
  int ret;
  struct bgp *bgp;
  union sockunion su;
  struct peer *peer = NULL;
  struct peer_group *group = NULL;

  bgp = vty->index;

  ret = str2sockunion (peer_str, &su);
  if (ret == 0)
    {
      /* IP address, locate peer. */
      peer = peer_lookup (bgp, &su);
    }
  else
    {
      /* Not IP, could match either peer configured on interface or a group. */
      peer = peer_lookup_by_conf_if (bgp, peer_str);
      if (!peer)
        group = peer_group_lookup (bgp, peer_str);
    }

  if (peer)
    {
      if (peer_dynamic_neighbor (peer))
        {
          vty_out (vty, "%% Operation not allowed on a dynamic neighbor%s",
	           VTY_NEWLINE);
          return NULL;
        }

      return peer;
    }

  if (group)
    return group->conf;

  vty_out (vty, "%% Specify remote-as or peer-group commands first%s",
	   VTY_NEWLINE);

  return NULL;
}

int
bgp_vty_return (struct vty *vty, int ret)
{
  const char *str = NULL;

  switch (ret)
    {
    case BGP_ERR_INVALID_VALUE:
      str = "Invalid value";
      break;
    case BGP_ERR_INVALID_FLAG:
      str = "Invalid flag";
      break;
    case BGP_ERR_PEER_GROUP_SHUTDOWN:
      str = "Peer-group has been shutdown. Activate the peer-group first";
      break;
    case BGP_ERR_PEER_FLAG_CONFLICT:
      str = "Can't set override-capability and strict-capability-match at the same time";
      break;
    case BGP_ERR_PEER_GROUP_NO_REMOTE_AS:
      str = "Specify remote-as or peer-group remote AS first";
      break;
    case BGP_ERR_PEER_GROUP_CANT_CHANGE:
      str = "Cannot change the peer-group. Deconfigure first";
      break;
    case BGP_ERR_PEER_GROUP_MISMATCH:
      str = "Peer is not a member of this peer-group";
      break;
    case BGP_ERR_PEER_FILTER_CONFLICT:
      str = "Prefix/distribute list can not co-exist";
      break;
    case BGP_ERR_NOT_INTERNAL_PEER:
      str = "Invalid command. Not an internal neighbor";
      break;
    case BGP_ERR_REMOVE_PRIVATE_AS:
      str = "remove-private-AS cannot be configured for IBGP peers";
      break;
    case BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP:
      str = "Local-AS allowed only for EBGP peers";
      break;
    case BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS:
      str = "Cannot have local-as same as BGP AS number";
      break;
    case BGP_ERR_TCPSIG_FAILED:
      str = "Error while applying TCP-Sig to session(s)";
      break;
    case BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK:
      str = "ebgp-multihop and ttl-security cannot be configured together";
      break;
    case BGP_ERR_NO_IBGP_WITH_TTLHACK:
      str = "ttl-security only allowed for EBGP peers";
      break;
    case BGP_ERR_AS_OVERRIDE:
      str = "as-override cannot be configured for IBGP peers";
      break;
    case BGP_ERR_INVALID_DYNAMIC_NEIGHBORS_LIMIT:
      str = "Invalid limit for number of dynamic neighbors";
      break;
    case BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_EXISTS:
      str = "Dynamic neighbor listen range already exists";
      break;
    case BGP_ERR_INVALID_FOR_DYNAMIC_PEER:
      str = "Operation not allowed on a dynamic neighbor";
      break;
    }
  if (str)
    {
      vty_out (vty, "%% %s%s", str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* BGP clear sort. */
enum clear_sort
{
  clear_all,
  clear_peer,
  clear_group,
  clear_external,
  clear_as
};

static void
bgp_clear_vty_error (struct vty *vty, struct peer *peer, afi_t afi,
		     safi_t safi, int error)
{
  switch (error)
    {
    case BGP_ERR_AF_UNCONFIGURED:
      vty_out (vty,
	       "%%BGP: Enable %s %s address family for the neighbor %s%s",
	       afi == AFI_IP6 ? "IPv6" : safi == SAFI_MPLS_VPN ? "VPNv4" : "IPv4",
	       safi == SAFI_MULTICAST ? "Multicast" : "Unicast",
	       peer->host, VTY_NEWLINE);
      break;
    case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
      vty_out (vty, "%%BGP: Inbound soft reconfig for %s not possible as it%s      has neither refresh capability, nor inbound soft reconfig%s", peer->host, VTY_NEWLINE, VTY_NEWLINE);
      break;
    default:
      break;
    }
}

/* `clear ip bgp' functions. */
static int
bgp_clear (struct vty *vty, struct bgp *bgp,  afi_t afi, safi_t safi,
           enum clear_sort sort,enum bgp_clear_type stype, const char *arg)
{
  int ret;
  struct peer *peer;
  struct listnode *node, *nnode;

  /* Clear all neighbors. */
  /*
   * Pass along pointer to next node to peer_clear() when walking all nodes
   * on the BGP instance as that may get freed if it is a doppelganger
   */
  if (sort == clear_all)
    {
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
	{
	  if (stype == BGP_CLEAR_SOFT_NONE)
	    ret = peer_clear (peer, &nnode);
	  else if (peer->afc[afi][safi])
	    ret = peer_clear_soft (peer, afi, safi, stype);
          else
            ret = 0;

	  if (ret < 0)
	    bgp_clear_vty_error (vty, peer, afi, safi, ret);
	}

      /* This is to apply read-only mode on this clear. */
      if (stype == BGP_CLEAR_SOFT_NONE)
        bgp->update_delay_over = 0;

      return CMD_SUCCESS;
    }

  /* Clear specified neighbors. */
  if (sort == clear_peer)
    {
      union sockunion su;
      int ret;

      /* Make sockunion for lookup. */
      ret = str2sockunion (arg, &su);
      if (ret < 0)
        {
          peer = peer_lookup_by_conf_if (bgp, arg);
          if (!peer)
            {
	      peer = peer_lookup_by_hostname(bgp, arg);
	      if (!peer)
		{
		  vty_out (vty, "Malformed address or name: %s%s", arg, VTY_NEWLINE);
		  return CMD_WARNING;
		}
            }
        }
      else
        {
          peer = peer_lookup (bgp, &su);
          if (! peer)
            {
              vty_out (vty, "%%BGP: Unknown neighbor - \"%s\"%s", arg, VTY_NEWLINE);
              return CMD_WARNING;
            }
        }

      if (stype == BGP_CLEAR_SOFT_NONE)
	ret = peer_clear (peer, NULL);
      else
	ret = peer_clear_soft (peer, afi, safi, stype);

      if (ret < 0)
	bgp_clear_vty_error (vty, peer, afi, safi, ret);

      return CMD_SUCCESS;
    }

  /* Clear all peer-group members. */
  if (sort == clear_group)
    {
      struct peer_group *group;

      group = peer_group_lookup (bgp, arg);
      if (! group)
	{
	  vty_out (vty, "%%BGP: No such peer-group %s%s", arg, VTY_NEWLINE);
	  return CMD_WARNING;
	}

      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
	{
	  if (stype == BGP_CLEAR_SOFT_NONE)
	    {
	      peer_clear (peer, NULL);
	      continue;
	    }

	  if (! peer->afc[afi][safi])
	    continue;

	  ret = peer_clear_soft (peer, afi, safi, stype);

	  if (ret < 0)
	    bgp_clear_vty_error (vty, peer, afi, safi, ret);
	}
      return CMD_SUCCESS;
    }

  if (sort == clear_external)
    {
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
	{
	  if (peer->sort == BGP_PEER_IBGP)
	    continue;

	  if (stype == BGP_CLEAR_SOFT_NONE)
	    ret = peer_clear (peer, &nnode);
	  else
	    ret = peer_clear_soft (peer, afi, safi, stype);

	  if (ret < 0)
	    bgp_clear_vty_error (vty, peer, afi, safi, ret);
	}
      return CMD_SUCCESS;
    }

  if (sort == clear_as)
    {
      as_t as;
      int find = 0;

      VTY_GET_INTEGER_RANGE ("AS", as, arg, 1, BGP_AS4_MAX);

      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
	{
	  if (peer->as != as)
	    continue;

	  find = 1;
	  if (stype == BGP_CLEAR_SOFT_NONE)
	    ret = peer_clear (peer, &nnode);
	  else
	    ret = peer_clear_soft (peer, afi, safi, stype);

	  if (ret < 0)
	    bgp_clear_vty_error (vty, peer, afi, safi, ret);
	}
      if (! find)
	vty_out (vty, "%%BGP: No peer is configured with AS %s%s", arg,
		 VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  return CMD_SUCCESS;
}

static int
bgp_clear_vty (struct vty *vty, const char *name, afi_t afi, safi_t safi,
               enum clear_sort sort, enum bgp_clear_type stype,
               const char *arg)
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  if (name)
    {
      bgp = bgp_lookup_by_name (name);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP instance %s%s", name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return bgp_clear (vty, bgp, afi, safi, sort, stype, arg);
}

/* clear soft inbound */
static void
bgp_clear_star_soft_in (struct vty *vty)
{
  bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                 BGP_CLEAR_SOFT_IN, NULL);
#ifdef HAVE_IPV6
  bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
                 BGP_CLEAR_SOFT_IN, NULL);
#endif /* HAVE_IPV6 */
}

/* clear soft outbound */
static void
bgp_clear_star_soft_out (struct vty *vty)
{
  bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
		 BGP_CLEAR_SOFT_OUT, NULL);
#ifdef HAVE_IPV6
  bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
		 BGP_CLEAR_SOFT_OUT, NULL);
#endif /* HAVE_IPV6 */
}


/* BGP global configuration.  */

DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       BGP_STR
       "Enable bgp multiple instance\n")
{
  bgp_option_set (BGP_OPT_MULTIPLE_INSTANCE);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       NO_STR
       BGP_STR
       "BGP multiple instance\n")
{
  int ret;

  ret = bgp_option_unset (BGP_OPT_MULTIPLE_INSTANCE);
  if (ret < 0)
    {
      vty_out (vty, "%% There are more than two BGP instances%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (bgp_config_type,
       bgp_config_type_cmd,
       "bgp config-type (cisco|zebra)",
       BGP_STR
       "Configuration type\n"
       "cisco\n"
       "zebra\n")
{
  if (strncmp (argv[0], "c", 1) == 0)
    bgp_option_set (BGP_OPT_CONFIG_CISCO);
  else
    bgp_option_unset (BGP_OPT_CONFIG_CISCO);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_config_type,
       no_bgp_config_type_cmd,
       "no bgp config-type",
       NO_STR
       BGP_STR
       "Display configuration type\n")
{
  bgp_option_unset (BGP_OPT_CONFIG_CISCO);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_config_type,
       no_bgp_config_type_val_cmd,
       "no bgp config-type (cisco|zebra)",
       NO_STR
       BGP_STR
       "Configuration type\n"
       "cisco\n"
       "zebra\n")

DEFUN (no_synchronization,
       no_synchronization_cmd,
       "no synchronization",
       NO_STR
       "Perform IGP synchronization\n")
{
  return CMD_SUCCESS;
}

DEFUN (no_auto_summary,
       no_auto_summary_cmd,
       "no auto-summary",
       NO_STR
       "Enable automatic network number summarization\n")
{
  return CMD_SUCCESS;
}

/* "router bgp" commands. */
DEFUN (router_bgp, 
       router_bgp_cmd, 
       "router bgp " CMD_AS_RANGE,
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  int ret;
  as_t as;
  struct bgp *bgp;
  const char *name = NULL;
  enum bgp_instance_type inst_type;

  // "router bgp" without an ASN
  if (argc < 1)
    {
      //Pending: Make VRF option available for ASN less config
      bgp = bgp_get_default();

      if (bgp == NULL)
        {
          vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      if (listcount(bm->bgp) > 1)
        {
          vty_out (vty, "%% Multiple BGP processes are configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  // "router bgp X"
  else
    {
      VTY_GET_INTEGER_RANGE ("AS", as, argv[0], 1, BGP_AS4_MAX);

      inst_type = BGP_INSTANCE_TYPE_DEFAULT;
      if (argc == 3)
        {
          name = argv[2];
          if (!strcmp(argv[1], "vrf")) 
            inst_type = BGP_INSTANCE_TYPE_VRF;
          else if (!strcmp(argv[1], "view")) 
            inst_type = BGP_INSTANCE_TYPE_VIEW;
        }

      ret = bgp_get (&bgp, &as, name, inst_type);
      switch (ret)
        {
        case BGP_ERR_MULTIPLE_INSTANCE_NOT_SET:
          vty_out (vty, "Please specify 'bgp multiple-instance' first%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        case BGP_ERR_AS_MISMATCH:
          vty_out (vty, "BGP is already running; AS is %u%s", as, VTY_NEWLINE);
          return CMD_WARNING;
        case BGP_ERR_INSTANCE_MISMATCH:
          vty_out (vty, "BGP instance name and AS number mismatch%s", VTY_NEWLINE);
          vty_out (vty, "BGP instance is already running; AS is %u%s",
                   as, VTY_NEWLINE);
          return CMD_WARNING;
        }

      /* Pending: handle when user tries to change a view to vrf n vv. */
    }

  vty->node = BGP_NODE;
  vty->index = bgp;

  return CMD_SUCCESS;
}

ALIAS (router_bgp,
       router_bgp_instance_cmd,
       "router bgp " CMD_AS_RANGE " (view|vrf) WORD",
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\nBGP VRF\n"
       "View/VRF name\n")

ALIAS (router_bgp,
       router_bgp_noasn_cmd,
       "router bgp",
       ROUTER_STR
       BGP_STR)

/* "no router bgp" commands. */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp " CMD_AS_RANGE,
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  as_t as;
  struct bgp *bgp;
  const char *name = NULL;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], 1, BGP_AS4_MAX);

  if (argc == 3)
    name = argv[2];

  /* Lookup bgp structure. */
  bgp = bgp_lookup (as, name);
  if (! bgp)
    {
      vty_out (vty, "%% Can't find BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_delete (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_router_bgp,
       no_router_bgp_instance_cmd,
       "no router bgp " CMD_AS_RANGE " (view|vrf) WORD",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\nBGP VRF\n"
       "View/VRF name\n")

/* BGP router-id.  */

DEFUN (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
  int ret;
  struct in_addr id;
  struct bgp *bgp;

  bgp = vty->index;

  ret = inet_aton (argv[0], &id);
  if (! ret)
    {
      vty_out (vty, "%% Malformed bgp router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (IPV4_ADDR_SAME (&bgp->router_id_static, &id))
    return CMD_SUCCESS;

  bgp->router_id_static = id;
  bgp_router_id_set (bgp, &id);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_router_id,
       no_bgp_router_id_cmd,
       "no bgp router-id",
       NO_STR
       BGP_STR
       "Override configured router identifier\n")
{
  int ret;
  struct in_addr id;
  struct bgp *bgp;

  bgp = vty->index;

  if (argc == 1)
    {
      ret = inet_aton (argv[0], &id);
      if (! ret)
	{
	  vty_out (vty, "%% Malformed BGP router identifier%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (! IPV4_ADDR_SAME (&bgp->router_id_static, &id))
	{
	  vty_out (vty, "%% BGP router-id doesn't match%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  bgp->router_id_static.s_addr = 0;
  bgp_router_id_set (bgp, &bgp->router_id_zebra);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_router_id,
       no_bgp_router_id_val_cmd,
       "no bgp router-id A.B.C.D",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")

/* BGP Cluster ID.  */

DEFUN (bgp_cluster_id,
       bgp_cluster_id_cmd,
       "bgp cluster-id A.B.C.D",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr cluster;

  bgp = vty->index;

  ret = inet_aton (argv[0], &cluster);
  if (! ret)
    {
      vty_out (vty, "%% Malformed bgp cluster identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_cluster_id_set (bgp, &cluster);
  bgp_clear_star_soft_out (vty);

  return CMD_SUCCESS;
}

ALIAS (bgp_cluster_id,
       bgp_cluster_id32_cmd,
       "bgp cluster-id <1-4294967295>",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")

DEFUN (no_bgp_cluster_id,
       no_bgp_cluster_id_cmd,
       "no bgp cluster-id",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr cluster;

  bgp = vty->index;

  if (argc == 1)
    {
      ret = inet_aton (argv[0], &cluster);
      if (! ret)
	{
	  vty_out (vty, "%% Malformed bgp cluster identifier%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  bgp_cluster_id_unset (bgp);
  bgp_clear_star_soft_out (vty);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_cluster_id,
       no_bgp_cluster_id_ip_cmd,
       "no bgp cluster-id A.B.C.D",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")

ALIAS (no_bgp_cluster_id,
       no_bgp_cluster_id_decimal_cmd,
       "no bgp cluster-id <1-4294967295>",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")

DEFUN (bgp_confederation_identifier,
       bgp_confederation_identifier_cmd,
       "bgp confederation identifier " CMD_AS_RANGE,
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")
{
  struct bgp *bgp;
  as_t as;

  bgp = vty->index;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], 1, BGP_AS4_MAX);

  bgp_confederation_id_set (bgp, as);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp_confederation_id_unset (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_arg_cmd,
       "no bgp confederation identifier " CMD_AS_RANGE,
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")

DEFUN (bgp_confederation_peers,
       bgp_confederation_peers_cmd,
       "bgp confederation peers ." CMD_AS_RANGE,
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  struct bgp *bgp;
  as_t as;
  int i;

  bgp = vty->index;

  for (i = 0; i < argc; i++)
    {
      VTY_GET_INTEGER_RANGE ("AS", as, argv[i], 1, BGP_AS4_MAX);

      if (bgp->as == as)
	{
	  vty_out (vty, "%% Local member-AS not allowed in confed peer list%s",
		   VTY_NEWLINE);
	  continue;
	}

      bgp_confederation_peers_add (bgp, as);
    }
  return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_peers,
       no_bgp_confederation_peers_cmd,
       "no bgp confederation peers ." CMD_AS_RANGE,
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  struct bgp *bgp;
  as_t as;
  int i;

  bgp = vty->index;

  for (i = 0; i < argc; i++)
    {
      VTY_GET_INTEGER_RANGE ("AS", as, argv[i], 1, BGP_AS4_MAX);

      bgp_confederation_peers_remove (bgp, as);
    }
  return CMD_SUCCESS;
}

/**
 * Central routine for maximum-paths configuration.
 * @peer_type: BGP_PEER_EBGP or BGP_PEER_IBGP
 * @set: 1 for setting values, 0 for removing the max-paths config.
 */
static int
bgp_maxpaths_config_vty (struct vty *vty, int peer_type, const char *mpaths,
			 u_int16_t options, int set)
{
  struct bgp *bgp;
  u_int16_t maxpaths = 0;
  int ret;
  afi_t afi;
  safi_t safi;

  bgp = vty->index;
  afi = bgp_node_afi (vty);
  safi = bgp_node_safi (vty);

  if (set)
    {
      VTY_GET_INTEGER_RANGE ("maximum-paths", maxpaths, mpaths, 1,
                             MULTIPATH_NUM);
      ret = bgp_maximum_paths_set (bgp, afi, safi, peer_type, maxpaths,
				   options);
    }
  else
    ret = bgp_maximum_paths_unset (bgp, afi, safi, peer_type);

  if (ret < 0)
    {
      vty_out (vty,
	       "%% Failed to %sset maximum-paths %s %u for afi %u, safi %u%s",
	       (set == 1) ? "" : "un",
	       (peer_type == BGP_PEER_EBGP) ? "ebgp" : "ibgp",
	       maxpaths, afi, safi, VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin,
       bgp_maxmed_admin_cmd,
       "bgp max-med administrative ",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->v_maxmed_admin = 1;
  bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin_medv,
       bgp_maxmed_admin_medv_cmd,
       "bgp max-med administrative <0-4294967294>",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->v_maxmed_admin = 1;
  VTY_GET_INTEGER ("max-med admin med-value", bgp->maxmed_admin_value, argv[0]);

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_admin,
       no_bgp_maxmed_admin_cmd,
       "no bgp max-med administrative",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
  bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_maxmed_admin,
       no_bgp_maxmed_admin_medv_cmd,
       "no bgp max-med administrative <0-4294967294>",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")


DEFUN (bgp_maxmed_onstartup,
       bgp_maxmed_onstartup_cmd,
       "bgp max-med on-startup <5-86400>",
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (argc != 1)
    {
      vty_out (vty, "%% Must supply max-med on-startup period");
      return CMD_WARNING;
    }

  VTY_GET_INTEGER ("max-med on-startup period", bgp->v_maxmed_onstartup, argv[0]);
  bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_onstartup_medv,
       bgp_maxmed_onstartup_medv_cmd,
       "bgp max-med on-startup <5-86400> <0-4294967294>",
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (argc != 2)
    {
      vty_out (vty, "%% Must supply max-med on-startup period and med value");
      return CMD_WARNING;
    }

  VTY_GET_INTEGER ("max-med on-startup period", bgp->v_maxmed_onstartup, argv[0]);
  VTY_GET_INTEGER ("max-med on-startup med-value", bgp->maxmed_onstartup_value, argv[1]);

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_cmd,
       "no bgp max-med on-startup",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  /* Cancel max-med onstartup if its on */
  if (bgp->t_maxmed_onstartup)
    {
      THREAD_TIMER_OFF (bgp->t_maxmed_onstartup);
      bgp->maxmed_onstartup_over = 1;
    }

  bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
  bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

  bgp_maxmed_update(bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_period_cmd,
       "no bgp max-med on-startup <5-86400>",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n")

ALIAS (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_period_medv_cmd,
       "no bgp max-med on-startup <5-86400> <0-4294967294>",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")

static int
bgp_update_delay_config_vty (struct vty *vty, const char *delay,
                             const char *wait)
{
  struct bgp *bgp;
  u_int16_t update_delay;
  u_int16_t establish_wait;


  bgp = vty->index;

  VTY_GET_INTEGER_RANGE ("update-delay", update_delay, delay,
                         BGP_UPDATE_DELAY_MIN, BGP_UPDATE_DELAY_MAX);

  if (!wait) /* update-delay <delay> */
    {
      bgp->v_update_delay = update_delay;
      bgp->v_establish_wait = bgp->v_update_delay;
      return CMD_SUCCESS;
    }

  /* update-delay <delay> <establish-wait> */
  establish_wait = atoi (wait);
  if (update_delay < establish_wait)
    {
      vty_out (vty, "%%Failed: update-delay less than the establish-wait!%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp->v_update_delay = update_delay;
  bgp->v_establish_wait = establish_wait;

  return CMD_SUCCESS;
}

static int
bgp_update_delay_deconfig_vty (struct vty *vty)
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->v_update_delay = BGP_UPDATE_DELAY_DEF;
  bgp->v_establish_wait = bgp->v_update_delay;

  return CMD_SUCCESS;
}

int
bgp_config_write_update_delay (struct vty *vty, struct bgp *bgp)
{
  if (bgp->v_update_delay != BGP_UPDATE_DELAY_DEF)
    {
      vty_out (vty, " update-delay %d", bgp->v_update_delay);
      if (bgp->v_update_delay != bgp->v_establish_wait)
        vty_out (vty, " %d", bgp->v_establish_wait);
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  return 0;
}


/* Update-delay configuration */
DEFUN (bgp_update_delay,
       bgp_update_delay_cmd,
       "update-delay <0-3600>",
       "Force initial delay for best-path and updates\n"
       "Seconds\n")
{
  return bgp_update_delay_config_vty(vty, argv[0], NULL);
}

DEFUN (bgp_update_delay_establish_wait,
       bgp_update_delay_establish_wait_cmd,
       "update-delay <0-3600> <1-3600>",
       "Force initial delay for best-path and updates\n"
       "Seconds\n"
       "Wait for peers to be established\n"
       "Seconds\n")
{
  return bgp_update_delay_config_vty(vty, argv[0], argv[1]);
}

/* Update-delay deconfiguration */
DEFUN (no_bgp_update_delay,
       no_bgp_update_delay_cmd,
       "no update-delay <0-3600>",
       "Force initial delay for best-path and updates\n"
       "Seconds\n")
{
  return bgp_update_delay_deconfig_vty(vty);
}

ALIAS (no_bgp_update_delay,
       no_bgp_update_delay_establish_wait_cmd,
       "no update-delay <0-3600> <1-3600>",
       "Force initial delay for best-path and updates\n"
       "Seconds\n"
       "Wait for peers to be established\n"
       "Seconds\n")

static int
bgp_wpkt_quanta_config_vty (struct vty *vty, const char *num, char set)
{
  struct bgp *bgp;

  bgp = vty->index;

  if (set)
    VTY_GET_INTEGER_RANGE ("write-quanta", bgp->wpkt_quanta, num,
			   1, 10000);
  else
    bgp->wpkt_quanta = BGP_WRITE_PACKET_MAX;

  return CMD_SUCCESS;
}

int
bgp_config_write_wpkt_quanta (struct vty *vty, struct bgp *bgp)
{
  if (bgp->wpkt_quanta != BGP_WRITE_PACKET_MAX)
      vty_out (vty, " write-quanta %d%s",
               bgp->wpkt_quanta, VTY_NEWLINE);

  return 0;
}


/* Update-delay configuration */
DEFUN (bgp_wpkt_quanta,
       bgp_wpkt_quanta_cmd,
       "write-quanta <1-10000>",
       "How many packets to write to peer socket per run\n"
       "Number of packets\n")
{
  return bgp_wpkt_quanta_config_vty(vty, argv[0], 1);
}

/* Update-delay deconfiguration */
DEFUN (no_bgp_wpkt_quanta,
       no_bgp_wpkt_quanta_cmd,
       "no write-quanta <1-10000>",
       "How many packets to write to peer socket per run\n"
       "Number of packets\n")
{
  return bgp_wpkt_quanta_config_vty(vty, argv[0], 0);
}

static int
bgp_coalesce_config_vty (struct vty *vty, const char *num, char set)
{
  struct bgp *bgp;

  bgp = vty->index;

  if (set)
    VTY_GET_INTEGER_RANGE ("coalesce-time", bgp->coalesce_time, num,
			   0, 4294967295);
  else
    bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;

  return CMD_SUCCESS;
}

int
bgp_config_write_coalesce_time (struct vty *vty, struct bgp *bgp)
{
  if (bgp->coalesce_time != BGP_DEFAULT_SUBGROUP_COALESCE_TIME)
      vty_out (vty, " coalesce-time %d%s",
               bgp->coalesce_time, VTY_NEWLINE);

  return 0;
}


DEFUN (bgp_coalesce_time,
       bgp_coalesce_time_cmd,
       "coalesce-time <0-4294967295>",
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
  return bgp_coalesce_config_vty(vty, argv[0], 1);
}

DEFUN (no_bgp_coalesce_time,
       no_bgp_coalesce_time_cmd,
       "no coalesce-time <0-4294967295>",
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
  return bgp_coalesce_config_vty(vty, argv[0], 0);
}

/* Maximum-paths configuration */
DEFUN (bgp_maxpaths,
       bgp_maxpaths_cmd,
       "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
  return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP, argv[0], 0, 1);
}

DEFUN (bgp_maxpaths_ibgp,
       bgp_maxpaths_ibgp_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n")
{
  return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP, argv[0], 0, 1);
}

DEFUN (bgp_maxpaths_ibgp_cluster,
       bgp_maxpaths_ibgp_cluster_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM) " equal-cluster-length",
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")
{
  return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP, argv[0],
				 BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN, 1);
}

DEFUN (no_bgp_maxpaths,
       no_bgp_maxpaths_cmd,
       "no maximum-paths",
       NO_STR
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
  return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP, NULL, 0, 0);
}

ALIAS (no_bgp_maxpaths,
       no_bgp_maxpaths_arg_cmd,
       "no maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
       NO_STR
       "Forward packets over multiple paths\n"
       "Number of paths\n")

DEFUN (no_bgp_maxpaths_ibgp,
       no_bgp_maxpaths_ibgp_cmd,
       "no maximum-paths ibgp",
       NO_STR
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n")
{
  return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP, NULL, 0, 0);
}

ALIAS (no_bgp_maxpaths_ibgp,
       no_bgp_maxpaths_ibgp_arg_cmd,
       "no maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
       NO_STR
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n")

ALIAS (no_bgp_maxpaths_ibgp,
       no_bgp_maxpaths_ibgp_cluster_cmd,
       "no maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM) " equal-cluster-length",
       NO_STR
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")

int
bgp_config_write_maxpaths (struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi, int *write)
{
  if (bgp->maxpaths[afi][safi].maxpaths_ebgp != MULTIPATH_NUM)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  maximum-paths %d%s",
	       bgp->maxpaths[afi][safi].maxpaths_ebgp, VTY_NEWLINE);
    }

  if (bgp->maxpaths[afi][safi].maxpaths_ibgp != MULTIPATH_NUM)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  maximum-paths ibgp %d",
	       bgp->maxpaths[afi][safi].maxpaths_ibgp);
      if (CHECK_FLAG (bgp->maxpaths[afi][safi].ibgp_flags,
		      BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))
	vty_out (vty, " equal-cluster-length");
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  return 0;
}

/* BGP timers.  */

DEFUN (bgp_timers,
       bgp_timers_cmd,
       "timers bgp <0-65535> <0-65535>",
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  struct bgp *bgp;
  unsigned long keepalive = 0;
  unsigned long holdtime = 0;

  bgp = vty->index;

  VTY_GET_INTEGER ("keepalive", keepalive, argv[0]);
  VTY_GET_INTEGER ("holdtime", holdtime, argv[1]);

  /* Holdtime value check. */
  if (holdtime < 3 && holdtime != 0)
    {
      vty_out (vty, "%% hold time value must be either 0 or greater than 3%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_timers_set (bgp, keepalive, holdtime);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_timers,
       no_bgp_timers_cmd,
       "no timers bgp",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_timers_unset (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_timers,
       no_bgp_timers_arg_cmd,
       "no timers bgp <0-65535> <0-65535>",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

DEFUN (bgp_client_to_client_reflection,
       bgp_client_to_client_reflection_cmd,
       "bgp client-to-client reflection",
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
  bgp_clear_star_soft_out (vty);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_client_to_client_reflection,
       no_bgp_client_to_client_reflection_cmd,
       "no bgp client-to-client reflection",
       NO_STR
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
  bgp_clear_star_soft_out (vty);

  return CMD_SUCCESS;
}

/* "bgp always-compare-med" configuration. */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

/* "bgp deterministic-med" configuration. */
DEFUN (bgp_deterministic_med,
       bgp_deterministic_med_cmd,
       "bgp deterministic-med",
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (!bgp_flag_check(bgp, BGP_FLAG_DETERMINISTIC_MED))
    {
      bgp_flag_set (bgp, BGP_FLAG_DETERMINISTIC_MED);
      bgp_recalculate_all_bestpaths (bgp);
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_deterministic_med,
       no_bgp_deterministic_med_cmd,
       "no bgp deterministic-med",
       NO_STR
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  struct bgp *bgp;
  int bestpath_per_as_used;
  afi_t afi;
  safi_t safi;
  struct peer *peer;
  struct listnode *node, *nnode;

  bgp = vty->index;

  if (bgp_flag_check(bgp, BGP_FLAG_DETERMINISTIC_MED))
    {
      bestpath_per_as_used = 0;

      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          for (afi = AFI_IP; afi < AFI_MAX; afi++)
            for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
              if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS))
                {
                  bestpath_per_as_used = 1;
                  break;
                }

          if (bestpath_per_as_used)
            break;
        }

      if (bestpath_per_as_used)
        {
          vty_out (vty, "bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        }
      else
        {
          bgp_flag_unset (bgp, BGP_FLAG_DETERMINISTIC_MED);
          bgp_recalculate_all_bestpaths (bgp);
        }
    }

  return CMD_SUCCESS;
}

/* "bgp graceful-restart" configuration. */
DEFUN (bgp_graceful_restart,
       bgp_graceful_restart_cmd,
       "bgp graceful-restart",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_GRACEFUL_RESTART);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart,
       no_bgp_graceful_restart_cmd,
       "no bgp graceful-restart",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_GRACEFUL_RESTART);
  return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_stalepath_time,
       bgp_graceful_restart_stalepath_time_cmd,
       "bgp graceful-restart stalepath-time <1-3600>",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")
{
  struct bgp *bgp;
  u_int32_t stalepath;

  bgp = vty->index;
  if (! bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("stalepath-time", stalepath, argv[0], 1, 3600);
  bgp->stalepath_time = stalepath;
  return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_cmd,
       "no bgp graceful-restart stalepath-time",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  if (! bgp)
    return CMD_WARNING;

  bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_val_cmd,
       "no bgp graceful-restart stalepath-time <1-3600>",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")

/* "bgp fast-external-failover" configuration. */
DEFUN (bgp_fast_external_failover,
       bgp_fast_external_failover_cmd,
       "bgp fast-external-failover",
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_fast_external_failover,
       no_bgp_fast_external_failover_cmd,
       "no bgp fast-external-failover",
       NO_STR
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
  return CMD_SUCCESS;
}

/* "bgp enforce-first-as" configuration. */
DEFUN (bgp_enforce_first_as,
       bgp_enforce_first_as_cmd,
       "bgp enforce-first-as",
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ENFORCE_FIRST_AS);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_enforce_first_as,
       no_bgp_enforce_first_as_cmd,
       "no bgp enforce-first-as",
       NO_STR
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ENFORCE_FIRST_AS);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}

/* "bgp bestpath compare-routerid" configuration.  */
DEFUN (bgp_bestpath_compare_router_id,
       bgp_bestpath_compare_router_id_cmd,
       "bgp bestpath compare-routerid",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_COMPARE_ROUTER_ID);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_compare_router_id,
       no_bgp_bestpath_compare_router_id_cmd,
       "no bgp bestpath compare-routerid",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_COMPARE_ROUTER_ID);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

/* "bgp bestpath as-path ignore" configuration.  */
DEFUN (bgp_bestpath_aspath_ignore,
       bgp_bestpath_aspath_ignore_cmd,
       "bgp bestpath as-path ignore",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ASPATH_IGNORE);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_ignore,
       no_bgp_bestpath_aspath_ignore_cmd,
       "no bgp bestpath as-path ignore",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ASPATH_IGNORE);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

/* "bgp bestpath as-path confed" configuration.  */
DEFUN (bgp_bestpath_aspath_confed,
       bgp_bestpath_aspath_confed_cmd,
       "bgp bestpath as-path confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ASPATH_CONFED);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_confed,
       no_bgp_bestpath_aspath_confed_cmd,
       "no bgp bestpath as-path confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ASPATH_CONFED);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

/* "bgp bestpath as-path multipath-relax" configuration.  */
DEFUN (bgp_bestpath_aspath_multipath_relax,
       bgp_bestpath_aspath_multipath_relax_cmd,
       "bgp bestpath as-path multipath-relax {as-set|no-as-set}",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX);

  /* no-as-set is now the default behavior so we can silently
   * ignore it */
  if (argv[0] != NULL && strncmp (argv[0], "a", 1) == 0)
    bgp_flag_set (bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
  else
    bgp_flag_unset (bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET) ;

  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_multipath_relax,
       no_bgp_bestpath_aspath_multipath_relax_cmd,
       "no bgp bestpath as-path multipath-relax {as-set|no-as-set}",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
  bgp_flag_unset (bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

/* "bgp log-neighbor-changes" configuration.  */
DEFUN (bgp_log_neighbor_changes,
       bgp_log_neighbor_changes_cmd,
       "bgp log-neighbor-changes",
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_log_neighbor_changes,
       no_bgp_log_neighbor_changes_cmd,
       "no bgp log-neighbor-changes",
       NO_STR
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
  return CMD_SUCCESS;
}

/* "bgp bestpath med" configuration. */
DEFUN (bgp_bestpath_med,
       bgp_bestpath_med_cmd,
       "bgp bestpath med (confed|missing-as-worst)",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;
  
  bgp = vty->index;

  if (strncmp (argv[0], "confed", 1) == 0)
    bgp_flag_set (bgp, BGP_FLAG_MED_CONFED);
  else
    bgp_flag_set (bgp, BGP_FLAG_MED_MISSING_AS_WORST);

  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (bgp_bestpath_med2,
       bgp_bestpath_med2_cmd,
       "bgp bestpath med confed missing-as-worst",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;
  
  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_MED_CONFED);
  bgp_flag_set (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

ALIAS (bgp_bestpath_med2,
       bgp_bestpath_med3_cmd,
       "bgp bestpath med missing-as-worst confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

DEFUN (no_bgp_bestpath_med,
       no_bgp_bestpath_med_cmd,
       "no bgp bestpath med (confed|missing-as-worst)",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  
  if (strncmp (argv[0], "confed", 1) == 0)
    bgp_flag_unset (bgp, BGP_FLAG_MED_CONFED);
  else
    bgp_flag_unset (bgp, BGP_FLAG_MED_MISSING_AS_WORST);

  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_med2,
       no_bgp_bestpath_med2_cmd,
       "no bgp bestpath med confed missing-as-worst",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;
  
  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_MED_CONFED);
  bgp_flag_unset (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
  bgp_recalculate_all_bestpaths (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_bestpath_med2,
       no_bgp_bestpath_med3_cmd,
       "no bgp bestpath med missing-as-worst confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

/* "no bgp default ipv4-unicast". */
DEFUN (no_bgp_default_ipv4_unicast,
       no_bgp_default_ipv4_unicast_cmd,
       "no bgp default ipv4-unicast",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

DEFUN (bgp_default_ipv4_unicast,
       bgp_default_ipv4_unicast_cmd,
       "bgp default ipv4-unicast",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

/* Display hostname in certain command outputs */
DEFUN (bgp_default_show_hostname,
       bgp_default_show_hostname_cmd,
       "bgp default show-hostname",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Show hostname in certain command ouputs\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_SHOW_HOSTNAME);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_default_show_hostname,
       no_bgp_default_show_hostname_cmd,
       "no bgp default show-hostname",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Show hostname in certain command ouputs\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_SHOW_HOSTNAME);
  return CMD_SUCCESS;
}

/* "bgp network import-check" configuration.  */
DEFUN (bgp_network_import_check,
       bgp_network_import_check_cmd,
       "bgp network import-check",
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  if (!bgp_flag_check(bgp, BGP_FLAG_IMPORT_CHECK))
    {
      bgp_flag_set (bgp, BGP_FLAG_IMPORT_CHECK);
      bgp_static_redo_import_check(bgp);
    }

  return CMD_SUCCESS;
}

ALIAS_HIDDEN (bgp_network_import_check,
              bgp_network_import_check_exact_cmd,
              "bgp network import-check exact",
              "BGP specific commands\n"
              "BGP network command\n"
              "Check BGP network route exists in IGP\n"
              "Match route precisely\n")

DEFUN (no_bgp_network_import_check,
       no_bgp_network_import_check_cmd,
       "no bgp network import-check",
       NO_STR
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  if (bgp_flag_check(bgp, BGP_FLAG_IMPORT_CHECK))
    {
      bgp_flag_unset (bgp, BGP_FLAG_IMPORT_CHECK);
      bgp_static_redo_import_check(bgp);
    }

  return CMD_SUCCESS;
}

DEFUN (bgp_default_local_preference,
       bgp_default_local_preference_cmd,
       "bgp default local-preference <0-4294967295>",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
  struct bgp *bgp;
  u_int32_t local_pref;

  bgp = vty->index;

  VTY_GET_INTEGER ("local preference", local_pref, argv[0]);

  bgp_default_local_preference_set (bgp, local_pref);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_default_local_preference,
       no_bgp_default_local_preference_cmd,
       "no bgp default local-preference",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_default_local_preference_unset (bgp);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_default_local_preference,
       no_bgp_default_local_preference_val_cmd,
       "no bgp default local-preference <0-4294967295>",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")

DEFUN (bgp_default_subgroup_pkt_queue_max,
       bgp_default_subgroup_pkt_queue_max_cmd,
       "bgp default subgroup-pkt-queue-max <20-100>",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")
{
  struct bgp *bgp;
  u_int32_t max_size;

  bgp = vty->index;

  VTY_GET_INTEGER ("subgroup packet queue max", max_size, argv[0]);

  bgp_default_subgroup_pkt_queue_max_set (bgp, max_size);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_default_subgroup_pkt_queue_max,
       no_bgp_default_subgroup_pkt_queue_max_cmd,
       "no bgp default subgroup-pkt-queue-max",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_default_subgroup_pkt_queue_max_unset (bgp);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_default_subgroup_pkt_queue_max,
       no_bgp_default_subgroup_pkt_queue_max_val_cmd,
       "no bgp default subgroup-pkt-queue-max <20-100>",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")

DEFUN (bgp_rr_allow_outbound_policy,
       bgp_rr_allow_outbound_policy_cmd,
       "bgp route-reflector allow-outbound-policy",
       "BGP specific commands\n"
       "Allow modifications made by out route-map\n"
       "on ibgp neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (!bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
    {
      bgp_flag_set(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
      update_group_announce_rrclients(bgp);
      bgp_clear_star_soft_out (vty);
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_rr_allow_outbound_policy,
       no_bgp_rr_allow_outbound_policy_cmd,
       "no bgp route-reflector allow-outbound-policy",
       NO_STR
       "BGP specific commands\n"
       "Allow modifications made by out route-map\n"
       "on ibgp neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
    {
      bgp_flag_unset(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
      update_group_announce_rrclients(bgp);
      bgp_clear_star_soft_out (vty);
    }

  return CMD_SUCCESS;
}

DEFUN (bgp_listen_limit,
       bgp_listen_limit_cmd,
       "bgp listen limit " DYNAMIC_NEIGHBOR_LIMIT_RANGE,
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value\n")
{
  struct bgp *bgp;
  int listen_limit;

  bgp = vty->index;

  VTY_GET_INTEGER_RANGE ("listen limit", listen_limit, argv[0],
                         BGP_DYNAMIC_NEIGHBORS_LIMIT_MIN,
                         BGP_DYNAMIC_NEIGHBORS_LIMIT_MAX);

  bgp_listen_limit_set (bgp, listen_limit);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_listen_limit,
       no_bgp_listen_limit_cmd,
       "no bgp listen limit",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "unset maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value to default\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_listen_limit_unset (bgp);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_listen_limit,
       no_bgp_listen_limit_val_cmd,
       "no bgp listen limit " DYNAMIC_NEIGHBOR_LIMIT_RANGE,
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value\n")

/*
 * Check if this listen range is already configured. Check for exact
 * match or overlap based on input.
 */
static struct peer_group *
listen_range_exists (struct bgp *bgp, struct prefix *range, int exact)
{
  struct listnode *node, *nnode;
  struct listnode *node1, *nnode1;
  struct peer_group *group;
  struct prefix *lr;
  afi_t afi;
  int match;

  afi = family2afi(range->family);
  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    {
      for (ALL_LIST_ELEMENTS (group->listen_range[afi], node1,
                              nnode1, lr))
        {
          if (exact)
            match = prefix_same (range, lr);
          else
            match = (prefix_match (range, lr) || prefix_match (lr, range));
          if (match)
            return group;
        }
    }

  return NULL;
}

DEFUN (bgp_listen_range,
       bgp_listen_range_cmd,
       LISTEN_RANGE_CMD "peer-group WORD" ,
       "BGP specific commands\n"
       "Configure BGP Dynamic Neighbors\n"
       "add a listening range for Dynamic Neighbors\n"
       LISTEN_RANGE_ADDR_STR)
{
  struct bgp *bgp;
  struct prefix range;
  struct peer_group *group, *existing_group;
  afi_t afi;
  int ret;

  bgp = vty->index;

  //VTY_GET_IPV4_PREFIX ("listen range", range, argv[0]);

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (argv[0], &range);
  if (! ret)
    {
      vty_out (vty, "%% Malformed listen range%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  afi = family2afi(range.family);

#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&range.u.prefix6))
    {
      vty_out (vty, "%% Malformed listen range (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&range);

  /* Check if same listen range is already configured. */
  existing_group = listen_range_exists (bgp, &range, 1);
  if (existing_group)
    {
      if (strcmp (existing_group->name, argv[1]) == 0)
        return CMD_SUCCESS;
      else
        {
          vty_out (vty, "%% Same listen range is attached to peer-group %s%s",
                   existing_group->name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Check if an overlapping listen range exists. */
  if (listen_range_exists (bgp, &range, 0))
    {
      vty_out (vty, "%% Listen range overlaps with existing listen range%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  group = peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_listen_range_add(group, &range);
  return bgp_vty_return (vty, ret);
}

DEFUN (no_bgp_listen_range,
       no_bgp_listen_range_cmd,
       "no bgp listen range A.B.C.D/M peer-group WORD" ,
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "delete a listening range for Dynamic Neighbors\n"
       "Remove Dynamic Neighbors listening range\n")
{
  struct bgp *bgp;
  struct prefix range;
  struct peer_group *group;
  afi_t afi;
  int ret;

  bgp = vty->index;

  // VTY_GET_IPV4_PREFIX ("listen range", range, argv[0]);

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (argv[0], &range);
  if (! ret)
    {
      vty_out (vty, "%% Malformed listen range%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  afi = family2afi(range.family);

#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&range.u.prefix6))
    {
      vty_out (vty, "%% Malformed listen range (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&range);


  group = peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Peer-group does not exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_listen_range_del(group, &range);
  return bgp_vty_return (vty, ret);
}

int
bgp_config_write_listen (struct vty *vty, struct bgp *bgp)
{
  struct peer_group *group;
  struct listnode *node, *nnode, *rnode, *nrnode;
  struct prefix *range;
  afi_t afi;
  char buf[PREFIX2STR_BUFFER];

  if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
      vty_out (vty, " bgp listen limit %d%s",
               bgp->dynamic_neighbors_limit, VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    {
      for (afi = AFI_IP; afi < AFI_MAX; afi++)
        {
          for (ALL_LIST_ELEMENTS (group->listen_range[afi], rnode, nrnode, range))
            {
              prefix2str(range, buf, sizeof(buf));
              vty_out(vty, " bgp listen range %s peer-group %s%s",
                      buf, group->name, VTY_NEWLINE);
            }
        }
    }

  return 0;
}


DEFUN (bgp_disable_connected_route_check,
       bgp_disable_connected_route_check_cmd,
       "bgp disable-ebgp-connected-route-check",
       "BGP specific commands\n"
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_disable_connected_route_check,
       no_bgp_disable_connected_route_check_cmd,
       "no bgp disable-ebgp-connected-route-check",
       NO_STR
       "BGP specific commands\n"
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
  bgp_clear_star_soft_in (vty);

  return CMD_SUCCESS;
}


static int
peer_remote_as_vty (struct vty *vty, const char *peer_str, 
                    const char *as_str, afi_t afi, safi_t safi)
{
  int ret;
  struct bgp *bgp;
  as_t as;
  int as_type = AS_SPECIFIED;
  union sockunion su;

  bgp = vty->index;

  if (strncmp(as_str, "internal", strlen("internal")) == 0)
    {
      as = 0;
      as_type = AS_INTERNAL;
    }
  else if (strncmp(as_str, "external", strlen("external")) == 0)
    {
      as = 0;
      as_type = AS_EXTERNAL;
    }
  else
    {
      /* Get AS number.  */
      VTY_GET_INTEGER_RANGE ("AS", as, as_str, 1, BGP_AS4_MAX);
    }

  /* If peer is peer group, call proper function.  */
  ret = str2sockunion (peer_str, &su);
  if (ret < 0)
    {
      /* Check for peer by interface */
      ret = peer_remote_as (bgp, NULL, peer_str, &as, as_type, afi, safi);
      if (ret < 0)
        {
          ret = peer_group_remote_as (bgp, peer_str, &as, as_type);
          if (ret < 0)
            {
              vty_out (vty, "%% Create the peer-group or interface first%s",
                       VTY_NEWLINE);
              return CMD_WARNING;
            }
          return CMD_SUCCESS;
        }
    }
  else
    {
      if (peer_address_self_check (bgp, &su))
        {
          vty_out (vty, "%% Can not configure the local system as neighbor%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        }
      ret = peer_remote_as (bgp, &su, NULL, &as, as_type, afi, safi);
    }

  /* This peer belongs to peer group.  */
  switch (ret)
    {
    case BGP_ERR_PEER_GROUP_MEMBER:
      vty_out (vty, "%% Peer-group AS %u. Cannot configure remote-as for member%s", as, VTY_NEWLINE);
      return CMD_WARNING;
    case BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
      vty_out (vty, "%% The AS# can not be changed from %u to %s, peer-group members must be all internal or all external%s", as, as_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       NEIGHBOR_CMD2 "remote-as (" CMD_AS_RANGE "|external|internal)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_remote_as_vty (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST);
}

static int
peer_conf_interface_get (struct vty *vty, const char *conf_if, afi_t afi,
                         safi_t safi, int v6only, const char *peer_group_name)
{
  as_t as;
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;
  int ret = 0;
  union sockunion su;

  bgp = vty->index;
  group = peer_group_lookup (bgp, conf_if);

  if (group)
    {
      vty_out (vty, "%% Name conflict with peer-group %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup_by_conf_if (bgp, conf_if);
  if (!peer)
    {
      if (bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4)
          && afi == AFI_IP && safi == SAFI_UNICAST)
        peer = peer_create (NULL, conf_if, bgp, bgp->as, 0, AS_UNSPECIFIED, 0, 0, NULL);
      else
        peer = peer_create (NULL, conf_if, bgp, bgp->as, 0, AS_UNSPECIFIED, afi, safi, NULL);

      if (peer && v6only)
        SET_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY);

      /* Request zebra to initiate IPv6 RAs on this interface. We do this
       * any unnumbered peer in order to not worry about run-time transitions
       * (e.g., peering is initially IPv4, but the IPv4 /30 or /31 address
       * gets deleted later etc.)
       */
      if (peer->ifp)
        bgp_zebra_initiate_radv (bgp, peer);
    }
  else if ((v6only && !CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY)) ||
           (!v6only && CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY)))
    {
      if (v6only)
        SET_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY);
      else
        UNSET_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY);

      /* v6only flag changed. Reset bgp seesion */
      if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status))
        {
          peer->last_reset = PEER_DOWN_V6ONLY_CHANGE;
          bgp_notify_send (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_CONFIG_CHANGE);
        }
      else
        bgp_session_reset(peer);
    }

  if (!peer)
    return CMD_WARNING;

  if (peer_group_name)
    {
      group = peer_group_lookup (bgp, peer_group_name);
      if (! group)
        {
          vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      ret = peer_group_bind (bgp, &su, peer, group, &as);
    }

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_interface_config,
       neighbor_interface_config_cmd,
       "neighbor WORD interface",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n")
{
  if (argc == 2)
    return peer_conf_interface_get (vty, argv[0], AFI_IP, SAFI_UNICAST, 0, argv[1]);
  else
    return peer_conf_interface_get (vty, argv[0], AFI_IP, SAFI_UNICAST, 0, NULL);
}

ALIAS (neighbor_interface_config,
       neighbor_interface_config_peergroup_cmd,
       "neighbor WORD interface peer-group WORD",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Member of the peer-group\n"
       "peer-group name\n")

DEFUN (neighbor_interface_config_v6only,
       neighbor_interface_config_v6only_cmd,
       "neighbor WORD interface v6only",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Enable BGP with v6 link-local only\n")
{
  if (argc == 2)
    return peer_conf_interface_get (vty, argv[0], AFI_IP, SAFI_UNICAST, 1, argv[1]);
  else
    return peer_conf_interface_get (vty, argv[0], AFI_IP, SAFI_UNICAST, 1, NULL);
}

ALIAS (neighbor_interface_config_v6only,
       neighbor_interface_config_v6only_peergroup_cmd,
       "neighbor WORD interface v6only peer-group WORD",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "peer-group name\n")

DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Configure peer-group\n")
{
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;

  bgp = vty->index;
  peer = peer_lookup_by_conf_if (bgp, argv[0]);
  if (peer)
    {
      vty_out (vty, "%% Name conflict with interface: %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  group = peer_group_get (bgp, argv[0]);
  if (! group)
    return CMD_WARNING;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       NO_NEIGHBOR_CMD2,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2)
{
  int ret;
  union sockunion su;
  struct peer_group *group;
  struct peer *peer;
  struct peer *other;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      /* look up for neighbor by interface name config. */
      peer = peer_lookup_by_conf_if (vty->index, argv[0]);
      if (peer)
        {
          /* Request zebra to terminate IPv6 RAs on this interface. */
          if (peer->ifp)
            bgp_zebra_terminate_radv (peer->bgp, peer);
          peer_delete (peer);
          return CMD_SUCCESS;
        }

      group = peer_group_lookup (vty->index, argv[0]);
      if (group)
	peer_group_delete (group);
      else
	{
	  vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      peer = peer_lookup (vty->index, &su);
      if (peer)
	{
          if (peer_dynamic_neighbor (peer))
            {
              vty_out (vty, "%% Operation not allowed on a dynamic neighbor%s",
                       VTY_NEWLINE);
              return CMD_WARNING;
            }

	  other = peer->doppelganger;
	  peer_delete (peer);
	  if (other && other->status != Deleted)
	    peer_delete(other);
	}
    }

  return CMD_SUCCESS;
}

ALIAS (no_neighbor,
       no_neighbor_remote_as_cmd,
       NO_NEIGHBOR_CMD "remote-as (" CMD_AS_RANGE "|internal|external)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)

DEFUN (no_neighbor_interface_config,
       no_neighbor_interface_config_cmd,
       "no neighbor WORD interface",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n")
{
  struct peer *peer;

  /* look up for neighbor by interface name config. */
  peer = peer_lookup_by_conf_if (vty->index, argv[0]);
  if (peer)
    {
      /* Request zebra to terminate IPv6 RAs on this interface. */
      if (peer->ifp)
        bgp_zebra_terminate_radv (peer->bgp, peer);
      peer_delete (peer);
    }
  else
    {
      vty_out (vty, "%% Create the bgp interface first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

ALIAS (no_neighbor_interface_config,
       no_neighbor_interface_config_peergroup_cmd,
       "no neighbor WORD interface peer-group WORD",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n"
       "Member of the peer-group\n"
       "peer-group name\n")

ALIAS (no_neighbor_interface_config,
       no_neighbor_interface_config_v6only_cmd,
       "no neighbor WORD interface v6only",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n"
       "Enable BGP with v6 link-local only\n")

ALIAS (no_neighbor_interface_config,
       no_neighbor_interface_config_v6only_peergroup_cmd,
       "no neighbor WORD interface v6only peer-group WORD",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "peer-group name\n")


DEFUN (no_neighbor_peer_group,
       no_neighbor_peer_group_cmd,
       "no neighbor WORD peer-group",
       NO_STR
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
  struct peer_group *group;

  group = peer_group_lookup (vty->index, argv[0]);
  if (group)
    peer_group_delete (group);
  else
    {
      vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_neighbor_interface_peer_group_remote_as,
       no_neighbor_interface_peer_group_remote_as_cmd,
       "no neighbor WORD remote-as (" CMD_AS_RANGE "|internal|external)",
       NO_STR
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Specify a BGP neighbor\n"
       AS_STR)
{
  struct peer_group *group;
  struct peer *peer;

  /* look up for neighbor by interface name config. */
  peer = peer_lookup_by_conf_if (vty->index, argv[0]);
  if (peer)
    {
      peer_as_change (peer, 0, AS_SPECIFIED);
      return CMD_SUCCESS;
    }

  group = peer_group_lookup (vty->index, argv[0]);
  if (group)
    peer_group_remote_as_delete (group);
  else
    {
      vty_out (vty, "%% Create the peer-group or interface first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_local_as,
       neighbor_local_as_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_set (peer, atoi (argv[1]), 0, 0);
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_local_as_no_prepend,
       neighbor_local_as_no_prepend_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_set (peer, atoi (argv[1]), 1, 0);
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_local_as_no_prepend_replace_as,
       neighbor_local_as_no_prepend_replace_as_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend replace-as",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_set (peer, atoi (argv[1]), 1, 1);
  return bgp_vty_return (vty, ret);
}


DEFUN (no_neighbor_local_as,
       no_neighbor_local_as_cmd,
       NO_NEIGHBOR_CMD2 "local-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_unset (peer);
  return bgp_vty_return (vty, ret);
}

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val2_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val3_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend replace-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n")

DEFUN (neighbor_solo,
       neighbor_solo_cmd,
       NEIGHBOR_CMD2 "solo",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = update_group_adjust_soloness(peer, 1);
  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_solo,
       no_neighbor_solo_cmd,
       NO_NEIGHBOR_CMD2 "solo",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = update_group_adjust_soloness(peer, 0);
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_password,
       neighbor_password_cmd,
       NEIGHBOR_CMD2 "password LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_password_set (peer, argv[1]);
  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_password,
       no_neighbor_password_cmd,
       NO_NEIGHBOR_CMD2 "password",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_password_unset (peer);
  return bgp_vty_return (vty, ret);
}

ALIAS (no_neighbor_password,
       no_neighbor_password_val_cmd,
       NO_NEIGHBOR_CMD2 "password LINE",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       NEIGHBOR_CMD2 "activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_activate (peer, bgp_node_afi (vty), bgp_node_safi (vty));

  if (ret)
    return CMD_WARNING;
  return CMD_SUCCESS;
}

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       NO_NEIGHBOR_CMD2 "activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  int ret;
  struct peer *peer;

  /* Lookup peer. */
  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_deactivate (peer, bgp_node_afi (vty), bgp_node_safi (vty));

  if (ret)
    return CMD_WARNING;
  return CMD_SUCCESS;
}

DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       NEIGHBOR_CMD2 "peer-group WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "peer-group name\n")
{
  int ret;
  as_t as;
  union sockunion su;
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;

  bgp = vty->index;
  peer = NULL;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (bgp, argv[0]);
      if (!peer)
        {
          vty_out (vty, "%% Malformed address or name: %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      if (peer_address_self_check (bgp, &su))
        {
          vty_out (vty, "%% Can not configure the local system as neighbor%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        }

      /* Disallow for dynamic neighbor. */
      peer = peer_lookup (bgp, &su);
      if (peer && peer_dynamic_neighbor (peer))
        {
          vty_out (vty, "%% Operation not allowed on a dynamic neighbor%s",
	           VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  group = peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_bind (bgp, &su, peer, group, &as);

  if (ret == BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT)
    {
      vty_out (vty, "%% Peer with AS %u cannot be in this peer-group, members must be all internal or all external%s", as, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_cmd,
       NO_NEIGHBOR_CMD2 "peer-group WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "peer-group name\n")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;

  bgp = vty->index;

  peer = peer_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  group = peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_unbind (bgp, peer, group);

  return bgp_vty_return (vty, ret);
}

static int
peer_flag_modify_vty (struct vty *vty, const char *ip_str, 
                      u_int16_t flag, int set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  if (set)
    ret = peer_flag_set (peer, flag);
  else
    ret = peer_flag_unset (peer, flag);

  return bgp_vty_return (vty, ret);
}

static int
peer_flag_set_vty (struct vty *vty, const char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (vty, ip_str, flag, 1);
}

static int
peer_flag_unset_vty (struct vty *vty, const char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (vty, ip_str, flag, 0);
}

/* neighbor passive. */
DEFUN (neighbor_passive,
       neighbor_passive_cmd,
       NEIGHBOR_CMD2 "passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_PASSIVE);
}

DEFUN (no_neighbor_passive,
       no_neighbor_passive_cmd,
       NO_NEIGHBOR_CMD2 "passive",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_PASSIVE);
}

/* neighbor shutdown. */
DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       NEIGHBOR_CMD2 "shutdown",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_SHUTDOWN);
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       NO_NEIGHBOR_CMD2 "shutdown",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_SHUTDOWN);
}

/* neighbor capability dynamic. */
DEFUN (neighbor_capability_dynamic,
       neighbor_capability_dynamic_cmd,
       NEIGHBOR_CMD2 "capability dynamic",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

DEFUN (no_neighbor_capability_dynamic,
       no_neighbor_capability_dynamic_cmd,
       NO_NEIGHBOR_CMD2 "capability dynamic",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

/* neighbor dont-capability-negotiate */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       NEIGHBOR_CMD2 "dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       NO_NEIGHBOR_CMD2 "dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

/* neighbor capability extended next hop encoding */
DEFUN (neighbor_capability_enhe,
       neighbor_capability_enhe_cmd,
       NEIGHBOR_CMD2 "capability extended-nexthop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_CAPABILITY_ENHE);
}

DEFUN (no_neighbor_capability_enhe,
       no_neighbor_capability_enhe_cmd,
       NO_NEIGHBOR_CMD2 "capability extended-nexthop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_CAPABILITY_ENHE);
}

static int
peer_af_flag_modify_vty (struct vty *vty, const char *peer_str, afi_t afi,
			 safi_t safi, u_int32_t flag, int set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (! peer)
    return CMD_WARNING;

  if (set)
    ret = peer_af_flag_set (peer, afi, safi, flag);
  else
    ret = peer_af_flag_unset (peer, afi, safi, flag);

  return bgp_vty_return (vty, ret);
}

static int
peer_af_flag_set_vty (struct vty *vty, const char *peer_str, afi_t afi,
		      safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify_vty (vty, peer_str, afi, safi, flag, 1);
}

static int
peer_af_flag_unset_vty (struct vty *vty, const char *peer_str, afi_t afi,
			safi_t safi, u_int32_t flag)
{
  return peer_af_flag_modify_vty (vty, peer_str, afi, safi, flag, 0);
}

/* neighbor capability orf prefix-list. */
DEFUN (neighbor_capability_orf_prefix,
       neighbor_capability_orf_prefix_cmd,
       NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  u_int16_t flag = 0;

  if (strncmp (argv[1], "s", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM;
  else if (strncmp (argv[1], "r", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_RM;
  else if (strncmp (argv[1], "b", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM|PEER_FLAG_ORF_PREFIX_RM;
  else
    return CMD_WARNING;

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flag);
}

DEFUN (no_neighbor_capability_orf_prefix,
       no_neighbor_capability_orf_prefix_cmd,
       NO_NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  u_int16_t flag = 0;

  if (strncmp (argv[1], "s", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM;
  else if (strncmp (argv[1], "r", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_RM;
  else if (strncmp (argv[1], "b", 1) == 0)
    flag = PEER_FLAG_ORF_PREFIX_SM|PEER_FLAG_ORF_PREFIX_RM;
  else
    return CMD_WARNING;

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty), flag);
}

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       NEIGHBOR_CMD2 "next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), PEER_FLAG_NEXTHOP_SELF);
}

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self_force,
       neighbor_nexthop_self_force_cmd,
       NEIGHBOR_CMD2 "next-hop-self force",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_FORCE_NEXTHOP_SELF);
}

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       NO_NEIGHBOR_CMD2 "next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_NEXTHOP_SELF);
}

DEFUN (no_neighbor_nexthop_self_force,
       no_neighbor_nexthop_self_force_cmd,
       NO_NEIGHBOR_CMD2 "next-hop-self force",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_FORCE_NEXTHOP_SELF);
}

/* neighbor as-override */
DEFUN (neighbor_as_override,
       neighbor_as_override_cmd,
       NEIGHBOR_CMD2 "as-override",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
                               bgp_node_safi (vty),
                               PEER_FLAG_AS_OVERRIDE);
}

DEFUN (no_neighbor_as_override,
       no_neighbor_as_override_cmd,
       NO_NEIGHBOR_CMD2 "as-override",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
                                 bgp_node_safi (vty),
                                 PEER_FLAG_AS_OVERRIDE);
}

/* neighbor remove-private-AS. */
DEFUN (neighbor_remove_private_as,
       neighbor_remove_private_as_cmd,
       NEIGHBOR_CMD2 "remove-private-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_REMOVE_PRIVATE_AS);
}

DEFUN (neighbor_remove_private_as_all,
       neighbor_remove_private_as_all_cmd,
       NEIGHBOR_CMD2 "remove-private-AS all",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
                               PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

DEFUN (neighbor_remove_private_as_replace_as,
       neighbor_remove_private_as_replace_as_cmd,
       NEIGHBOR_CMD2 "remove-private-AS replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
                               PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

DEFUN (neighbor_remove_private_as_all_replace_as,
       neighbor_remove_private_as_all_replace_as_cmd,
       NEIGHBOR_CMD2 "remove-private-AS all replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers"
       "Replace private ASNs with our ASN in outbound updates\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
                               PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

DEFUN (no_neighbor_remove_private_as,
       no_neighbor_remove_private_as_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_REMOVE_PRIVATE_AS);
}

DEFUN (no_neighbor_remove_private_as_all,
       no_neighbor_remove_private_as_all_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS all",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

DEFUN (no_neighbor_remove_private_as_replace_as,
       no_neighbor_remove_private_as_replace_as_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

DEFUN (no_neighbor_remove_private_as_all_replace_as,
       no_neighbor_remove_private_as_all_replace_as_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS all replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers"
       "Replace private ASNs with our ASN in outbound updates\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}


/* neighbor send-community. */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       NEIGHBOR_CMD2 "send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_SEND_COMMUNITY);
}

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       NO_NEIGHBOR_CMD2 "send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_SEND_COMMUNITY);
}

/* neighbor send-community extended. */
DEFUN (neighbor_send_community_type,
       neighbor_send_community_type_cmd,
       NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  if (strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_SEND_COMMUNITY);
  if (strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_SEND_EXT_COMMUNITY);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       (PEER_FLAG_SEND_COMMUNITY|
				PEER_FLAG_SEND_EXT_COMMUNITY));
}

DEFUN (no_neighbor_send_community_type,
       no_neighbor_send_community_type_cmd,
       NO_NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  if (strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				   bgp_node_safi (vty),
				   PEER_FLAG_SEND_COMMUNITY);
  if (strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				   bgp_node_safi (vty),
				   PEER_FLAG_SEND_EXT_COMMUNITY);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 (PEER_FLAG_SEND_COMMUNITY |
				  PEER_FLAG_SEND_EXT_COMMUNITY));
}

/* neighbor soft-reconfig. */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0],
			       bgp_node_afi (vty), bgp_node_safi (vty),
			       PEER_FLAG_SOFT_RECONFIG);
}

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       NO_NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0],
				 bgp_node_afi (vty), bgp_node_safi (vty),
				 PEER_FLAG_SOFT_RECONFIG);
}

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       NEIGHBOR_CMD2 "route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  struct peer *peer;


  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_REFLECTOR_CLIENT);
}

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       NO_NEIGHBOR_CMD2 "route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_REFLECTOR_CLIENT);
}

/* neighbor route-server-client. */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       NEIGHBOR_CMD2 "route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
                               bgp_node_safi (vty),
                               PEER_FLAG_RSERVER_CLIENT);
}

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       NO_NEIGHBOR_CMD2 "route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
                                 bgp_node_safi (vty),
                                 PEER_FLAG_RSERVER_CLIENT);
}

DEFUN (neighbor_nexthop_local_unchanged,
       neighbor_nexthop_local_unchanged_cmd,
       NEIGHBOR_CMD2 "nexthop-local unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
                                bgp_node_safi (vty),
                                PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED );
}

DEFUN (no_neighbor_nexthop_local_unchanged,
       no_neighbor_nexthop_local_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "nexthop-local unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local-nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
                                PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED );
}

DEFUN (neighbor_attr_unchanged,
       neighbor_attr_unchanged_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       (PEER_FLAG_AS_PATH_UNCHANGED |
				PEER_FLAG_NEXTHOP_UNCHANGED |
				PEER_FLAG_MED_UNCHANGED));
}

DEFUN (neighbor_attr_unchanged1,
       neighbor_attr_unchanged1_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = 0;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);
}

DEFUN (neighbor_attr_unchanged2,
       neighbor_attr_unchanged2_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_FLAG_AS_PATH_UNCHANGED;

  if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);

}

DEFUN (neighbor_attr_unchanged3,
       neighbor_attr_unchanged3_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_FLAG_NEXTHOP_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);
}

DEFUN (neighbor_attr_unchanged4,
       neighbor_attr_unchanged4_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  u_int16_t flags = PEER_FLAG_MED_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);
}

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged5_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged6_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged7_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged8_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged9_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged10_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

DEFUN (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged",
       NO_STR	 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 (PEER_FLAG_AS_PATH_UNCHANGED |
				  PEER_FLAG_NEXTHOP_UNCHANGED |
				  PEER_FLAG_MED_UNCHANGED));
}

DEFUN (no_neighbor_attr_unchanged1,
       no_neighbor_attr_unchanged1_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = 0;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty), flags);
}

DEFUN (no_neighbor_attr_unchanged2,
       no_neighbor_attr_unchanged2_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_FLAG_AS_PATH_UNCHANGED;

  if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);
}

DEFUN (no_neighbor_attr_unchanged3,
       no_neighbor_attr_unchanged3_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_FLAG_NEXTHOP_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty), flags);
}

DEFUN (no_neighbor_attr_unchanged4,
       no_neighbor_attr_unchanged4_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  u_int16_t flags = PEER_FLAG_MED_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_FLAG_NEXTHOP_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty), flags);
}

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged5_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged6_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged7_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged8_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged9_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged10_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

/* EBGP multihop configuration. */
static int
peer_ebgp_multihop_set_vty (struct vty *vty, const char *ip_str, 
                            const char *ttl_str)
{
  struct peer *peer;
  unsigned int ttl;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  if (! ttl_str)
    ttl = MAXTTL;
  else
    VTY_GET_INTEGER_RANGE ("TTL", ttl, ttl_str, 1, MAXTTL);

  return bgp_vty_return (vty,  peer_ebgp_multihop_set (peer, ttl));
}

static int
peer_ebgp_multihop_unset_vty (struct vty *vty, const char *ip_str) 
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  return bgp_vty_return (vty, peer_ebgp_multihop_unset (peer));
}

/* neighbor ebgp-multihop. */
DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_set_vty (vty, argv[0], NULL);
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop " CMD_RANGE_STR(1, MAXTTL),
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_ttl_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop " CMD_RANGE_STR(1, MAXTTL),
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

/* disable-connected-check */
DEFUN (neighbor_disable_connected_check,
       neighbor_disable_connected_check_cmd,
       NEIGHBOR_CMD2 "disable-connected-check",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

DEFUN (no_neighbor_disable_connected_check,
       no_neighbor_disable_connected_check_cmd,
       NO_NEIGHBOR_CMD2 "disable-connected-check",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

/* Enforce multihop.  */
ALIAS (neighbor_disable_connected_check,
       neighbor_enforce_multihop_cmd,
       NEIGHBOR_CMD2 "enforce-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

/* Enforce multihop.  */
ALIAS (no_neighbor_disable_connected_check,
       no_neighbor_enforce_multihop_cmd,
       NO_NEIGHBOR_CMD2 "enforce-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

DEFUN (neighbor_description,
       neighbor_description_cmd,
       NEIGHBOR_CMD2 "description .LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  struct peer *peer;
  char *str;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 1)
    return CMD_SUCCESS;

  str = argv_concat(argv, argc, 1);

  peer_description_set (peer, str);

  XFREE (MTYPE_TMP, str);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       NO_NEIGHBOR_CMD2 "description",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  peer_description_unset (peer);

  return CMD_SUCCESS;
}

ALIAS (no_neighbor_description,
       no_neighbor_description_val_cmd,
       NO_NEIGHBOR_CMD2 "description .LINE",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

/* Neighbor update-source. */
static int
peer_update_source_vty (struct vty *vty, const char *peer_str, 
                        const char *source_str)
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (! peer)
    return CMD_WARNING;

  if (peer->conf_if)
    return CMD_WARNING;

  if (source_str)
    {
      union sockunion su;
      int ret = str2sockunion (source_str, &su);

      if (ret == 0)
	peer_update_source_addr_set (peer, &su);
      else
	peer_update_source_if_set (peer, source_str);
    }
  else
    peer_update_source_unset (peer);

  return CMD_SUCCESS;
}

#define BGP_UPDATE_SOURCE_STR "A.B.C.D|X:X::X:X|WORD"
#define BGP_UPDATE_SOURCE_REQ_STR "(" BGP_UPDATE_SOURCE_STR ")"
#define BGP_UPDATE_SOURCE_OPT_STR "{" BGP_UPDATE_SOURCE_STR "}"
#define BGP_UPDATE_SOURCE_HELP_STR \
  "IPv4 address\n" \
  "IPv6 address\n" \
  "Interface name (requires zebra to be running)\n"

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       NEIGHBOR_CMD2 "update-source " BGP_UPDATE_SOURCE_REQ_STR,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
  return peer_update_source_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       NO_NEIGHBOR_CMD2 "update-source " BGP_UPDATE_SOURCE_OPT_STR,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
  return peer_update_source_vty (vty, argv[0], NULL);
}

static int
peer_default_originate_set_vty (struct vty *vty, const char *peer_str, 
                                afi_t afi, safi_t safi, 
                                const char *rmap, int set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (! peer)
    return CMD_WARNING;

  if (set)
    ret = peer_default_originate_set (peer, afi, safi, rmap);
  else
    ret = peer_default_originate_unset (peer, afi, safi);

  return bgp_vty_return (vty, ret);
}

/* neighbor default-originate. */
DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       NEIGHBOR_CMD2 "default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_afi (vty),
					 bgp_node_safi (vty), NULL, 1);
}

DEFUN (neighbor_default_originate_rmap,
       neighbor_default_originate_rmap_cmd,
       NEIGHBOR_CMD2 "default-originate route-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_afi (vty),
					 bgp_node_safi (vty), argv[1], 1);
}

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       NO_NEIGHBOR_CMD2 "default-originate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_afi (vty),
					 bgp_node_safi (vty), NULL, 0);
}

ALIAS (no_neighbor_default_originate,
       no_neighbor_default_originate_rmap_cmd,
       NO_NEIGHBOR_CMD2 "default-originate route-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")

/* Set neighbor's BGP port.  */
static int
peer_port_vty (struct vty *vty, const char *ip_str, int afi, 
               const char *port_str)
{
  struct peer *peer;
  u_int16_t port;
  struct servent *sp;

  peer = peer_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  if (! port_str)
    { 
      sp = getservbyname ("bgp", "tcp");
      port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);
    }
  else
    {
      VTY_GET_INTEGER("port", port, port_str);
    }

  peer_port_set (peer, port);

  return CMD_SUCCESS;
}

/* Set specified peer's BGP port.  */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       NEIGHBOR_CMD "port <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
  return peer_port_vty (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       NO_NEIGHBOR_CMD "port",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")
{
  return peer_port_vty (vty, argv[0], AFI_IP, NULL);
}

ALIAS (no_neighbor_port,
       no_neighbor_port_val_cmd,
       NO_NEIGHBOR_CMD "port <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")

/* neighbor weight. */
static int
peer_weight_set_vty (struct vty *vty, const char *ip_str, 
                     const char *weight_str)
{
  int ret;
  struct peer *peer;
  unsigned long weight;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE("weight", weight, weight_str, 0, 65535);

  ret = peer_weight_set (peer, weight);
  return bgp_vty_return (vty, ret);
}

static int
peer_weight_unset_vty (struct vty *vty, const char *ip_str)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_weight_unset (peer);
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       NEIGHBOR_CMD2 "weight <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       NO_NEIGHBOR_CMD2 "weight",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n")
{
  return peer_weight_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_weight,
       no_neighbor_weight_val_cmd,
       NO_NEIGHBOR_CMD2 "weight <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

/* Override capability negotiation. */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       NEIGHBOR_CMD2 "override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       NO_NEIGHBOR_CMD2 "override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       NEIGHBOR_CMD "strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       NO_NEIGHBOR_CMD "strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

static int
peer_timers_set_vty (struct vty *vty, const char *ip_str, 
                     const char *keep_str, const char *hold_str)
{
  int ret;
  struct peer *peer;
  u_int32_t keepalive;
  u_int32_t holdtime;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("Keepalive", keepalive, keep_str, 0, 65535);
  VTY_GET_INTEGER_RANGE ("Holdtime", holdtime, hold_str, 0, 65535);

  ret = peer_timers_set (peer, keepalive, holdtime);

  return bgp_vty_return (vty, ret);
}

static int
peer_timers_unset_vty (struct vty *vty, const char *ip_str)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_timers_unset (peer);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_timers,
       neighbor_timers_cmd,
       NEIGHBOR_CMD2 "timers <0-65535> <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  return peer_timers_set_vty (vty, argv[0], argv[1], argv[2]);
}

DEFUN (no_neighbor_timers,
       no_neighbor_timers_cmd,
       NO_NEIGHBOR_CMD2 "timers",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n")
{
  return peer_timers_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_timers,
       no_neighbor_timers_val_cmd,
       NO_NEIGHBOR_CMD2 "timers <0-65535> <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

static int
peer_timers_connect_set_vty (struct vty *vty, const char *ip_str, 
                             const char *time_str)
{
  int ret;
  struct peer *peer;
  u_int32_t connect;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("Connect time", connect, time_str, 0, 65535);

  ret = peer_timers_connect_set (peer, connect);

  return bgp_vty_return (vty, ret);
}

static int
peer_timers_connect_unset_vty (struct vty *vty, const char *ip_str)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_timers_connect_unset (peer);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       NEIGHBOR_CMD2 "timers connect <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       NO_NEIGHBOR_CMD2 "timers connect",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n")
{
  return peer_timers_connect_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_timers_connect,
       no_neighbor_timers_connect_val_cmd,
       NO_NEIGHBOR_CMD2 "timers connect <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

static int
peer_advertise_interval_vty (struct vty *vty, const char *ip_str, 
                             const char *time_str, int set)  
{
  int ret;
  struct peer *peer;
  u_int32_t routeadv = 0;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  if (time_str)
    VTY_GET_INTEGER_RANGE ("advertise interval", routeadv, time_str, 0, 600);

  if (set)
    ret = peer_advertise_interval_set (peer, routeadv);
  else
    ret = peer_advertise_interval_unset (peer);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_advertise_interval,
       neighbor_advertise_interval_cmd,
       NEIGHBOR_CMD2 "advertisement-interval <0-600>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
  return peer_advertise_interval_vty (vty, argv[0], argv[1], 1);
}

DEFUN (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n")
{
  return peer_advertise_interval_vty (vty, argv[0], NULL, 0);
}

ALIAS (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_val_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval <0-600>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")

/* Time to wait before processing route-map updates */
DEFUN (bgp_set_route_map_delay_timer,
       bgp_set_route_map_delay_timer_cmd,
       "bgp route-map delay-timer <0-600>",
       SET_STR
       "BGP route-map delay timer\n"
       "Time in secs to wait before processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{
  u_int32_t rmap_delay_timer;

  if (argv[0])
    {
      VTY_GET_INTEGER_RANGE ("delay-timer", rmap_delay_timer, argv[0], 0, 600);
      bm->rmap_update_timer = rmap_delay_timer;

      /* if the dynamic update handling is being disabled, and a timer is
       * running, stop the timer and act as if the timer has already fired.
       */
      if (!rmap_delay_timer && bm->t_rmap_update )
	{
	  BGP_TIMER_OFF(bm->t_rmap_update);
	  thread_execute (bm->master, bgp_route_map_update_timer, NULL, 0);
	}
      return CMD_SUCCESS;
    }
  else
    return CMD_WARNING;
}

DEFUN (no_bgp_set_route_map_delay_timer,
       no_bgp_set_route_map_delay_timer_cmd,
       "no bgp route-map delay-timer",
       NO_STR
       "Default BGP route-map delay timer\n"
       "Reset to default time to wait for processing route-map changes\n")
{

  bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;

  return CMD_SUCCESS;
}

ALIAS (no_bgp_set_route_map_delay_timer,
       no_bgp_set_route_map_delay_timer_val_cmd,
       "no bgp route-map delay-timer <0-600>",
       NO_STR
       "Default BGP route-map delay timer\n"
       "Reset to default time to wait for processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")

/* neighbor interface */
static int
peer_interface_vty (struct vty *vty, const char *ip_str, const char *str)
{
  struct peer *peer;

  peer = peer_lookup_vty (vty, ip_str);
  if (! peer || peer->conf_if)
    return CMD_WARNING;

  if (str)
    peer_interface_set (peer, str);
  else
    peer_interface_unset (peer);

  return CMD_SUCCESS;
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       NEIGHBOR_CMD "interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  if (argc == 3)
    return peer_interface_vty (vty, argv[0], argv[1]);
  else
    return peer_interface_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_interface,
       no_neighbor_interface_cmd,
       NO_NEIGHBOR_CMD2 "interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return peer_interface_vty (vty, argv[0], NULL);
}

/* Set distribute list to the peer. */
static int
peer_distribute_set_vty (struct vty *vty, const char *ip_str, 
                         afi_t afi, safi_t safi,
			 const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_set (peer, afi, safi, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_distribute_unset_vty (struct vty *vty, const char *ip_str, afi_t afi,
			   safi_t safi, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_unset (peer, afi, safi, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_distribute_set_vty (vty, argv[0], bgp_node_afi (vty),
				  bgp_node_safi (vty), argv[1], argv[2]);
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       NO_NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_distribute_unset_vty (vty, argv[0], bgp_node_afi (vty),
				    bgp_node_safi (vty), argv[2]);
}

/* Set prefix list to the peer. */
static int
peer_prefix_list_set_vty (struct vty *vty, const char *ip_str, afi_t afi,
			  safi_t safi, const char *name_str, 
                          const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_set (peer, afi, safi, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_prefix_list_unset_vty (struct vty *vty, const char *ip_str, afi_t afi,
			    safi_t safi, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;
  
  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_unset (peer, afi, safi, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_prefix_list_set_vty (vty, argv[0], bgp_node_afi (vty),
				   bgp_node_safi (vty), argv[1], argv[2]);
}

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       NO_NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_prefix_list_unset_vty (vty, argv[0], bgp_node_afi (vty),
				     bgp_node_safi (vty), argv[2]);
}

static int
peer_aslist_set_vty (struct vty *vty, const char *ip_str, 
                     afi_t afi, safi_t safi,
		     const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_set (peer, afi, safi, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_aslist_unset_vty (struct vty *vty, const char *ip_str, 
                       afi_t afi, safi_t safi,
		       const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_unset (peer, afi, safi, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return peer_aslist_set_vty (vty, argv[0], bgp_node_afi (vty),
			      bgp_node_safi (vty), argv[1], argv[2]);
}

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       NO_NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return peer_aslist_unset_vty (vty, argv[0], bgp_node_afi (vty),
				bgp_node_safi (vty), argv[2]);
}

/* Set route-map to the peer. */
static int
peer_route_map_set_vty (struct vty *vty, const char *ip_str, 
                        afi_t afi, safi_t safi,
			const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = RMAP_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 2) == 0)
    direct = RMAP_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = RMAP_OUT;

  ret = peer_route_map_set (peer, afi, safi, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_route_map_unset_vty (struct vty *vty, const char *ip_str, afi_t afi,
			  safi_t safi, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = RMAP_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 2) == 0)
    direct = RMAP_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = RMAP_OUT;

  ret = peer_route_map_unset (peer, afi, safi, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       NEIGHBOR_CMD2 "route-map WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return peer_route_map_set_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty), argv[1], argv[2]);
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       NO_NEIGHBOR_CMD2 "route-map WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
  return peer_route_map_unset_vty (vty, argv[0], bgp_node_afi (vty),
				   bgp_node_safi (vty), argv[2]);
}

/* Set unsuppress-map to the peer. */
static int
peer_unsuppress_map_set_vty (struct vty *vty, const char *ip_str, afi_t afi,
			     safi_t safi, const char *name_str)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_unsuppress_map_set (peer, afi, safi, name_str);

  return bgp_vty_return (vty, ret);
}

/* Unset route-map from the peer. */
static int
peer_unsuppress_map_unset_vty (struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_unsuppress_map_unset (peer, afi, safi);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_unsuppress_map,
       neighbor_unsuppress_map_cmd,
       NEIGHBOR_CMD2 "unsuppress-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return peer_unsuppress_map_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1]);
}

DEFUN (no_neighbor_unsuppress_map,
       no_neighbor_unsuppress_map_cmd,
       NO_NEIGHBOR_CMD2 "unsuppress-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return peer_unsuppress_map_unset_vty (vty, argv[0], bgp_node_afi (vty),
					bgp_node_safi (vty));
}

static int
peer_maximum_prefix_set_vty (struct vty *vty, const char *ip_str, afi_t afi,
			     safi_t safi, const char *num_str,  
			     const char *threshold_str, int warning,
			     const char *restart_str)
{
  int ret;
  struct peer *peer;
  u_int32_t max;
  u_char threshold;
  u_int16_t restart;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER ("maximum number", max, num_str);
  if (threshold_str)
    threshold = atoi (threshold_str);
  else
    threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

  if (restart_str)
    restart = atoi (restart_str);
  else
    restart = 0;

  ret = peer_maximum_prefix_set (peer, afi, safi, max, threshold, warning, restart);

  return bgp_vty_return (vty, ret);
}

static int
peer_maximum_prefix_unset_vty (struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_maximum_prefix_unset (peer, afi, safi);

  return bgp_vty_return (vty, ret);
}

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], NULL, 0,
				      NULL);
}

DEFUN (neighbor_maximum_prefix_threshold,
       neighbor_maximum_prefix_threshold_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], argv[2], 0,
				      NULL);
}

DEFUN (neighbor_maximum_prefix_warning,
       neighbor_maximum_prefix_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], NULL, 1,
				      NULL);
}

DEFUN (neighbor_maximum_prefix_threshold_warning,
       neighbor_maximum_prefix_threshold_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], argv[2], 1, NULL);
}

DEFUN (neighbor_maximum_prefix_restart,
       neighbor_maximum_prefix_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], NULL, 0, argv[2]);
}

DEFUN (neighbor_maximum_prefix_threshold_restart,
       neighbor_maximum_prefix_threshold_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_afi (vty),
				      bgp_node_safi (vty), argv[1], argv[2], 0, argv[3]);
}

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n")
{
  return peer_maximum_prefix_unset_vty (vty, argv[0], bgp_node_afi (vty),
					bgp_node_safi (vty));
}
 
ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_val_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

/* "neighbor allowas-in" */
DEFUN (neighbor_allowas_in,
       neighbor_allowas_in_cmd,
       NEIGHBOR_CMD2 "allowas-in",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n")
{
  int ret;
  struct peer *peer;
  unsigned int allow_num;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 1)
    allow_num = 3;
  else
    VTY_GET_INTEGER_RANGE ("AS number", allow_num, argv[1], 1, 10);

  ret = peer_allowas_in_set (peer, bgp_node_afi (vty), bgp_node_safi (vty),
			     allow_num);

  return bgp_vty_return (vty, ret);
}

ALIAS (neighbor_allowas_in,
       neighbor_allowas_in_arg_cmd,
       NEIGHBOR_CMD2 "allowas-in <1-10>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n"
       "Number of occurances of AS number\n")

DEFUN (no_neighbor_allowas_in,
       no_neighbor_allowas_in_cmd,
       NO_NEIGHBOR_CMD2 "allowas-in",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n")
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_allowas_in_unset (peer, bgp_node_afi (vty), bgp_node_safi (vty));

  return bgp_vty_return (vty, ret);
}

ALIAS (no_neighbor_allowas_in,
       no_neighbor_allowas_in_val_cmd,
       NO_NEIGHBOR_CMD2 "allowas-in <1-10>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n"
       "Number of occurances of AS number\n")

DEFUN (neighbor_ttl_security,
       neighbor_ttl_security_cmd,
       NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  struct peer *peer;
  int gtsm_hops;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  VTY_GET_INTEGER_RANGE ("", gtsm_hops, argv[1], 1, 254);

  return bgp_vty_return (vty, peer_ttl_security_hops_set (peer, gtsm_hops));
}

DEFUN (no_neighbor_ttl_security,
       no_neighbor_ttl_security_cmd,
       NO_NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_vty_return (vty, peer_ttl_security_hops_unset (peer));
}

DEFUN (neighbor_addpath_tx_all_paths,
       neighbor_addpath_tx_all_paths_cmd,
       NEIGHBOR_CMD2 "addpath-tx-all-paths",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_ADDPATH_TX_ALL_PATHS);
}

DEFUN (no_neighbor_addpath_tx_all_paths,
       no_neighbor_addpath_tx_all_paths_cmd,
       NO_NEIGHBOR_CMD2 "addpath-tx-all-paths",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_ADDPATH_TX_ALL_PATHS);
}

DEFUN (neighbor_addpath_tx_bestpath_per_as,
       neighbor_addpath_tx_bestpath_per_as_cmd,
       NEIGHBOR_CMD2 "addpath-tx-bestpath-per-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_afi (vty),
			       bgp_node_safi (vty),
			       PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS);
}

DEFUN (no_neighbor_addpath_tx_bestpath_per_as,
       no_neighbor_addpath_tx_bestpath_per_as_cmd,
       NO_NEIGHBOR_CMD2 "addpath-tx-bestpath-per-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_afi (vty),
				 bgp_node_safi (vty),
				 PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS);
}


/* Address family configuration.  */
DEFUN (address_family_ipv4,
       address_family_ipv4_cmd,
       "address-family ipv4",
       "Enter Address Family command mode\n"
       "Address family\n")
{
  vty->node = BGP_IPV4_NODE;
  return CMD_SUCCESS;
}

DEFUN (address_family_ipv4_safi,
       address_family_ipv4_safi_cmd,
       "address-family ipv4 (unicast|multicast)",
       "Enter Address Family command mode\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    vty->node = BGP_IPV4M_NODE;
  else
    vty->node = BGP_IPV4_NODE;

  return CMD_SUCCESS;
}

DEFUN (address_family_ipv6,
       address_family_ipv6_cmd,
       "address-family ipv6",
       "Enter Address Family command mode\n"
       "Address family\n")
{
  vty->node = BGP_IPV6_NODE;
  return CMD_SUCCESS;
}

DEFUN (address_family_ipv6_safi,
       address_family_ipv6_safi_cmd,
       "address-family ipv6 (unicast|multicast)",
       "Enter Address Family command mode\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    vty->node = BGP_IPV6M_NODE;
  else
    vty->node = BGP_IPV6_NODE;

  return CMD_SUCCESS;
}

DEFUN (address_family_vpnv4,
       address_family_vpnv4_cmd,
       "address-family vpnv4",
       "Enter Address Family command mode\n"
       "Address family\n")
{
  vty->node = BGP_VPNV4_NODE;
  return CMD_SUCCESS;
}

ALIAS (address_family_vpnv4,
       address_family_vpnv4_unicast_cmd,
       "address-family vpnv4 unicast",
       "Enter Address Family command mode\n"
       "Address family\n"
       "Address Family Modifier\n")

DEFUN (exit_address_family,
       exit_address_family_cmd,
       "exit-address-family",
       "Exit from Address Family configuration mode\n")
{
  if (vty->node == BGP_IPV4_NODE
      || vty->node == BGP_IPV4M_NODE
      || vty->node == BGP_VPNV4_NODE
      || vty->node == BGP_IPV6_NODE
      || vty->node == BGP_IPV6M_NODE)
    vty->node = BGP_NODE;
  return CMD_SUCCESS;
}

/* Recalculate bestpath and re-advertise a prefix */
static int
bgp_clear_prefix (struct vty *vty, const char *view_name, const char *ip_str,
                  afi_t afi, safi_t safi, struct prefix_rd *prd)
{
  int ret;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_table *rib;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
        {
          vty_out (vty, "%% Can't find BGP instance %s%s", view_name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);
  rib = bgp->rib[afi][safi];

  if (safi == SAFI_MPLS_VPN)
    {
      for (rn = bgp_table_top (rib); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            {
              if ((rm = bgp_node_match (table, &match)) != NULL)
                {
                  if (rm->p.prefixlen == match.prefixlen)
                    {
                      SET_FLAG (rn->flags, BGP_NODE_USER_CLEAR);
                      bgp_process (bgp, rm, afi, safi);
                    }
                  bgp_unlock_node (rm);
                }
            }
        }
    }
  else
    {
      if ((rn = bgp_node_match (rib, &match)) != NULL)
        {
          if (rn->p.prefixlen == match.prefixlen)
            {
              SET_FLAG (rn->flags, BGP_NODE_USER_CLEAR);
              bgp_process (bgp, rn, afi, safi);
            }
          bgp_unlock_node (rn);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear ip bgp *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n")
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], 0, 0, clear_all, BGP_CLEAR_SOFT_NONE, NULL);    

  return bgp_clear_vty (vty, NULL, 0, 0, clear_all, BGP_CLEAR_SOFT_NONE, NULL);
}

ALIAS (clear_ip_bgp_all,
       clear_ip_bgp_instance_all_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " *",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_all_cmd,
       "clear bgp *",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_instance_all_cmd,
       "clear bgp " BGP_INSTANCE_CMD " *",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_ipv6_all_cmd,
       "clear bgp ipv6 *",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_instance_ipv6_all_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 *",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n")

DEFUN (clear_ip_bgp_peer,
       clear_ip_bgp_peer_cmd, 
       "clear ip bgp (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], 0, 0, clear_peer, BGP_CLEAR_SOFT_NONE, argv[2]);

  return bgp_clear_vty (vty, NULL, 0, 0, clear_peer, BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALIAS (clear_ip_bgp_peer,
       clear_ip_bgp_instance_peer_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_peer_cmd, 
       "clear bgp (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_instance_peer_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_ipv6_peer_cmd, 
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_instance_ipv6_peer_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD)",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n")

DEFUN (clear_ip_bgp_peer_group,
       clear_ip_bgp_peer_group_cmd, 
       "clear ip bgp peer-group WORD",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], 0, 0, clear_group, BGP_CLEAR_SOFT_NONE, argv[2]);

  return bgp_clear_vty (vty, NULL, 0, 0, clear_group, BGP_CLEAR_SOFT_NONE, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group,
       clear_ip_bgp_instance_peer_group_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_peer_group_cmd, 
       "clear bgp peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_instance_peer_group_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_ipv6_peer_group_cmd, 
       "clear bgp ipv6 peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_instance_ipv6_peer_group_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

DEFUN (clear_ip_bgp_external,
       clear_ip_bgp_external_cmd,
       "clear ip bgp external",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n")
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], 0, 0, clear_external, BGP_CLEAR_SOFT_NONE, NULL);

  return bgp_clear_vty (vty, NULL, 0, 0, clear_external, BGP_CLEAR_SOFT_NONE, NULL);
}

ALIAS (clear_ip_bgp_external,
       clear_ip_bgp_instance_external_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_external_cmd, 
       "clear bgp external",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_instance_external_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_ipv6_external_cmd, 
       "clear bgp ipv6 external",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_instance_ipv6_external_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n")

DEFUN (clear_ip_bgp_prefix,
       clear_ip_bgp_prefix_cmd,
       "clear ip bgp prefix A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear bestpath and re-advertise\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  if (argc == 3)
    return bgp_clear_prefix (vty, argv[1], argv[2], AFI_IP, SAFI_UNICAST, NULL);

  return bgp_clear_prefix (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL);
}

ALIAS (clear_ip_bgp_prefix,
       clear_ip_bgp_instance_prefix_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " prefix A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

ALIAS (clear_ip_bgp_prefix,
       clear_bgp_prefix_cmd,
       "clear bgp prefix A.B.C.D/M",
       CLEAR_STR
       BGP_STR
       "Clear bestpath and re-advertise\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

ALIAS (clear_ip_bgp_prefix,
       clear_bgp_instance_prefix_cmd,
       "clear bgp " BGP_INSTANCE_CMD " prefix A.B.C.D/M",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (clear_ip_bgp_as,
       clear_ip_bgp_as_cmd,
       "clear ip bgp " CMD_AS_RANGE,
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n")
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], 0, 0, clear_as, BGP_CLEAR_SOFT_NONE, argv[2]);

  return bgp_clear_vty (vty, NULL, 0, 0, clear_as, BGP_CLEAR_SOFT_NONE, argv[0]);
}       

ALIAS (clear_ip_bgp_as,
       clear_ip_bgp_instance_as_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE,
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_as_cmd,
       "clear bgp " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_instance_as_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_ipv6_as_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_instance_ipv6_as_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n")

/* Outbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_soft_out_cmd,
       "clear ip bgp * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_instance_all_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_out_cmd,
       "clear ip bgp * out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_instance_all_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_soft_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
			  BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_OUT, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_out,
       clear_ip_bgp_instance_all_ipv4_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, argv[0], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_instance_all_ipv4_soft_out,
       clear_ip_bgp_instance_all_ipv4_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_soft_out_cmd,
       "clear ip bgp * vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_all,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_out_cmd,
       "clear ip bgp * vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_all_soft_out,
       clear_bgp_all_soft_out_cmd,
       "clear bgp * soft out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_all_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " * soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_all_out_cmd,
       "clear bgp * out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_all_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " * out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_soft_out_cmd,
       "clear bgp ipv6 * soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_ipv6_all_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 * soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_out_cmd,
       "clear bgp ipv6 * out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_ipv6_all_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 * out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_ipv6_safi_prefix,
       clear_bgp_ipv6_safi_prefix_cmd,
       "clear bgp ipv6 (unicast|multicast) prefix X:X::X:X/M",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Address Family Modifier\n"
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_prefix (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL);
  else
    return bgp_clear_prefix (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL);
}

DEFUN (clear_bgp_instance_ipv6_safi_prefix,
       clear_bgp_instance_ipv6_safi_prefix_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (unicast|multicast) prefix X:X::X:X/M",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Address Family Modifier\n"
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_prefix (vty, argv[1], argv[3], AFI_IP6, SAFI_MULTICAST, NULL);
  else
    return bgp_clear_prefix (vty, argv[1], argv[3], AFI_IP6, SAFI_UNICAST, NULL);
}

DEFUN (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_soft_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_instance_peer_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_instance_peer_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_soft_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_ipv4_soft_out,
       clear_ip_bgp_instance_peer_ipv4_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_OUT, argv[2]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_instance_peer_ipv4_soft_out,
       clear_ip_bgp_instance_peer_ipv4_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

/* NOTE: WORD peers have not been tested for vpnv4 */
DEFUN (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_soft_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_peer,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_out_cmd,
       "clear ip bgp (A.B.C.D|WORD) vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_peer_soft_out,
       clear_bgp_peer_soft_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) soft out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_instance_peer_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD) soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_soft_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_instance_ipv6_peer_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD) soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_peer_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_instance_peer_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD) out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_instance_ipv6_peer_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD) out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_soft_out_cmd, 
       "clear ip bgp peer-group WORD soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_instance_peer_group_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_out_cmd, 
       "clear ip bgp peer-group WORD out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_instance_peer_group_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_soft_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_group_ipv4_soft_out,
       clear_ip_bgp_instance_peer_group_ipv4_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_OUT, argv[2]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_instance_peer_group_ipv4_soft_out,
       clear_ip_bgp_instance_peer_group_ipv4_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_soft_out_cmd,
       "clear bgp peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_instance_peer_group_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_soft_out_cmd,
       "clear bgp ipv6 peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_instance_ipv6_peer_group_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_out_cmd,
       "clear bgp peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_instance_peer_group_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_out_cmd,
       "clear bgp ipv6 peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_instance_ipv6_peer_group_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_soft_out_cmd, 
       "clear ip bgp external soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_instance_external_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_out_cmd,
       "clear ip bgp external out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_instance_external_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_soft_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_OUT, NULL);
}

DEFUN (clear_ip_bgp_instance_external_ipv4_soft_out,
       clear_ip_bgp_instance_external_ipv4_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_instance_external_ipv4_soft_out,
       clear_ip_bgp_instance_external_ipv4_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_external_soft_out,
       clear_bgp_external_soft_out_cmd,
       "clear bgp external soft out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_OUT, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_instance_external_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_soft_out_cmd,
       "clear bgp ipv6 external soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_instance_ipv6_external_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_external_out_cmd,
       "clear bgp external out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_instance_external_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_out_cmd,
       "clear bgp ipv6 external WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_instance_ipv6_external_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external WORD out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_instance_as_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_instance_as_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_OUT, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

DEFUN (clear_ip_bgp_instance_as_ipv4_soft_out,
       clear_ip_bgp_instance_as_ipv4_soft_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_OUT, argv[2]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_ip_bgp_instance_as_ipv4_soft_out,
       clear_ip_bgp_instance_as_ipv4_out_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_as,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       BGP_SOFT_OUT_STR)

DEFUN (clear_bgp_as_soft_out,
       clear_bgp_as_soft_out_cmd,
       "clear bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_OUT, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_instance_as_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_soft_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_instance_ipv6_as_soft_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_as_out_cmd,
       "clear bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_instance_as_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_instance_ipv6_as_out_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_OUT_STR)

/* Inbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_soft_in_cmd,
       "clear ip bgp * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_instance_all_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_in_cmd,
       "clear ip bgp * in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_instance_all_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_all_in_prefix_filter,
       clear_ip_bgp_all_in_prefix_filter_cmd,
       "clear ip bgp * in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  if (argc== 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_soft_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
			  BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_in,
       clear_ip_bgp_instance_all_ipv4_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_instance_all_ipv4_soft_in,
       clear_ip_bgp_instance_all_ipv4_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_all_ipv4_in_prefix_filter,
       clear_ip_bgp_all_ipv4_in_prefix_filter_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
			  BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_soft_in_cmd,
       "clear ip bgp * vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_all,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_in_cmd,
       "clear ip bgp * vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_all_soft_in,
       clear_bgp_all_soft_in_cmd,
       "clear bgp * soft in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_all_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " * soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_soft_in_cmd,
       "clear bgp ipv6 * soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_ipv6_all_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 * soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_all_in_cmd,
       "clear bgp * in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_all_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " * in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_in_cmd,
       "clear bgp ipv6 * in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_ipv6_all_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 * in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_all_in_prefix_filter,
       clear_bgp_all_in_prefix_filter_cmd,
       "clear bgp * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_all_in_prefix_filter,
       clear_bgp_ipv6_all_in_prefix_filter_cmd,
       "clear bgp ipv6 * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_soft_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_instance_peer_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)
       
ALIAS (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_instance_peer_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_peer_in_prefix_filter,
       clear_ip_bgp_peer_in_prefix_filter_cmd,
       "clear ip bgp (A.B.C.D|WORD) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_soft_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_ipv4_soft_in,
       clear_ip_bgp_instance_peer_ipv4_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN, argv[2]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_instance_peer_ipv4_soft_in,
       clear_ip_bgp_instance_peer_ipv4_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_peer_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR
       "Push out the existing ORF prefix-list\n")
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_soft_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_peer,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_in_cmd,
       "clear ip bgp (A.B.C.D|WORD) vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_peer_soft_in,
       clear_bgp_peer_soft_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) soft in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_instance_peer_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD) soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_soft_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_instance_ipv6_peer_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD) soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_peer_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_instance_peer_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD) in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_instance_ipv6_peer_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD) in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_peer_in_prefix_filter,
       clear_bgp_peer_in_prefix_filter_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_in_prefix_filter,
       clear_bgp_ipv6_peer_in_prefix_filter_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_IN_STR
       "Push out the existing ORF prefix-list\n")

DEFUN (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_soft_in_cmd,
       "clear ip bgp peer-group WORD soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_instance_peer_group_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_in_cmd,
       "clear ip bgp peer-group WORD in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_instance_peer_group_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_peer_group_in_prefix_filter,
       clear_ip_bgp_peer_group_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_soft_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_group_ipv4_soft_in,
       clear_ip_bgp_instance_peer_group_ipv4_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN, argv[2]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_instance_peer_group_ipv4_soft_in,
       clear_ip_bgp_instance_peer_group_ipv4_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_peer_group_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_soft_in_cmd,
       "clear bgp peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_instance_peer_group_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_soft_in_cmd,
       "clear bgp ipv6 peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_instance_ipv6_peer_group_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_in_cmd,
       "clear bgp peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_instance_peer_group_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_in_cmd,
       "clear bgp ipv6 peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_instance_ipv6_peer_group_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_peer_group_in_prefix_filter_cmd,
       "clear bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_ipv6_peer_group_in_prefix_filter_cmd,
       "clear bgp ipv6 peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_soft_in_cmd,
       "clear ip bgp external soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_instance_external_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_in_cmd,
       "clear ip bgp external in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_instance_external_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_external_in_prefix_filter,
       clear_ip_bgp_external_in_prefix_filter_cmd,
       "clear ip bgp external in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_soft_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN, NULL);
}

DEFUN (clear_ip_bgp_instance_external_ipv4_soft_in,
       clear_ip_bgp_instance_external_ipv4_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_instance_external_ipv4_soft_in,
       clear_ip_bgp_instance_external_ipv4_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_external_ipv4_in_prefix_filter,
       clear_ip_bgp_external_ipv4_in_prefix_filter_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_bgp_external_soft_in,
       clear_bgp_external_soft_in_cmd,
       "clear bgp external soft in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_IN, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_instance_external_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_soft_in_cmd,
       "clear bgp ipv6 external soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_instance_ipv6_external_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_external_in_cmd,
       "clear bgp external in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_instance_external_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_in_cmd,
       "clear bgp ipv6 external WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_instance_ipv6_external_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external WORD in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_external_in_prefix_filter,
       clear_bgp_external_in_prefix_filter_cmd,
       "clear bgp external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_external_in_prefix_filter,
       clear_bgp_ipv6_external_in_prefix_filter_cmd,
       "clear bgp ipv6 external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_instance_as_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_instance_as_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_as_in_prefix_filter,
       clear_ip_bgp_as_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_IN, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

DEFUN (clear_ip_bgp_instance_as_ipv4_soft_in,
       clear_ip_bgp_instance_as_ipv4_soft_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN, argv[2]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_ip_bgp_instance_as_ipv4_soft_in,
       clear_ip_bgp_instance_as_ipv4_in_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_ip_bgp_as_ipv4_in_prefix_filter,
       clear_ip_bgp_as_ipv4_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_as,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_as_soft_in,
       clear_bgp_as_soft_in_cmd,
       "clear bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_IN, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_instance_as_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_soft_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_instance_ipv6_as_soft_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_as_in_cmd,
       "clear bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_instance_as_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_instance_ipv6_as_in_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR)

DEFUN (clear_bgp_as_in_prefix_filter,
       clear_bgp_as_in_prefix_filter_cmd,
       "clear bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_as_in_prefix_filter,
       clear_bgp_ipv6_as_in_prefix_filter_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n")

/* Both soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft,
       clear_ip_bgp_all_soft_cmd,
       "clear ip bgp * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_ip_bgp_all_soft,
       clear_ip_bgp_instance_all_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR)


DEFUN (clear_ip_bgp_all_ipv4_soft,
       clear_ip_bgp_all_ipv4_soft_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_all,
			  BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_soft,
       clear_ip_bgp_instance_all_ipv4_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_all,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_all,
                        BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft,
       clear_ip_bgp_all_vpnv4_soft_cmd,
       "clear ip bgp * vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_all,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_all_soft,
       clear_bgp_all_soft_cmd,
       "clear bgp * soft",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       BGP_SOFT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_all,
                          BGP_CLEAR_SOFT_BOTH, NULL);
 
  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_all,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_bgp_all_soft,
       clear_bgp_instance_all_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " * soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all peers\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_all_soft,
       clear_bgp_ipv6_all_soft_cmd,
       "clear bgp ipv6 * soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_all_soft,
       clear_bgp_instance_ipv6_all_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 * soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all peers\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_peer_soft,
       clear_ip_bgp_peer_soft_cmd,
       "clear ip bgp (A.B.C.D|WORD) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft,
       clear_ip_bgp_instance_peer_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_peer_ipv4_soft,
       clear_ip_bgp_peer_ipv4_soft_cmd,
       "clear ip bgp (A.B.C.D|WORD) ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_ipv4_soft,
       clear_ip_bgp_instance_peer_ipv4_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " (A.B.C.D|WORD) ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_peer,
			  BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_BOTH, argv[2]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft,
       clear_ip_bgp_peer_vpnv4_soft_cmd,
       "clear ip bgp (A.B.C.D|WORD) vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP neighbor on interface to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_peer,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_peer_soft,
       clear_bgp_peer_soft_cmd,
       "clear bgp (A.B.C.D|X:X::X:X|WORD) soft",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_peer,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_peer,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_soft,
       clear_bgp_instance_peer_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " (A.B.C.D|X:X::X:X|WORD) soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_peer_soft,
       clear_bgp_ipv6_peer_soft_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X|WORD) soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_peer_soft,
       clear_bgp_instance_ipv6_peer_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 (A.B.C.D|X:X::X:X|WORD) soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_peer_group_soft,
       clear_ip_bgp_peer_group_soft_cmd,
       "clear ip bgp peer-group WORD soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft,
       clear_ip_bgp_instance_peer_group_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_peer_group_ipv4_soft,
       clear_ip_bgp_peer_group_ipv4_soft_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_instance_peer_group_ipv4_soft,
       clear_ip_bgp_instance_peer_group_ipv4_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " peer-group WORD ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_group,
			  BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_BOTH, argv[2]);
}

DEFUN (clear_bgp_peer_group_soft,
       clear_bgp_peer_group_soft_cmd,
       "clear bgp peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_group,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_group,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft,
       clear_bgp_instance_peer_group_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_peer_group_soft,
       clear_bgp_ipv6_peer_group_soft_cmd,
       "clear bgp ipv6 peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_peer_group_soft,
       clear_bgp_instance_ipv6_peer_group_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_external_soft,
       clear_ip_bgp_external_soft_cmd,
       "clear ip bgp external soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_ip_bgp_external_soft,
       clear_ip_bgp_instance_external_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_external_ipv4_soft,
       clear_ip_bgp_external_ipv4_soft_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_instance_external_ipv4_soft,
       clear_ip_bgp_instance_external_ipv4_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " external ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_external,
			  BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_bgp_external_soft,
       clear_bgp_external_soft_cmd,
       "clear bgp external soft",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR)
{
  if (argc == 2)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_external,
                          BGP_CLEAR_SOFT_BOTH, NULL);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_external,
			BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_bgp_external_soft,
       clear_bgp_instance_external_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " external soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear all external peers\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_external_soft,
       clear_bgp_ipv6_external_soft_cmd,
       "clear bgp ipv6 external soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_external_soft,
       clear_bgp_instance_ipv6_external_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 external soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear all external peers\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_as_soft,
       clear_ip_bgp_as_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft,
       clear_ip_bgp_instance_as_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)

DEFUN (clear_ip_bgp_as_ipv4_soft,
       clear_ip_bgp_as_ipv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_BOTH, argv[0]);

  return bgp_clear_vty (vty, NULL,AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_instance_as_ipv4_soft,
       clear_ip_bgp_instance_as_ipv4_soft_cmd,
       "clear ip bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  if (strncmp (argv[3], "m", 1) == 0)
    return bgp_clear_vty (vty, argv[1], AFI_IP, SAFI_MULTICAST, clear_as,
			  BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, argv[1],AFI_IP, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_BOTH, argv[2]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft,
       clear_ip_bgp_as_vpnv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       BGP_SOFT_STR)
{
  return bgp_clear_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, clear_as,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_as_soft,
       clear_bgp_as_soft_cmd,
       "clear bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)
{
  if (argc == 3)
    return bgp_clear_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, clear_as,
                          BGP_CLEAR_SOFT_BOTH, argv[2]);

  return bgp_clear_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, clear_as,
			BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_as_soft,
       clear_bgp_instance_as_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_as_soft,
       clear_bgp_ipv6_as_soft_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)

ALIAS (clear_bgp_as_soft,
       clear_bgp_instance_ipv6_as_soft_cmd,
       "clear bgp " BGP_INSTANCE_CMD " ipv6 " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       BGP_SOFT_STR)

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show bgp views",
       SHOW_STR
       BGP_STR
       "Show the defined BGP views\n")
{
  struct list *inst = bm->bgp;
  struct listnode *node;
  struct bgp *bgp;

  if (!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "BGP Multiple Instance is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  vty_out (vty, "Defined BGP views:%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO(inst, node, bgp))
    {
      /* Skip VRFs. */
      if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
        continue;
      vty_out (vty, "\t%s (AS%u)%s",
               bgp->name ? bgp->name : "(null)",
               bgp->as, VTY_NEWLINE);
    }
  
  return CMD_SUCCESS;
}

DEFUN (show_bgp_vrfs,
       show_bgp_vrfs_cmd,
       "show bgp vrfs {json}",
       SHOW_STR
       BGP_STR
       "Show BGP VRFs\n"
       "JavaScript Object Notation\n")
{
  struct list *inst = bm->bgp;
  struct listnode *node;
  struct bgp *bgp;
  u_char uj = use_json(argc, argv);
  json_object *json = NULL;
  json_object *json_vrfs = NULL;
  int count = 0;
  static char header[] = "Type  Id     RouterId          #PeersCfg  #PeersEstb  Name";

  if (!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "BGP Multiple Instance is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (uj)
    {
      json = json_object_new_object();
      json_vrfs = json_object_new_object();
    }

  for (ALL_LIST_ELEMENTS_RO(inst, node, bgp))
    {
      const char *name, *type;
      struct peer *peer;
      struct listnode *node, *nnode;
      int peers_cfg, peers_estb;
      json_object *json_vrf = NULL;
      int vrf_id_ui;

      /* Skip Views. */
      if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
        continue;

      count++;
      if (!uj && count == 1)
        vty_out (vty, "%s%s", header, VTY_NEWLINE);

      peers_cfg = peers_estb = 0;
      if (uj)
        json_vrf = json_object_new_object();


      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
            continue;
          peers_cfg++;
          if (peer->status == Established)
            peers_estb++;
        }

      if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
        {
          name = "Default";
          type = "DFLT";
        }
      else
        {
          name = bgp->name;
          type = "VRF";
        }

      vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN) ? -1 : bgp->vrf_id;
      if (uj)
        {
          json_object_string_add(json_vrf, "type", type);
          json_object_int_add(json_vrf, "vrfId", vrf_id_ui);
          json_object_string_add(json_vrf, "routerId", inet_ntoa (bgp->router_id));
          json_object_int_add(json_vrf, "numConfiguredPeers", peers_cfg);
          json_object_int_add(json_vrf, "numEstablishedPeers", peers_estb);

          json_object_object_add(json_vrfs, name, json_vrf);
        }
      else
        vty_out (vty, "%4s  %-5d  %-16s  %9u  %10u  %s%s",
                 type, vrf_id_ui, inet_ntoa (bgp->router_id),
                 peers_cfg, peers_estb, name,
                 VTY_NEWLINE);
    }

  if (uj)
    {
      json_object_object_add(json, "vrfs", json_vrfs);

      json_object_int_add(json, "totalVrfs", count);

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      if (count)
        vty_out (vty, "%sTotal number of VRFs (including default): %d%s",
                 VTY_NEWLINE, count, VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN (show_bgp_memory, 
       show_bgp_memory_cmd,
       "show bgp memory",
       SHOW_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
  char memstrbuf[MTYPE_MEMSTR_LEN];
  unsigned long count;
  
  /* RIB related usage stats */
  count = mtype_stats_alloc (MTYPE_BGP_NODE);
  vty_out (vty, "%ld RIB nodes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_node)),
           VTY_NEWLINE);
  
  count = mtype_stats_alloc (MTYPE_BGP_ROUTE);
  vty_out (vty, "%ld BGP routes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_info)),
           VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_BGP_ROUTE_EXTRA)))
    vty_out (vty, "%ld BGP route ancillaries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_info_extra)),
             VTY_NEWLINE);
  
  if ((count = mtype_stats_alloc (MTYPE_BGP_STATIC)))
    vty_out (vty, "%ld Static routes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_static)),
             VTY_NEWLINE);

  if ((count = mtype_stats_alloc (MTYPE_BGP_PACKET)))
    vty_out (vty, "%ld Packets, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bpacket)),
             VTY_NEWLINE);
  
  /* Adj-In/Out */
  if ((count = mtype_stats_alloc (MTYPE_BGP_ADJ_IN)))
    vty_out (vty, "%ld Adj-In entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_in)),
             VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_BGP_ADJ_OUT)))
    vty_out (vty, "%ld Adj-Out entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_out)),
             VTY_NEWLINE);
  
  if ((count = mtype_stats_alloc (MTYPE_BGP_NEXTHOP_CACHE)))
    vty_out (vty, "%ld Nexthop cache entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_nexthop_cache)),
             VTY_NEWLINE);

  if ((count = mtype_stats_alloc (MTYPE_BGP_DAMP_INFO)))
    vty_out (vty, "%ld Dampening entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_damp_info)),
             VTY_NEWLINE);

  /* Attributes */
  count = attr_count();
  vty_out (vty, "%ld BGP attributes, using %s of memory%s", count, 
           mtype_memstr (memstrbuf, sizeof (memstrbuf), 
                         count * sizeof(struct attr)), 
           VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_ATTR_EXTRA)))
    vty_out (vty, "%ld BGP extra attributes, using %s of memory%s", count, 
             mtype_memstr (memstrbuf, sizeof (memstrbuf), 
                           count * sizeof(struct attr_extra)), 
             VTY_NEWLINE);
  
  if ((count = attr_unknown_count()))
    vty_out (vty, "%ld unknown attributes%s", count, VTY_NEWLINE);
  
  /* AS_PATH attributes */
  count = aspath_count ();
  vty_out (vty, "%ld BGP AS-PATH entries, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct aspath)),
           VTY_NEWLINE);
  
  count = mtype_stats_alloc (MTYPE_AS_SEG);
  vty_out (vty, "%ld BGP AS-PATH segments, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct assegment)),
           VTY_NEWLINE);
  
  /* Other attributes */
  if ((count = community_count ()))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct community)),
             VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_ECOMMUNITY)))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct ecommunity)),
             VTY_NEWLINE);
  
  if ((count = mtype_stats_alloc (MTYPE_CLUSTER)))
    vty_out (vty, "%ld Cluster lists, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct cluster_list)),
             VTY_NEWLINE);
  
  /* Peer related usage */
  count = mtype_stats_alloc (MTYPE_BGP_PEER);
  vty_out (vty, "%ld peers, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct peer)),
           VTY_NEWLINE);
  
  if ((count = mtype_stats_alloc (MTYPE_BGP_PEER_GROUP)))
    vty_out (vty, "%ld peer groups, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct peer_group)),
             VTY_NEWLINE);
  
  /* Other */
  if ((count = mtype_stats_alloc (MTYPE_HASH)))
    vty_out (vty, "%ld hash tables, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash)),
             VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_HASH_BACKET)))
    vty_out (vty, "%ld hash buckets, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash_backet)),
             VTY_NEWLINE);
  if ((count = mtype_stats_alloc (MTYPE_BGP_REGEXP)))
    vty_out (vty, "%ld compiled regexes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (regex_t)),
             VTY_NEWLINE);
  return CMD_SUCCESS;
}

/* Show BGP peer's summary information. */
static int
bgp_show_summary (struct vty *vty, struct bgp *bgp, int afi, int safi,
                  u_char use_json, json_object *json)
{
  struct peer *peer;
  struct listnode *node, *nnode;
  unsigned int count = 0, dn_count = 0;
  char timebuf[BGP_UPTIME_LEN], dn_flag[2];
  int len;
  json_object *json_peer = NULL;
  json_object *json_peers = NULL;

  /* Header string for each address family. */
  static char header[] = "Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd";

  if (use_json)
    {
      if (json == NULL)
        json = json_object_new_object();

      json_peers = json_object_new_object();
    }

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
	continue;

      if (peer->afc[afi][safi])
	{
          if (!count)
            {
              unsigned long ents;
              char memstrbuf[MTYPE_MEMSTR_LEN];
              int vrf_id_ui;

              vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN) ? -1 : bgp->vrf_id;

              /* Usage summary and header */
              if (use_json)
                {
                  json_object_string_add(json, "routerId", inet_ntoa (bgp->router_id));
                  json_object_int_add(json, "as", bgp->as);
                  json_object_int_add(json, "vrfId", vrf_id_ui);
                  json_object_string_add(json, "vrfName",
                                         (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                                         ? "Default" : bgp->name);
                }
              else
                {
                  vty_out (vty,
                           "BGP router identifier %s, local AS number %u vrf-id %d",
                           inet_ntoa (bgp->router_id), bgp->as, vrf_id_ui);
                  vty_out (vty, "%s", VTY_NEWLINE);
                }

              if (bgp_update_delay_configured(bgp))
                {
                  if (use_json)
                    {
                      json_object_int_add(json, "updateDelayLimit", bgp->v_update_delay);

                      if (bgp->v_update_delay != bgp->v_establish_wait)
                        json_object_int_add(json, "updateDelayEstablishWait", bgp->v_establish_wait);

                      if (bgp_update_delay_active(bgp))
                        {
                          json_object_string_add(json, "updateDelayFirstNeighbor", bgp->update_delay_begin_time);
                          json_object_boolean_true_add(json, "updateDelayInProgress");
                        }
                      else
                        {
                          if (bgp->update_delay_over)
                            {
                              json_object_string_add(json, "updateDelayFirstNeighbor",
                                                     bgp->update_delay_begin_time);
                              json_object_string_add(json, "updateDelayBestpathResumed",
                                                     bgp->update_delay_end_time);
                              json_object_string_add(json, "updateDelayZebraUpdateResume",
                                                     bgp->update_delay_zebra_resume_time);
                              json_object_string_add(json, "updateDelayPeerUpdateResume",
                                                     bgp->update_delay_peers_resume_time);
                            }
                        }
                    }
                  else
                    {
                      vty_out (vty, "Read-only mode update-delay limit: %d seconds%s",
                               bgp->v_update_delay, VTY_NEWLINE);
                      if (bgp->v_update_delay != bgp->v_establish_wait)
                        vty_out (vty, "                   Establish wait: %d seconds%s",
                                 bgp->v_establish_wait, VTY_NEWLINE);

                      if (bgp_update_delay_active(bgp))
                        {
                          vty_out (vty, "  First neighbor established: %s%s",
                                   bgp->update_delay_begin_time, VTY_NEWLINE);
                          vty_out (vty, "  Delay in progress%s", VTY_NEWLINE);
                        }
                      else
                        {
                          if (bgp->update_delay_over)
                            {
                              vty_out (vty, "  First neighbor established: %s%s",
                                       bgp->update_delay_begin_time, VTY_NEWLINE);
                              vty_out (vty, "          Best-paths resumed: %s%s",
                                       bgp->update_delay_end_time, VTY_NEWLINE);
                              vty_out (vty, "        zebra update resumed: %s%s",
                                       bgp->update_delay_zebra_resume_time, VTY_NEWLINE);
                              vty_out (vty, "        peers update resumed: %s%s",
                                       bgp->update_delay_peers_resume_time, VTY_NEWLINE);
                            }
                        }
                    }
                }

              if (use_json)
                {
                  if (bgp_maxmed_onstartup_configured(bgp) && bgp->maxmed_active)
                    json_object_boolean_true_add(json, "maxMedOnStartup");
                  if (bgp->v_maxmed_admin)
                    json_object_boolean_true_add(json, "maxMedAdministrative");

                  json_object_int_add(json, "tableVersion", bgp_table_version(bgp->rib[afi][safi]));

                  ents = bgp_table_count (bgp->rib[afi][safi]);
                  json_object_int_add(json, "ribCount", ents);
                  json_object_int_add(json, "ribMemory", ents * sizeof (struct bgp_node));

                  ents = listcount (bgp->peer);
                  json_object_int_add(json, "peerCount", ents);
                  json_object_int_add(json, "peerMemory", ents * sizeof (struct peer));

                  if ((ents = listcount (bgp->group)))
                    {
                      json_object_int_add(json, "peerGroupCount", ents);
                      json_object_int_add(json, "peerGroupMemory", ents * sizeof (struct peer_group));
                    }

                  if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING))
                    json_object_boolean_true_add(json, "dampeningEnabled");
                }
              else
                {
                  if (bgp_maxmed_onstartup_configured(bgp) && bgp->maxmed_active)
                    vty_out (vty, "Max-med on-startup active%s", VTY_NEWLINE);
                  if (bgp->v_maxmed_admin)
                    vty_out (vty, "Max-med administrative active%s", VTY_NEWLINE);

                 vty_out(vty, "BGP table version %" PRIu64 "%s",
                         bgp_table_version(bgp->rib[afi][safi]), VTY_NEWLINE);

                  ents = bgp_table_count (bgp->rib[afi][safi]);
                  vty_out (vty, "RIB entries %ld, using %s of memory%s", ents,
                           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                         ents * sizeof (struct bgp_node)),
                           VTY_NEWLINE);

                  /* Peer related usage */
                  ents = listcount (bgp->peer);
                  vty_out (vty, "Peers %ld, using %s of memory%s",
                           ents,
                           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                         ents * sizeof (struct peer)),
                           VTY_NEWLINE);

                  if ((ents = listcount (bgp->group)))
                    vty_out (vty, "Peer groups %ld, using %s of memory%s", ents,
                             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                           ents * sizeof (struct peer_group)),
                             VTY_NEWLINE);

                  if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING))
                    vty_out (vty, "Dampening enabled.%s", VTY_NEWLINE);
                  vty_out (vty, "%s", VTY_NEWLINE);
                  vty_out (vty, "%s%s", header, VTY_NEWLINE);
                }
            }
          
          count++;

          if (use_json)
            {
              json_peer = json_object_new_object();

              if (peer_dynamic_neighbor(peer))
                json_object_boolean_true_add(json_peer, "dynamicPeer");

              if (peer->hostname)
                json_object_string_add(json_peer, "hostname", peer->hostname);

              if (peer->domainname)
                json_object_string_add(json_peer, "domainname", peer->domainname);

              json_object_int_add(json_peer, "remoteAs", peer->as);
              json_object_int_add(json_peer, "version", 4);
              json_object_int_add(json_peer, "msgRcvd",
                                  peer->open_in + peer->update_in + peer->keepalive_in
                                  + peer->notify_in + peer->refresh_in
                                  + peer->dynamic_cap_in);
              json_object_int_add(json_peer, "msgSent",
                                  peer->open_out + peer->update_out + peer->keepalive_out
                                  + peer->notify_out + peer->refresh_out
                                  + peer->dynamic_cap_out);

              json_object_int_add(json_peer, "tableVersion", peer->version[afi][safi]);
              json_object_int_add(json_peer, "outq", peer->obuf->count);
              json_object_int_add(json_peer, "inq", 0);
              peer_uptime (peer->uptime, timebuf, BGP_UPTIME_LEN, use_json, json_peer);
              json_object_int_add(json_peer, "prefixReceivedCount", peer->pcount[afi][safi]);

              if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
                json_object_string_add(json_peer, "state", "Idle (Admin)");
              else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
                json_object_string_add(json_peer, "state", "Idle (PfxCt)");
              else
                json_object_string_add(json_peer, "state", LOOKUP(bgp_status_msg, peer->status));

              if (peer->conf_if)
                json_object_string_add(json_peer, "idType", "interface");
              else if (peer->su.sa.sa_family == AF_INET)
                json_object_string_add(json_peer, "idType", "ipv4");
              else if (peer->su.sa.sa_family == AF_INET6)
                json_object_string_add(json_peer, "idType", "ipv6");

              json_object_object_add(json_peers, peer->host, json_peer);
            }
          else
            {
              memset(dn_flag, '\0', sizeof(dn_flag));
              if (peer_dynamic_neighbor(peer))
                {
                  dn_count++;
                  dn_flag[0] = '*';
                }

	      if (peer->hostname && bgp_flag_check(bgp, BGP_FLAG_SHOW_HOSTNAME))
		len = vty_out (vty, "%s%s(%s)", dn_flag, peer->hostname,
			       peer->host);
	      else
		len = vty_out (vty, "%s%s", dn_flag, peer->host);
              len = 16 - len;

              if (len < 1)
                vty_out (vty, "%s%*s", VTY_NEWLINE, 16, " ");
              else
                vty_out (vty, "%*s", len, " ");

              vty_out (vty, "4 ");

              vty_out (vty, "%5u %7d %7d %8" PRIu64 " %4d %4zd ",
                       peer->as,
                       peer->open_in + peer->update_in + peer->keepalive_in
                       + peer->notify_in + peer->refresh_in
                       + peer->dynamic_cap_in,
                       peer->open_out + peer->update_out + peer->keepalive_out
                       + peer->notify_out + peer->refresh_out
                       + peer->dynamic_cap_out,
                       peer->version[afi][safi],
                       0,
                       peer->obuf->count);

              vty_out (vty, "%-8s",
                       peer_uptime (peer->uptime, timebuf, BGP_UPTIME_LEN, 0, NULL));

              if (peer->status == Established)
                  vty_out (vty, " %8ld", peer->pcount[afi][safi]);
              else
                {
                  if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
                    vty_out (vty, " Idle (Admin)");
                  else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
                    vty_out (vty, " Idle (PfxCt)");
                  else
                    vty_out (vty, " %-11s", LOOKUP(bgp_status_msg, peer->status));
                }
              vty_out (vty, "%s", VTY_NEWLINE);
            }
	}
    }

  if (use_json)
    {
      json_object_object_add(json, "peers", json_peers);

      json_object_int_add(json, "totalPeers", count);
      json_object_int_add(json, "dynamicPeers", dn_count);

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      if (count)
        vty_out (vty, "%sTotal number of neighbors %d%s", VTY_NEWLINE,
                count, VTY_NEWLINE);
      else
        {
          if (use_json)
            vty_out(vty, "{\"error\": {\"message\": \"No %s neighbor configured\"}}%s",
                    afi == AFI_IP ? "IPv4" : "IPv6", VTY_NEWLINE);
          else
            vty_out (vty, "No %s neighbor is configured%s",
                     afi == AFI_IP ? "IPv4" : "IPv6", VTY_NEWLINE);
        }

      if (dn_count && ! use_json)
        {
          vty_out(vty, "* - dynamic neighbor%s", VTY_NEWLINE);
          vty_out(vty,
                  "%d dynamic neighbor(s), limit %d%s",
                  dn_count, bgp->dynamic_neighbors_limit, VTY_NEWLINE);
        }
    }

  return CMD_SUCCESS;
}

static int
bgp_show_summary_vty (struct vty *vty, const char *name,
                      afi_t afi, safi_t safi, u_char use_json)
{
  struct bgp *bgp;

  if (name)
    {
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
	{
	  vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      bgp_show_summary (vty, bgp, afi, safi, use_json, NULL);
      return CMD_SUCCESS;
    }

  bgp = bgp_get_default ();

  if (bgp)
    bgp_show_summary (vty, bgp, afi, safi, use_json, NULL);

  return CMD_SUCCESS;
}

static void
bgp_show_all_instances_summary_vty (struct vty *vty, afi_t afi, safi_t safi,
                                    u_char use_json)
{
  struct listnode *node, *nnode;
  struct bgp *bgp;
  json_object *json = NULL;
  int is_first = 1;

  if (use_json)
    vty_out (vty, "{%s", VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      if (use_json)
        {
          if (!(json = json_object_new_object()))
            {
              zlog_err("Unable to allocate memory for JSON object");
              vty_out (vty,
                       "{\"error\": {\"message:\": \"Unable to allocate memory for JSON object\"}}}%s",
                       VTY_NEWLINE);
              return;
            }

          if (! is_first)
            vty_out (vty, ",%s", VTY_NEWLINE);
          else
            is_first = 0;

          vty_out(vty, "\"%s\":", (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                  ? "Default" : bgp->name);
        }
      else
        {
          vty_out (vty, "%sInstance %s:%s",
                   VTY_NEWLINE,
                   (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                   ? "Default" : bgp->name, VTY_NEWLINE);
        }
      bgp_show_summary (vty, bgp, afi, safi, use_json, json);
    }

  if (use_json)
    vty_out (vty, "}%s", VTY_NEWLINE);

}

/* `show ip bgp summary' commands. */
DEFUN (show_ip_bgp_summary,
       show_ip_bgp_summary_cmd,
       "show ip bgp summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, NULL, AFI_IP, SAFI_UNICAST, uj);
}

DEFUN (show_ip_bgp_instance_summary,
       show_ip_bgp_instance_summary_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, argv[1], AFI_IP, SAFI_UNICAST, uj);
}

DEFUN (show_ip_bgp_instance_all_summary,
       show_ip_bgp_instance_all_summary_cmd,
       "show ip bgp " BGP_INSTANCE_ALL_CMD " summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  bgp_show_all_instances_summary_vty (vty, AFI_IP, SAFI_UNICAST, uj);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_summary, 
       show_ip_bgp_ipv4_summary_cmd,
       "show ip bgp ipv4 (unicast|multicast) summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_summary_vty (vty, NULL, AFI_IP, SAFI_MULTICAST, uj);

  return bgp_show_summary_vty (vty, NULL, AFI_IP, SAFI_UNICAST, uj);
}

ALIAS (show_ip_bgp_ipv4_summary,
       show_bgp_ipv4_safi_summary_cmd,
       "show bgp ipv4 (unicast|multicast) summary {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_instance_ipv4_summary,
       show_ip_bgp_instance_ipv4_summary_cmd,
       "show ip bgp view WORD ipv4 (unicast|multicast) summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  if (strncmp (argv[1], "m", 1) == 0)
    return bgp_show_summary_vty (vty, argv[0], AFI_IP, SAFI_MULTICAST, uj);
  else
    return bgp_show_summary_vty (vty, argv[0], AFI_IP, SAFI_UNICAST, uj);
}

ALIAS (show_ip_bgp_instance_ipv4_summary,
       show_bgp_instance_ipv4_safi_summary_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) summary {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_vpnv4_all_summary,
       show_ip_bgp_vpnv4_all_summary_cmd,
       "show ip bgp vpnv4 all summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, uj);
}

DEFUN (show_ip_bgp_vpnv4_rd_summary,
       show_ip_bgp_vpnv4_rd_summary_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn summary {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  int ret;
  struct prefix_rd prd;
  u_char uj = use_json(argc, argv);

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_summary_vty (vty, NULL, AFI_IP, SAFI_MPLS_VPN, uj);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_summary,
       show_bgp_summary_cmd,
       "show bgp summary {json}",
       SHOW_STR
       BGP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  return bgp_show_summary_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, use_json(argc, argv));
}

DEFUN (show_bgp_instance_summary,
       show_bgp_instance_summary_cmd,
       "show bgp " BGP_INSTANCE_CMD " summary {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  return bgp_show_summary_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, use_json(argc, argv));
}

DEFUN (show_bgp_instance_all_summary,
       show_bgp_instance_all_summary_cmd,
       "show bgp " BGP_INSTANCE_ALL_CMD " summary {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  bgp_show_all_instances_summary_vty (vty, AFI_IP6, SAFI_UNICAST, uj);
  return CMD_SUCCESS;
}

ALIAS (show_bgp_summary, 
       show_bgp_ipv6_summary_cmd,
       "show bgp ipv6 summary {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Summary of BGP neighbor status\n")

ALIAS (show_bgp_instance_summary,
       show_bgp_instance_ipv6_summary_cmd,
       "show bgp " BGP_INSTANCE_CMD " ipv6 summary {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_bgp_ipv6_safi_summary,
       show_bgp_ipv6_safi_summary_cmd,
       "show bgp ipv6 (unicast|multicast) summary {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_summary_vty (vty, NULL, AFI_IP6, SAFI_MULTICAST, uj);

  return bgp_show_summary_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, uj);
}

DEFUN (show_bgp_instance_ipv6_safi_summary,
       show_bgp_instance_ipv6_safi_summary_cmd,
       "show bgp " BGP_INSTANCE_CMD " ipv6 (unicast|multicast) summary {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  if (strncmp (argv[2], "m", 1) == 0)
    return bgp_show_summary_vty (vty, argv[1], AFI_IP6, SAFI_MULTICAST, uj);

  return bgp_show_summary_vty (vty, argv[1], AFI_IP6, SAFI_UNICAST, uj);
}

/* old command */
DEFUN (show_ipv6_bgp_summary, 
       show_ipv6_bgp_summary_cmd,
       "show ipv6 bgp summary {json}",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, NULL, AFI_IP6, SAFI_UNICAST, uj);
}

/* old command */
DEFUN (show_ipv6_mbgp_summary, 
       show_ipv6_mbgp_summary_cmd,
       "show ipv6 mbgp summary {json}",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, NULL, AFI_IP6, SAFI_MULTICAST, uj);
}
#endif /* HAVE_IPV6 */

const char *
afi_safi_print (afi_t afi, safi_t safi)
{
  if (afi == AFI_IP && safi == SAFI_UNICAST)
    return "IPv4 Unicast";
  else if (afi == AFI_IP && safi == SAFI_MULTICAST)
    return "IPv4 Multicast";
  else if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
    return "VPNv4 Unicast";
  else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
    return "IPv6 Unicast";
  else if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
    return "IPv6 Multicast";
  else
    return "Unknown";
}

/* Show BGP peer's information. */
enum show_type
{
  show_all,
  show_peer
};

static void
bgp_show_peer_afi_orf_cap (struct vty *vty, struct peer *p, afi_t afi, safi_t safi,
                           u_int16_t adv_smcap, u_int16_t adv_rmcap, u_int16_t rcv_smcap,
                           u_int16_t rcv_rmcap, u_char use_json, json_object *json_pref)
{
  /* Send-Mode */
  if (CHECK_FLAG (p->af_cap[afi][safi], adv_smcap)
      || CHECK_FLAG (p->af_cap[afi][safi], rcv_smcap))
    {
      if (use_json)
        {
          if (CHECK_FLAG (p->af_cap[afi][safi], adv_smcap) && CHECK_FLAG (p->af_cap[afi][safi], rcv_smcap))
	    json_object_string_add(json_pref, "sendMode", "advertisedAndReceived");
          else if (CHECK_FLAG (p->af_cap[afi][safi], adv_smcap))
	    json_object_string_add(json_pref, "sendMode", "advertised");
          else if (CHECK_FLAG (p->af_cap[afi][safi], rcv_smcap))
	    json_object_string_add(json_pref, "sendMode", "received");
        }
      else
        {
          vty_out (vty, "      Send-mode: ");
          if (CHECK_FLAG (p->af_cap[afi][safi], adv_smcap))
	    vty_out (vty, "advertised");
          if (CHECK_FLAG (p->af_cap[afi][safi], rcv_smcap))
	    vty_out (vty, "%sreceived",
		     CHECK_FLAG (p->af_cap[afi][safi], adv_smcap) ?
	             ", " : "");
          vty_out (vty, "%s", VTY_NEWLINE);
        }
    }

  /* Receive-Mode */
  if (CHECK_FLAG (p->af_cap[afi][safi], adv_rmcap)
      || CHECK_FLAG (p->af_cap[afi][safi], rcv_rmcap))
    {
      if (use_json)
        {
          if (CHECK_FLAG (p->af_cap[afi][safi], adv_rmcap) && CHECK_FLAG (p->af_cap[afi][safi], rcv_rmcap))
	    json_object_string_add(json_pref, "recvMode", "advertisedAndReceived");
          else if (CHECK_FLAG (p->af_cap[afi][safi], adv_rmcap))
	    json_object_string_add(json_pref, "recvMode", "advertised");
          else if (CHECK_FLAG (p->af_cap[afi][safi], rcv_rmcap))
	    json_object_string_add(json_pref, "recvMode", "received");
        }
      else
        {
          vty_out (vty, "      Receive-mode: ");
          if (CHECK_FLAG (p->af_cap[afi][safi], adv_rmcap))
	    vty_out (vty, "advertised");
          if (CHECK_FLAG (p->af_cap[afi][safi], rcv_rmcap))
            vty_out (vty, "%sreceived",
                     CHECK_FLAG (p->af_cap[afi][safi], adv_rmcap) ?
                     ", " : "");
          vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}

static void
bgp_show_peer_afi (struct vty *vty, struct peer *p, afi_t afi, safi_t safi,
                   u_char use_json, json_object *json_neigh)
{
  struct bgp_filter *filter;
  struct peer_af *paf;
  char orf_pfx_name[BUFSIZ];
  int orf_pfx_count;
  json_object *json_af = NULL;
  json_object *json_prefA = NULL;
  json_object *json_prefB = NULL;
  json_object *json_addr = NULL;

  if (use_json)
    {
      json_addr = json_object_new_object();
      json_af = json_object_new_object();
      json_prefA = json_object_new_object();
      json_prefB = json_object_new_object();
      filter = &p->filter[afi][safi];

      if (peer_group_active(p))
        json_object_string_add(json_addr, "peerGroupMember", p->group->name);

      paf = peer_af_find(p, afi, safi);
      if (paf && PAF_SUBGRP(paf))
        {
          json_object_int_add(json_addr, "updateGroupId", PAF_UPDGRP(paf)->id);
          json_object_int_add(json_addr, "subGroupId", PAF_SUBGRP(paf)->id);
          json_object_int_add(json_addr, "packetQueueLength", bpacket_queue_virtual_length(paf));
        }

      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
        {
          json_object_int_add(json_af, "orfType", ORF_TYPE_PREFIX);
          bgp_show_peer_afi_orf_cap (vty, p, afi, safi,
				     PEER_CAP_ORF_PREFIX_SM_ADV,
				     PEER_CAP_ORF_PREFIX_RM_ADV,
				     PEER_CAP_ORF_PREFIX_SM_RCV,
				     PEER_CAP_ORF_PREFIX_RM_RCV, use_json, json_prefA);
          json_object_object_add(json_af, "orfPrefixList", json_prefA);
        }

      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
        {
          json_object_int_add(json_af, "orfOldType", ORF_TYPE_PREFIX_OLD);
          bgp_show_peer_afi_orf_cap (vty, p, afi, safi,
				     PEER_CAP_ORF_PREFIX_SM_ADV,
				     PEER_CAP_ORF_PREFIX_RM_ADV,
				     PEER_CAP_ORF_PREFIX_SM_OLD_RCV,
				     PEER_CAP_ORF_PREFIX_RM_OLD_RCV, use_json, json_prefB);
          json_object_object_add(json_af, "orfOldPrefixList", json_prefB);
        }

      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
        json_object_object_add(json_addr, "afDependentCap", json_af);

      sprintf (orf_pfx_name, "%s.%d.%d", p->host, afi, safi);
      orf_pfx_count =  prefix_bgp_show_prefix_list (NULL, afi, orf_pfx_name, use_json);

      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND)
          || orf_pfx_count)
        {
          if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND))
	    json_object_boolean_true_add(json_neigh, "orfSent");
          if (orf_pfx_count)
            json_object_int_add(json_addr, "orfRecvCounter", orf_pfx_count);
        }
      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH))
        json_object_string_add(json_addr, "orfFirstUpdate", "deferredUntilORFOrRouteRefreshRecvd");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
        json_object_boolean_true_add(json_addr, "routeReflectorClient");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        json_object_boolean_true_add(json_addr, "routeServerClient");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
        json_object_boolean_true_add(json_addr, "inboundSoftConfigPermit");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
        json_object_boolean_true_add(json_addr, "privateAsNumsAllReplacedInUpdatesToNbr");
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
        json_object_boolean_true_add(json_addr, "privateAsNumsReplacedInUpdatesToNbr");
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
        json_object_boolean_true_add(json_addr, "privateAsNumsAllRemovedInUpdatesToNbr");
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS))
        json_object_boolean_true_add(json_addr, "privateAsNumsRemovedInUpdatesToNbr");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_ADDPATH_TX_ALL_PATHS))
        json_object_boolean_true_add(json_addr, "addpathTxAllPaths");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS))
        json_object_boolean_true_add(json_addr, "addpathTxBestpathPerAS");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
        json_object_string_add(json_addr, "overrideASNsInOutboundUpdates", "ifAspathEqualRemoteAs");

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF) ||
          CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF))
        json_object_boolean_true_add(json_addr, "routerAlwaysNextHop");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_AS_PATH_UNCHANGED))
        json_object_boolean_true_add(json_addr, "unchangedAsPathPropogatedToNbr");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED))
        json_object_boolean_true_add(json_addr, "unchangedNextHopPropogatedToNbr");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
        json_object_boolean_true_add(json_addr, "unchangedMedPropogatedToNbr");
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
          || CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
        {
          if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
	      && CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
	    json_object_string_add(json_addr, "commAttriSentToNbr", "extendedAndStandard");
          else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
	    json_object_string_add(json_addr, "commAttriSentToNbr", "extended");
          else
	    json_object_string_add(json_addr, "commAttriSentToNbr", "standard");
        }
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE))
        {
          if (p->default_rmap[afi][safi].name)
	    json_object_string_add(json_addr, "defaultRouteMap", p->default_rmap[afi][safi].name);

          if (paf && PAF_SUBGRP(paf) && CHECK_FLAG(PAF_SUBGRP(paf)->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE))
            json_object_boolean_true_add(json_addr, "defaultSent");
          else
            json_object_boolean_true_add(json_addr, "defaultNotSent");
        }

      if (filter->plist[FILTER_IN].name
          || filter->dlist[FILTER_IN].name
          || filter->aslist[FILTER_IN].name
          || filter->map[RMAP_IN].name)
        json_object_boolean_true_add(json_addr, "inboundPathPolicyConfig");
      if (filter->plist[FILTER_OUT].name
          || filter->dlist[FILTER_OUT].name
          || filter->aslist[FILTER_OUT].name
          || filter->map[RMAP_OUT].name
          || filter->usmap.name)
        json_object_boolean_true_add(json_addr, "outboundPathPolicyConfig");

      /* prefix-list */
      if (filter->plist[FILTER_IN].name)
        json_object_string_add(json_addr, "incomingUpdatePrefixFilterList", filter->plist[FILTER_IN].name);
      if (filter->plist[FILTER_OUT].name)
        json_object_string_add(json_addr, "outgoingUpdatePrefixFilterList", filter->plist[FILTER_OUT].name);

      /* distribute-list */
      if (filter->dlist[FILTER_IN].name)
        json_object_string_add(json_addr, "incomingUpdateNetworkFilterList", filter->dlist[FILTER_IN].name);
      if (filter->dlist[FILTER_OUT].name)
        json_object_string_add(json_addr, "outgoingUpdateNetworkFilterList", filter->dlist[FILTER_OUT].name);

      /* filter-list. */
      if (filter->aslist[FILTER_IN].name)
        json_object_string_add(json_addr, "incomingUpdateAsPathFilterList", filter->aslist[FILTER_IN].name);
      if (filter->aslist[FILTER_OUT].name)
        json_object_string_add(json_addr, "outgoingUpdateAsPathFilterList", filter->aslist[FILTER_OUT].name);

      /* route-map. */
      if (filter->map[RMAP_IN].name)
        json_object_string_add(json_addr, "routeMapForIncomingAdvertisements", filter->map[RMAP_IN].name);
      if (filter->map[RMAP_OUT].name)
        json_object_string_add(json_addr, "routeMapForOutgoingAdvertisements", filter->map[RMAP_OUT].name);

      /* unsuppress-map */
      if (filter->usmap.name)
        json_object_string_add(json_addr, "selectiveUnsuppressRouteMap", filter->usmap.name);

      /* Receive prefix count */
      json_object_int_add(json_addr, "acceptedPrefixCounter", p->pcount[afi][safi]);

      /* Maximum prefix */
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
        {
          json_object_int_add(json_addr, "prefixAllowedMax", p->pmax[afi][safi]);
          if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_WARNING))
            json_object_boolean_true_add(json_addr, "prefixAllowedMaxWarning");
          json_object_int_add(json_addr, "prefixAllowedWarningThresh", p->pmax_threshold[afi][safi]);
          if (p->pmax_restart[afi][safi])
            json_object_int_add(json_addr, "prefixAllowedRestartIntervalMsecs", p->pmax_restart[afi][safi] * 60000);
        }
      json_object_object_add(json_neigh, afi_safi_print (afi, safi), json_addr);

    }
  else
    {
      filter = &p->filter[afi][safi];

      vty_out (vty, " For address family: %s%s", afi_safi_print (afi, safi),
	       VTY_NEWLINE);

      if (peer_group_active(p))
        vty_out (vty, "  %s peer-group member%s", p->group->name, VTY_NEWLINE);

      paf = peer_af_find(p, afi, safi);
      if (paf && PAF_SUBGRP(paf))
        {
          vty_out (vty, "  Update group %" PRIu64 ", subgroup %" PRIu64 "%s",
	           PAF_UPDGRP(paf)->id, PAF_SUBGRP(paf)->id, VTY_NEWLINE);
          vty_out (vty, "  Packet Queue length %d%s",
                   bpacket_queue_virtual_length(paf), VTY_NEWLINE);
        }
      else
        {
          vty_out(vty, "  Not part of any update group%s", VTY_NEWLINE);
        }
      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
        vty_out (vty, "  AF-dependant capabilities:%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
        {
          vty_out (vty, "    Outbound Route Filter (ORF) type (%d) Prefix-list:%s",
                   ORF_TYPE_PREFIX, VTY_NEWLINE);
          bgp_show_peer_afi_orf_cap (vty, p, afi, safi,
				     PEER_CAP_ORF_PREFIX_SM_ADV,
				     PEER_CAP_ORF_PREFIX_RM_ADV,
				     PEER_CAP_ORF_PREFIX_SM_RCV,
				     PEER_CAP_ORF_PREFIX_RM_RCV, use_json, NULL);
        }
      if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
          || CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
        {
          vty_out (vty, "    Outbound Route Filter (ORF) type (%d) Prefix-list:%s",
	           ORF_TYPE_PREFIX_OLD, VTY_NEWLINE);
          bgp_show_peer_afi_orf_cap (vty, p, afi, safi,
				     PEER_CAP_ORF_PREFIX_SM_ADV,
				     PEER_CAP_ORF_PREFIX_RM_ADV,
				     PEER_CAP_ORF_PREFIX_SM_OLD_RCV,
				     PEER_CAP_ORF_PREFIX_RM_OLD_RCV, use_json, NULL);
        }

      sprintf (orf_pfx_name, "%s.%d.%d", p->host, afi, safi);
      orf_pfx_count =  prefix_bgp_show_prefix_list (NULL, afi, orf_pfx_name, use_json);

      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND)
          || orf_pfx_count)
        {
          vty_out (vty, "  Outbound Route Filter (ORF):");
          if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_PREFIX_SEND))
	      vty_out (vty, " sent;");
          if (orf_pfx_count)
            vty_out (vty, " received (%d entries)", orf_pfx_count);
          vty_out (vty, "%s", VTY_NEWLINE);
        }
      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH))
          vty_out (vty, "  First update is deferred until ORF or ROUTE-REFRESH is received%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
        vty_out (vty, "  Route-Reflector Client%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        vty_out (vty, "  Route-Server Client%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
        vty_out (vty, "  Inbound soft reconfiguration allowed%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
        vty_out (vty, "  Private AS numbers (all) replaced in updates to this neighbor%s", VTY_NEWLINE);
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
        vty_out (vty, "  Private AS numbers replaced in updates to this neighbor%s", VTY_NEWLINE);
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
        vty_out (vty, "  Private AS numbers (all) removed in updates to this neighbor%s", VTY_NEWLINE);
      else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_REMOVE_PRIVATE_AS))
        vty_out (vty, "  Private AS numbers removed in updates to this neighbor%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_ADDPATH_TX_ALL_PATHS))
        vty_out (vty, "  Advertise all paths via addpath%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS))
        vty_out (vty, "  Advertise bestpath per AS via addpath%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
        vty_out (vty, "  Override ASNs in outbound updates if aspath equals remote-as%s", VTY_NEWLINE);

      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF) ||
          CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF))
        vty_out (vty, "  NEXT_HOP is always this router%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_AS_PATH_UNCHANGED))
        vty_out (vty, "  AS_PATH is propagated unchanged to this neighbor%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED))
        vty_out (vty, "  NEXT_HOP is propagated unchanged to this neighbor%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
        vty_out (vty, "  MED is propagated unchanged to this neighbor%s", VTY_NEWLINE);
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
          || CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
        {
          vty_out (vty, "  Community attribute sent to this neighbor");
          if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
	      && CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
	    vty_out (vty, "(both)%s", VTY_NEWLINE);
          else if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY))
	    vty_out (vty, "(extended)%s", VTY_NEWLINE);
          else
	    vty_out (vty, "(standard)%s", VTY_NEWLINE);
        }
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE))
        {
          vty_out (vty, "  Default information originate,");

          if (p->default_rmap[afi][safi].name)
	    vty_out (vty, " default route-map %s%s,",
	             p->default_rmap[afi][safi].map ? "*" : "",
	             p->default_rmap[afi][safi].name);
          if (paf && PAF_SUBGRP(paf) && CHECK_FLAG(PAF_SUBGRP(paf)->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE))
            vty_out (vty, " default sent%s", VTY_NEWLINE);
          else
            vty_out (vty, " default not sent%s", VTY_NEWLINE);
        }

      if (filter->plist[FILTER_IN].name
          || filter->dlist[FILTER_IN].name
          || filter->aslist[FILTER_IN].name
          || filter->map[RMAP_IN].name)
        vty_out (vty, "  Inbound path policy configured%s", VTY_NEWLINE);
      if (filter->plist[FILTER_OUT].name
          || filter->dlist[FILTER_OUT].name
          || filter->aslist[FILTER_OUT].name
          || filter->map[RMAP_OUT].name
          || filter->usmap.name)
        vty_out (vty, "  Outbound path policy configured%s", VTY_NEWLINE);

      /* prefix-list */
      if (filter->plist[FILTER_IN].name)
        vty_out (vty, "  Incoming update prefix filter list is %s%s%s",
	         filter->plist[FILTER_IN].plist ? "*" : "",
	         filter->plist[FILTER_IN].name,
	         VTY_NEWLINE);
      if (filter->plist[FILTER_OUT].name)
        vty_out (vty, "  Outgoing update prefix filter list is %s%s%s",
	         filter->plist[FILTER_OUT].plist ? "*" : "",
	         filter->plist[FILTER_OUT].name,
	         VTY_NEWLINE);

      /* distribute-list */
      if (filter->dlist[FILTER_IN].name)
        vty_out (vty, "  Incoming update network filter list is %s%s%s",
	         filter->dlist[FILTER_IN].alist ? "*" : "",
	         filter->dlist[FILTER_IN].name,
	         VTY_NEWLINE);
      if (filter->dlist[FILTER_OUT].name)
        vty_out (vty, "  Outgoing update network filter list is %s%s%s",
	         filter->dlist[FILTER_OUT].alist ? "*" : "",
	         filter->dlist[FILTER_OUT].name,
	         VTY_NEWLINE);

      /* filter-list. */
      if (filter->aslist[FILTER_IN].name)
        vty_out (vty, "  Incoming update AS path filter list is %s%s%s",
	         filter->aslist[FILTER_IN].aslist ? "*" : "",
	         filter->aslist[FILTER_IN].name,
	         VTY_NEWLINE);
      if (filter->aslist[FILTER_OUT].name)
        vty_out (vty, "  Outgoing update AS path filter list is %s%s%s",
	         filter->aslist[FILTER_OUT].aslist ? "*" : "",
	         filter->aslist[FILTER_OUT].name,
	         VTY_NEWLINE);

      /* route-map. */
      if (filter->map[RMAP_IN].name)
        vty_out (vty, "  Route map for incoming advertisements is %s%s%s",
                 filter->map[RMAP_IN].map ? "*" : "",
                 filter->map[RMAP_IN].name,
	         VTY_NEWLINE);
      if (filter->map[RMAP_OUT].name)
        vty_out (vty, "  Route map for outgoing advertisements is %s%s%s",
                 filter->map[RMAP_OUT].map ? "*" : "",
                 filter->map[RMAP_OUT].name,
                 VTY_NEWLINE);

      /* unsuppress-map */
      if (filter->usmap.name)
        vty_out (vty, "  Route map for selective unsuppress is %s%s%s",
	         filter->usmap.map ? "*" : "",
	         filter->usmap.name, VTY_NEWLINE);

      /* Receive prefix count */
      vty_out (vty, "  %ld accepted prefixes%s", p->pcount[afi][safi], VTY_NEWLINE);

      /* Maximum prefix */
      if (CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
        {
          vty_out (vty, "  Maximum prefixes allowed %ld%s%s", p->pmax[afi][safi],
	           CHECK_FLAG (p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_WARNING)
	           ? " (warning-only)" : "", VTY_NEWLINE);
          vty_out (vty, "  Threshold for warning message %d%%",
	           p->pmax_threshold[afi][safi]);
          if (p->pmax_restart[afi][safi])
            vty_out (vty, ", restart interval %d min", p->pmax_restart[afi][safi]);
          vty_out (vty, "%s", VTY_NEWLINE);
        }

      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

static void
bgp_show_peer (struct vty *vty, struct peer *p, u_char use_json, json_object *json)
{
  struct bgp *bgp;
  char buf1[PREFIX2STR_BUFFER], buf[SU_ADDRSTRLEN];
  char timebuf[BGP_UPTIME_LEN];
  char dn_flag[2];
  const char *subcode_str;
  const char *code_str;
  afi_t afi;
  safi_t safi;
  u_int16_t i;
  u_char *msg;
  json_object *json_neigh = NULL;

  bgp = p->bgp;

  if (use_json)
    json_neigh = json_object_new_object();

  if (!use_json)
    {
      if (p->conf_if) /* Configured interface name. */
        vty_out (vty, "BGP neighbor on %s: %s, ", p->conf_if,
                 BGP_PEER_SU_UNSPEC(p) ? "None" :
                 sockunion2str (&p->su, buf, SU_ADDRSTRLEN));
      else /* Configured IP address. */
        {
          memset(dn_flag, '\0', sizeof(dn_flag));
          if (peer_dynamic_neighbor(p))
            dn_flag[0] = '*';

          vty_out (vty, "BGP neighbor is %s%s, ", dn_flag, p->host);
        }
    }

  if (use_json)
    {
      if (p->conf_if && BGP_PEER_SU_UNSPEC(p))
        json_object_string_add(json_neigh, "bgpNeighborAddr", "none");
      else if (p->conf_if && !BGP_PEER_SU_UNSPEC(p))
        json_object_string_add(json_neigh, "bgpNeighborAddr", sockunion2str (&p->su, buf, SU_ADDRSTRLEN));

      json_object_int_add(json_neigh, "remoteAs", p->as);

      if (p->change_local_as)
        json_object_int_add(json_neigh, "localAs", p->change_local_as);
      else
        json_object_int_add(json_neigh, "localAs", p->local_as);

      if (CHECK_FLAG (p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
        json_object_boolean_true_add(json_neigh, "localAsNoPrepend");

      if (CHECK_FLAG (p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS))
        json_object_boolean_true_add(json_neigh, "localAsReplaceAs");
    }
  else
    {
      if ((p->as_type == AS_SPECIFIED) ||
	  (p->as_type == AS_EXTERNAL) ||
	  (p->as_type == AS_INTERNAL))
	vty_out (vty, "remote AS %u, ", p->as);
      else
	vty_out (vty, "remote AS Unspecified, ");
      vty_out (vty, "local AS %u%s%s, ",
	       p->change_local_as ? p->change_local_as : p->local_as,
	       CHECK_FLAG (p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND) ?
	       " no-prepend" : "",
	       CHECK_FLAG (p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS) ?
	       " replace-as" : "");
    }
  /* peer type internal, external, confed-internal or confed-external */
  if (p->as == p->local_as)
    {
      if (use_json)
        {
          if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
            json_object_boolean_true_add(json_neigh, "nbrConfedInternalLink");
          else
            json_object_boolean_true_add(json_neigh, "nbrInternalLink");
        }
      else
        {
          if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
            vty_out (vty, "confed-internal link%s", VTY_NEWLINE);
          else
            vty_out (vty, "internal link%s", VTY_NEWLINE);
        }
    }
  else
    {
      if (use_json)
        {
          if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
            json_object_boolean_true_add(json_neigh, "nbrConfedExternalLink");
          else
            json_object_boolean_true_add(json_neigh, "nbrExternalLink");
        }
      else
        {
         if (bgp_confederation_peers_check(bgp, p->as))
           vty_out (vty, "confed-external link%s", VTY_NEWLINE);
         else
           vty_out (vty, "external link%s", VTY_NEWLINE);
        }
    }

  /* Description. */
  if (p->desc)
    {
      if (use_json)
        json_object_string_add(json_neigh, "nbrDesc", p->desc);
      else
        vty_out (vty, " Description: %s%s", p->desc, VTY_NEWLINE);
    }

  if (p->hostname)
    {
      if (use_json)
        {
          if (p->hostname)
            json_object_string_add(json_neigh, "hostname", p->hostname);

          if (p->domainname)
            json_object_string_add(json_neigh, "domainname", p->domainname);
        }
      else
        {
          if (p->domainname && (p->domainname[0] != '\0'))
            vty_out(vty, "Hostname: %s.%s%s", p->hostname, p->domainname,
                    VTY_NEWLINE);
          else
            vty_out(vty, "Hostname: %s%s", p->hostname, VTY_NEWLINE);
        }

    }

  /* Peer-group */
  if (p->group)
    {
      if (use_json)
        {
          json_object_string_add(json_neigh, "peerGroup", p->group->name);

          if (dn_flag[0])
            {
              struct prefix *prefix = NULL, *range = NULL;

              prefix = sockunion2hostprefix(&(p->su));
              if (prefix)
                range = peer_group_lookup_dynamic_neighbor_range (p->group, prefix);

              if (range)
                {
                  prefix2str(range, buf1, sizeof(buf1));
                  json_object_string_add(json_neigh, "peerSubnetRangeGroup", buf1);
                }
            }
        }
      else
        {
          vty_out (vty, " Member of peer-group %s for session parameters%s",
                   p->group->name, VTY_NEWLINE);

          if (dn_flag[0])
            {
              struct prefix *prefix = NULL, *range = NULL;

              prefix = sockunion2hostprefix(&(p->su));
              if (prefix)
                range = peer_group_lookup_dynamic_neighbor_range (p->group, prefix);

              if (range)
                {
                  prefix2str(range, buf1, sizeof(buf1));
                  vty_out (vty, " Belongs to the subnet range group: %s%s", buf1, VTY_NEWLINE);
                }
            }
        }
    }

  if (use_json)
    {
      /* Administrative shutdown. */
      if (CHECK_FLAG (p->flags, PEER_FLAG_SHUTDOWN))
        json_object_boolean_true_add(json_neigh, "adminShutDown");

      /* BGP Version. */
      json_object_int_add(json_neigh, "bgpVersion", 4);
      json_object_string_add(json_neigh, "remoteRouterId", inet_ntop (AF_INET, &p->remote_id, buf1, BUFSIZ));

      /* Confederation */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION) && bgp_confederation_peers_check (bgp, p->as))
        json_object_boolean_true_add(json_neigh, "nbrCommonAdmin");

      /* Status. */
      json_object_string_add(json_neigh, "bgpState", LOOKUP (bgp_status_msg, p->status));

      if (p->status == Established)
        {
          time_t uptime;
          struct tm *tm;

          uptime = bgp_clock();
          uptime -= p->uptime;
          tm = gmtime(&uptime);

          json_object_int_add(json_neigh, "bgpTimerUp", (tm->tm_sec * 1000) + (tm->tm_min * 60000) + (tm->tm_hour * 3600000));
        }

      else if (p->status == Active)
        {
          if (CHECK_FLAG (p->flags, PEER_FLAG_PASSIVE))
            json_object_string_add(json_neigh, "bgpStateIs", "passive");
          else if (CHECK_FLAG (p->sflags, PEER_STATUS_NSF_WAIT))
            json_object_string_add(json_neigh, "bgpStateIs", "passiveNSF");
        }

      /* read timer */
      time_t uptime;
      struct tm *tm;

      uptime = bgp_clock();
      uptime -= p->readtime;
      tm = gmtime(&uptime);
      json_object_int_add(json_neigh, "bgpTimerLastRead", (tm->tm_sec * 1000) + (tm->tm_min * 60000) + (tm->tm_hour * 3600000));

      uptime = bgp_clock();
      uptime -= p->last_write;
      tm = gmtime(&uptime);
      json_object_int_add(json_neigh, "bgpTimerLastRead", (tm->tm_sec * 1000) + (tm->tm_min * 60000) + (tm->tm_hour * 3600000));

      /* Configured timer values. */
      json_object_int_add(json_neigh, "bgpTimerHoldTimeMsecs", p->v_holdtime * 1000);
      json_object_int_add(json_neigh, "bgpTimerKeepAliveIntervalMsecs", p->v_keepalive * 1000);

      if (CHECK_FLAG (p->config, PEER_CONFIG_TIMER))
        {
          json_object_int_add(json_neigh, "bgpTimerConfiguredHoldTimeMsecs", p->holdtime * 1000);
          json_object_int_add(json_neigh, "bgpTimerConfiguredKeepAliveIntervalMsecs", p->keepalive * 1000);
        }
    }
  else
    {
      /* Administrative shutdown. */
      if (CHECK_FLAG (p->flags, PEER_FLAG_SHUTDOWN))
        vty_out (vty, " Administratively shut down%s", VTY_NEWLINE);

      /* BGP Version. */
      vty_out (vty, "  BGP version 4");
      vty_out (vty, ", remote router ID %s%s", inet_ntop (AF_INET, &p->remote_id, buf1, BUFSIZ),
               VTY_NEWLINE);

      /* Confederation */
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION)
          && bgp_confederation_peers_check (bgp, p->as))
        vty_out (vty, "  Neighbor under common administration%s", VTY_NEWLINE);
  
      /* Status. */
      vty_out (vty, "  BGP state = %s", LOOKUP (bgp_status_msg, p->status));

      if (p->status == Established)
        vty_out (vty, ", up for %8s", peer_uptime (p->uptime, timebuf, BGP_UPTIME_LEN, 0, NULL));

      else if (p->status == Active)
        {
          if (CHECK_FLAG (p->flags, PEER_FLAG_PASSIVE))
            vty_out (vty, " (passive)");
        else if (CHECK_FLAG (p->sflags, PEER_STATUS_NSF_WAIT))
               vty_out (vty, " (NSF passive)");
        }
      vty_out (vty, "%s", VTY_NEWLINE);

      /* read timer */
      vty_out (vty, "  Last read %s", peer_uptime (p->readtime, timebuf, BGP_UPTIME_LEN, 0, NULL));
      vty_out (vty, ", Last write %s%s",
               peer_uptime (p->last_write, timebuf, BGP_UPTIME_LEN, 0, NULL), VTY_NEWLINE);

      /* Configured timer values. */
      vty_out (vty, "  Hold time is %d, keepalive interval is %d seconds%s",
	       p->v_holdtime, p->v_keepalive, VTY_NEWLINE);
      if (CHECK_FLAG (p->config, PEER_CONFIG_TIMER))
        {
          vty_out (vty, "  Configured hold time is %d", p->holdtime);
          vty_out (vty, ", keepalive interval is %d seconds%s",
	           p->keepalive, VTY_NEWLINE);
        }
    }
  /* Capability. */
  if (p->status == Established) 
    {
      if (p->cap
	  || p->afc_adv[AFI_IP][SAFI_UNICAST]
	  || p->afc_recv[AFI_IP][SAFI_UNICAST]
	  || p->afc_adv[AFI_IP][SAFI_MULTICAST]
	  || p->afc_recv[AFI_IP][SAFI_MULTICAST]
#ifdef HAVE_IPV6
	  || p->afc_adv[AFI_IP6][SAFI_UNICAST]
	  || p->afc_recv[AFI_IP6][SAFI_UNICAST]
	  || p->afc_adv[AFI_IP6][SAFI_MULTICAST]
	  || p->afc_recv[AFI_IP6][SAFI_MULTICAST]
#endif /* HAVE_IPV6 */
	  || p->afc_adv[AFI_IP][SAFI_MPLS_VPN]
	  || p->afc_recv[AFI_IP][SAFI_MPLS_VPN])
	{
          if (use_json)
            {
	      json_object *json_cap = NULL;

              json_cap = json_object_new_object();

	      /* AS4 */
	      if (CHECK_FLAG (p->cap, PEER_CAP_AS4_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV))
	        {
	          if (CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV) && CHECK_FLAG (p->cap, PEER_CAP_AS4_RCV))
		    json_object_string_add(json_cap, "4byteAs", "advertisedAndReceived");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV))
		    json_object_string_add(json_cap, "4byteAs", "advertised");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_AS4_RCV))
		    json_object_string_add(json_cap, "4byteAs", "received");
	        }

	      /* AddPath */
	      if (CHECK_FLAG (p->cap, PEER_CAP_ADDPATH_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_ADDPATH_ADV))
                {
	          json_object *json_add = NULL;
                  const char *print_store;

                  json_add = json_object_new_object();

                  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
                    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
                      {
	                json_object *json_sub = NULL;
                        json_sub = json_object_new_object();
                        print_store = afi_safi_print (afi, safi);

                        if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV))
                          {
	                    if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV) && CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV))
	                      json_object_boolean_true_add(json_sub, "txAdvertisedAndReceived");
	                    else if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV))
		              json_object_boolean_true_add(json_sub, "txAdvertised");
	                    else if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV))
		              json_object_boolean_true_add(json_sub, "txReceived");
                          }

                        if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
                          {
	                    if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) && CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
	                      json_object_boolean_true_add(json_sub, "rxAdvertisedAndReceived");
	                    else if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV))
		              json_object_boolean_true_add(json_sub, "rxAdvertised");
	                    else if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
		              json_object_boolean_true_add(json_sub, "rxReceived");
                          }

                        if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
                          json_object_object_add(json_add, print_store, json_sub);
                      }

                  json_object_object_add(json_cap, "addPath", json_add);
                }

	      /* Dynamic */
	      if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
	        {
	          if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV) && CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV))
		    json_object_string_add(json_cap, "dynamic", "advertisedAndReceived");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
		    json_object_string_add(json_cap, "dynamic", "advertised");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV))
		    json_object_string_add(json_cap, "dynamic", "received");
	        }

	      /* Extended nexthop */
	      if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV))
	        {
	          json_object *json_nxt = NULL;
                  const char *print_store;

                  json_nxt = json_object_new_object();

	          if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV) && CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV))
		    json_object_string_add(json_cap, "extendedNexthop", "advertisedAndReceived");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV))
		    json_object_string_add(json_cap, "extendedNexthop", "advertised");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV))
		    json_object_string_add(json_cap, "extendedNexthop", "received");

                  if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV))
		    {
                      for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
                        {
                          if (CHECK_FLAG (p->af_cap[AFI_IP][safi], PEER_CAP_ENHE_AF_RCV))
                            {
                              print_store = afi_safi_print (AFI_IP, safi);
                              json_object_string_add(json_nxt, print_store, "recieved");
                            }
                        }
                      json_object_object_add(json_cap, "extendedNexthopFamililesByPeer", json_nxt);
                    }
	        }

	      /* Route Refresh */
	      if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV)
	          || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
	        {
	          if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV) && (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV) || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV)))
                    {
		      if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV) && CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV))
                        json_object_string_add(json_cap, "routeRefresh", "advertisedAndReceivedOldNew");
                      else
                        {
                          if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                            json_object_string_add(json_cap, "routeRefresh", "advertisedAndReceivedOld");
                          else
                            json_object_string_add(json_cap, "routeRefresh", "advertisedAndReceivedNew");
                        }
                    }
	          else if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV))
		    json_object_string_add(json_cap, "routeRefresh", "advertised");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV) || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
		    json_object_string_add(json_cap, "routeRefresh", "received");
                }

	      /* Multiprotocol Extensions */
	      json_object *json_multi = NULL;
              json_multi = json_object_new_object();

	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        {
                  for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	            {
                      if (p->afc_adv[afi][safi] || p->afc_recv[afi][safi])
		        {
	                  json_object *json_exten = NULL;
                          json_exten = json_object_new_object();

                          if (p->afc_adv[afi][safi] && p->afc_recv[afi][safi])
                            json_object_boolean_true_add(json_exten, "advertisedAndReceived");
                          else if (p->afc_adv[afi][safi])
                            json_object_boolean_true_add(json_exten, "advertised");
                          else if (p->afc_recv[afi][safi])
                            json_object_boolean_true_add(json_exten, "received");

                          json_object_object_add(json_multi, afi_safi_print (afi, safi), json_exten);
		        }
                    }
                }
              json_object_object_add(json_cap, "multiprotocolExtensions", json_multi);

	      /* Gracefull Restart */
	      if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV))
	        {
	          if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV) && CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV))
		    json_object_string_add(json_cap, "gracefulRestart", "advertisedAndReceived");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV))
		    json_object_string_add(json_cap, "gracefulRestartCapability", "advertised");
	          else if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV))
		    json_object_string_add(json_cap, "gracefulRestartCapability", "received");

	          if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV))
		    {
		      int restart_af_count = 0;
                      json_object *json_restart = NULL;
                      json_restart = json_object_new_object();

		      json_object_int_add(json_cap, "gracefulRestartRemoteTimerMsecs", p->v_gr_restart * 1000);

		      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
		        {
                          for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
		            {
                              if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_RESTART_AF_RCV))
			        {
	                          json_object *json_sub = NULL;
                                  json_sub = json_object_new_object();

                                  if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_RESTART_AF_PRESERVE_RCV))
                                    json_object_boolean_true_add(json_sub, "preserved");
			          restart_af_count++;
                                  json_object_object_add(json_restart, afi_safi_print (afi, safi), json_sub);
			        }
                            }
                        }
		      if (! restart_af_count)
		        json_object_string_add(json_cap, "addressFamiliesByPeer", "none");
                      else
                        json_object_object_add(json_cap, "addressFamiliesByPeer", json_restart);
                    }
                }
              json_object_object_add(json_neigh, "neighborCapabilities", json_cap);
            }
          else
            {
	      vty_out (vty, "  Neighbor capabilities:%s", VTY_NEWLINE);

	      /* AS4 */
	      if (CHECK_FLAG (p->cap, PEER_CAP_AS4_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV))
	        {
	          vty_out (vty, "    4 Byte AS:");
	          if (CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV))
		    vty_out (vty, " advertised");
	          if (CHECK_FLAG (p->cap, PEER_CAP_AS4_RCV))
		    vty_out (vty, " %sreceived",
			     CHECK_FLAG (p->cap, PEER_CAP_AS4_ADV) ? "and " : "");
	          vty_out (vty, "%s", VTY_NEWLINE);
	        }

	      /* AddPath */
	      if (CHECK_FLAG (p->cap, PEER_CAP_ADDPATH_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_ADDPATH_ADV))
                {
	          vty_out (vty, "    AddPath:%s", VTY_NEWLINE);

                  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
                    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
                      {
                        if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV) ||
                            CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV))
                          {
                            vty_out (vty, "      %s: TX ", afi_safi_print (afi, safi));

                            if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV))
                              vty_out (vty, "advertised %s", afi_safi_print (afi, safi));

                            if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV))
                              vty_out (vty, "%sreceived", CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV) ? " and " : "" );

                            vty_out (vty, "%s", VTY_NEWLINE);
                          }

                        if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) ||
                        CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
                          {
                            vty_out (vty, "      %s: RX ", afi_safi_print (afi, safi));

                            if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV))
                              vty_out (vty, "advertised %s", afi_safi_print (afi, safi));

                            if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_RCV))
                              vty_out (vty, "%sreceived", CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) ? " and " : "" );

                            vty_out (vty, "%s", VTY_NEWLINE);
                          }
                      }
                }

	      /* Dynamic */
	      if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
	        {
	          vty_out (vty, "    Dynamic:");
	          if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV))
		    vty_out (vty, " advertised");
	          if (CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_RCV))
		    vty_out (vty, " %sreceived",
			     CHECK_FLAG (p->cap, PEER_CAP_DYNAMIC_ADV) ? "and " : "");
	          vty_out (vty, "%s", VTY_NEWLINE);
	        }

	      /* Extended nexthop */
	      if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV))
	        {
	          vty_out (vty, "    Extended nexthop:");
	          if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV))
		    vty_out (vty, " advertised");
	          if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV))
		    vty_out (vty, " %sreceived",
			     CHECK_FLAG (p->cap, PEER_CAP_ENHE_ADV) ? "and " : "");
	          vty_out (vty, "%s", VTY_NEWLINE);

                  if (CHECK_FLAG (p->cap, PEER_CAP_ENHE_RCV))
		    {
		      vty_out (vty, "      Address families by peer:%s        ", VTY_NEWLINE);
                      for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
                        if (CHECK_FLAG (p->af_cap[AFI_IP][safi], PEER_CAP_ENHE_AF_RCV))
                          vty_out (vty, "           %s%s",
                                   afi_safi_print (AFI_IP, safi), VTY_NEWLINE);
                    }
	        }

	      /* Route Refresh */
              if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV)
                  || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
                  || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                {
                  vty_out (vty, "    Route refresh:");
                  if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV))
                    vty_out (vty, " advertised");
                  if (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)
                      || CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV))
                    vty_out (vty, " %sreceived(%s)",
                             CHECK_FLAG (p->cap, PEER_CAP_REFRESH_ADV) ? "and " : "",
                             (CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV)
                             && CHECK_FLAG (p->cap, PEER_CAP_REFRESH_NEW_RCV)) ?
                             "old & new" : CHECK_FLAG (p->cap, PEER_CAP_REFRESH_OLD_RCV) ? "old" : "new");

                  vty_out (vty, "%s", VTY_NEWLINE);
                }

	      /* Multiprotocol Extensions */
	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	          if (p->afc_adv[afi][safi] || p->afc_recv[afi][safi])
		    {
		      vty_out (vty, "    Address family %s:", afi_safi_print (afi, safi));
		      if (p->afc_adv[afi][safi])
		        vty_out (vty, " advertised");
		      if (p->afc_recv[afi][safi])
		        vty_out (vty, " %sreceived", p->afc_adv[afi][safi] ? "and " : "");
		      vty_out (vty, "%s", VTY_NEWLINE);
		    }

              /* Hostname capability */
              if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV) ||
                  CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV))
                {
                  vty_out (vty, "    Hostname Capability:");
                  if (CHECK_FLAG (p->cap, PEER_CAP_HOSTNAME_ADV))
                    vty_out (vty, " advertised");
                  if (CHECK_FLAG (p->cap, PEER_CAP_HOSTNAME_RCV))
                    vty_out (vty, " %sreceived",
                             CHECK_FLAG (p->cap, PEER_CAP_HOSTNAME_ADV) ? "and " : "");
                  vty_out (vty, "%s", VTY_NEWLINE);
                }

	      /* Gracefull Restart */
	      if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV)
	          || CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV))
	        {
	          vty_out (vty, "    Graceful Restart Capabilty:");
	          if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV))
		    vty_out (vty, " advertised");
	          if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV))
		    vty_out (vty, " %sreceived",
			     CHECK_FLAG (p->cap, PEER_CAP_RESTART_ADV) ? "and " : "");
	          vty_out (vty, "%s", VTY_NEWLINE);

	          if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV))
		    {
		      int restart_af_count = 0;

		      vty_out (vty, "      Remote Restart timer is %d seconds%s",
			       p->v_gr_restart, VTY_NEWLINE);
		      vty_out (vty, "      Address families by peer:%s        ", VTY_NEWLINE);

		      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
		        for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
		          if (CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_RESTART_AF_RCV))
			    {
			      vty_out (vty, "%s%s(%s)", restart_af_count ? ", " : "",
				       afi_safi_print (afi, safi),
				       CHECK_FLAG (p->af_cap[afi][safi], PEER_CAP_RESTART_AF_PRESERVE_RCV) ?
				       "preserved" : "not preserved");
			      restart_af_count++;
			    }
		      if (! restart_af_count)
		        vty_out (vty, "none");
		      vty_out (vty, "%s", VTY_NEWLINE);
	            }
	        }
            }
	}
    }

  /* graceful restart information */
  if (CHECK_FLAG (p->cap, PEER_CAP_RESTART_RCV)
      || p->t_gr_restart
      || p->t_gr_stale)
    {
      json_object *json_grace = NULL;
      json_object *json_grace_send = NULL;
      json_object *json_grace_recv = NULL;
      int eor_send_af_count = 0;
      int eor_receive_af_count = 0;

      if (use_json)
        {
          json_grace = json_object_new_object();
          json_grace_send = json_object_new_object();
          json_grace_recv = json_object_new_object();

          if (p->status == Established)
	    {
	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        {
                  for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	            {
                      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_EOR_SEND))
		        {
		          json_object_boolean_true_add(json_grace_send, afi_safi_print (afi, safi));
		          eor_send_af_count++;
		        }
                    }
                }
	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        {
                  for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	            {
                      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_EOR_RECEIVED))
		        {
		          json_object_boolean_true_add(json_grace_recv, afi_safi_print (afi, safi));
                          eor_receive_af_count++;
                        }
		    }
                }
            }

          json_object_object_add(json_grace, "endOfRibSend", json_grace_send);
          json_object_object_add(json_grace, "endOfRibRecv", json_grace_recv);

          if (p->t_gr_restart)
            json_object_int_add(json_grace, "gracefulRestartTimerMsecs", thread_timer_remain_second (p->t_gr_restart) * 1000);

          if (p->t_gr_stale)
            json_object_int_add(json_grace, "gracefulStalepathTimerMsecs", thread_timer_remain_second (p->t_gr_stale) * 1000);

          json_object_object_add(json_neigh, "gracefulRestartInfo", json_grace);
        }
      else
        {
          vty_out (vty, "  Graceful restart informations:%s", VTY_NEWLINE);
          if (p->status == Established)
	    {
	      vty_out (vty, "    End-of-RIB send: ");
	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        {
                  for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	            {
                      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_EOR_SEND))
		        {
		          vty_out (vty, "%s%s", eor_send_af_count ? ", " : "",
			           afi_safi_print (afi, safi));
		          eor_send_af_count++;
		        }
                    }
                }
	      vty_out (vty, "%s", VTY_NEWLINE);
	      vty_out (vty, "    End-of-RIB received: ");
	      for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	        {
                  for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	            {
                      if (CHECK_FLAG (p->af_sflags[afi][safi], PEER_STATUS_EOR_RECEIVED))
		        {
		          vty_out (vty, "%s%s", eor_receive_af_count ? ", " : "",
		                   afi_safi_print (afi, safi));
		          eor_receive_af_count++;
                        }
		    }
                }
	      vty_out (vty, "%s", VTY_NEWLINE);
            }

          if (p->t_gr_restart)
            vty_out (vty, "    The remaining time of restart timer is %ld%s",
                     thread_timer_remain_second (p->t_gr_restart), VTY_NEWLINE);
      
          if (p->t_gr_stale)
            vty_out (vty, "    The remaining time of stalepath timer is %ld%s",
                     thread_timer_remain_second (p->t_gr_stale), VTY_NEWLINE);
        }
    }
  if (use_json)
    {
      json_object *json_stat = NULL;
      json_stat = json_object_new_object();
      /* Packet counts. */
      json_object_int_add(json_stat, "depthInq", 0);
      json_object_int_add(json_stat, "depthOutq", (unsigned long) p->obuf->count);
      json_object_int_add(json_stat, "opensSent",  p->open_out);
      json_object_int_add(json_stat, "opensRecv", p->open_in);
      json_object_int_add(json_stat, "notificationsSent", p->notify_out);
      json_object_int_add(json_stat, "notificationsRecv", p->notify_in);
      json_object_int_add(json_stat, "updatesSent", p->update_out);
      json_object_int_add(json_stat, "updatesRecv", p->update_in);
      json_object_int_add(json_stat, "keepalivesSent", p->keepalive_out);
      json_object_int_add(json_stat, "keepalivesRecv", p->keepalive_in);
      json_object_int_add(json_stat, "routeRefreshSent", p->refresh_out);
      json_object_int_add(json_stat, "routeRefreshRecv", p->refresh_in);
      json_object_int_add(json_stat, "capabilitySent", p->dynamic_cap_out);
      json_object_int_add(json_stat, "capabilityRecv", p->dynamic_cap_in);
      json_object_int_add(json_stat, "totalSent", p->open_out + p->notify_out + p->update_out + p->keepalive_out + p->refresh_out + p->dynamic_cap_out);
      json_object_int_add(json_stat, "totalRecv", p->open_in + p->notify_in + p->update_in + p->keepalive_in + p->refresh_in + p->dynamic_cap_in);
      json_object_object_add(json_neigh, "messageStats", json_stat);
    }
  else
    {
      /* Packet counts. */
      vty_out (vty, "  Message statistics:%s", VTY_NEWLINE);
      vty_out (vty, "    Inq depth is 0%s", VTY_NEWLINE);
      vty_out (vty, "    Outq depth is %lu%s", (unsigned long) p->obuf->count, VTY_NEWLINE);
      vty_out (vty, "                         Sent       Rcvd%s", VTY_NEWLINE);
      vty_out (vty, "    Opens:         %10d %10d%s", p->open_out, p->open_in, VTY_NEWLINE);
      vty_out (vty, "    Notifications: %10d %10d%s", p->notify_out, p->notify_in, VTY_NEWLINE);
      vty_out (vty, "    Updates:       %10d %10d%s", p->update_out, p->update_in, VTY_NEWLINE);
      vty_out (vty, "    Keepalives:    %10d %10d%s", p->keepalive_out, p->keepalive_in, VTY_NEWLINE);
      vty_out (vty, "    Route Refresh: %10d %10d%s", p->refresh_out, p->refresh_in, VTY_NEWLINE);
      vty_out (vty, "    Capability:    %10d %10d%s", p->dynamic_cap_out, p->dynamic_cap_in, VTY_NEWLINE);
      vty_out (vty, "    Total:         %10d %10d%s", p->open_out + p->notify_out +
               p->update_out + p->keepalive_out + p->refresh_out + p->dynamic_cap_out,
               p->open_in + p->notify_in + p->update_in + p->keepalive_in + p->refresh_in +
               p->dynamic_cap_in, VTY_NEWLINE);
    }

  if (use_json)
    {
      /* advertisement-interval */
      json_object_int_add(json_neigh, "minBtwnAdvertisementRunsTimerMsecs", p->v_routeadv * 1000);

      /* Update-source. */
      if (p->update_if || p->update_source)
        {
          if (p->update_if)
            json_object_string_add(json_neigh, "updateSource", p->update_if);
          else if (p->update_source)
            json_object_string_add(json_neigh, "updateSource", sockunion2str (p->update_source, buf1, SU_ADDRSTRLEN));
        }

      /* Default weight */
      if (CHECK_FLAG (p->config, PEER_CONFIG_WEIGHT))
        json_object_int_add(json_neigh, "defaultWeight", p->weight);

    }
  else
    {
      /* advertisement-interval */
      vty_out (vty, "  Minimum time between advertisement runs is %d seconds%s",
               p->v_routeadv, VTY_NEWLINE);

      /* Update-source. */
      if (p->update_if || p->update_source)
        {
          vty_out (vty, "  Update source is ");
          if (p->update_if)
            vty_out (vty, "%s", p->update_if);
          else if (p->update_source)
            vty_out (vty, "%s", sockunion2str (p->update_source, buf1, SU_ADDRSTRLEN));
          vty_out (vty, "%s", VTY_NEWLINE);
        }

      /* Default weight */
      if (CHECK_FLAG (p->config, PEER_CONFIG_WEIGHT))
        vty_out (vty, "  Default weight %d%s", p->weight, VTY_NEWLINE);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

  /* Address Family Information */
  json_object *json_hold = NULL;

  if (use_json)
    json_hold = json_object_new_object();

  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
      if (p->afc[afi][safi])
	bgp_show_peer_afi (vty, p, afi, safi, use_json, json_hold);

  if (use_json)
    {
      json_object_int_add(json_hold, "connectionsEstablished", p->established);
      json_object_int_add(json_hold, "connectionsDropped", p->dropped);
    }
  else
    vty_out (vty, "  Connections established %d; dropped %d%s", p->established, p->dropped,
	     VTY_NEWLINE);

  if (! p->last_reset)
    {
      if (use_json)
        json_object_string_add(json_hold, "lastReset", "never");
      else
        vty_out (vty, "  Last reset never%s", VTY_NEWLINE);
    }
  else
    {
      if (use_json)
        {
          time_t uptime;
          struct tm *tm;

          uptime = bgp_clock();
          uptime -= p->resettime;
          tm = gmtime(&uptime);
          json_object_int_add(json_hold, "lastResetTimerMsecs", (tm->tm_sec * 1000) + (tm->tm_min * 60000) + (tm->tm_hour * 3600000));
          json_object_string_add(json_hold, "lastResetDueTo", peer_down_str[(int) p->last_reset]);
          if (p->last_reset_cause_size)
            {
              msg = p->last_reset_cause;
              char adapter[BUFSIZ];
              sprintf(adapter, "%s", msg);
              json_object_string_add(json_hold, "messageReceivedThatCausedBgpNotification", adapter);
            }
        }
      else
        {
          vty_out (vty, "  Last reset %s, ",
                   peer_uptime (p->resettime, timebuf, BGP_UPTIME_LEN, 0, NULL));

          if (p->last_reset == PEER_DOWN_NOTIFY_SEND ||
              p->last_reset == PEER_DOWN_NOTIFY_RECEIVED)
            {
              code_str = bgp_notify_code_str(p->notify.code);
              subcode_str = bgp_notify_subcode_str(p->notify.code, p->notify.subcode);
              vty_out (vty, "due to NOTIFICATION %s (%s%s)%s",
                       p->last_reset == PEER_DOWN_NOTIFY_SEND ? "sent" : "received",
                       code_str, subcode_str, VTY_NEWLINE);
            }
          else
            {
              vty_out (vty, "due to %s%s",
                       peer_down_str[(int) p->last_reset], VTY_NEWLINE);
            }

          if (p->last_reset_cause_size)
            {
              msg = p->last_reset_cause;
              vty_out(vty, "  Message received that caused BGP to send a NOTIFICATION:%s    ", VTY_NEWLINE);
              for (i = 1; i <= p->last_reset_cause_size; i++)
                {
                  vty_out(vty, "%02X", *msg++);

                  if (i != p->last_reset_cause_size)
                    {
                      if (i % 16 == 0)
                        {
                          vty_out(vty, "%s    ", VTY_NEWLINE);
                        }
                      else if (i % 4 == 0)
                        {
                          vty_out(vty, " ");
                        }
                    }
                }
              vty_out(vty, "%s", VTY_NEWLINE);
            }
        }
    }

  if (CHECK_FLAG (p->sflags, PEER_STATUS_PREFIX_OVERFLOW))
    {
      if (use_json)
        json_object_boolean_true_add(json_hold, "prefixesConfigExceedMax");
      else
        vty_out (vty, "  Peer had exceeded the max. no. of prefixes configured.%s", VTY_NEWLINE);

      if (p->t_pmax_restart)
        {
          if (use_json)
            {
              json_object_boolean_true_add(json_hold, "reducePrefixNumFrom");
              json_object_int_add(json_hold, "restartInTimerMsec", thread_timer_remain_second (p->t_pmax_restart) * 1000);
            }
          else
            vty_out (vty, "  Reduce the no. of prefix from %s, will restart in %ld seconds%s",
                     p->host, thread_timer_remain_second (p->t_pmax_restart),
                     VTY_NEWLINE);
        }
      else
        {
          if (use_json)
            json_object_boolean_true_add(json_hold, "reducePrefixNumAndClearIpBgp");
          else
            vty_out (vty, "  Reduce the no. of prefix and clear ip bgp %s to restore peering%s",
	             p->host, VTY_NEWLINE);
        }
    }

  if (use_json)
    json_object_object_add(json_neigh, "addressFamilyInfo", json_hold);

  /* EBGP Multihop and GTSM */
  if (p->sort != BGP_PEER_IBGP)
    {
      if (use_json)
        {
          if (p->gtsm_hops > 0)
            json_object_int_add(json_neigh, "externalBgpNbrMaxHopsAway", p->gtsm_hops);
          else if (p->ttl > 1)
            json_object_int_add(json_neigh, "externalBgpNbrMaxHopsAway", p->ttl);
        }
      else
        {
          if (p->gtsm_hops > 0)
            vty_out (vty, "  External BGP neighbor may be up to %d hops away.%s",
                     p->gtsm_hops, VTY_NEWLINE);
          else if (p->ttl > 1)
            vty_out (vty, "  External BGP neighbor may be up to %d hops away.%s",
                     p->ttl, VTY_NEWLINE);
        }
    }
  else
    {
      if (p->gtsm_hops > 0)
        {
          if (use_json)
            json_object_int_add(json_neigh, "internalBgpNbrMaxHopsAway", p->gtsm_hops);
          else
            vty_out (vty, "  Internal BGP neighbor may be up to %d hops away.%s",
                     p->gtsm_hops, VTY_NEWLINE);
        }
    }

  /* Local address. */
  if (p->su_local)
    {
      if (use_json)
        {
          json_object_string_add(json_neigh, "hostLocal", sockunion2str (p->su_local, buf1, SU_ADDRSTRLEN));
          json_object_int_add(json_neigh, "portLocal", ntohs (p->su_local->sin.sin_port));
        }
      else
        vty_out (vty, "Local host: %s, Local port: %d%s",
	         sockunion2str (p->su_local, buf1, SU_ADDRSTRLEN),
	         ntohs (p->su_local->sin.sin_port),
	         VTY_NEWLINE);
    }
      
  /* Remote address. */
  if (p->su_remote)
    {
      if (use_json)
        {
          json_object_string_add(json_neigh, "hostForeign", sockunion2str (p->su_remote, buf1, SU_ADDRSTRLEN));
          json_object_int_add(json_neigh, "portForeign", ntohs (p->su_remote->sin.sin_port));
        }
      else
        vty_out (vty, "Foreign host: %s, Foreign port: %d%s",
	       sockunion2str (p->su_remote, buf1, SU_ADDRSTRLEN),
	       ntohs (p->su_remote->sin.sin_port),
	       VTY_NEWLINE);
    }

  /* Nexthop display. */
  if (p->su_local)
    {
      if (use_json)
        {
          json_object_string_add(json_neigh, "nexthop", inet_ntop (AF_INET, &p->nexthop.v4, buf1, BUFSIZ));
#ifdef HAVE_IPV6
          json_object_string_add(json_neigh, "nexthopGlobal", inet_ntop (AF_INET6, &p->nexthop.v6_global, buf1, BUFSIZ));
          json_object_string_add(json_neigh, "nexthopLocal", inet_ntop (AF_INET6, &p->nexthop.v6_local, buf1, BUFSIZ));
          if (p->shared_network)
            json_object_string_add(json_neigh, "bgpConnection", "sharedNetwork");
          else
            json_object_string_add(json_neigh, "bgpConnection", "nonSharedNetwork");
#endif /* HAVE_IPV6 */
        }
      else
        {
          vty_out (vty, "Nexthop: %s%s",
	           inet_ntop (AF_INET, &p->nexthop.v4, buf1, BUFSIZ),
	           VTY_NEWLINE);
#ifdef HAVE_IPV6
          vty_out (vty, "Nexthop global: %s%s",
	           inet_ntop (AF_INET6, &p->nexthop.v6_global, buf1, BUFSIZ),
	           VTY_NEWLINE);
          vty_out (vty, "Nexthop local: %s%s",
	           inet_ntop (AF_INET6, &p->nexthop.v6_local, buf1, BUFSIZ),
	           VTY_NEWLINE);
          vty_out (vty, "BGP connection: %s%s",
	           p->shared_network ? "shared network" : "non shared network",
	           VTY_NEWLINE);
#endif /* HAVE_IPV6 */
        }
    }

  /* Timer information. */
  if (use_json)
    {
      if (p->t_start)
        json_object_int_add(json_neigh, "nextStartTimerDueInMsecs", thread_timer_remain_second (p->t_start) * 1000);
      if (p->t_connect)
        json_object_int_add(json_neigh, "nextConnectTimerDueInMsecs", thread_timer_remain_second (p->t_connect) * 1000);
      if (p->t_routeadv)
        {
          json_object_int_add(json_neigh, "mraiInterval", p->v_routeadv);
          json_object_int_add(json_neigh, "mraiTimerExpireInMsecs", thread_timer_remain_second (p->t_routeadv) * 1000);
        }

      if (p->t_read)
        json_object_string_add(json_neigh, "readThread", "on");
      else
        json_object_string_add(json_neigh, "readThread", "off");
      if (p->t_write)
        json_object_string_add(json_neigh, "writeThread", "on");
      else
        json_object_string_add(json_neigh, "writeThread", "off");
    }
  else
    {
      if (p->t_start)
        vty_out (vty, "Next start timer due in %ld seconds%s",
                 thread_timer_remain_second (p->t_start), VTY_NEWLINE);
      if (p->t_connect)
        vty_out (vty, "Next connect timer due in %ld seconds%s",
                 thread_timer_remain_second (p->t_connect), VTY_NEWLINE);
      if (p->t_routeadv)
        vty_out (vty, "MRAI (interval %u) timer expires in %ld seconds%s",
                 p->v_routeadv, thread_timer_remain_second (p->t_routeadv),
                 VTY_NEWLINE);

      vty_out (vty, "Read thread: %s  Write thread: %s%s",
               p->t_read ? "on" : "off",
               p->t_write ? "on" : "off",
               VTY_NEWLINE);
    }

  if (p->notify.code == BGP_NOTIFY_OPEN_ERR
      && p->notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
    bgp_capability_vty_out (vty, p, use_json, json_neigh);

  if (!use_json)
    vty_out (vty, "%s", VTY_NEWLINE);

  /* BFD information. */
  bgp_bfd_show_info(vty, p, use_json, json_neigh);

  if (use_json)
    {
      if (p->conf_if) /* Configured interface name. */
        json_object_object_add(json, p->conf_if, json_neigh);
      else /* Configured IP address. */
        json_object_object_add(json, p->host, json_neigh);
    }
}

static int
bgp_show_neighbor (struct vty *vty, struct bgp *bgp, enum show_type type,
                   union sockunion *su, const char *conf_if, u_char use_json, json_object *json)
{
  struct listnode *node, *nnode;
  struct peer *peer;
  int find = 0;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
	continue;

      switch (type)
        {
          case show_all:
            bgp_show_peer (vty, peer, use_json, json);
          break;
          case show_peer:
            if (conf_if)
              {
                if ((peer->conf_if && !strcmp(peer->conf_if, conf_if)) ||
                    (peer->hostname && !strcmp(peer->hostname, conf_if)))
                  {
                    find = 1;
                    bgp_show_peer (vty, peer, use_json, json);
                  }
              }
            else
              {
               if (sockunion_same (&peer->su, su))
                 {
                   find = 1;
                   bgp_show_peer (vty, peer, use_json, json);
                 }
              }
          break;
	}
    }

  if (type == show_peer && ! find)
    {
      if (use_json)
        json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
      else
        vty_out (vty, "%% No such neighbor%s", VTY_NEWLINE);
    }

  if (use_json)
    {
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

static int 
bgp_show_neighbor_vty (struct vty *vty, const char *name, 
                       enum show_type type, const char *ip_str, u_char use_json,
                       json_object *json)
{
  int ret;
  struct bgp *bgp;
  union sockunion su;

  if (use_json && (json == NULL))
    json = json_object_new_object();

  if (name)
    {
      bgp = bgp_lookup_by_name (name);
      if (! bgp)
        {
          if (use_json)
            {
              json_object_boolean_true_add(json, "bgpNoSuchInstance");
              vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
              json_object_free(json);
            }
          else
            vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);

          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
    }

  if (bgp)
    {
      if (ip_str)
        {
          ret = str2sockunion (ip_str, &su);
          if (ret < 0)
            bgp_show_neighbor (vty, bgp, type, NULL, ip_str, use_json, json);
          else
            bgp_show_neighbor (vty, bgp, type, &su, NULL, use_json, json);
        }
      else
        {
          bgp_show_neighbor (vty, bgp, type, NULL, NULL, use_json, json);
        }
    }

  return CMD_SUCCESS;
}

static void
bgp_show_all_instances_neighbors_vty (struct vty *vty, u_char use_json)
{
  struct listnode *node, *nnode;
  struct bgp *bgp;
  json_object *json = NULL;
  int is_first = 1;

  if (use_json)
    vty_out (vty, "{%s", VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      if (use_json)
        {
          if (!(json = json_object_new_object()))
            {
              zlog_err("Unable to allocate memory for JSON object");
              vty_out (vty,
                       "{\"error\": {\"message:\": \"Unable to allocate memory for JSON object\"}}}%s",
                       VTY_NEWLINE);
              return;
            }

          json_object_int_add(json, "vrfId",
                              (bgp->vrf_id == VRF_UNKNOWN)
                              ? -1 : bgp->vrf_id);
          json_object_string_add(json, "vrfName",
                                 (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                                 ? "Default" : bgp->name);

          if (! is_first)
            vty_out (vty, ",%s", VTY_NEWLINE);
          else
            is_first = 0;

          vty_out(vty, "\"%s\":", (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                  ? "Default" : bgp->name);
        }
      else
        {
          vty_out (vty, "%sInstance %s:%s",
                   VTY_NEWLINE,
                   (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                   ? "Default" : bgp->name,
                   VTY_NEWLINE);
        }
      bgp_show_neighbor (vty, bgp, show_all, NULL, NULL, use_json, json);
    }

  if (use_json)
    vty_out (vty, "}%s", VTY_NEWLINE);
}

/* "show ip bgp neighbors" commands.  */
DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  return bgp_show_neighbor_vty (vty, NULL, show_all, NULL, uj, NULL);
}

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_ipv4_neighbors_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_all_neighbors_cmd,
       "show ip bgp vpnv4 all neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_rd_neighbors_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_neighbors_cmd,
       "show bgp neighbors {json}",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_ipv6_neighbors_cmd,
       "show bgp ipv6 neighbors {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_neighbors_peer,
       show_ip_bgp_neighbors_peer_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  return bgp_show_neighbor_vty (vty, NULL, show_peer, argv[argc - 2], uj, NULL);
}

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_ipv4_neighbors_peer_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_all_neighbors_peer_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_rd_neighbors_peer_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_neighbors_peer_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_ipv6_neighbors_peer_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_instance_neighbors,
       show_ip_bgp_instance_neighbors_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  return bgp_show_neighbor_vty (vty, argv[1], show_all, NULL, uj, NULL);
}

DEFUN (show_ip_bgp_instance_all_neighbors,
       show_ip_bgp_instance_all_neighbors_cmd,
       "show ip bgp " BGP_INSTANCE_ALL_CMD " neighbors {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  bgp_show_all_instances_neighbors_vty (vty, uj);
  return CMD_SUCCESS;
}

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_neighbors_cmd,
       "show bgp " BGP_INSTANCE_CMD " neighbors {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_ipv6_neighbors_cmd,
       "show bgp " BGP_INSTANCE_CMD " ipv6 neighbors {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_instance_neighbors_peer,
       show_ip_bgp_instance_neighbors_peer_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);

  return bgp_show_neighbor_vty (vty, argv[1], show_peer, argv[2], uj, NULL);
}

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_neighbors_peer_cmd,
       "show bgp " BGP_INSTANCE_CMD " neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_ipv6_neighbors_peer_cmd,
       "show bgp " BGP_INSTANCE_CMD " ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) {json}",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "JavaScript Object Notation\n")
       
/* Show BGP's AS paths internal data.  There are both `show ip bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths, 
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Path information\n")
{
  vty_out (vty, "Address Refcnt Path%s", VTY_NEWLINE);
  aspath_print_all_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_paths, 
       show_ip_bgp_ipv4_paths_cmd,
       "show ip bgp ipv4 (unicast|multicast) paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Path information\n")
{
  vty_out (vty, "Address Refcnt Path\r\n");
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}

#include "hash.h"

static void
community_show_all_iterator (struct hash_backet *backet, struct vty *vty)
{
  struct community *com;

  com = (struct community *) backet->data;
  vty_out (vty, "[%p] (%ld) %s%s", backet, com->refcnt,
	   community_str (com), VTY_NEWLINE);
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info, 
       show_ip_bgp_community_info_cmd,
       "show ip bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
  vty_out (vty, "Address Refcnt Community%s", VTY_NEWLINE);

  hash_iterate (community_hash (), 
		(void (*) (struct hash_backet *, void *))
		community_show_all_iterator,
		vty);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_attr_info, 
       show_ip_bgp_attr_info_cmd,
       "show ip bgp attribute-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")
{
  attr_show_all (vty);
  return CMD_SUCCESS;
}

static int bgp_show_update_groups(struct vty *vty, const char *name,
                                  int afi, int safi,
                                  u_int64_t subgrp_id)
{
  struct bgp *bgp;

 if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (bgp)
    update_group_show(bgp, afi, safi, vty, subgrp_id);
  return CMD_SUCCESS;
}

static void
bgp_show_all_instances_updgrps_vty (struct vty *vty, afi_t afi, safi_t safi)
{
  struct listnode *node, *nnode;
  struct bgp *bgp;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      vty_out (vty, "%sInstance %s:%s",
               VTY_NEWLINE,
               (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) ? "Default" : bgp->name,
               VTY_NEWLINE);
      update_group_show(bgp, afi, safi, vty, 0);
    }
}

DEFUN (show_ip_bgp_updgrps,
       show_ip_bgp_updgrps_cmd,
       "show ip bgp update-groups",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed info about dynamic update groups\n")
{
  return (bgp_show_update_groups(vty, NULL, AFI_IP, SAFI_UNICAST, 0));
}

DEFUN (show_ip_bgp_instance_updgrps,
       show_ip_bgp_instance_updgrps_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " update-groups",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about dynamic update groups\n")
{
  return (bgp_show_update_groups(vty, argv[1], AFI_IP, SAFI_UNICAST, 0));
}

DEFUN (show_ip_bgp_instance_all_updgrps,
       show_ip_bgp_instance_all_updgrps_cmd,
       "show ip bgp " BGP_INSTANCE_ALL_CMD " update-groups",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed info about dynamic update groups\n")
{
  bgp_show_all_instances_updgrps_vty (vty, AFI_IP, SAFI_UNICAST);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_ipv6_updgrps,
       show_bgp_ipv6_updgrps_cmd,
       "show bgp update-groups",
       SHOW_STR
       BGP_STR
       "Detailed info about v6 dynamic update groups\n")
{
  return (bgp_show_update_groups(vty, NULL, AFI_IP6, SAFI_UNICAST, 0));
}

DEFUN (show_bgp_instance_ipv6_updgrps,
       show_bgp_instance_ipv6_updgrps_cmd,
       "show bgp " BGP_INSTANCE_CMD " update-groups",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about v6 dynamic update groups\n")
{
  return (bgp_show_update_groups(vty, argv[1], AFI_IP6, SAFI_UNICAST, 0));
}

DEFUN (show_bgp_instance_all_ipv6_updgrps,
       show_bgp_instance_all_ipv6_updgrps_cmd,
       "show bgp " BGP_INSTANCE_ALL_CMD " update-groups",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed info about v6 dynamic update groups\n")
{
  bgp_show_all_instances_updgrps_vty (vty, AFI_IP6, SAFI_UNICAST);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps,
       show_bgp_updgrps_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) update-groups",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed info about dynamic update groups\n")
{
  afi_t afi;
  safi_t safi;

  afi = (strcmp(argv[0], "ipv4") == 0) ? AFI_IP : AFI_IP6;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return (bgp_show_update_groups(vty, NULL, afi, safi, 0));
}

DEFUN (show_ip_bgp_updgrps_s,
       show_ip_bgp_updgrps_s_cmd,
       "show ip bgp update-groups SUBGROUP-ID",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed info about dynamic update groups\n"
       "Specific subgroup to display detailed info for\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[0]);
  return (bgp_show_update_groups(vty, NULL, AFI_IP, SAFI_UNICAST, subgrp_id));
}

DEFUN (show_ip_bgp_instance_updgrps_s,
       show_ip_bgp_instance_updgrps_s_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " update-groups SUBGROUP-ID",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Specific subgroup to display detailed info for\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);
  return (bgp_show_update_groups(vty, argv[1], AFI_IP, SAFI_UNICAST, subgrp_id));
}

DEFUN (show_bgp_ipv6_updgrps_s,
       show_bgp_ipv6_updgrps_s_cmd,
       "show bgp update-groups SUBGROUP-ID",
       SHOW_STR
       BGP_STR
       "Detailed info about v6 dynamic update groups\n"
       "Specific subgroup to display detailed info for\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[0]);
  return(bgp_show_update_groups(vty, NULL, AFI_IP6, SAFI_UNICAST, subgrp_id));
}

DEFUN (show_bgp_instance_ipv6_updgrps_s,
       show_bgp_instance_ipv6_updgrps_s_cmd,
       "show bgp " BGP_INSTANCE_CMD " update-groups SUBGROUP-ID",
       SHOW_STR
       BGP_STR
       "Detailed info about v6 dynamic update groups\n"
       "Specific subgroup to display detailed info for\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);
  return(bgp_show_update_groups(vty, argv[1], AFI_IP6, SAFI_UNICAST, subgrp_id));
}

DEFUN (show_bgp_updgrps_s,
       show_bgp_updgrps_s_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) update-groups SUBGROUP-ID",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed info about v6 dynamic update groups\n"
       "Specific subgroup to display detailed info for")
{
  afi_t afi;
  safi_t safi;
  u_int64_t subgrp_id;

  afi = (strcmp(argv[0], "ipv4") == 0) ? AFI_IP : AFI_IP6;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);
  return(bgp_show_update_groups(vty, NULL, afi, safi, subgrp_id));
}

DEFUN (show_bgp_updgrps_stats,
       show_bgp_updgrps_stats_cmd,
       "show bgp update-groups statistics",
       SHOW_STR
       BGP_STR
       "BGP update groups\n"
       "Statistics\n")
{
  struct bgp *bgp;

  bgp = bgp_get_default();
  if (bgp)
    update_group_show_stats(bgp, vty);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_instance_updgrps_stats,
       show_bgp_instance_updgrps_stats_cmd,
       "show bgp " BGP_INSTANCE_CMD " update-groups statistics",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP update groups\n"
       "Statistics\n")
{
  struct bgp *bgp;

  bgp = bgp_lookup_by_name (argv[1]);
  if (bgp)
    update_group_show_stats(bgp, vty);

  return CMD_SUCCESS;
}

static void
show_bgp_updgrps_adj_info_aux (struct vty *vty, const char *name,
                               afi_t afi, safi_t safi,
			       const char *what, u_int64_t subgrp_id)
{
  struct bgp *bgp;

 if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (bgp)
    {
      if (!strcmp(what, "advertise-queue"))
        update_group_show_adj_queue(bgp, afi, safi, vty, subgrp_id);
      else if (!strcmp(what, "advertised-routes"))
        update_group_show_advertised(bgp, afi, safi, vty, subgrp_id);
      else if (!strcmp(what, "packet-queue"))
        update_group_show_packet_queue(bgp, afi, safi, vty, subgrp_id);
    }
}

DEFUN (show_ip_bgp_updgrps_adj,
       show_ip_bgp_updgrps_adj_cmd,
       "show ip bgp update-groups (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP update groups\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")

{
  show_bgp_updgrps_adj_info_aux(vty, NULL, AFI_IP, SAFI_UNICAST, argv[0], 0);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_instance_updgrps_adj,
       show_ip_bgp_instance_updgrps_adj_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " update-groups (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP update groups\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")

{
  show_bgp_updgrps_adj_info_aux(vty, argv[1], AFI_IP, SAFI_UNICAST, argv[2], 0);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_afi_adj,
       show_bgp_updgrps_afi_adj_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) update-groups (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP update groups\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n"
       "Specific subgroup info wanted for\n")
{
  afi_t afi;
  safi_t safi;

  afi = (strcmp(argv[0], "ipv4") == 0) ? AFI_IP : AFI_IP6;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  show_bgp_updgrps_adj_info_aux(vty, NULL, afi, safi, argv[2], 0);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_adj,
       show_bgp_updgrps_adj_cmd,
       "show bgp update-groups (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       "BGP update groups\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")
{
  show_bgp_updgrps_adj_info_aux(vty, NULL, AFI_IP6, SAFI_UNICAST, argv[0], 0);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_instance_updgrps_adj,
       show_bgp_instance_updgrps_adj_cmd,
       "show bgp " BGP_INSTANCE_CMD " update-groups (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP update groups\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")
{
  show_bgp_updgrps_adj_info_aux(vty, argv[1], AFI_IP6, SAFI_UNICAST, argv[2], 0);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_updgrps_adj_s,
       show_ip_bgp_updgrps_adj_s_cmd,
       "show ip bgp update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP update groups\n"
       "Specific subgroup to display info for\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")

{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[0]);

  show_bgp_updgrps_adj_info_aux(vty, NULL, AFI_IP, SAFI_UNICAST, argv[1], subgrp_id);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_instance_updgrps_adj_s,
       show_ip_bgp_instance_updgrps_adj_s_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP update groups\n"
       "Specific subgroup to display info for\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")

{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);

  show_bgp_updgrps_adj_info_aux(vty, argv[1], AFI_IP, SAFI_UNICAST, argv[3], subgrp_id);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_afi_adj_s,
       show_bgp_updgrps_afi_adj_s_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP update groups\n"
       "Specific subgroup to display info for\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n"
       "Specific subgroup info wanted for\n")
{
  afi_t afi;
  safi_t safi;
  u_int64_t subgrp_id;

  afi = (strcmp(argv[0], "ipv4") == 0) ? AFI_IP : AFI_IP6;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);

  show_bgp_updgrps_adj_info_aux(vty, NULL, afi, safi, argv[3], subgrp_id);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_adj_s,
       show_bgp_updgrps_adj_s_cmd,
       "show bgp update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       "BGP update groups\n"
       "Specific subgroup to display info for\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[0]);

  show_bgp_updgrps_adj_info_aux(vty, NULL, AFI_IP6, SAFI_UNICAST, argv[1], subgrp_id);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_instance_updgrps_adj_s,
       show_bgp_instance_updgrps_adj_s_cmd,
       "show bgp " BGP_INSTANCE_CMD " update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)",
       SHOW_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP update groups\n"
       "Specific subgroup to display info for\n"
       "Advertisement queue\n"
       "Announced routes\n"
       "Packet queue\n")
{
  u_int64_t subgrp_id;

  VTY_GET_ULL("subgroup-id", subgrp_id, argv[2]);

  show_bgp_updgrps_adj_info_aux(vty, argv[1], AFI_IP6, SAFI_UNICAST, argv[3], subgrp_id);
  return CMD_SUCCESS;
}



static int
bgp_show_one_peer_group (struct vty *vty, struct peer_group *group)
{
  struct listnode *node, *nnode;
  struct prefix *range;
  struct peer *conf;
  struct peer *peer;
  char buf[PREFIX2STR_BUFFER];
  afi_t afi;
  safi_t safi;
  const char *peer_status;
  const char *af_str;
  int lr_count;
  int dynamic;
  int af_cfgd;

  conf = group->conf;

  if (conf->as_type == AS_SPECIFIED ||
      conf->as_type == AS_EXTERNAL) {
  vty_out (vty, "%sBGP peer-group %s, remote AS %d%s",
           VTY_NEWLINE, group->name, conf->as, VTY_NEWLINE);
  } else if (conf->as_type == AS_INTERNAL) {
    vty_out (vty, "%sBGP peer-group %s, remote AS %d%s",
	     VTY_NEWLINE, group->name, group->bgp->as, VTY_NEWLINE);
  } else {
    vty_out (vty, "%sBGP peer-group %s%s",
	     VTY_NEWLINE, group->name, VTY_NEWLINE);
  }

  if ((group->bgp->as == conf->as) || (conf->as_type == AS_INTERNAL))
    vty_out (vty, "  Peer-group type is internal%s", VTY_NEWLINE);
  else
    vty_out (vty, "  Peer-group type is external%s", VTY_NEWLINE);

  /* Display AFs configured. */
  vty_out (vty, "  Configured address-families:");
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
      {
        if (conf->afc[afi][safi])
          {
            af_cfgd = 1;
            vty_out (vty, " %s;", afi_safi_print(afi, safi));
          }
      }
  if (!af_cfgd)
    vty_out (vty, " none%s", VTY_NEWLINE);
  else
    vty_out (vty, "%s", VTY_NEWLINE);

  /* Display listen ranges (for dynamic neighbors), if any */
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      if (afi == AFI_IP)
        af_str = "IPv4";
      else if (afi == AFI_IP6)
        af_str = "IPv6";
      lr_count = listcount(group->listen_range[afi]);
      if (lr_count)
        {
          vty_out(vty,
                  "  %d %s listen range(s)%s",
                  lr_count, af_str, VTY_NEWLINE);


          for (ALL_LIST_ELEMENTS (group->listen_range[afi], node,
                                  nnode, range))
            {
              prefix2str(range, buf, sizeof(buf));
              vty_out(vty, "    %s%s", buf, VTY_NEWLINE);
            }
        }
    }

  /* Display group members and their status */
  if (listcount(group->peer))
    {
      vty_out (vty, "  Peer-group members:%s", VTY_NEWLINE);
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          if (CHECK_FLAG (peer->flags, PEER_FLAG_SHUTDOWN))
            peer_status = "Idle (Admin)";
          else if (CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
            peer_status = "Idle (PfxCt)";
          else
            peer_status = LOOKUP(bgp_status_msg, peer->status);

          dynamic = peer_dynamic_neighbor(peer);
          vty_out (vty, "    %s %s %s %s",
                   peer->host, dynamic ? "(dynamic)" : "",
                   peer_status, VTY_NEWLINE);
        }
    }

  return CMD_SUCCESS;
}

/* Show BGP peer group's information. */
enum show_group_type
{
  show_all_groups,
  show_peer_group
};

static int
bgp_show_peer_group (struct vty *vty, struct bgp *bgp,
                     enum show_group_type type, const char *group_name)
{
  struct listnode *node, *nnode;
  struct peer_group *group;
  int find = 0;

  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    {
      switch (type)
	{
	case show_all_groups:
	  bgp_show_one_peer_group (vty, group);
	  break;
	case show_peer_group:
          if (group_name && (strcmp(group->name, group_name) == 0))
            {
              find = 1;
              bgp_show_one_peer_group (vty, group);
	    }
	  break;
	}
    }

  if (type == show_peer_group && ! find)
    vty_out (vty, "%% No such peer-groupr%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

static int
bgp_show_peer_group_vty (struct vty *vty, const char *name,
                         enum show_group_type type, const char *group_name)
{
  struct bgp *bgp;
  int ret = CMD_SUCCESS;

  if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (! bgp)
    {
      vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show_peer_group (vty, bgp, type, group_name);

  return ret;
}

DEFUN (show_ip_bgp_peer_groups,
       show_ip_bgp_peer_groups_cmd,
       "show ip bgp peer-group",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on all BGP peer groups\n")
{
  return bgp_show_peer_group_vty (vty, NULL, show_all_groups, NULL);
}

DEFUN (show_ip_bgp_instance_peer_groups,
       show_ip_bgp_instance_peer_groups_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " peer-group",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on all BGP peer groups\n")
{
  return bgp_show_peer_group_vty (vty, argv[1], show_all_groups, NULL);
}

DEFUN (show_ip_bgp_peer_group,
       show_ip_bgp_peer_group_cmd,
       "show ip bgp peer-group WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP peer-group name\n"
       "Detailed information on a BGP peer group\n")
{
  return bgp_show_peer_group_vty (vty, NULL, show_peer_group, argv[0]);
}

DEFUN (show_ip_bgp_instance_peer_group,
       show_ip_bgp_instance_peer_group_cmd,
       "show ip bgp " BGP_INSTANCE_CMD " peer-group WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "BGP peer-group name\n"
       "Detailed information on a BGP peer group\n")
{
  return bgp_show_peer_group_vty (vty, argv[1], show_peer_group, argv[2]);
}

/* Redistribute VTY commands.  */

DEFUN (bgp_redistribute_ipv4,
       bgp_redistribute_ipv4_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  bgp_redist_add(vty->index, AFI_IP, type, 0);
  return bgp_redistribute_set (vty->index, AFI_IP, type, 0);
}

DEFUN (bgp_redistribute_ipv4_rmap,
       bgp_redistribute_ipv4_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  red = bgp_redist_add(vty->index, AFI_IP, type, 0);
  bgp_redistribute_rmap_set (red, argv[1]);
  return bgp_redistribute_set (vty->index, AFI_IP, type, 0);
}

DEFUN (bgp_redistribute_ipv4_metric,
       bgp_redistribute_ipv4_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  red = bgp_redist_add(vty->index, AFI_IP, type, 0);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, type, 0);
}

DEFUN (bgp_redistribute_ipv4_rmap_metric,
       bgp_redistribute_ipv4_rmap_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  red = bgp_redist_add(vty->index, AFI_IP, type, 0);
  bgp_redistribute_rmap_set (red, argv[1]);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, type, 0);
}

DEFUN (bgp_redistribute_ipv4_metric_rmap,
       bgp_redistribute_ipv4_metric_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  red = bgp_redist_add(vty->index, AFI_IP, type, 0);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, type, metric);
  bgp_redistribute_rmap_set (red, argv[2]);
  return bgp_redistribute_set (vty->index, AFI_IP, type, 0);
}

DEFUN (bgp_redistribute_ipv4_ospf,
       bgp_redistribute_ipv4_ospf_cmd,
       "redistribute (ospf|table) <1-65535>",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n")
{
  u_short instance;
  u_short protocol;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  bgp_redist_add(vty->index, AFI_IP, protocol, instance);
  return bgp_redistribute_set (vty->index, AFI_IP, protocol, instance);
}

DEFUN (bgp_redistribute_ipv4_ospf_rmap,
       bgp_redistribute_ipv4_ospf_rmap_cmd,
       "redistribute (ospf|table) <1-65535> route-map WORD",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  struct bgp_redist *red;
  u_short instance;
  int protocol;

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);
  red = bgp_redist_add(vty->index, AFI_IP, protocol, instance);
  bgp_redistribute_rmap_set (red, argv[2]);
  return bgp_redistribute_set (vty->index, AFI_IP, protocol, instance);
}

DEFUN (bgp_redistribute_ipv4_ospf_metric,
       bgp_redistribute_ipv4_ospf_metric_cmd,
       "redistribute (ospf|table) <1-65535> metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  u_int32_t metric;
  struct bgp_redist *red;
  u_short instance;
  int protocol;

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  red = bgp_redist_add(vty->index, AFI_IP, protocol, instance);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, protocol, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, protocol, instance);
}

DEFUN (bgp_redistribute_ipv4_ospf_rmap_metric,
       bgp_redistribute_ipv4_ospf_rmap_metric_cmd,
       "redistribute (ospf|table) <1-65535> route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  u_int32_t metric;
  struct bgp_redist *red;
  u_short instance;
  int protocol;

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);
  VTY_GET_INTEGER ("metric", metric, argv[3]);

  red = bgp_redist_add(vty->index, AFI_IP, protocol, instance);
  bgp_redistribute_rmap_set (red, argv[2]);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, protocol, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, protocol, instance);
}

DEFUN (bgp_redistribute_ipv4_ospf_metric_rmap,
       bgp_redistribute_ipv4_ospf_metric_rmap_cmd,
       "redistribute (ospf|table) <1-65535> metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  u_int32_t metric;
  struct bgp_redist *red;
  u_short instance;
  int protocol;

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  red = bgp_redist_add(vty->index, AFI_IP, protocol, instance);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP, protocol, metric);
  bgp_redistribute_rmap_set (red, argv[3]);
  return bgp_redistribute_set (vty->index, AFI_IP, protocol, instance);
}

DEFUN (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_cmd,
       "no redistribute (ospf|table) <1-65535>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n")
{
  u_short instance;
  int protocol;

  if (strncmp(argv[0], "o", 1) == 0)
    protocol = ZEBRA_ROUTE_OSPF;
  else
    protocol = ZEBRA_ROUTE_TABLE;

  VTY_GET_INTEGER ("Instance ID", instance, argv[1]);
  return bgp_redistribute_unset (vty->index, AFI_IP, protocol, instance);
}

ALIAS (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_rmap_cmd,
       "no redistribute (ospf|table) <1-65535> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

ALIAS (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_metric_cmd,
       "no redistribute (ospf|table) <1-65535> metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_rmap_metric_cmd,
       "no redistribute (ospf|table) <1-65535> route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_metric_rmap_cmd,
       "no redistribute (ospf|table) <1-65535> metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFUN (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_redistribute_unset (vty->index, AFI_IP, type, 0);
}

ALIAS (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")

ALIAS (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

#ifdef HAVE_IPV6
DEFUN (bgp_redistribute_ipv6,
       bgp_redistribute_ipv6_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redist_add(vty->index, AFI_IP6, type, 0);
  return bgp_redistribute_set (vty->index, AFI_IP6, type, 0);
}

DEFUN (bgp_redistribute_ipv6_rmap,
       bgp_redistribute_ipv6_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  red = bgp_redist_add(vty->index, AFI_IP6, type, 0);
  bgp_redistribute_rmap_set (red, argv[1]);
  return bgp_redistribute_set (vty->index, AFI_IP6, type, 0);
}

DEFUN (bgp_redistribute_ipv6_metric,
       bgp_redistribute_ipv6_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  red = bgp_redist_add(vty->index, AFI_IP6, type, 0);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP6, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP6, type, 0);
}

DEFUN (bgp_redistribute_ipv6_rmap_metric,
       bgp_redistribute_ipv6_rmap_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  red = bgp_redist_add(vty->index, AFI_IP6, type, 0);
  bgp_redistribute_rmap_set (red, argv[1]);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP6, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP6, type, 0);
}

DEFUN (bgp_redistribute_ipv6_metric_rmap,
       bgp_redistribute_ipv6_metric_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  u_int32_t metric;
  struct bgp_redist *red;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  red = bgp_redist_add(vty->index, AFI_IP6, type, 0);
  bgp_redistribute_metric_set(vty->index, red, AFI_IP6, SAFI_UNICAST, metric);
  bgp_redistribute_rmap_set (red, argv[2]);
  return bgp_redistribute_set (vty->index, AFI_IP6, type, 0);
}

DEFUN (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_redistribute_unset (vty->index, AFI_IP6, type, 0);
}

ALIAS (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")

ALIAS (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")

ALIAS (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
#endif /* HAVE_IPV6 */

int
bgp_config_write_redistribute (struct vty *vty, struct bgp *bgp, afi_t afi,
			       safi_t safi, int *write)
{
  int i;

  /* Unicast redistribution only.  */
  if (safi != SAFI_UNICAST)
    return 0;

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      /* Redistribute BGP does not make sense.  */
      if (i != ZEBRA_ROUTE_BGP)
	{
          struct list *red_list;
          struct listnode *node;
          struct bgp_redist *red;

          red_list = bgp->redist[afi][i];
          if (!red_list)
            continue;

          for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
            {
              /* Display "address-family" when it is not yet diplayed.  */
              bgp_config_write_family_header (vty, afi, safi, write);

              /* "redistribute" configuration.  */
              vty_out (vty, "  redistribute %s", zebra_route_string(i));
              if (red->instance)
                vty_out (vty, " %d", red->instance);
              if (red->redist_metric_flag)
                vty_out (vty, " metric %u", red->redist_metric);
              if (red->rmap.name)
                vty_out (vty, " route-map %s", red->rmap.name);
              vty_out (vty, "%s", VTY_NEWLINE);
            }
	}
    }
  return *write;
}

/* BGP node structure. */
static struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
  1,
};

static struct cmd_node bgp_ipv4_unicast_node =
{
  BGP_IPV4_NODE,
  "%s(config-router-af)# ",
  1,
};

static struct cmd_node bgp_ipv4_multicast_node =
{
  BGP_IPV4M_NODE,
  "%s(config-router-af)# ",
  1,
};

static struct cmd_node bgp_ipv6_unicast_node =
{
  BGP_IPV6_NODE,
  "%s(config-router-af)# ",
  1,
};

static struct cmd_node bgp_ipv6_multicast_node =
{
  BGP_IPV6M_NODE,
  "%s(config-router-af)# ",
  1,
};

static struct cmd_node bgp_vpnv4_node =
{
  BGP_VPNV4_NODE,
  "%s(config-router-af)# ",
  1
};

static void community_list_vty (void);

void
bgp_vty_init (void)
{
  /* Install bgp top node. */
  install_node (&bgp_node, bgp_config_write);
  install_node (&bgp_ipv4_unicast_node, NULL);
  install_node (&bgp_ipv4_multicast_node, NULL);
  install_node (&bgp_ipv6_unicast_node, NULL);
  install_node (&bgp_ipv6_multicast_node, NULL);
  install_node (&bgp_vpnv4_node, NULL);

  /* Install default VTY commands to new nodes.  */
  install_default (BGP_NODE);
  install_default (BGP_IPV4_NODE);
  install_default (BGP_IPV4M_NODE);
  install_default (BGP_IPV6_NODE);
  install_default (BGP_IPV6M_NODE);
  install_default (BGP_VPNV4_NODE);
  
  /* "bgp multiple-instance" commands. */
  install_element (CONFIG_NODE, &bgp_multiple_instance_cmd);
  install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd);

  /* "bgp config-type" commands. */
  install_element (CONFIG_NODE, &bgp_config_type_cmd);
  install_element (CONFIG_NODE, &no_bgp_config_type_val_cmd);

  /* bgp route-map delay-timer commands. */
  install_element (CONFIG_NODE, &bgp_set_route_map_delay_timer_cmd);
  install_element (CONFIG_NODE, &no_bgp_set_route_map_delay_timer_cmd);
  install_element (CONFIG_NODE, &no_bgp_set_route_map_delay_timer_val_cmd);

  /* Dummy commands (Currently not supported) */
  install_element (BGP_NODE, &no_synchronization_cmd);
  install_element (BGP_NODE, &no_auto_summary_cmd);

  /* "router bgp" commands. */
  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &router_bgp_instance_cmd);
  install_element (CONFIG_NODE, &router_bgp_noasn_cmd);

  /* "no router bgp" commands. */
  install_element (CONFIG_NODE, &no_router_bgp_cmd);
  install_element (CONFIG_NODE, &no_router_bgp_instance_cmd);

  /* "bgp router-id" commands. */
  install_element (BGP_NODE, &bgp_router_id_cmd);
  install_element (BGP_NODE, &no_bgp_router_id_cmd);
  install_element (BGP_NODE, &no_bgp_router_id_val_cmd);

  /* "bgp cluster-id" commands. */
  install_element (BGP_NODE, &bgp_cluster_id_cmd);
  install_element (BGP_NODE, &bgp_cluster_id32_cmd);
  install_element (BGP_NODE, &no_bgp_cluster_id_cmd);
  install_element (BGP_NODE, &no_bgp_cluster_id_ip_cmd);
  install_element (BGP_NODE, &no_bgp_cluster_id_decimal_cmd);

  /* "bgp confederation" commands. */
  install_element (BGP_NODE, &bgp_confederation_identifier_cmd);
  install_element (BGP_NODE, &no_bgp_confederation_identifier_cmd);
  install_element (BGP_NODE, &no_bgp_confederation_identifier_arg_cmd);

  /* "bgp confederation peers" commands. */
  install_element (BGP_NODE, &bgp_confederation_peers_cmd);
  install_element (BGP_NODE, &no_bgp_confederation_peers_cmd);

  /* bgp max-med command */
  install_element (BGP_NODE, &bgp_maxmed_admin_cmd);
  install_element (BGP_NODE, &no_bgp_maxmed_admin_cmd);
  install_element (BGP_NODE, &bgp_maxmed_admin_medv_cmd);
  install_element (BGP_NODE, &no_bgp_maxmed_admin_medv_cmd);
  install_element (BGP_NODE, &bgp_maxmed_onstartup_cmd);
  install_element (BGP_NODE, &no_bgp_maxmed_onstartup_cmd);
  install_element (BGP_NODE, &no_bgp_maxmed_onstartup_period_cmd);
  install_element (BGP_NODE, &bgp_maxmed_onstartup_medv_cmd);
  install_element (BGP_NODE, &no_bgp_maxmed_onstartup_period_medv_cmd);

  /* bgp disable-ebgp-connected-nh-check */
  install_element (BGP_NODE, &bgp_disable_connected_route_check_cmd);
  install_element (BGP_NODE, &no_bgp_disable_connected_route_check_cmd);

  /* bgp update-delay command */
  install_element (BGP_NODE, &bgp_update_delay_cmd);
  install_element (BGP_NODE, &no_bgp_update_delay_cmd);
  install_element (BGP_NODE, &bgp_update_delay_establish_wait_cmd);
  install_element (BGP_NODE, &no_bgp_update_delay_establish_wait_cmd);

  install_element (BGP_NODE, &bgp_wpkt_quanta_cmd);
  install_element (BGP_NODE, &no_bgp_wpkt_quanta_cmd);

  install_element (BGP_NODE, &bgp_coalesce_time_cmd);
  install_element (BGP_NODE, &no_bgp_coalesce_time_cmd);

  /* "maximum-paths" commands. */
  install_element (BGP_NODE, &bgp_maxpaths_cmd);
  install_element (BGP_NODE, &no_bgp_maxpaths_cmd);
  install_element (BGP_NODE, &no_bgp_maxpaths_arg_cmd);
  install_element (BGP_IPV4_NODE, &bgp_maxpaths_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_maxpaths_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_maxpaths_arg_cmd);
  install_element (BGP_IPV6_NODE, &bgp_maxpaths_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_maxpaths_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_maxpaths_arg_cmd);
  install_element (BGP_NODE, &bgp_maxpaths_ibgp_cmd);
  install_element(BGP_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
  install_element (BGP_NODE, &no_bgp_maxpaths_ibgp_cmd);
  install_element (BGP_NODE, &no_bgp_maxpaths_ibgp_arg_cmd);
  install_element (BGP_NODE, &no_bgp_maxpaths_ibgp_cluster_cmd);
  install_element (BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cmd);
  install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_maxpaths_ibgp_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_maxpaths_ibgp_cluster_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_maxpaths_ibgp_arg_cmd);
  install_element (BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cmd);
  install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_maxpaths_ibgp_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_maxpaths_ibgp_arg_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_maxpaths_ibgp_cluster_cmd);

  /* "timers bgp" commands. */
  install_element (BGP_NODE, &bgp_timers_cmd);
  install_element (BGP_NODE, &no_bgp_timers_cmd);
  install_element (BGP_NODE, &no_bgp_timers_arg_cmd);

  /* route-map delay-timer commands - per instance for backwards compat. */
  install_element (BGP_NODE, &bgp_set_route_map_delay_timer_cmd);
  install_element (BGP_NODE, &no_bgp_set_route_map_delay_timer_cmd);
  install_element (BGP_NODE, &no_bgp_set_route_map_delay_timer_val_cmd);

  /* "bgp client-to-client reflection" commands */
  install_element (BGP_NODE, &no_bgp_client_to_client_reflection_cmd);
  install_element (BGP_NODE, &bgp_client_to_client_reflection_cmd);

  /* "bgp always-compare-med" commands */
  install_element (BGP_NODE, &bgp_always_compare_med_cmd);
  install_element (BGP_NODE, &no_bgp_always_compare_med_cmd);
  
  /* "bgp deterministic-med" commands */
  install_element (BGP_NODE, &bgp_deterministic_med_cmd);
  install_element (BGP_NODE, &no_bgp_deterministic_med_cmd);

  /* "bgp graceful-restart" commands */
  install_element (BGP_NODE, &bgp_graceful_restart_cmd);
  install_element (BGP_NODE, &no_bgp_graceful_restart_cmd);
  install_element (BGP_NODE, &bgp_graceful_restart_stalepath_time_cmd);
  install_element (BGP_NODE, &no_bgp_graceful_restart_stalepath_time_cmd);
  install_element (BGP_NODE, &no_bgp_graceful_restart_stalepath_time_val_cmd);
 
  /* "bgp fast-external-failover" commands */
  install_element (BGP_NODE, &bgp_fast_external_failover_cmd);
  install_element (BGP_NODE, &no_bgp_fast_external_failover_cmd);

  /* "bgp enforce-first-as" commands */
  install_element (BGP_NODE, &bgp_enforce_first_as_cmd);
  install_element (BGP_NODE, &no_bgp_enforce_first_as_cmd);

  /* "bgp bestpath compare-routerid" commands */
  install_element (BGP_NODE, &bgp_bestpath_compare_router_id_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_compare_router_id_cmd);

  /* "bgp bestpath as-path ignore" commands */
  install_element (BGP_NODE, &bgp_bestpath_aspath_ignore_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_aspath_ignore_cmd);

  /* "bgp bestpath as-path confed" commands */
  install_element (BGP_NODE, &bgp_bestpath_aspath_confed_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_aspath_confed_cmd);

  /* "bgp bestpath as-path multipath-relax" commands */
  install_element (BGP_NODE, &bgp_bestpath_aspath_multipath_relax_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_aspath_multipath_relax_cmd);

  /* "bgp log-neighbor-changes" commands */
  install_element (BGP_NODE, &bgp_log_neighbor_changes_cmd);
  install_element (BGP_NODE, &no_bgp_log_neighbor_changes_cmd);

  /* "bgp bestpath med" commands */
  install_element (BGP_NODE, &bgp_bestpath_med_cmd);
  install_element (BGP_NODE, &bgp_bestpath_med2_cmd);
  install_element (BGP_NODE, &bgp_bestpath_med3_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_med_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_med2_cmd);
  install_element (BGP_NODE, &no_bgp_bestpath_med3_cmd);

  /* "no bgp default ipv4-unicast" commands. */
  install_element (BGP_NODE, &no_bgp_default_ipv4_unicast_cmd);
  install_element (BGP_NODE, &bgp_default_ipv4_unicast_cmd);
  
  /* "bgp network import-check" commands. */
  install_element (BGP_NODE, &bgp_network_import_check_cmd);
  install_element (BGP_NODE, &bgp_network_import_check_exact_cmd);
  install_element (BGP_NODE, &no_bgp_network_import_check_cmd);

  /* "bgp default local-preference" commands. */
  install_element (BGP_NODE, &bgp_default_local_preference_cmd);
  install_element (BGP_NODE, &no_bgp_default_local_preference_cmd);
  install_element (BGP_NODE, &no_bgp_default_local_preference_val_cmd);

  /* bgp default show-hostname */
  install_element (BGP_NODE, &bgp_default_show_hostname_cmd);
  install_element (BGP_NODE, &no_bgp_default_show_hostname_cmd);

  /* "bgp default subgroup-pkt-queue-max" commands. */
  install_element (BGP_NODE, &bgp_default_subgroup_pkt_queue_max_cmd);
  install_element (BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_cmd);
  install_element (BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_val_cmd);

  /* bgp ibgp-allow-policy-mods command */
  install_element (BGP_NODE, &bgp_rr_allow_outbound_policy_cmd);
  install_element (BGP_NODE, &no_bgp_rr_allow_outbound_policy_cmd);

  /* "bgp listen limit" commands. */
  install_element (BGP_NODE, &bgp_listen_limit_cmd);
  install_element (BGP_NODE, &no_bgp_listen_limit_cmd);
  install_element (BGP_NODE, &no_bgp_listen_limit_val_cmd);

  /* "bgp listen range" commands. */
  install_element (BGP_NODE, &bgp_listen_range_cmd);
  install_element (BGP_NODE, &no_bgp_listen_range_cmd);

  /* "neighbor remote-as" commands. */
  install_element (BGP_NODE, &neighbor_remote_as_cmd);
  install_element (BGP_NODE, &neighbor_interface_config_cmd);
  install_element (BGP_NODE, &neighbor_interface_config_v6only_cmd);
  install_element (BGP_NODE, &neighbor_interface_config_peergroup_cmd);
  install_element (BGP_NODE, &neighbor_interface_config_v6only_peergroup_cmd);
  install_element (BGP_NODE, &no_neighbor_cmd);
  install_element (BGP_NODE, &no_neighbor_remote_as_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_config_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_config_v6only_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_config_peergroup_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_config_v6only_peergroup_cmd);

  /* "neighbor peer-group" commands. */
  install_element (BGP_NODE, &neighbor_peer_group_cmd);
  install_element (BGP_NODE, &no_neighbor_peer_group_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_peer_group_remote_as_cmd);

  /* "neighbor local-as" commands. */
  install_element (BGP_NODE, &neighbor_local_as_cmd);
  install_element (BGP_NODE, &neighbor_local_as_no_prepend_cmd);
  install_element (BGP_NODE, &neighbor_local_as_no_prepend_replace_as_cmd);
  install_element (BGP_NODE, &no_neighbor_local_as_cmd);
  install_element (BGP_NODE, &no_neighbor_local_as_val_cmd);
  install_element (BGP_NODE, &no_neighbor_local_as_val2_cmd);
  install_element (BGP_NODE, &no_neighbor_local_as_val3_cmd);

  /* "neighbor solo" commands. */
  install_element (BGP_NODE, &neighbor_solo_cmd);
  install_element (BGP_NODE, &no_neighbor_solo_cmd);

  /* "neighbor password" commands. */
  install_element (BGP_NODE, &neighbor_password_cmd);
  install_element (BGP_NODE, &no_neighbor_password_cmd);
  install_element (BGP_NODE, &no_neighbor_password_val_cmd);

  /* "neighbor activate" commands. */
  install_element (BGP_NODE, &neighbor_activate_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_activate_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_activate_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_activate_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_activate_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_activate_cmd);

  /* "no neighbor activate" commands. */
  install_element (BGP_NODE, &no_neighbor_activate_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_activate_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_activate_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_activate_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_activate_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_activate_cmd);

  /* "neighbor peer-group" set commands.
   * Long term we should only accept this command under BGP_NODE and not all of
   * the afi/safi sub-contexts. For now though we need to accept it for backwards
   * compatibility. This changed when we stopped requiring that peers be assigned
   * to their peer-group under each address-family sub-context.
   */
  install_element (BGP_NODE, &neighbor_set_peer_group_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_set_peer_group_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_set_peer_group_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_set_peer_group_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_set_peer_group_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_set_peer_group_cmd);

  /* "no neighbor peer-group unset" commands. */
  install_element (BGP_NODE, &no_neighbor_set_peer_group_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_set_peer_group_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_set_peer_group_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_set_peer_group_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_set_peer_group_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_set_peer_group_cmd);
  
  /* "neighbor softreconfiguration inbound" commands.*/
  install_element (BGP_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_NODE, &no_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_soft_reconfiguration_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_soft_reconfiguration_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_soft_reconfiguration_cmd);

  /* "neighbor attribute-unchanged" commands.  */
  install_element (BGP_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_NODE, &no_neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_attr_unchanged10_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged1_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged2_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged3_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged4_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged5_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged6_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged7_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged8_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged9_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_attr_unchanged10_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged1_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged2_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged3_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged4_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged5_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged6_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged7_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged8_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged9_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_attr_unchanged10_cmd);

  /* "nexthop-local unchanged" commands */
  install_element (BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_nexthop_local_unchanged_cmd);

  /* "neighbor next-hop-self" commands. */
  install_element (BGP_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_nexthop_self_cmd);

  /* "neighbor next-hop-self force" commands. */
  install_element (BGP_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_NODE, &no_neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_nexthop_self_force_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_nexthop_self_force_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_nexthop_self_force_cmd);

  /* "neighbor as-override" commands. */
  install_element (BGP_NODE, &neighbor_as_override_cmd);
  install_element (BGP_NODE, &no_neighbor_as_override_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_as_override_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_as_override_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_as_override_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_as_override_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_as_override_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_as_override_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_as_override_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_as_override_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_as_override_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_as_override_cmd);

  /* "neighbor remove-private-AS" commands. */
  install_element (BGP_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_remove_private_as_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_remove_private_as_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_remove_private_as_all_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_remove_private_as_all_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_remove_private_as_replace_as_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_remove_private_as_all_replace_as_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_remove_private_as_all_replace_as_cmd);

  /* "neighbor send-community" commands.*/
  install_element (BGP_NODE, &neighbor_send_community_cmd);
  install_element (BGP_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_NODE, &no_neighbor_send_community_type_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_send_community_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_send_community_type_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_send_community_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_send_community_type_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_send_community_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_send_community_type_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_send_community_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_send_community_type_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_send_community_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_send_community_type_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_send_community_type_cmd);

  /* "neighbor route-reflector" commands.*/
  install_element (BGP_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_route_reflector_client_cmd);

  /* "neighbor route-server" commands.*/
  install_element (BGP_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_NODE, &no_neighbor_route_server_client_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_route_server_client_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_route_server_client_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_route_server_client_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_route_server_client_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_route_server_client_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_route_server_client_cmd);

  /* "neighbor addpath-tx-all-paths" commands.*/
  install_element (BGP_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);

  /* "neighbor addpath-tx-bestpath-per-AS" commands.*/
  install_element (BGP_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_addpath_tx_bestpath_per_as_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_addpath_tx_bestpath_per_as_cmd);

  /* "neighbor passive" commands. */
  install_element (BGP_NODE, &neighbor_passive_cmd);
  install_element (BGP_NODE, &no_neighbor_passive_cmd);


  /* "neighbor shutdown" commands. */
  install_element (BGP_NODE, &neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_neighbor_shutdown_cmd);

  /* "neighbor capability extended-nexthop" commands.*/
  install_element (BGP_NODE, &neighbor_capability_enhe_cmd);
  install_element (BGP_NODE, &no_neighbor_capability_enhe_cmd);

  /* "neighbor capability orf prefix-list" commands.*/
  install_element (BGP_NODE, &neighbor_capability_orf_prefix_cmd);
  install_element (BGP_NODE, &no_neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_capability_orf_prefix_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_capability_orf_prefix_cmd);

  /* "neighbor capability dynamic" commands.*/
  install_element (BGP_NODE, &neighbor_capability_dynamic_cmd);
  install_element (BGP_NODE, &no_neighbor_capability_dynamic_cmd);

  /* "neighbor dont-capability-negotiate" commands. */
  install_element (BGP_NODE, &neighbor_dont_capability_negotiate_cmd);
  install_element (BGP_NODE, &no_neighbor_dont_capability_negotiate_cmd);

  /* "neighbor ebgp-multihop" commands. */
  install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &neighbor_ebgp_multihop_ttl_cmd);
  install_element (BGP_NODE, &no_neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &no_neighbor_ebgp_multihop_ttl_cmd);

  /* "neighbor disable-connected-check" commands.  */
  install_element (BGP_NODE, &neighbor_disable_connected_check_cmd);
  install_element (BGP_NODE, &no_neighbor_disable_connected_check_cmd);
  install_element (BGP_NODE, &neighbor_enforce_multihop_cmd);
  install_element (BGP_NODE, &no_neighbor_enforce_multihop_cmd);

  /* "neighbor description" commands. */
  install_element (BGP_NODE, &neighbor_description_cmd);
  install_element (BGP_NODE, &no_neighbor_description_cmd);
  install_element (BGP_NODE, &no_neighbor_description_val_cmd);

  /* "neighbor update-source" commands. "*/
  install_element (BGP_NODE, &neighbor_update_source_cmd);
  install_element (BGP_NODE, &no_neighbor_update_source_cmd);

  /* "neighbor default-originate" commands. */
  install_element (BGP_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_NODE, &neighbor_default_originate_rmap_cmd);
  install_element (BGP_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_NODE, &no_neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_default_originate_rmap_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_default_originate_rmap_cmd);

  /* "neighbor port" commands. */
  install_element (BGP_NODE, &neighbor_port_cmd);
  install_element (BGP_NODE, &no_neighbor_port_cmd);
  install_element (BGP_NODE, &no_neighbor_port_val_cmd);

  /* "neighbor weight" commands. */
  install_element (BGP_NODE, &neighbor_weight_cmd);
  install_element (BGP_NODE, &no_neighbor_weight_cmd);
  install_element (BGP_NODE, &no_neighbor_weight_val_cmd);

  /* "neighbor override-capability" commands. */
  install_element (BGP_NODE, &neighbor_override_capability_cmd);
  install_element (BGP_NODE, &no_neighbor_override_capability_cmd);

  /* "neighbor strict-capability-match" commands. */
  install_element (BGP_NODE, &neighbor_strict_capability_cmd);
  install_element (BGP_NODE, &no_neighbor_strict_capability_cmd);

  /* "neighbor timers" commands. */
  install_element (BGP_NODE, &neighbor_timers_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_val_cmd);

  /* "neighbor timers connect" commands. */
  install_element (BGP_NODE, &neighbor_timers_connect_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_connect_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_connect_val_cmd);

  /* "neighbor advertisement-interval" commands. */
  install_element (BGP_NODE, &neighbor_advertise_interval_cmd);
  install_element (BGP_NODE, &no_neighbor_advertise_interval_cmd);
  install_element (BGP_NODE, &no_neighbor_advertise_interval_val_cmd);

  /* "neighbor interface" commands. */
  install_element (BGP_NODE, &neighbor_interface_cmd);
  install_element (BGP_NODE, &no_neighbor_interface_cmd);

  /* "neighbor distribute" commands. */
  install_element (BGP_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_distribute_list_cmd);

  /* "neighbor prefix-list" commands. */
  install_element (BGP_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_prefix_list_cmd);

  /* "neighbor filter-list" commands. */
  install_element (BGP_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_filter_list_cmd);

  /* "neighbor route-map" commands. */
  install_element (BGP_NODE, &neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_route_map_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_route_map_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_route_map_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_route_map_cmd);

  /* "neighbor unsuppress-map" commands. */
  install_element (BGP_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_NODE, &no_neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_unsuppress_map_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_unsuppress_map_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_unsuppress_map_cmd);  

  /* "neighbor maximum-prefix" commands. */
  install_element (BGP_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_maximum_prefix_threshold_restart_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_val_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_threshold_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_warning_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_threshold_warning_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_restart_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_threshold_restart_cmd);

  /* "neighbor allowas-in" */
  install_element (BGP_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_NODE, &no_neighbor_allowas_in_val_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_IPV4_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_allowas_in_val_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_IPV4M_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_IPV4M_NODE, &no_neighbor_allowas_in_val_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_allowas_in_val_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_IPV6M_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_IPV6M_NODE, &no_neighbor_allowas_in_val_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_allowas_in_cmd);
  install_element (BGP_VPNV4_NODE, &neighbor_allowas_in_arg_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_allowas_in_cmd);
  install_element (BGP_VPNV4_NODE, &no_neighbor_allowas_in_val_cmd);

  /* address-family commands. */
  install_element (BGP_NODE, &address_family_ipv4_cmd);
  install_element (BGP_NODE, &address_family_ipv4_safi_cmd);
#ifdef HAVE_IPV6
  install_element (BGP_NODE, &address_family_ipv6_cmd);
  install_element (BGP_NODE, &address_family_ipv6_safi_cmd);
#endif /* HAVE_IPV6 */
  install_element (BGP_NODE, &address_family_vpnv4_cmd);
  install_element (BGP_NODE, &address_family_vpnv4_unicast_cmd);

  /* "exit-address-family" command. */
  install_element (BGP_IPV4_NODE, &exit_address_family_cmd);
  install_element (BGP_IPV4M_NODE, &exit_address_family_cmd);
  install_element (BGP_IPV6_NODE, &exit_address_family_cmd);
  install_element (BGP_IPV6M_NODE, &exit_address_family_cmd);
  install_element (BGP_VPNV4_NODE, &exit_address_family_cmd);

  /* "clear ip bgp commands" */
  install_element (ENABLE_NODE, &clear_ip_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_cmd);

  install_element (ENABLE_NODE, &clear_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_cmd);

  /* "clear ip bgp neighbor soft in" */
  install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_ipv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_ipv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_in_cmd);

  install_element (ENABLE_NODE, &clear_bgp_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_all_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_all_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_in_prefix_filter_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_soft_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_in_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_in_prefix_filter_cmd);

  /* clear ip bgp prefix  */
  install_element (ENABLE_NODE, &clear_ip_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_prefix_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_safi_prefix_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_safi_prefix_cmd);

  /* "clear ip bgp neighbor soft out" */
  install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_ipv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_ipv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_out_cmd);

  install_element (ENABLE_NODE, &clear_bgp_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_all_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_soft_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_out_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_out_cmd);

  /* "clear ip bgp neighbor soft" */
  install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_all_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_peer_group_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_external_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_external_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_instance_as_ipv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_cmd);

  install_element (ENABLE_NODE, &clear_bgp_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_as_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_as_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_all_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_peer_group_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_external_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_ipv6_as_soft_cmd);
  install_element (ENABLE_NODE, &clear_bgp_instance_ipv6_as_soft_cmd);

  /* "show ip bgp summary" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_updgrps_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_updgrps_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_all_updgrps_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_updgrps_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_updgrps_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_updgrps_s_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_updgrps_s_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_s_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_updgrps_s_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_updgrps_s_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_updgrps_adj_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_updgrps_adj_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_adj_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_updgrps_adj_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_afi_adj_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_updgrps_adj_s_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_adj_s_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_updgrps_adj_s_cmd);
  install_element (VIEW_NODE, &show_bgp_updgrps_afi_adj_s_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_all_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_ipv4_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv4_safi_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_summary_cmd);
#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_all_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_safi_summary_cmd);
#endif /* HAVE_IPV6 */
  install_element (RESTRICTED_NODE, &show_ip_bgp_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_all_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv6_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_updgrps_s_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_updgrps_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_updgrps_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv6_updgrps_s_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_updgrps_adj_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_updgrps_adj_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_adj_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_updgrps_adj_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_afi_adj_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_updgrps_adj_s_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_adj_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_updgrps_adj_s_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_updgrps_afi_adj_s_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_all_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_ipv4_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv4_safi_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_summary_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_summary_cmd);
#ifdef HAVE_IPV6
  install_element (RESTRICTED_NODE, &show_bgp_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_all_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv6_summary_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv6_safi_summary_cmd);
#endif /* HAVE_IPV6 */
  install_element (ENABLE_NODE, &show_ip_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_updgrps_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_updgrps_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_all_updgrps_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_updgrps_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_updgrps_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_updgrps_s_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_updgrps_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_updgrps_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_updgrps_s_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_updgrps_adj_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_updgrps_adj_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_adj_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_updgrps_adj_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_afi_adj_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_updgrps_adj_s_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_adj_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_updgrps_adj_s_cmd);
  install_element (ENABLE_NODE, &show_bgp_updgrps_afi_adj_s_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_all_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_ipv4_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv4_safi_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_summary_cmd);
#ifdef HAVE_IPV6
  install_element (ENABLE_NODE, &show_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_all_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_summary_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_safi_summary_cmd);
#endif /* HAVE_IPV6 */

  /* "show ip bgp neighbors" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_all_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_instance_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_all_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_neighbors_peer_cmd);

#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbors_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_neighbors_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_neighbors_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_bgp_instance_ipv6_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_neighbors_peer_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_instance_ipv6_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_neighbors_peer_cmd);

  /* Old commands.  */
  install_element (VIEW_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_summary_cmd);
#endif /* HAVE_IPV6 */

  /* "show ip bgp peer-group" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_peer_groups_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_peer_groups_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_peer_group_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_peer_group_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_peer_groups_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_peer_groups_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_peer_group_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_peer_group_cmd);

  /* "show ip bgp paths" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_paths_cmd);

  /* "show ip bgp community" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_community_info_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_info_cmd);

  /* "show ip bgp attribute-info" commands. */
  install_element (VIEW_NODE, &show_ip_bgp_attr_info_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_attr_info_cmd);

  /* "redistribute" commands.  */
  install_element (BGP_NODE, &bgp_redistribute_ipv4_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_rmap_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_rmap_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_metric_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_metric_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_rmap_metric_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_metric_rmap_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_rmap_metric_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_metric_rmap_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_ospf_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_ospf_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_ospf_rmap_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_ospf_rmap_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_ospf_metric_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_ospf_metric_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_rmap_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_metric_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_metric_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_rmap_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_rmap_metric_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_metric_rmap_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_rmap_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_rmap_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_metric_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_metric_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
  install_element (BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
#ifdef HAVE_IPV6
  install_element (BGP_IPV6_NODE, &bgp_redistribute_ipv6_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_cmd);
  install_element (BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_rmap_cmd);
  install_element (BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_metric_cmd);
  install_element (BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_metric_cmd);
  install_element (BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_rmap_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_rmap_metric_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_metric_rmap_cmd);
#endif /* HAVE_IPV6 */

  /* ttl_security commands */
  install_element (BGP_NODE, &neighbor_ttl_security_cmd);
  install_element (BGP_NODE, &no_neighbor_ttl_security_cmd);

  /* "show bgp memory" commands. */
  install_element (VIEW_NODE, &show_bgp_memory_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_memory_cmd);
  install_element (ENABLE_NODE, &show_bgp_memory_cmd);
  
  /* "show bgp views" commands. */
  install_element (VIEW_NODE, &show_bgp_views_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_views_cmd);
  install_element (ENABLE_NODE, &show_bgp_views_cmd);
  
  /* "show bgp vrfs" commands. */
  install_element (VIEW_NODE, &show_bgp_vrfs_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_vrfs_cmd);
  install_element (ENABLE_NODE, &show_bgp_vrfs_cmd);
  
  /* Community-list. */
  community_list_vty ();
}

#include "memory.h"
#include "bgp_regex.h"
#include "bgp_clist.h"
#include "bgp_ecommunity.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *
community_direct_str (int direct)
{
  switch (direct)
    {
    case COMMUNITY_DENY:
      return "deny";
    case COMMUNITY_PERMIT:
      return "permit";
    default:
      return "unknown";
    }
}

/* Display error string.  */
static void
community_list_perror (struct vty *vty, int ret)
{
  switch (ret)
    {
    case COMMUNITY_LIST_ERR_CANT_FIND_LIST:
      vty_out (vty, "%% Can't find community-list%s", VTY_NEWLINE);
      break;
    case COMMUNITY_LIST_ERR_MALFORMED_VAL:
      vty_out (vty, "%% Malformed community-list value%s", VTY_NEWLINE);
      break;
    case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
      vty_out (vty, "%% Community name conflict, previously defined as standard community%s", VTY_NEWLINE);
      break;
    case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
      vty_out (vty, "%% Community name conflict, previously defined as expanded community%s", VTY_NEWLINE);
      break;
    }
}

/* VTY interface for community_set() function.  */
static int
community_list_set_vty (struct vty *vty, int argc, const char **argv, 
                        int style, int reject_all_digit_name)
{
  int ret;
  int direct;
  char *str;

  /* Check the list type. */
  if (strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      vty_out (vty, "%% Matching condition must be permit or deny%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* All digit name check.  */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Concat community string argument.  */
  if (argc > 1)
    str = argv_concat (argv, argc, 2);
  else
    str = NULL;

  /* When community_list_set() return nevetive value, it means
     malformed community string.  */
  ret = community_list_set (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      /* Display error string.  */
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* Communiyt-list entry delete.  */
static int
community_list_unset_vty (struct vty *vty, int argc, const char **argv,
			  int style, int delete_all)
{
  int ret;
  int direct = 0;
  char *str = NULL;

  if (argc > 1)
    {
      /* Check the list direct. */
      if (strncmp (argv[1], "p", 1) == 0)
	direct = COMMUNITY_PERMIT;
      else if (strncmp (argv[1], "d", 1) == 0)
	direct = COMMUNITY_DENY;
      else
	{
	  vty_out (vty, "%% Matching condition must be permit or deny%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}

      /* Concat community string argument.  */
      str = argv_concat (argv, argc, 2);
    }

  /* Unset community list.  */
  ret = community_list_unset (bgp_clist, argv[0], str, direct, style, delete_all);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"

DEFUN (ip_community_list_standard,
       ip_community_list_standard_cmd,
       "ip community-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}

ALIAS (ip_community_list_standard,
       ip_community_list_standard2_cmd,
       "ip community-list <1-99> (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_expanded,
       ip_community_list_expanded_cmd,
       "ip community-list <100-500> (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (ip_community_list_name_standard,
       ip_community_list_name_standard_cmd,
       "ip community-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 1);
}

ALIAS (ip_community_list_name_standard,
       ip_community_list_name_standard2_cmd,
       "ip community-list standard WORD (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_name_expanded,
       ip_community_list_name_expanded_cmd,
       "ip community-list expanded WORD (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_community_list_standard_all,
       no_ip_community_list_standard_all_cmd,
       "no ip community-list <1-99>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 1);
}

DEFUN (no_ip_community_list_standard_direction,
       no_ip_community_list_standard_direction_cmd,
       "no ip community-list <1-99> (deny|permit)",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}


DEFUN (no_ip_community_list_expanded_all,
       no_ip_community_list_expanded_all_cmd,
       "no ip community-list <100-500>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_community_list_name_standard_all,
       no_ip_community_list_name_standard_all_cmd,
       "no ip community-list standard WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 1);
}

DEFUN (no_ip_community_list_name_expanded_all,
       no_ip_community_list_name_expanded_all_cmd,
       "no ip community-list expanded WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_community_list_standard,
       no_ip_community_list_standard_cmd,
       "no ip community-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_community_list_expanded,
       no_ip_community_list_expanded_cmd,
       "no ip community-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (no_ip_community_list_name_standard,
       no_ip_community_list_name_standard_cmd,
       "no ip community-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify a standard community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_community_list_name_standard_brief,
       no_ip_community_list_name_standard_brief_cmd,
       "no ip community-list standard WORD (deny|permit)",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify a standard community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_community_list_name_expanded,
       no_ip_community_list_name_expanded_cmd,
       "no ip community-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify an expanded community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED, 0);
}

static void
community_list_show (struct vty *vty, struct community_list *list)
{
  struct community_entry *entry;

  for (entry = list->head; entry; entry = entry->next)
    {
      if (entry == list->head)
	{
	  if (all_digit (list->name))
	    vty_out (vty, "Community %s list %s%s",
		     entry->style == COMMUNITY_LIST_STANDARD ?
		     "standard" : "(expanded) access",
		     list->name, VTY_NEWLINE);
	  else
	    vty_out (vty, "Named Community %s list %s%s",
		     entry->style == COMMUNITY_LIST_STANDARD ?
		     "standard" : "expanded",
		     list->name, VTY_NEWLINE);
	}
      if (entry->any)
	vty_out (vty, "    %s%s",
		 community_direct_str (entry->direct), VTY_NEWLINE);
      else
	vty_out (vty, "    %s %s%s",
		 community_direct_str (entry->direct),
		 entry->style == COMMUNITY_LIST_STANDARD
		 ? community_str (entry->u.com) : entry->config,
		 VTY_NEWLINE);
    }
}

DEFUN (show_ip_community_list,
       show_ip_community_list_cmd,
       "show ip community-list",
       SHOW_STR
       IP_STR
       "List community-list\n")
{
  struct community_list *list;
  struct community_list_master *cm;

  cm = community_list_master_lookup (bgp_clist, COMMUNITY_LIST_MASTER);
  if (! cm)
    return CMD_SUCCESS;

  for (list = cm->num.head; list; list = list->next)
    community_list_show (vty, list);

  for (list = cm->str.head; list; list = list->next)
    community_list_show (vty, list);

  return CMD_SUCCESS;
}

DEFUN (show_ip_community_list_arg,
       show_ip_community_list_arg_cmd,
       "show ip community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, argv[0], COMMUNITY_LIST_MASTER);
  if (! list)
    {
      vty_out (vty, "%% Can't find community-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  community_list_show (vty, list);

  return CMD_SUCCESS;
}

static int
extcommunity_list_set_vty (struct vty *vty, int argc, const char **argv, 
                           int style, int reject_all_digit_name)
{
  int ret;
  int direct;
  char *str;

  /* Check the list type. */
  if (strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      vty_out (vty, "%% Matching condition must be permit or deny%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* All digit name check.  */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Concat community string argument.  */
  if (argc > 1)
    str = argv_concat (argv, argc, 2);
  else
    str = NULL;

  ret = extcommunity_list_set (bgp_clist, argv[0], str, direct, style);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

static int
extcommunity_list_unset_vty (struct vty *vty, int argc, const char **argv,
			     int style, int delete_all)
{
  int ret;
  int direct = 0;
  char *str = NULL;

  if (argc > 1)
    {
      /* Check the list direct. */
      if (strncmp (argv[1], "p", 1) == 0)
	direct = COMMUNITY_PERMIT;
      else if (strncmp (argv[1], "d", 1) == 0)
	direct = COMMUNITY_DENY;
      else
	{
	  vty_out (vty, "%% Matching condition must be permit or deny%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}

      /* Concat community string argument.  */
      str = argv_concat (argv, argc, 2);
    }

  /* Unset community list.  */
  ret = extcommunity_list_unset (bgp_clist, argv[0], str, direct, style, delete_all);

  /* Free temporary community list string allocated by
     argv_concat().  */
  if (str)
    XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in 'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

DEFUN (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard_cmd,
       "ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

ALIAS (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard2_cmd,
       "ip extcommunity-list <1-99> (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_expanded,
       ip_extcommunity_list_expanded_cmd,
       "ip extcommunity-list <100-500> (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard_cmd,
       "ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 1);
}

ALIAS (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard2_cmd,
       "ip extcommunity-list standard WORD (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_name_expanded,
       ip_extcommunity_list_name_expanded_cmd,
       "ip extcommunity-list expanded WORD (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_extcommunity_list_standard_all,
       no_ip_extcommunity_list_standard_all_cmd,
       "no ip extcommunity-list <1-99>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 1);
}

DEFUN (no_ip_extcommunity_list_standard_direction,
       no_ip_extcommunity_list_standard_direction_cmd,
       "no ip extcommunity-list <1-99> (deny|permit)",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_extcommunity_list_expanded_all,
       no_ip_extcommunity_list_expanded_all_cmd,
       "no ip extcommunity-list <100-500>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_extcommunity_list_name_standard_all,
       no_ip_extcommunity_list_name_standard_all_cmd,
       "no ip extcommunity-list standard WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 1);
}

DEFUN (no_ip_extcommunity_list_name_expanded_all,
       no_ip_extcommunity_list_name_expanded_all_cmd,
       "no ip extcommunity-list expanded WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_ip_extcommunity_list_standard,
       no_ip_extcommunity_list_standard_cmd,
       "no ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_extcommunity_list_expanded,
       no_ip_extcommunity_list_expanded_cmd,
       "no ip extcommunity-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (no_ip_extcommunity_list_name_standard,
       no_ip_extcommunity_list_name_standard_cmd,
       "no ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_extcommunity_list_name_standard_brief,
       no_ip_extcommunity_list_name_standard_brief_cmd,
       "no ip extcommunity-list standard WORD (deny|permit)",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_STANDARD, 0);
}

DEFUN (no_ip_extcommunity_list_name_expanded,
       no_ip_extcommunity_list_name_expanded_cmd,
       "no ip extcommunity-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv, EXTCOMMUNITY_LIST_EXPANDED, 0);
}

static void
extcommunity_list_show (struct vty *vty, struct community_list *list)
{
  struct community_entry *entry;

  for (entry = list->head; entry; entry = entry->next)
    {
      if (entry == list->head)
	{
	  if (all_digit (list->name))
	    vty_out (vty, "Extended community %s list %s%s",
		     entry->style == EXTCOMMUNITY_LIST_STANDARD ?
		     "standard" : "(expanded) access",
		     list->name, VTY_NEWLINE);
	  else
	    vty_out (vty, "Named extended community %s list %s%s",
		     entry->style == EXTCOMMUNITY_LIST_STANDARD ?
		     "standard" : "expanded",
		     list->name, VTY_NEWLINE);
	}
      if (entry->any)
	vty_out (vty, "    %s%s",
		 community_direct_str (entry->direct), VTY_NEWLINE);
      else
	vty_out (vty, "    %s %s%s",
		 community_direct_str (entry->direct),
		 entry->style == EXTCOMMUNITY_LIST_STANDARD ?
		 entry->u.ecom->str : entry->config,
		 VTY_NEWLINE);
    }
}

DEFUN (show_ip_extcommunity_list,
       show_ip_extcommunity_list_cmd,
       "show ip extcommunity-list",
       SHOW_STR
       IP_STR
       "List extended-community list\n")
{
  struct community_list *list;
  struct community_list_master *cm;

  cm = community_list_master_lookup (bgp_clist, EXTCOMMUNITY_LIST_MASTER);
  if (! cm)
    return CMD_SUCCESS;

  for (list = cm->num.head; list; list = list->next)
    extcommunity_list_show (vty, list);

  for (list = cm->str.head; list; list = list->next)
    extcommunity_list_show (vty, list);

  return CMD_SUCCESS;
}

DEFUN (show_ip_extcommunity_list_arg,
       show_ip_extcommunity_list_arg_cmd,
       "show ip extcommunity-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, argv[0], EXTCOMMUNITY_LIST_MASTER);
  if (! list)
    {
      vty_out (vty, "%% Can't find extcommunity-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  extcommunity_list_show (vty, list);

  return CMD_SUCCESS;
}

/* Return configuration string of community-list entry.  */
static const char *
community_list_config_str (struct community_entry *entry)
{
  const char *str;

  if (entry->any)
    str = "";
  else
    {
      if (entry->style == COMMUNITY_LIST_STANDARD)
	str = community_str (entry->u.com);
      else
	str = entry->config;
    }
  return str;
}

/* Display community-list and extcommunity-list configuration.  */
static int
community_list_config_write (struct vty *vty)
{
  struct community_list *list;
  struct community_entry *entry;
  struct community_list_master *cm;
  int write = 0;

  /* Community-list.  */
  cm = community_list_master_lookup (bgp_clist, COMMUNITY_LIST_MASTER);

  for (list = cm->num.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
	vty_out (vty, "ip community-list %s %s %s%s",
		 list->name, community_direct_str (entry->direct),
		 community_list_config_str (entry),
		 VTY_NEWLINE);
	write++;
      }
  for (list = cm->str.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
	vty_out (vty, "ip community-list %s %s %s %s%s",
		 entry->style == COMMUNITY_LIST_STANDARD
		 ? "standard" : "expanded",
		 list->name, community_direct_str (entry->direct),
		 community_list_config_str (entry),
		 VTY_NEWLINE);
	write++;
      }

  /* Extcommunity-list.  */
  cm = community_list_master_lookup (bgp_clist, EXTCOMMUNITY_LIST_MASTER);

  for (list = cm->num.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
	vty_out (vty, "ip extcommunity-list %s %s %s%s",
		 list->name, community_direct_str (entry->direct),
		 community_list_config_str (entry), VTY_NEWLINE);
	write++;
      }
  for (list = cm->str.head; list; list = list->next)
    for (entry = list->head; entry; entry = entry->next)
      {
	vty_out (vty, "ip extcommunity-list %s %s %s %s%s",
		 entry->style == EXTCOMMUNITY_LIST_STANDARD
		 ? "standard" : "expanded",
		 list->name, community_direct_str (entry->direct),
		 community_list_config_str (entry), VTY_NEWLINE);
	write++;
      }
  return write;
}

static struct cmd_node community_list_node =
{
  COMMUNITY_LIST_NODE,
  "",
  1				/* Export to vtysh.  */
};

static void
community_list_vty (void)
{
  install_node (&community_list_node, community_list_config_write);

  /* Community-list.  */
  install_element (CONFIG_NODE, &ip_community_list_standard_cmd);
  install_element (CONFIG_NODE, &ip_community_list_standard2_cmd);
  install_element (CONFIG_NODE, &ip_community_list_expanded_cmd);
  install_element (CONFIG_NODE, &ip_community_list_name_standard_cmd);
  install_element (CONFIG_NODE, &ip_community_list_name_standard2_cmd);
  install_element (CONFIG_NODE, &ip_community_list_name_expanded_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_standard_all_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_standard_direction_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_expanded_all_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_name_standard_all_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_name_expanded_all_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_standard_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_expanded_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_name_standard_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_name_standard_brief_cmd);
  install_element (CONFIG_NODE, &no_ip_community_list_name_expanded_cmd);
  install_element (VIEW_NODE, &show_ip_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_community_list_arg_cmd);
  install_element (ENABLE_NODE, &show_ip_community_list_cmd);
  install_element (ENABLE_NODE, &show_ip_community_list_arg_cmd);

  /* Extcommunity-list.  */
  install_element (CONFIG_NODE, &ip_extcommunity_list_standard_cmd);
  install_element (CONFIG_NODE, &ip_extcommunity_list_standard2_cmd);
  install_element (CONFIG_NODE, &ip_extcommunity_list_expanded_cmd);
  install_element (CONFIG_NODE, &ip_extcommunity_list_name_standard_cmd);
  install_element (CONFIG_NODE, &ip_extcommunity_list_name_standard2_cmd);
  install_element (CONFIG_NODE, &ip_extcommunity_list_name_expanded_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_standard_all_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_standard_direction_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_expanded_all_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_name_standard_all_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_name_expanded_all_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_standard_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_expanded_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_name_standard_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_name_standard_brief_cmd);
  install_element (CONFIG_NODE, &no_ip_extcommunity_list_name_expanded_cmd);
  install_element (VIEW_NODE, &show_ip_extcommunity_list_cmd);
  install_element (VIEW_NODE, &show_ip_extcommunity_list_arg_cmd);
  install_element (ENABLE_NODE, &show_ip_extcommunity_list_cmd);
  install_element (ENABLE_NODE, &show_ip_extcommunity_list_arg_cmd);
}
