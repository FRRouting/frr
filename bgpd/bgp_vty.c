/* BGP VTY interface.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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

#include "command.h"
#include "lib/json.h"
#include "lib_errors.h"
#include "lib/zclient.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "stream.h"
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "memory_vty.h"
#include "hash.h"
#include "queue.h"
#include "filter.h"
#include "frrstr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"

static struct peer_group *listen_range_exists(struct bgp *bgp,
					      struct prefix *range, int exact);

static enum node_type bgp_node_type(afi_t afi, safi_t safi)
{
	switch (afi) {
	case AFI_IP:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_IPV4_NODE;
			break;
		case SAFI_MULTICAST:
			return BGP_IPV4M_NODE;
			break;
		case SAFI_LABELED_UNICAST:
			return BGP_IPV4L_NODE;
			break;
		case SAFI_MPLS_VPN:
			return BGP_VPNV4_NODE;
			break;
		case SAFI_FLOWSPEC:
			return BGP_FLOWSPECV4_NODE;
		default:
			/* not expected */
			return BGP_IPV4_NODE;
			break;
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_IPV6_NODE;
			break;
		case SAFI_MULTICAST:
			return BGP_IPV6M_NODE;
			break;
		case SAFI_LABELED_UNICAST:
			return BGP_IPV6L_NODE;
			break;
		case SAFI_MPLS_VPN:
			return BGP_VPNV6_NODE;
			break;
		case SAFI_FLOWSPEC:
			return BGP_FLOWSPECV6_NODE;
		default:
			/* not expected */
			return BGP_IPV4_NODE;
			break;
		}
		break;
	case AFI_L2VPN:
		return BGP_EVPN_NODE;
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		// We should never be here but to clarify the switch statement..
		return BGP_IPV4_NODE;
		break;
	}

	// Impossible to happen
	return BGP_IPV4_NODE;
}

static const char *get_afi_safi_vty_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		return "IPv4 Unicast";
	else if (afi == AFI_IP && safi == SAFI_MULTICAST)
		return "IPv4 Multicast";
	else if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
		return "IPv4 Labeled Unicast";
	else if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
		return "IPv4 VPN";
	else if (afi == AFI_IP && safi == SAFI_ENCAP)
		return "IPv4 Encap";
	else if (afi == AFI_IP && safi == SAFI_FLOWSPEC)
		return "IPv4 Flowspec";
	else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		return "IPv6 Unicast";
	else if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		return "IPv6 Multicast";
	else if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
		return "IPv6 Labeled Unicast";
	else if (afi == AFI_IP6 && safi == SAFI_MPLS_VPN)
		return "IPv6 VPN";
	else if (afi == AFI_IP6 && safi == SAFI_ENCAP)
		return "IPv6 Encap";
	else if (afi == AFI_IP6 && safi == SAFI_FLOWSPEC)
		return "IPv6 Flowspec";
	else if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		return "L2VPN EVPN";
	else
		return "Unknown";
}

/*
 * Please note that we have intentionally camelCased
 * the return strings here.  So if you want
 * to use this function, please ensure you
 * are doing this within json output
 */
static const char *get_afi_safi_json_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		return "ipv4Unicast";
	else if (afi == AFI_IP && safi == SAFI_MULTICAST)
		return "ipv4Multicast";
	else if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
		return "ipv4LabeledUnicast";
	else if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
		return "ipv4Vpn";
	else if (afi == AFI_IP && safi == SAFI_ENCAP)
		return "ipv4Encap";
	else if (afi == AFI_IP && safi == SAFI_FLOWSPEC)
		return "ipv4Flowspec";
	else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		return "ipv6Unicast";
	else if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		return "ipv6Multicast";
	else if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
		return "ipv6LabeledUnicast";
	else if (afi == AFI_IP6 && safi == SAFI_MPLS_VPN)
		return "ipv6Vpn";
	else if (afi == AFI_IP6 && safi == SAFI_ENCAP)
		return "ipv6Encap";
	else if (afi == AFI_IP6 && safi == SAFI_FLOWSPEC)
		return "ipv6Flowspec";
	else if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		return "l2VpnEvpn";
	else
		return "Unknown";
}

/* Utility function to get address family from current node.  */
afi_t bgp_node_afi(struct vty *vty)
{
	afi_t afi;
	switch (vty->node) {
	case BGP_IPV6_NODE:
	case BGP_IPV6M_NODE:
	case BGP_IPV6L_NODE:
	case BGP_VPNV6_NODE:
	case BGP_FLOWSPECV6_NODE:
		afi = AFI_IP6;
		break;
	case BGP_EVPN_NODE:
		afi = AFI_L2VPN;
		break;
	default:
		afi = AFI_IP;
		break;
	}
	return afi;
}

/* Utility function to get subsequent address family from current
   node.  */
safi_t bgp_node_safi(struct vty *vty)
{
	safi_t safi;
	switch (vty->node) {
	case BGP_VPNV4_NODE:
	case BGP_VPNV6_NODE:
		safi = SAFI_MPLS_VPN;
		break;
	case BGP_IPV4M_NODE:
	case BGP_IPV6M_NODE:
		safi = SAFI_MULTICAST;
		break;
	case BGP_EVPN_NODE:
		safi = SAFI_EVPN;
		break;
	case BGP_IPV4L_NODE:
	case BGP_IPV6L_NODE:
		safi = SAFI_LABELED_UNICAST;
		break;
	case BGP_FLOWSPECV4_NODE:
	case BGP_FLOWSPECV6_NODE:
		safi = SAFI_FLOWSPEC;
		break;
	default:
		safi = SAFI_UNICAST;
		break;
	}
	return safi;
}

/**
 * Converts an AFI in string form to afi_t
 *
 * @param afi string, one of
 *  - "ipv4"
 *  - "ipv6"
 *  - "l2vpn"
 * @return the corresponding afi_t
 */
afi_t bgp_vty_afi_from_str(const char *afi_str)
{
	afi_t afi = AFI_MAX; /* unknown */
	if (strmatch(afi_str, "ipv4"))
		afi = AFI_IP;
	else if (strmatch(afi_str, "ipv6"))
		afi = AFI_IP6;
	else if (strmatch(afi_str, "l2vpn"))
		afi = AFI_L2VPN;
	return afi;
}

int argv_find_and_parse_afi(struct cmd_token **argv, int argc, int *index,
			    afi_t *afi)
{
	int ret = 0;
	if (argv_find(argv, argc, "ipv4", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP6;
	} else if (argv_find(argv, argc, "l2vpn", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_L2VPN;
	}
	return ret;
}

/* supports <unicast|multicast|vpn|labeled-unicast> */
safi_t bgp_vty_safi_from_str(const char *safi_str)
{
	safi_t safi = SAFI_MAX; /* unknown */
	if (strmatch(safi_str, "multicast"))
		safi = SAFI_MULTICAST;
	else if (strmatch(safi_str, "unicast"))
		safi = SAFI_UNICAST;
	else if (strmatch(safi_str, "vpn"))
		safi = SAFI_MPLS_VPN;
	else if (strmatch(safi_str, "evpn"))
		safi = SAFI_EVPN;
	else if (strmatch(safi_str, "labeled-unicast"))
		safi = SAFI_LABELED_UNICAST;
	else if (strmatch(safi_str, "flowspec"))
		safi = SAFI_FLOWSPEC;
	return safi;
}

int argv_find_and_parse_safi(struct cmd_token **argv, int argc, int *index,
			     safi_t *safi)
{
	int ret = 0;
	if (argv_find(argv, argc, "unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_UNICAST;
	} else if (argv_find(argv, argc, "multicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MULTICAST;
	} else if (argv_find(argv, argc, "labeled-unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_LABELED_UNICAST;
	} else if (argv_find(argv, argc, "vpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MPLS_VPN;
	} else if (argv_find(argv, argc, "evpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_EVPN;
	} else if (argv_find(argv, argc, "flowspec", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_FLOWSPEC;
	}
	return ret;
}

/*
 * bgp_vty_find_and_parse_afi_safi_bgp
 *
 * For a given 'show ...' command, correctly parse the afi/safi/bgp out from it
 * This function *assumes* that the calling function pre-sets the afi/safi/bgp
 * to appropriate values for the calling function.  This is to allow the
 * calling function to make decisions appropriate for the show command
 * that is being parsed.
 *
 * The show commands are generally of the form:
 * "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>
 * [<unicast|multicast|vpn|labeled-unicast>]] ..."
 *
 * Since we use argv_find if the show command in particular doesn't have:
 * [ip]
 * [<view|vrf> VIEWVRFNAME]
 * [<ipv4|ipv6> [<unicast|multicast|vpn|labeled-unicast>]]
 * The command parsing should still be ok.
 *
 * vty  -> The vty for the command so we can output some useful data in
 *         the event of a parse error in the vrf.
 * argv -> The command tokens
 * argc -> How many command tokens we have
 * idx  -> The current place in the command, generally should be 0 for this
 * function
 * afi  -> The parsed afi if it was included in the show command, returned here
 * safi -> The parsed safi if it was included in the show command, returned here
 * bgp  -> Pointer to the bgp data structure we need to fill in.
 * use_json -> json is configured or not
 *
 * The function returns the correct location in the parse tree for the
 * last token found.
 *
 * Returns 0 for failure to parse correctly, else the idx position of where
 * it found the last token.
 */
int bgp_vty_find_and_parse_afi_safi_bgp(struct vty *vty,
					struct cmd_token **argv, int argc,
					int *idx, afi_t *afi, safi_t *safi,
					struct bgp **bgp, bool use_json)
{
	char *vrf_name = NULL;

	assert(afi);
	assert(safi);
	assert(bgp);

	if (argv_find(argv, argc, "ip", idx))
		*afi = AFI_IP;

	if (argv_find(argv, argc, "view", idx))
		vrf_name = argv[*idx + 1]->arg;
	else if (argv_find(argv, argc, "vrf", idx)) {
		vrf_name = argv[*idx + 1]->arg;
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			vrf_name = NULL;
	}
	if (vrf_name) {
		if (strmatch(vrf_name, "all"))
			*bgp = NULL;
		else {
			*bgp = bgp_lookup_by_name(vrf_name);
			if (!*bgp) {
				if (use_json) {
					json_object *json = NULL;
					json = json_object_new_object();
					json_object_string_add(
					  json, "warning",
					  "View/Vrf is unknown");
					vty_out(vty, "%s\n",
						json_object_to_json_string_ext(json,
							JSON_C_TO_STRING_PRETTY));
					json_object_free(json);
				}
				else
					vty_out(vty, "View/Vrf %s is unknown\n",
						vrf_name);
				*idx = 0;
				return 0;
			}
		}
	} else {
		*bgp = bgp_get_default();
		if (!*bgp) {
			if (use_json) {
				json_object *json = NULL;
				json = json_object_new_object();
				json_object_string_add(
					json, "warning",
					"Default BGP instance not found");
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(json,
						JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}
			else
				vty_out(vty,
					"Default BGP instance not found\n");
			*idx = 0;
			return 0;
		}
	}

	if (argv_find_and_parse_afi(argv, argc, idx, afi))
		argv_find_and_parse_safi(argv, argc, idx, safi);

	*idx += 1;
	return *idx;
}

static int peer_address_self_check(struct bgp *bgp, union sockunion *su)
{
	struct interface *ifp = NULL;

	if (su->sa.sa_family == AF_INET)
		ifp = if_lookup_by_ipv4_exact(&su->sin.sin_addr, bgp->vrf_id);
	else if (su->sa.sa_family == AF_INET6)
		ifp = if_lookup_by_ipv6_exact(&su->sin6.sin6_addr,
					      su->sin6.sin6_scope_id,
					      bgp->vrf_id);

	if (ifp)
		return 1;

	return 0;
}

/* Utility function for looking up peer from VTY.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
static struct peer *peer_lookup_vty(struct vty *vty, const char *ip_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer;

	if (!bgp) {
		return NULL;
	}

	ret = str2sockunion(ip_str, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, ip_str);
		if (!peer) {
			if ((peer = peer_lookup_by_hostname(bgp, ip_str))
			    == NULL) {
				vty_out(vty,
					"%% Malformed address or name: %s\n",
					ip_str);
				return NULL;
			}
		}
	} else {
		peer = peer_lookup(bgp, &su);
		if (!peer) {
			vty_out(vty,
				"%% Specify remote-as or peer-group commands first\n");
			return NULL;
		}
		if (peer_dynamic_neighbor(peer)) {
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return NULL;
		}
	}
	return peer;
}

/* Utility function for looking up peer or peer group.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
struct peer *peer_and_group_lookup_vty(struct vty *vty, const char *peer_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer = NULL;
	struct peer_group *group = NULL;

	if (!bgp) {
		return NULL;
	}

	ret = str2sockunion(peer_str, &su);
	if (ret == 0) {
		/* IP address, locate peer. */
		peer = peer_lookup(bgp, &su);
	} else {
		/* Not IP, could match either peer configured on interface or a
		 * group. */
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			group = peer_group_lookup(bgp, peer_str);
	}

	if (peer) {
		if (peer_dynamic_neighbor(peer)) {
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return NULL;
		}

		return peer;
	}

	if (group)
		return group->conf;

	vty_out(vty, "%% Specify remote-as or peer-group commands first\n");

	return NULL;
}

int bgp_vty_return(struct vty *vty, int ret)
{
	const char *str = NULL;

	switch (ret) {
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
	case BGP_ERR_INVALID_FOR_DIRECT_PEER:
		str = "Operation not allowed on a directly connected neighbor";
		break;
	case BGP_ERR_PEER_SAFI_CONFLICT:
		str = "Cannot activate peer for both 'ipv4 unicast' and 'ipv4 labeled-unicast'";
		break;
	}
	if (str) {
		vty_out(vty, "%% %s\n", str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* BGP clear sort. */
enum clear_sort {
	clear_all,
	clear_peer,
	clear_group,
	clear_external,
	clear_as
};

static void bgp_clear_vty_error(struct vty *vty, struct peer *peer, afi_t afi,
				safi_t safi, int error)
{
	switch (error) {
	case BGP_ERR_AF_UNCONFIGURED:
		vty_out(vty,
			"%%BGP: Enable %s address family for the neighbor %s\n",
			get_afi_safi_str(afi, safi, false), peer->host);
		break;
	case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
		vty_out(vty,
			"%%BGP: Inbound soft reconfig for %s not possible as it\n      has neither refresh capability, nor inbound soft reconfig\n",
			peer->host);
		break;
	default:
		break;
	}
}

static int bgp_peer_clear(struct peer *peer, afi_t afi, safi_t safi,
			  struct listnode *nnode, enum bgp_clear_type stype)
{
	int ret = 0;

	/* if afi/.safi not specified, spin thru all of them */
	if ((afi == AFI_UNSPEC) && (safi == SAFI_UNSPEC)) {
		afi_t tmp_afi;
		safi_t tmp_safi;

		FOREACH_AFI_SAFI (tmp_afi, tmp_safi) {
			if (!peer->afc[tmp_afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_SOFT_NONE)
				ret = peer_clear(peer, &nnode);
			else
				ret = peer_clear_soft(peer, tmp_afi, tmp_safi,
						      stype);
		}
	/* if afi specified and safi not, spin thru safis on this afi */
	} else if (safi == SAFI_UNSPEC) {
		safi_t tmp_safi;

		for (tmp_safi = SAFI_UNICAST;
		     tmp_safi < SAFI_MAX; tmp_safi++) {
			if (!peer->afc[afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_SOFT_NONE)
				ret = peer_clear(peer, &nnode);
			else
				ret = peer_clear_soft(peer, afi,
						      tmp_safi, stype);
		}
	/* both afi/safi specified, let the caller know if not defined */
	} else {
		if (!peer->afc[afi][safi])
			return 1;

		if (stype == BGP_CLEAR_SOFT_NONE)
			ret = peer_clear(peer, &nnode);
		else
			ret = peer_clear_soft(peer, afi, safi, stype);
	}

	return ret;
}

/* `clear ip bgp' functions. */
static int bgp_clear(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		     enum clear_sort sort, enum bgp_clear_type stype,
		     const char *arg)
{
	int ret = 0;
	bool found = false;
	struct peer *peer;
	struct listnode *node, *nnode;

	/* Clear all neighbors. */
	/*
	 * Pass along pointer to next node to peer_clear() when walking all
	 * nodes on the BGP instance as that may get freed if it is a
	 * doppelganger
	 */
	if (sort == clear_all) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			ret = bgp_peer_clear(peer, afi, safi, nnode,
							  stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
		}

		/* This is to apply read-only mode on this clear. */
		if (stype == BGP_CLEAR_SOFT_NONE)
			bgp->update_delay_over = 0;

		return CMD_SUCCESS;
	}

	/* Clear specified neighbor. */
	if (sort == clear_peer) {
		union sockunion su;

		/* Make sockunion for lookup. */
		ret = str2sockunion(arg, &su);
		if (ret < 0) {
			peer = peer_lookup_by_conf_if(bgp, arg);
			if (!peer) {
				peer = peer_lookup_by_hostname(bgp, arg);
				if (!peer) {
					vty_out(vty,
						"Malformed address or name: %s\n",
						arg);
					return CMD_WARNING;
				}
			}
		} else {
			peer = peer_lookup(bgp, &su);
			if (!peer) {
				vty_out(vty,
					"%%BGP: Unknown neighbor - \"%s\"\n",
					arg);
				return CMD_WARNING;
			}
		}

		ret = bgp_peer_clear(peer, afi, safi, NULL, stype);

		/* if afi/safi not defined for this peer, let caller know */
		if (ret == 1)
			ret = BGP_ERR_AF_UNCONFIGURED;

		if (ret < 0)
			bgp_clear_vty_error(vty, peer, afi, safi, ret);

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific peer-group. */
	if (sort == clear_group) {
		struct peer_group *group;

		group = peer_group_lookup(bgp, arg);
		if (!group) {
			vty_out(vty, "%%BGP: No such peer-group %s\n", arg);
			return CMD_WARNING;
		}

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			ret = bgp_peer_clear(peer, afi, safi, nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (!found)
			vty_out(vty,
				"%%BGP: No %s peer belonging to peer-group %s is configured\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	/* Clear all external (eBGP) neighbors. */
	if (sort == clear_external) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_IBGP)
				continue;

			ret = bgp_peer_clear(peer, afi, safi, nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (!found)
			vty_out(vty,
				"%%BGP: No external %s peer is configured\n",
				get_afi_safi_str(afi, safi, false));

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific AS. */
	if (sort == clear_as) {
		as_t as = strtoul(arg, NULL, 10);

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as != as)
				continue;

			ret = bgp_peer_clear(peer, afi, safi, nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (!found)
			vty_out(vty,
				"%%BGP: No %s peer is configured with AS %s\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	return CMD_SUCCESS;
}

static int bgp_clear_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, enum clear_sort sort,
			 enum bgp_clear_type stype, const char *arg)
{
	struct bgp *bgp;

	/* BGP structure lookup. */
	if (name) {
		bgp = bgp_lookup_by_name(name);
		if (bgp == NULL) {
			vty_out(vty, "Can't find BGP instance %s\n", name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	return bgp_clear(vty, bgp, afi, safi, sort, stype, arg);
}

/* clear soft inbound */
static void bgp_clear_star_soft_in(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_IN, NULL);
}

/* clear soft outbound */
static void bgp_clear_star_soft_out(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_OUT, NULL);
}


#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_vty_clippy.c"
#endif

DEFUN_HIDDEN (bgp_local_mac,
              bgp_local_mac_cmd,
              "bgp local-mac vni " CMD_VNI_RANGE " mac WORD seq (0-4294967295)",
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n"
              "mac-mobility sequence\n"
              "seq number\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	uint32_t seq;
	struct bgp *bgp;

	vni = strtoul(argv[3]->arg, NULL, 10);
	if (!prefix_str2mac(argv[5]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));
	seq = strtoul(argv[7]->arg, NULL, 10);

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_add(bgp, vni, &mac, &ip, 0 /* flags */, seq);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_bgp_local_mac,
              no_bgp_local_mac_cmd,
              "no bgp local-mac vni " CMD_VNI_RANGE " mac WORD",
              NO_STR
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	struct bgp *bgp;

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_del(bgp, vni, &mac, &ip, ZEBRA_NEIGH_ACTIVE);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

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
DEFUN_NOSH (router_bgp,
       router_bgp_cmd,
       "router bgp [(1-4294967295)$instasn [<view|vrf> VIEWVRFNAME]]",
       ROUTER_STR
       BGP_STR
       AS_STR
       BGP_INSTANCE_HELP_STR)
{
	int idx_asn = 2;
	int idx_view_vrf = 3;
	int idx_vrf = 4;
	int is_new_bgp = 0;
	int ret;
	as_t as;
	struct bgp *bgp;
	const char *name = NULL;
	enum bgp_instance_type inst_type;

	// "router bgp" without an ASN
	if (argc == 2) {
		// Pending: Make VRF option available for ASN less config
		bgp = bgp_get_default();

		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	// "router bgp X"
	else {
		as = strtoul(argv[idx_asn]->arg, NULL, 10);

		inst_type = BGP_INSTANCE_TYPE_DEFAULT;
		if (argc > 3) {
			name = argv[idx_vrf]->arg;

			if (!strcmp(argv[idx_view_vrf]->text, "vrf")) {
				if (strmatch(name, VRF_DEFAULT_NAME))
					name = NULL;
				else
					inst_type = BGP_INSTANCE_TYPE_VRF;
			} else if (!strcmp(argv[idx_view_vrf]->text, "view"))
				inst_type = BGP_INSTANCE_TYPE_VIEW;
		}

		if (inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			is_new_bgp = (bgp_lookup(as, name) == NULL);

		ret = bgp_get(&bgp, &as, name, inst_type);
		switch (ret) {
		case BGP_ERR_AS_MISMATCH:
			vty_out(vty, "BGP is already running; AS is %u\n", as);
			return CMD_WARNING_CONFIG_FAILED;
		case BGP_ERR_INSTANCE_MISMATCH:
			vty_out(vty,
				"BGP instance name and AS number mismatch\n");
			vty_out(vty,
				"BGP instance is already running; AS is %u\n",
				as);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/*
		 * If we just instantiated the default instance, complete
		 * any pending VRF-VPN leaking that was configured via
		 * earlier "router bgp X vrf FOO" blocks.
		 */
		if (is_new_bgp && inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			vpn_leak_postchange_all();

		if (inst_type == BGP_INSTANCE_TYPE_VRF)
			bgp_vpn_leak_export(bgp);
		/* Pending: handle when user tries to change a view to vrf n vv.
		 */
	}

	/* unset the auto created flag as the user config is now present */
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);
	VTY_PUSH_CONTEXT(BGP_NODE, bgp);

	return CMD_SUCCESS;
}

/* "no router bgp" commands. */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp [(1-4294967295)$instasn [<view|vrf> VIEWVRFNAME]]",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       BGP_INSTANCE_HELP_STR)
{
	int idx_asn = 3;
	int idx_vrf = 5;
	as_t as;
	struct bgp *bgp;
	const char *name = NULL;

	// "no router bgp" without an ASN
	if (argc == 3) {
		// Pending: Make VRF option available for ASN less config
		bgp = bgp_get_default();

		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (bgp->l3vni) {
			vty_out(vty, "%% Please unconfigure l3vni %u",
				bgp->l3vni);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		as = strtoul(argv[idx_asn]->arg, NULL, 10);

		if (argc > 4)
			name = argv[idx_vrf]->arg;

		/* Lookup bgp structure. */
		bgp = bgp_lookup(as, name);
		if (!bgp) {
			vty_out(vty, "%% Can't find BGP instance\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (bgp->l3vni) {
			vty_out(vty, "%% Please unconfigure l3vni %u\n",
				bgp->l3vni);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Cannot delete default instance if vrf instances exist */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			struct listnode *node;
			struct bgp *tmp_bgp;

			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, tmp_bgp)) {
				if (tmp_bgp->inst_type
				    == BGP_INSTANCE_TYPE_VRF) {
					vty_out(vty,
						"%% Cannot delete default BGP instance. Dependent VRF instances exist\n");
					return CMD_WARNING_CONFIG_FAILED;
				}
			}
		}
	}

	if (bgp_vpn_leak_unimport(bgp, vty))
		return CMD_WARNING_CONFIG_FAILED;

	bgp_delete(bgp);

	return CMD_SUCCESS;
}


/* BGP router-id.  */

DEFPY (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_router_id_static_set(bgp, router_id);
	return CMD_SUCCESS;
}

DEFPY (no_bgp_router_id,
       no_bgp_router_id_cmd,
       "no bgp router-id [A.B.C.D]",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (router_id_str) {
		if (!IPV4_ADDR_SAME(&bgp->router_id_static, &router_id)) {
			vty_out(vty, "%% BGP router-id doesn't match\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	router_id.s_addr = 0;
	bgp_router_id_static_set(bgp, router_id);

	return CMD_SUCCESS;
}


/* BGP Cluster ID.  */
DEFUN (bgp_cluster_id,
       bgp_cluster_id_cmd,
       "bgp cluster-id <A.B.C.D|(1-4294967295)>",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ipv4 = 2;
	int ret;
	struct in_addr cluster;

	ret = inet_aton(argv[idx_ipv4]->arg, &cluster);
	if (!ret) {
		vty_out(vty, "%% Malformed bgp cluster identifier\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_cluster_id,
       no_bgp_cluster_id_cmd,
       "no bgp cluster-id [<A.B.C.D|(1-4294967295)>]",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_cluster_id_unset(bgp);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (bgp_confederation_identifier,
       bgp_confederation_identifier_cmd,
       "bgp confederation identifier (1-4294967295)",
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	as_t as;

	as = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_confederation_id_set(bgp, as);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier [(1-4294967295)]",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_confederation_id_unset(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_confederation_peers,
       bgp_confederation_peers_cmd,
       "bgp confederation peers (1-4294967295)...",
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_asn = 3;
	as_t as;
	int i;

	for (i = idx_asn; i < argc; i++) {
		as = strtoul(argv[i]->arg, NULL, 10);

		if (bgp->as == as) {
			vty_out(vty,
				"%% Local member-AS not allowed in confed peer list\n");
			continue;
		}

		bgp_confederation_peers_add(bgp, as);
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_peers,
       no_bgp_confederation_peers_cmd,
       "no bgp confederation peers (1-4294967295)...",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_asn = 4;
	as_t as;
	int i;

	for (i = idx_asn; i < argc; i++) {
		as = strtoul(argv[i]->arg, NULL, 10);

		bgp_confederation_peers_remove(bgp, as);
	}
	return CMD_SUCCESS;
}

/**
 * Central routine for maximum-paths configuration.
 * @peer_type: BGP_PEER_EBGP or BGP_PEER_IBGP
 * @set: 1 for setting values, 0 for removing the max-paths config.
 */
static int bgp_maxpaths_config_vty(struct vty *vty, int peer_type,
				   const char *mpaths, uint16_t options,
				   int set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint16_t maxpaths = 0;
	int ret;
	afi_t afi;
	safi_t safi;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (set) {
		maxpaths = strtol(mpaths, NULL, 10);
		if (maxpaths > multipath_num) {
			vty_out(vty,
				"%% Maxpaths Specified: %d is > than multipath num specified on bgp command line %d",
				maxpaths, multipath_num);
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = bgp_maximum_paths_set(bgp, afi, safi, peer_type, maxpaths,
					    options);
	} else
		ret = bgp_maximum_paths_unset(bgp, afi, safi, peer_type);

	if (ret < 0) {
		vty_out(vty,
			"%% Failed to %sset maximum-paths %s %u for afi %u, safi %u\n",
			(set == 1) ? "" : "un",
			(peer_type == BGP_PEER_EBGP) ? "ebgp" : "ibgp",
			maxpaths, afi, safi);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin,
       bgp_maxmed_admin_cmd,
       "bgp max-med administrative ",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->v_maxmed_admin = 1;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin_medv,
       bgp_maxmed_admin_medv_cmd,
       "bgp max-med administrative (0-4294967295)",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;

	bgp->v_maxmed_admin = 1;
	bgp->maxmed_admin_value = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_admin,
       no_bgp_maxmed_admin_cmd,
       "no bgp max-med administrative [(0-4294967295)]",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_onstartup,
       bgp_maxmed_onstartup_cmd,
       "bgp max-med on-startup (5-86400) [(0-4294967295)]",
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;

	argv_find(argv, argc, "(5-86400)", &idx);
	bgp->v_maxmed_onstartup = strtoul(argv[idx]->arg, NULL, 10);
	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		bgp->maxmed_onstartup_value = strtoul(argv[idx]->arg, NULL, 10);
	else
		bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_cmd,
       "no bgp max-med on-startup [(5-86400) [(0-4294967295)]]",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* Cancel max-med onstartup if its on */
	if (bgp->t_maxmed_onstartup) {
		THREAD_TIMER_OFF(bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}

	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

static int bgp_update_delay_config_vty(struct vty *vty, const char *delay,
				       const char *wait)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint16_t update_delay;
	uint16_t establish_wait;

	update_delay = strtoul(delay, NULL, 10);

	if (!wait) /* update-delay <delay> */
	{
		bgp->v_update_delay = update_delay;
		bgp->v_establish_wait = bgp->v_update_delay;
		return CMD_SUCCESS;
	}

	/* update-delay <delay> <establish-wait> */
	establish_wait = atoi(wait);
	if (update_delay < establish_wait) {
		vty_out(vty,
			"%%Failed: update-delay less than the establish-wait!\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp->v_update_delay = update_delay;
	bgp->v_establish_wait = establish_wait;

	return CMD_SUCCESS;
}

static int bgp_update_delay_deconfig_vty(struct vty *vty)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->v_update_delay = BGP_UPDATE_DELAY_DEF;
	bgp->v_establish_wait = bgp->v_update_delay;

	return CMD_SUCCESS;
}

void bgp_config_write_update_delay(struct vty *vty, struct bgp *bgp)
{
	if (bgp->v_update_delay != BGP_UPDATE_DELAY_DEF) {
		vty_out(vty, " update-delay %d", bgp->v_update_delay);
		if (bgp->v_update_delay != bgp->v_establish_wait)
			vty_out(vty, " %d", bgp->v_establish_wait);
		vty_out(vty, "\n");
	}
}


/* Update-delay configuration */
DEFUN (bgp_update_delay,
       bgp_update_delay_cmd,
       "update-delay (0-3600)",
       "Force initial delay for best-path and updates\n"
       "Seconds\n")
{
	int idx_number = 1;
	return bgp_update_delay_config_vty(vty, argv[idx_number]->arg, NULL);
}

DEFUN (bgp_update_delay_establish_wait,
       bgp_update_delay_establish_wait_cmd,
       "update-delay (0-3600) (1-3600)",
       "Force initial delay for best-path and updates\n"
       "Seconds\n"
       "Seconds\n")
{
	int idx_number = 1;
	int idx_number_2 = 2;
	return bgp_update_delay_config_vty(vty, argv[idx_number]->arg,
					   argv[idx_number_2]->arg);
}

/* Update-delay deconfiguration */
DEFUN (no_bgp_update_delay,
       no_bgp_update_delay_cmd,
       "no update-delay [(0-3600) [(1-3600)]]",
       NO_STR
       "Force initial delay for best-path and updates\n"
       "Seconds\n"
       "Seconds\n")
{
	return bgp_update_delay_deconfig_vty(vty);
}


static int bgp_wpkt_quanta_config_vty(struct vty *vty, uint32_t quanta,
				      bool set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	quanta = set ? quanta : BGP_WRITE_PACKET_MAX;
	atomic_store_explicit(&bgp->wpkt_quanta, quanta, memory_order_relaxed);

	return CMD_SUCCESS;
}

static int bgp_rpkt_quanta_config_vty(struct vty *vty, uint32_t quanta,
				      bool set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	quanta = set ? quanta : BGP_READ_PACKET_MAX;
	atomic_store_explicit(&bgp->rpkt_quanta, quanta, memory_order_relaxed);

	return CMD_SUCCESS;
}

void bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->wpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_WRITE_PACKET_MAX)
		vty_out(vty, " write-quanta %d\n", quanta);
}

void bgp_config_write_rpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->rpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_READ_PACKET_MAX)
		vty_out(vty, " read-quanta %d\n", quanta);
}

/* Packet quanta configuration
 *
 * XXX: The value set here controls the size of a stack buffer in the IO
 * thread. When changing these limits be careful to prevent stack overflow.
 *
 * Furthermore, the maximums used here should correspond to
 * BGP_WRITE_PACKET_MAX and BGP_READ_PACKET_MAX.
 */
DEFPY (bgp_wpkt_quanta,
       bgp_wpkt_quanta_cmd,
       "[no] write-quanta (1-64)$quanta",
       NO_STR
       "How many packets to write to peer socket per run\n"
       "Number of packets\n")
{
	return bgp_wpkt_quanta_config_vty(vty, quanta, !no);
}

DEFPY (bgp_rpkt_quanta,
       bgp_rpkt_quanta_cmd,
       "[no] read-quanta (1-10)$quanta",
       NO_STR
       "How many packets to read from peer socket per I/O cycle\n"
       "Number of packets\n")
{
	return bgp_rpkt_quanta_config_vty(vty, quanta, !no);
}

void bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp)
{
	if (!bgp->heuristic_coalesce)
		vty_out(vty, " coalesce-time %u\n", bgp->coalesce_time);
}


DEFUN (bgp_coalesce_time,
       bgp_coalesce_time_cmd,
       "coalesce-time (0-4294967295)",
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;
	argv_find(argv, argc, "(0-4294967295)", &idx);
	bgp->heuristic_coalesce = false;
	bgp->coalesce_time = strtoul(argv[idx]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_coalesce_time,
       no_bgp_coalesce_time_cmd,
       "no coalesce-time (0-4294967295)",
       NO_STR
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->heuristic_coalesce = true;
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	return CMD_SUCCESS;
}

/* Maximum-paths configuration */
DEFUN (bgp_maxpaths,
       bgp_maxpaths_cmd,
       "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	int idx_number = 1;
	return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP,
				       argv[idx_number]->arg, 0, 1);
}

ALIAS_HIDDEN(bgp_maxpaths, bgp_maxpaths_hidden_cmd,
	     "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
	     "Forward packets over multiple paths\n"
	     "Number of paths\n")

DEFUN (bgp_maxpaths_ibgp,
       bgp_maxpaths_ibgp_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n")
{
	int idx_number = 2;
	return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP,
				       argv[idx_number]->arg, 0, 1);
}

ALIAS_HIDDEN(bgp_maxpaths_ibgp, bgp_maxpaths_ibgp_hidden_cmd,
	     "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n")

DEFUN (bgp_maxpaths_ibgp_cluster,
       bgp_maxpaths_ibgp_cluster_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM) " equal-cluster-length",
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")
{
	int idx_number = 2;
	return bgp_maxpaths_config_vty(
		vty, BGP_PEER_IBGP, argv[idx_number]->arg,
		BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN, 1);
}

ALIAS_HIDDEN(bgp_maxpaths_ibgp_cluster, bgp_maxpaths_ibgp_cluster_hidden_cmd,
	     "maximum-paths ibgp " CMD_RANGE_STR(
		     1, MULTIPATH_NUM) " equal-cluster-length",
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n"
	     "Match the cluster length\n")

DEFUN (no_bgp_maxpaths,
       no_bgp_maxpaths_cmd,
       "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
       NO_STR
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP, NULL, 0, 0);
}

ALIAS_HIDDEN(no_bgp_maxpaths, no_bgp_maxpaths_hidden_cmd,
	     "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]", NO_STR
	     "Forward packets over multiple paths\n"
	     "Number of paths\n")

DEFUN (no_bgp_maxpaths_ibgp,
       no_bgp_maxpaths_ibgp_cmd,
       "no maximum-paths ibgp [" CMD_RANGE_STR(1, MULTIPATH_NUM) " [equal-cluster-length]]",
       NO_STR
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")
{
	return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP, NULL, 0, 0);
}

ALIAS_HIDDEN(no_bgp_maxpaths_ibgp, no_bgp_maxpaths_ibgp_hidden_cmd,
	     "no maximum-paths ibgp [" CMD_RANGE_STR(
		     1, MULTIPATH_NUM) " [equal-cluster-length]]",
	     NO_STR
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n"
	     "Match the cluster length\n")

void bgp_config_write_maxpaths(struct vty *vty, struct bgp *bgp, afi_t afi,
			       safi_t safi)
{
	if (bgp->maxpaths[afi][safi].maxpaths_ebgp != MULTIPATH_NUM) {
		vty_out(vty, "  maximum-paths %d\n",
			bgp->maxpaths[afi][safi].maxpaths_ebgp);
	}

	if (bgp->maxpaths[afi][safi].maxpaths_ibgp != MULTIPATH_NUM) {
		vty_out(vty, "  maximum-paths ibgp %d",
			bgp->maxpaths[afi][safi].maxpaths_ibgp);
		if (CHECK_FLAG(bgp->maxpaths[afi][safi].ibgp_flags,
			       BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))
			vty_out(vty, " equal-cluster-length");
		vty_out(vty, "\n");
	}
}

/* BGP timers.  */

DEFUN (bgp_timers,
       bgp_timers_cmd,
       "timers bgp (0-65535) (0-65535)",
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 2;
	int idx_number_2 = 3;
	unsigned long keepalive = 0;
	unsigned long holdtime = 0;

	keepalive = strtoul(argv[idx_number]->arg, NULL, 10);
	holdtime = strtoul(argv[idx_number_2]->arg, NULL, 10);

	/* Holdtime value check. */
	if (holdtime < 3 && holdtime != 0) {
		vty_out(vty,
			"%% hold time value must be either 0 or greater than 3\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_timers_set(bgp, keepalive, holdtime);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_timers,
       no_bgp_timers_cmd,
       "no timers bgp [(0-65535) (0-65535)]",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_timers_unset(bgp);

	return CMD_SUCCESS;
}


DEFUN (bgp_client_to_client_reflection,
       bgp_client_to_client_reflection_cmd,
       "bgp client-to-client reflection",
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out(vty, bgp->name);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

/* "bgp always-compare-med" configuration. */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}


DEFUN(bgp_ebgp_requires_policy, bgp_ebgp_requires_policy_cmd,
      "bgp ebgp-requires-policy",
      "BGP specific commands\n"
      "Require in and out policy for eBGP peers (RFC8212)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->ebgp_requires_policy = DEFAULT_EBGP_POLICY_ENABLED;
	return CMD_SUCCESS;
}

DEFUN(no_bgp_ebgp_requires_policy, no_bgp_ebgp_requires_policy_cmd,
      "no bgp ebgp-requires-policy",
      NO_STR
      "BGP specific commands\n"
      "Require in and out policy for eBGP peers (RFC8212)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->ebgp_requires_policy = DEFAULT_EBGP_POLICY_DISABLED;
	return CMD_SUCCESS;
}


/* "bgp deterministic-med" configuration. */
DEFUN (bgp_deterministic_med,
       bgp_deterministic_med_cmd,
       "bgp deterministic-med",
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!bgp_flag_check(bgp, BGP_FLAG_DETERMINISTIC_MED)) {
		bgp_flag_set(bgp, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int bestpath_per_as_used;
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct listnode *node, *nnode;

	if (bgp_flag_check(bgp, BGP_FLAG_DETERMINISTIC_MED)) {
		bestpath_per_as_used = 0;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi)
				if (bgp_addpath_dmed_required(
					peer->addpath_type[afi][safi])) {
					bestpath_per_as_used = 1;
					break;
				}

			if (bestpath_per_as_used)
				break;
		}

		if (bestpath_per_as_used) {
			vty_out(vty,
				"bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use\n");
			return CMD_WARNING_CONFIG_FAILED;
		} else {
			bgp_flag_unset(bgp, BGP_FLAG_DETERMINISTIC_MED);
			bgp_recalculate_all_bestpaths(bgp);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_GRACEFUL_RESTART);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart,
       no_bgp_graceful_restart_cmd,
       "no bgp graceful-restart",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_GRACEFUL_RESTART);
	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_stalepath_time,
       bgp_graceful_restart_stalepath_time_cmd,
       "bgp graceful-restart stalepath-time (1-4095)",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t stalepath;

	stalepath = strtoul(argv[idx_number]->arg, NULL, 10);
	bgp->stalepath_time = stalepath;
	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_restart_time,
       bgp_graceful_restart_restart_time_cmd,
       "bgp graceful-restart restart-time (1-4095)",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the time to wait to delete stale routes before a BGP open message is received\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t restart;

	restart = strtoul(argv[idx_number]->arg, NULL, 10);
	bgp->restart_time = restart;
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_cmd,
       "no bgp graceful-restart stalepath-time [(1-4095)]",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_restart_time,
       no_bgp_graceful_restart_restart_time_cmd,
       "no bgp graceful-restart restart-time [(1-4095)]",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the time to wait to delete stale routes before a BGP open message is received\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->restart_time = BGP_DEFAULT_RESTART_TIME;
	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_preserve_fw,
       bgp_graceful_restart_preserve_fw_cmd,
       "bgp graceful-restart preserve-fw-state",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_GR_PRESERVE_FWD);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_preserve_fw,
       no_bgp_graceful_restart_preserve_fw_cmd,
       "no bgp graceful-restart preserve-fw-state",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Unsets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_GR_PRESERVE_FWD);
	return CMD_SUCCESS;
}

/* "bgp graceful-shutdown" configuration */
DEFUN (bgp_graceful_shutdown,
       bgp_graceful_shutdown_cmd,
       "bgp graceful-shutdown",
       BGP_STR
       "Graceful shutdown parameters\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!bgp_flag_check(bgp, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		bgp_flag_set(bgp, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_static_redo_import_check(bgp);
		bgp_redistribute_redo(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
		bgp_clear_star_soft_in(vty, bgp->name);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_shutdown,
       no_bgp_graceful_shutdown_cmd,
       "no bgp graceful-shutdown",
       NO_STR
       BGP_STR
       "Graceful shutdown parameters\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (bgp_flag_check(bgp, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		bgp_flag_unset(bgp, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_static_redo_import_check(bgp);
		bgp_redistribute_redo(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
		bgp_clear_star_soft_in(vty, bgp->name);
	}

	return CMD_SUCCESS;
}

/* "bgp fast-external-failover" configuration. */
DEFUN (bgp_fast_external_failover,
       bgp_fast_external_failover_cmd,
       "bgp fast-external-failover",
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_fast_external_failover,
       no_bgp_fast_external_failover_cmd,
       "no bgp fast-external-failover",
       NO_STR
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);

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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath as-path multipath-relax" configuration.  */
DEFUN (bgp_bestpath_aspath_multipath_relax,
       bgp_bestpath_aspath_multipath_relax_cmd,
       "bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;
	bgp_flag_set(bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX);

	/* no-as-set is now the default behavior so we can silently
	 * ignore it */
	if (argv_find(argv, argc, "as-set", &idx))
		bgp_flag_set(bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	else
		bgp_flag_unset(bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_multipath_relax,
       no_bgp_bestpath_aspath_multipath_relax_cmd,
       "no bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	bgp_flag_unset(bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp log-neighbor-changes" configuration.  */
DEFUN (bgp_log_neighbor_changes,
       bgp_log_neighbor_changes_cmd,
       "bgp log-neighbor-changes",
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_log_neighbor_changes,
       no_bgp_log_neighbor_changes_cmd,
       "no bgp log-neighbor-changes",
       NO_STR
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return CMD_SUCCESS;
}

/* "bgp bestpath med" configuration. */
DEFUN (bgp_bestpath_med,
       bgp_bestpath_med_cmd,
       "bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;
	if (argv_find(argv, argc, "confed", &idx))
		bgp_flag_set(bgp, BGP_FLAG_MED_CONFED);
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		bgp_flag_set(bgp, BGP_FLAG_MED_MISSING_AS_WORST);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_med,
       no_bgp_bestpath_med_cmd,
       "no bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;
	if (argv_find(argv, argc, "confed", &idx))
		bgp_flag_unset(bgp, BGP_FLAG_MED_CONFED);
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		bgp_flag_unset(bgp, BGP_FLAG_MED_MISSING_AS_WORST);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "no bgp default ipv4-unicast". */
DEFUN (no_bgp_default_ipv4_unicast,
       no_bgp_default_ipv4_unicast_cmd,
       "no bgp default ipv4-unicast",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_NO_DEFAULT_IPV4);
	return CMD_SUCCESS;
}

DEFUN (bgp_default_ipv4_unicast,
       bgp_default_ipv4_unicast_cmd,
       "bgp default ipv4-unicast",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_NO_DEFAULT_IPV4);
	return CMD_SUCCESS;
}

/* Display hostname in certain command outputs */
DEFUN (bgp_default_show_hostname,
       bgp_default_show_hostname_cmd,
       "bgp default show-hostname",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Show hostname in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_SHOW_HOSTNAME);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_show_hostname,
       no_bgp_default_show_hostname_cmd,
       "no bgp default show-hostname",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Show hostname in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_SHOW_HOSTNAME);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	if (!bgp_flag_check(bgp, BGP_FLAG_IMPORT_CHECK)) {
		bgp_flag_set(bgp, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
	}

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(bgp_network_import_check, bgp_network_import_check_exact_cmd,
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	if (bgp_flag_check(bgp, BGP_FLAG_IMPORT_CHECK)) {
		bgp_flag_unset(bgp, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_default_local_preference,
       bgp_default_local_preference_cmd,
       "bgp default local-preference (0-4294967295)",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t local_pref;

	local_pref = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_default_local_preference_set(bgp, local_pref);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_local_preference,
       no_bgp_default_local_preference_cmd,
       "no bgp default local-preference [(0-4294967295)]",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_default_local_preference_unset(bgp);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}


DEFUN (bgp_default_subgroup_pkt_queue_max,
       bgp_default_subgroup_pkt_queue_max_cmd,
       "bgp default subgroup-pkt-queue-max (20-100)",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t max_size;

	max_size = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_default_subgroup_pkt_queue_max_set(bgp, max_size);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_subgroup_pkt_queue_max,
       no_bgp_default_subgroup_pkt_queue_max_cmd,
       "no bgp default subgroup-pkt-queue-max [(20-100)]",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_default_subgroup_pkt_queue_max_unset(bgp);
	return CMD_SUCCESS;
}


DEFUN (bgp_rr_allow_outbound_policy,
       bgp_rr_allow_outbound_policy_cmd,
       "bgp route-reflector allow-outbound-policy",
       "BGP specific commands\n"
       "Allow modifications made by out route-map\n"
       "on ibgp neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
		bgp_flag_set(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
		bgp_flag_unset(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_listen_limit,
       bgp_listen_limit_cmd,
       "bgp listen limit (1-5000)",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	int listen_limit;

	listen_limit = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_listen_limit_set(bgp, listen_limit);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_listen_limit,
       no_bgp_listen_limit_cmd,
       "no bgp listen limit [(1-5000)]",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "unset maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value to default\n"
       "Configure Dynamic Neighbors listen limit value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_listen_limit_unset(bgp);
	return CMD_SUCCESS;
}


/*
 * Check if this listen range is already configured. Check for exact
 * match or overlap based on input.
 */
static struct peer_group *listen_range_exists(struct bgp *bgp,
					      struct prefix *range, int exact)
{
	struct listnode *node, *nnode;
	struct listnode *node1, *nnode1;
	struct peer_group *group;
	struct prefix *lr;
	afi_t afi;
	int match;

	afi = family2afi(range->family);
	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (ALL_LIST_ELEMENTS(group->listen_range[afi], node1, nnode1,
				       lr)) {
			if (exact)
				match = prefix_same(range, lr);
			else
				match = (prefix_match(range, lr)
					 || prefix_match(lr, range));
			if (match)
				return group;
		}
	}

	return NULL;
}

DEFUN (bgp_listen_range,
       bgp_listen_range_cmd,
       "bgp listen range <A.B.C.D/M|X:X::X:X/M> peer-group PGNAME",
       "BGP specific commands\n"
       "Configure BGP dynamic neighbors listen range\n"
       "Configure BGP dynamic neighbors listen range\n"
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix range;
	struct peer_group *group, *existing_group;
	afi_t afi;
	int ret;
	int idx = 0;

	argv_find(argv, argc, "A.B.C.D/M", &idx);
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	char *prefix = argv[idx]->arg;
	argv_find(argv, argc, "PGNAME", &idx);
	char *peergroup = argv[idx]->arg;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(prefix, &range);
	if (!ret) {
		vty_out(vty, "%% Malformed listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = family2afi(range.family);

	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&range.u.prefix6)) {
		vty_out(vty,
			"%% Malformed listen range (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&range);

	/* Check if same listen range is already configured. */
	existing_group = listen_range_exists(bgp, &range, 1);
	if (existing_group) {
		if (strcmp(existing_group->name, peergroup) == 0)
			return CMD_SUCCESS;
		else {
			vty_out(vty,
				"%% Same listen range is attached to peer-group %s\n",
				existing_group->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Check if an overlapping listen range exists. */
	if (listen_range_exists(bgp, &range, 0)) {
		vty_out(vty,
			"%% Listen range overlaps with existing listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	group = peer_group_lookup(bgp, peergroup);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_listen_range_add(group, &range);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_listen_range,
       no_bgp_listen_range_cmd,
       "no bgp listen range <A.B.C.D/M|X:X::X:X/M> peer-group PGNAME",
       NO_STR
       "BGP specific commands\n"
       "Unconfigure BGP dynamic neighbors listen range\n"
       "Unconfigure BGP dynamic neighbors listen range\n"
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix range;
	struct peer_group *group;
	afi_t afi;
	int ret;
	int idx = 0;

	argv_find(argv, argc, "A.B.C.D/M", &idx);
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	char *prefix = argv[idx]->arg;
	argv_find(argv, argc, "WORD", &idx);
	char *peergroup = argv[idx]->arg;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(prefix, &range);
	if (!ret) {
		vty_out(vty, "%% Malformed listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = family2afi(range.family);

	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&range.u.prefix6)) {
		vty_out(vty,
			"%% Malformed listen range (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&range);

	group = peer_group_lookup(bgp, peergroup);
	if (!group) {
		vty_out(vty, "%% Peer-group does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_listen_range_del(group, &range);
	return bgp_vty_return(vty, ret);
}

void bgp_config_write_listen(struct vty *vty, struct bgp *bgp)
{
	struct peer_group *group;
	struct listnode *node, *nnode, *rnode, *nrnode;
	struct prefix *range;
	afi_t afi;
	char buf[PREFIX2STR_BUFFER];

	if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
		vty_out(vty, " bgp listen limit %d\n",
			bgp->dynamic_neighbors_limit);

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (ALL_LIST_ELEMENTS(group->listen_range[afi], rnode,
					       nrnode, range)) {
				prefix2str(range, buf, sizeof(buf));
				vty_out(vty,
					" bgp listen range %s peer-group %s\n",
					buf, group->name);
			}
		}
	}
}


DEFUN (bgp_disable_connected_route_check,
       bgp_disable_connected_route_check_cmd,
       "bgp disable-ebgp-connected-route-check",
       "BGP specific commands\n"
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_set(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_disable_connected_route_check,
       no_bgp_disable_connected_route_check_cmd,
       "no bgp disable-ebgp-connected-route-check",
       NO_STR
       "BGP specific commands\n"
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_flag_unset(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}


static int peer_remote_as_vty(struct vty *vty, const char *peer_str,
			      const char *as_str, afi_t afi, safi_t safi)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	as_t as;
	int as_type = AS_SPECIFIED;
	union sockunion su;

	if (as_str[0] == 'i') {
		as = 0;
		as_type = AS_INTERNAL;
	} else if (as_str[0] == 'e') {
		as = 0;
		as_type = AS_EXTERNAL;
	} else {
		/* Get AS number.  */
		as = strtoul(as_str, NULL, 10);
	}

	/* If peer is peer group or interface peer, call proper function. */
	ret = str2sockunion(peer_str, &su);
	if (ret < 0) {
		struct peer *peer;

		/* Check if existing interface peer */
		peer = peer_lookup_by_conf_if(bgp, peer_str);

		ret = peer_remote_as(bgp, NULL, peer_str, &as, as_type, afi,
				     safi);

		/* if not interface peer, check peer-group settings */
		if (ret < 0 && !peer) {
			ret = peer_group_remote_as(bgp, peer_str, &as, as_type);
			if (ret < 0) {
				vty_out(vty,
					"%% Create the peer-group or interface first\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			return CMD_SUCCESS;
		}
	} else {
		if (peer_address_self_check(bgp, &su)) {
			vty_out(vty,
				"%% Can not configure the local system as neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = peer_remote_as(bgp, &su, NULL, &as, as_type, afi, safi);
	}

	/* This peer belongs to peer group.  */
	switch (ret) {
	case BGP_ERR_PEER_GROUP_MEMBER:
		vty_out(vty,
			"%% Peer-group member cannot override remote-as of peer-group\n");
		return CMD_WARNING_CONFIG_FAILED;
	case BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
		vty_out(vty,
			"%% Peer-group members must be all internal or all external\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return bgp_vty_return(vty, ret);
}

DEFUN (bgp_default_shutdown,
       bgp_default_shutdown_cmd,
       "[no] bgp default shutdown",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Apply administrative shutdown to newly configured peers\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->autoshutdown = !strmatch(argv[0]->text, "no");
	return CMD_SUCCESS;
}

DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remote-as <(1-4294967295)|internal|external>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	int idx_peer = 1;
	int idx_remote_as = 3;
	return peer_remote_as_vty(vty, argv[idx_peer]->arg,
				  argv[idx_remote_as]->arg, AFI_IP,
				  SAFI_UNICAST);
}

static int peer_conf_interface_get(struct vty *vty, const char *conf_if,
				   afi_t afi, safi_t safi, int v6only,
				   const char *peer_group_name,
				   const char *as_str)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	as_t as = 0;
	int as_type = AS_UNSPECIFIED;
	struct peer *peer;
	struct peer_group *group;
	int ret = 0;
	union sockunion su;

	group = peer_group_lookup(bgp, conf_if);

	if (group) {
		vty_out(vty, "%% Name conflict with peer-group \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (as_str) {
		if (as_str[0] == 'i') {
			as_type = AS_INTERNAL;
		} else if (as_str[0] == 'e') {
			as_type = AS_EXTERNAL;
		} else {
			/* Get AS number.  */
			as = strtoul(as_str, NULL, 10);
			as_type = AS_SPECIFIED;
		}
	}

	peer = peer_lookup_by_conf_if(bgp, conf_if);
	if (peer) {
		if (as_str)
			ret = peer_remote_as(bgp, NULL, conf_if, &as, as_type,
					     afi, safi);
	} else {
		if (bgp_flag_check(bgp, BGP_FLAG_NO_DEFAULT_IPV4)
		    && afi == AFI_IP && safi == SAFI_UNICAST)
			peer = peer_create(NULL, conf_if, bgp, bgp->as, as,
					   as_type, 0, 0, NULL);
		else
			peer = peer_create(NULL, conf_if, bgp, bgp->as, as,
					   as_type, afi, safi, NULL);

		if (!peer) {
			vty_out(vty, "%% BGP failed to create peer\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (v6only)
			peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);

		/* Request zebra to initiate IPv6 RAs on this interface. We do
		 * this
		 * any unnumbered peer in order to not worry about run-time
		 * transitions
		 * (e.g., peering is initially IPv4, but the IPv4 /30 or /31
		 * address
		 * gets deleted later etc.)
		 */
		if (peer->ifp)
			bgp_zebra_initiate_radv(bgp, peer);
	}

	if ((v6only && !CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
	    || (!v6only && CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))) {
		if (v6only)
			peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);
		else
			peer_flag_unset(peer, PEER_FLAG_IFPEER_V6ONLY);

		/* v6only flag changed. Reset bgp seesion */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_V6ONLY_CHANGE;
			bgp_notify_send(peer, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			bgp_session_reset(peer);
	}

	if (!CHECK_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE)) {
		SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE);
	}

	if (peer_group_name) {
		group = peer_group_lookup(bgp, peer_group_name);
		if (!group) {
			vty_out(vty, "%% Configure the peer-group first\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = peer_group_bind(bgp, &su, peer, group, &as);
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_interface_config,
       neighbor_interface_config_cmd,
       "neighbor WORD interface [peer-group PGNAME]",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	int idx_word = 1;
	int idx_peer_group_word = 4;

	if (argc > idx_peer_group_word)
		return peer_conf_interface_get(
			vty, argv[idx_word]->arg, AFI_IP, SAFI_UNICAST, 0,
			argv[idx_peer_group_word]->arg, NULL);
	else
		return peer_conf_interface_get(vty, argv[idx_word]->arg, AFI_IP,
					       SAFI_UNICAST, 0, NULL, NULL);
}

DEFUN (neighbor_interface_config_v6only,
       neighbor_interface_config_v6only_cmd,
       "neighbor WORD interface v6only [peer-group PGNAME]",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	int idx_word = 1;
	int idx_peer_group_word = 5;

	if (argc > idx_peer_group_word)
		return peer_conf_interface_get(
			vty, argv[idx_word]->arg, AFI_IP, SAFI_UNICAST, 1,
			argv[idx_peer_group_word]->arg, NULL);

	return peer_conf_interface_get(vty, argv[idx_word]->arg, AFI_IP,
				       SAFI_UNICAST, 1, NULL, NULL);
}


DEFUN (neighbor_interface_config_remote_as,
       neighbor_interface_config_remote_as_cmd,
       "neighbor WORD interface remote-as <(1-4294967295)|internal|external>",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	int idx_word = 1;
	int idx_remote_as = 4;
	return peer_conf_interface_get(vty, argv[idx_word]->arg, AFI_IP,
				       SAFI_UNICAST, 0, NULL,
				       argv[idx_remote_as]->arg);
}

DEFUN (neighbor_interface_v6only_config_remote_as,
       neighbor_interface_v6only_config_remote_as_cmd,
       "neighbor WORD interface v6only remote-as <(1-4294967295)|internal|external>",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP with v6 link-local only\n"
       "Enable BGP on interface\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	int idx_word = 1;
	int idx_remote_as = 5;
	return peer_conf_interface_get(vty, argv[idx_word]->arg, AFI_IP,
				       SAFI_UNICAST, 1, NULL,
				       argv[idx_remote_as]->arg);
}

DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Configure peer-group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 1;
	struct peer *peer;
	struct peer_group *group;

	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		vty_out(vty, "%% Name conflict with interface: \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	group = peer_group_get(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% BGP failed to find or create peer-group\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor <WORD|<A.B.C.D|X:X::X:X> [remote-as <(1-4294967295)|internal|external>]>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 2;
	int ret;
	union sockunion su;
	struct peer_group *group;
	struct peer *peer;
	struct peer *other;

	ret = str2sockunion(argv[idx_peer]->arg, &su);
	if (ret < 0) {
		/* look up for neighbor by interface name config. */
		peer = peer_lookup_by_conf_if(bgp, argv[idx_peer]->arg);
		if (peer) {
			/* Request zebra to terminate IPv6 RAs on this
			 * interface. */
			if (peer->ifp)
				bgp_zebra_terminate_radv(peer->bgp, peer);
			peer_notify_unconfig(peer);
			peer_delete(peer);
			return CMD_SUCCESS;
		}

		group = peer_group_lookup(bgp, argv[idx_peer]->arg);
		if (group) {
			peer_group_notify_unconfig(group);
			peer_group_delete(group);
		} else {
			vty_out(vty, "%% Create the peer-group first\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		peer = peer_lookup(bgp, &su);
		if (peer) {
			if (peer_dynamic_neighbor(peer)) {
				vty_out(vty,
					"%% Operation not allowed on a dynamic neighbor\n");
				return CMD_WARNING_CONFIG_FAILED;
			}

			other = peer->doppelganger;
			peer_notify_unconfig(peer);
			peer_delete(peer);
			if (other && other->status != Deleted) {
				peer_notify_unconfig(other);
				peer_delete(other);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_neighbor_interface_config,
       no_neighbor_interface_config_cmd,
       "no neighbor WORD interface [v6only] [peer-group PGNAME] [remote-as <(1-4294967295)|internal|external>]",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "Peer-group name\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer *peer;

	/* look up for neighbor by interface name config. */
	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		/* Request zebra to terminate IPv6 RAs on this interface. */
		if (peer->ifp)
			bgp_zebra_terminate_radv(peer->bgp, peer);
		peer_notify_unconfig(peer);
		peer_delete(peer);
	} else {
		vty_out(vty, "%% Create the bgp interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_neighbor_peer_group,
       no_neighbor_peer_group_cmd,
       "no neighbor WORD peer-group",
       NO_STR
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer_group *group;

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (group) {
		peer_group_notify_unconfig(group);
		peer_group_delete(group);
	} else {
		vty_out(vty, "%% Create the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_neighbor_interface_peer_group_remote_as,
       no_neighbor_interface_peer_group_remote_as_cmd,
       "no neighbor WORD remote-as <(1-4294967295)|internal|external>",
       NO_STR
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer_group *group;
	struct peer *peer;

	/* look up for neighbor by interface name config. */
	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		peer_as_change(peer, 0, AS_UNSPECIFIED);
		return CMD_SUCCESS;
	}

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (group)
		peer_group_remote_as_delete(group);
	else {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (neighbor_local_as,
       neighbor_local_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as (1-4294967295)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	as = strtoul(argv[idx_number]->arg, NULL, 10);
	ret = peer_local_as_set(peer, as, 0, 0);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_local_as_no_prepend,
       neighbor_local_as_no_prepend_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as (1-4294967295) no-prepend",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	as = strtoul(argv[idx_number]->arg, NULL, 10);
	ret = peer_local_as_set(peer, as, 1, 0);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_local_as_no_prepend_replace_as,
       neighbor_local_as_no_prepend_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as (1-4294967295) no-prepend replace-as",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	as = strtoul(argv[idx_number]->arg, NULL, 10);
	ret = peer_local_as_set(peer, as, 1, 1);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_local_as,
       no_neighbor_local_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> local-as [(1-4294967295) [no-prepend [replace-as]]]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_local_as_unset(peer);
	return bgp_vty_return(vty, ret);
}


DEFUN (neighbor_solo,
       neighbor_solo_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> solo",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
	int idx_peer = 1;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = update_group_adjust_soloness(peer, 1);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_solo,
       no_neighbor_solo_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> solo",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = update_group_adjust_soloness(peer, 0);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_password,
       neighbor_password_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> password LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
	int idx_peer = 1;
	int idx_line = 3;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_password_set(peer, argv[idx_line]->arg);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_password,
       no_neighbor_password_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> password [LINE]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_password_unset(peer);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
	int idx_peer = 1;
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_activate(peer, bgp_node_afi(vty), bgp_node_safi(vty));
	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(neighbor_activate, neighbor_activate_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> activate",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Enable the Address Family for this Neighbor\n")

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
	int idx_peer = 2;
	int ret;
	struct peer *peer;

	/* Lookup peer. */
	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_deactivate(peer, bgp_node_afi(vty), bgp_node_safi(vty));
	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(no_neighbor_activate, no_neighbor_activate_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> activate",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Enable the Address Family for this Neighbor\n")

DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 1;
	int idx_word = 3;
	int ret;
	as_t as;
	union sockunion su;
	struct peer *peer;
	struct peer_group *group;

	ret = str2sockunion(argv[idx_peer]->arg, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, argv[idx_peer]->arg);
		if (!peer) {
			vty_out(vty, "%% Malformed address or name: %s\n",
				argv[idx_peer]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		if (peer_address_self_check(bgp, &su)) {
			vty_out(vty,
				"%% Can not configure the local system as neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Disallow for dynamic neighbor. */
		peer = peer_lookup(bgp, &su);
		if (peer && peer_dynamic_neighbor(peer)) {
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_bind(bgp, &su, peer, group, &as);

	if (ret == BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT) {
		vty_out(vty,
			"%% Peer with AS %u cannot be in this peer-group, members must be all internal or all external\n",
			as);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(neighbor_set_peer_group, neighbor_set_peer_group_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Member of the peer-group\n"
	     "Peer-group name\n")

DEFUN (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 2;
	int idx_word = 4;
	int ret;
	struct peer *peer;
	struct peer_group *group;

	peer = peer_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	peer_notify_unconfig(peer);
	ret = peer_delete(peer);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(no_neighbor_set_peer_group, no_neighbor_set_peer_group_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Member of the peer-group\n"
	     "Peer-group name\n")

static int peer_flag_modify_vty(struct vty *vty, const char *ip_str,
				uint32_t flag, int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * If 'neighbor <interface>', then this is for directly connected peers,
	 * we should not accept disable-connected-check.
	 */
	if (peer->conf_if && (flag == PEER_FLAG_DISABLE_CONNECTED_CHECK)) {
		vty_out(vty,
			"%s is directly connected peer, cannot accept disable-"
			"connected-check\n",
			ip_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!set && flag == PEER_FLAG_SHUTDOWN)
		peer_tx_shutdown_message_unset(peer);

	if (set)
		ret = peer_flag_set(peer, flag);
	else
		ret = peer_flag_unset(peer, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_flag_set_vty(struct vty *vty, const char *ip_str, uint32_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 1);
}

static int peer_flag_unset_vty(struct vty *vty, const char *ip_str,
			       uint32_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 0);
}

/* neighbor passive. */
DEFUN (neighbor_passive,
       neighbor_passive_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg, PEER_FLAG_PASSIVE);
}

DEFUN (no_neighbor_passive,
       no_neighbor_passive_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> passive",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg, PEER_FLAG_PASSIVE);
}

/* neighbor shutdown. */
DEFUN (neighbor_shutdown_msg,
       neighbor_shutdown_msg_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> shutdown message MSG...",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n"
       "Add a shutdown message (draft-ietf-idr-shutdown-06)\n"
       "Shutdown message\n")
{
	int idx_peer = 1;

	if (argc >= 5) {
		struct peer *peer =
			peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
		char *message;

		if (!peer)
			return CMD_WARNING_CONFIG_FAILED;
		message = argv_concat(argv, argc, 4);
		peer_tx_shutdown_message_set(peer, message);
		XFREE(MTYPE_TMP, message);
	}

	return peer_flag_set_vty(vty, argv[idx_peer]->arg, PEER_FLAG_SHUTDOWN);
}

ALIAS(neighbor_shutdown_msg, neighbor_shutdown_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> shutdown",
      NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n")

DEFUN (no_neighbor_shutdown_msg,
       no_neighbor_shutdown_msg_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> shutdown message MSG...",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n"
       "Remove a shutdown message (draft-ietf-idr-shutdown-06)\n"
       "Shutdown message\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_SHUTDOWN);
}

ALIAS(no_neighbor_shutdown_msg, no_neighbor_shutdown_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> shutdown",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n")

/* neighbor capability dynamic. */
DEFUN (neighbor_capability_dynamic,
       neighbor_capability_dynamic_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability dynamic",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DYNAMIC_CAPABILITY);
}

DEFUN (no_neighbor_capability_dynamic,
       no_neighbor_capability_dynamic_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability dynamic",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DYNAMIC_CAPABILITY);
}

/* neighbor dont-capability-negotiate */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DONT_CAPABILITY);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DONT_CAPABILITY);
}

/* neighbor capability extended next hop encoding */
DEFUN (neighbor_capability_enhe,
       neighbor_capability_enhe_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability extended-nexthop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_CAPABILITY_ENHE);
}

DEFUN (no_neighbor_capability_enhe,
       no_neighbor_capability_enhe_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability extended-nexthop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_CAPABILITY_ENHE);
}

static int peer_af_flag_modify_vty(struct vty *vty, const char *peer_str,
				   afi_t afi, safi_t safi, uint32_t flag,
				   int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (set)
		ret = peer_af_flag_set(peer, afi, safi, flag);
	else
		ret = peer_af_flag_unset(peer, afi, safi, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_af_flag_set_vty(struct vty *vty, const char *peer_str,
				afi_t afi, safi_t safi, uint32_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 1);
}

static int peer_af_flag_unset_vty(struct vty *vty, const char *peer_str,
				  afi_t afi, safi_t safi, uint32_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 0);
}

/* neighbor capability orf prefix-list. */
DEFUN (neighbor_capability_orf_prefix,
       neighbor_capability_orf_prefix_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
	int idx_peer = 1;
	int idx_send_recv = 5;
	uint16_t flag = 0;

	if (strmatch(argv[idx_send_recv]->text, "send"))
		flag = PEER_FLAG_ORF_PREFIX_SM;
	else if (strmatch(argv[idx_send_recv]->text, "receive"))
		flag = PEER_FLAG_ORF_PREFIX_RM;
	else if (strmatch(argv[idx_send_recv]->text, "both"))
		flag = PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM;
	else {
		vty_out(vty, "%% BGP invalid orf prefix-list option\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), flag);
}

ALIAS_HIDDEN(
	neighbor_capability_orf_prefix,
	neighbor_capability_orf_prefix_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n")

DEFUN (no_neighbor_capability_orf_prefix,
       no_neighbor_capability_orf_prefix_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
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
	int idx_peer = 2;
	int idx_send_recv = 6;
	uint16_t flag = 0;

	if (strmatch(argv[idx_send_recv]->text, "send"))
		flag = PEER_FLAG_ORF_PREFIX_SM;
	else if (strmatch(argv[idx_send_recv]->text, "receive"))
		flag = PEER_FLAG_ORF_PREFIX_RM;
	else if (strmatch(argv[idx_send_recv]->text, "both"))
		flag = PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM;
	else {
		vty_out(vty, "%% BGP invalid orf prefix-list option\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      flag);
}

ALIAS_HIDDEN(
	no_neighbor_capability_orf_prefix,
	no_neighbor_capability_orf_prefix_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n")

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), PEER_FLAG_NEXTHOP_SELF);
}

ALIAS_HIDDEN(neighbor_nexthop_self, neighbor_nexthop_self_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n")

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self_force,
       neighbor_nexthop_self_force_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_FORCE_NEXTHOP_SELF);
}

ALIAS_HIDDEN(neighbor_nexthop_self_force,
	     neighbor_nexthop_self_force_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

ALIAS_HIDDEN(neighbor_nexthop_self_force,
	     neighbor_nexthop_self_all_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self all",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_NEXTHOP_SELF);
}

ALIAS_HIDDEN(no_neighbor_nexthop_self, no_neighbor_nexthop_self_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n")

DEFUN (no_neighbor_nexthop_self_force,
       no_neighbor_nexthop_self_force_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

ALIAS_HIDDEN(no_neighbor_nexthop_self_force,
	     no_neighbor_nexthop_self_force_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

ALIAS_HIDDEN(no_neighbor_nexthop_self_force,
	     no_neighbor_nexthop_self_all_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self all",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

/* neighbor as-override */
DEFUN (neighbor_as_override,
       neighbor_as_override_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), PEER_FLAG_AS_OVERRIDE);
}

ALIAS_HIDDEN(neighbor_as_override, neighbor_as_override_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Override ASNs in outbound updates if aspath equals remote-as\n")

DEFUN (no_neighbor_as_override,
       no_neighbor_as_override_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_AS_OVERRIDE);
}

ALIAS_HIDDEN(no_neighbor_as_override, no_neighbor_as_override_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Override ASNs in outbound updates if aspath equals remote-as\n")

/* neighbor remove-private-AS. */
DEFUN (neighbor_remove_private_as,
       neighbor_remove_private_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS);
}

ALIAS_HIDDEN(neighbor_remove_private_as, neighbor_remove_private_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n")

DEFUN (neighbor_remove_private_as_all,
       neighbor_remove_private_as_all_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

ALIAS_HIDDEN(neighbor_remove_private_as_all,
	     neighbor_remove_private_as_all_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Apply to all AS numbers")

DEFUN (neighbor_remove_private_as_replace_as,
       neighbor_remove_private_as_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

ALIAS_HIDDEN(neighbor_remove_private_as_replace_as,
	     neighbor_remove_private_as_replace_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Replace private ASNs with our ASN in outbound updates\n")

DEFUN (neighbor_remove_private_as_all_replace_as,
       neighbor_remove_private_as_all_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

ALIAS_HIDDEN(
	neighbor_remove_private_as_all_replace_as,
	neighbor_remove_private_as_all_replace_as_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n")

DEFUN (no_neighbor_remove_private_as,
       no_neighbor_remove_private_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as,
	     no_neighbor_remove_private_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n")

DEFUN (no_neighbor_remove_private_as_all,
       no_neighbor_remove_private_as_all_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as_all,
	     no_neighbor_remove_private_as_all_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Apply to all AS numbers\n")

DEFUN (no_neighbor_remove_private_as_replace_as,
       no_neighbor_remove_private_as_replace_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as_replace_as,
	     no_neighbor_remove_private_as_replace_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Replace private ASNs with our ASN in outbound updates\n")

DEFUN (no_neighbor_remove_private_as_all_replace_as,
       no_neighbor_remove_private_as_all_replace_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

ALIAS_HIDDEN(
	no_neighbor_remove_private_as_all_replace_as,
	no_neighbor_remove_private_as_all_replace_as_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n")


/* neighbor send-community. */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
	int idx_peer = 1;

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_SEND_COMMUNITY);
}

ALIAS_HIDDEN(neighbor_send_community, neighbor_send_community_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Send Community attribute to this neighbor\n")

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
	int idx_peer = 2;

	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_SEND_COMMUNITY);
}

ALIAS_HIDDEN(no_neighbor_send_community, no_neighbor_send_community_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Send Community attribute to this neighbor\n")

/* neighbor send-community extended. */
DEFUN (neighbor_send_community_type,
       neighbor_send_community_type_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Standard, Large and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n"
       "Send Large Community attributes\n")
{
	int idx_peer = 1;
	uint32_t flag = 0;
	const char *type = argv[argc - 1]->text;

	if (strmatch(type, "standard")) {
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
	} else if (strmatch(type, "extended")) {
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
	} else if (strmatch(type, "large")) {
		SET_FLAG(flag, PEER_FLAG_SEND_LARGE_COMMUNITY);
	} else if (strmatch(type, "both")) {
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
	} else { /* if (strmatch(type, "all")) */
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_LARGE_COMMUNITY);
	}

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), flag);
}

ALIAS_HIDDEN(
	neighbor_send_community_type, neighbor_send_community_type_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n")

DEFUN (no_neighbor_send_community_type,
       no_neighbor_send_community_type_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Standard, Large and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n"
       "Send Large Community attributes\n")
{
	int idx_peer = 2;
	uint32_t flag = 0;
	const char *type = argv[argc - 1]->text;

	if (strmatch(type, "standard")) {
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
	} else if (strmatch(type, "extended")) {
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
	} else if (strmatch(type, "large")) {
		SET_FLAG(flag, PEER_FLAG_SEND_LARGE_COMMUNITY);
	} else if (strmatch(type, "both")) {
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
	} else { /* if (strmatch(type, "all")) */
		SET_FLAG(flag, PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_EXT_COMMUNITY);
		SET_FLAG(flag, PEER_FLAG_SEND_LARGE_COMMUNITY);
	}

	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      flag);
}

ALIAS_HIDDEN(
	no_neighbor_send_community_type,
	no_neighbor_send_community_type_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n")

/* neighbor soft-reconfig. */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_SOFT_RECONFIG);
}

ALIAS_HIDDEN(neighbor_soft_reconfiguration,
	     neighbor_soft_reconfiguration_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Per neighbor soft reconfiguration\n"
	     "Allow inbound soft reconfiguration for this neighbor\n")

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_SOFT_RECONFIG);
}

ALIAS_HIDDEN(no_neighbor_soft_reconfiguration,
	     no_neighbor_soft_reconfiguration_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Per neighbor soft reconfiguration\n"
	     "Allow inbound soft reconfiguration for this neighbor\n")

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
	int idx_peer = 1;
	struct peer *peer;


	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REFLECTOR_CLIENT);
}

ALIAS_HIDDEN(neighbor_route_reflector_client,
	     neighbor_route_reflector_client_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Reflector client\n")

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REFLECTOR_CLIENT);
}

ALIAS_HIDDEN(no_neighbor_route_reflector_client,
	     no_neighbor_route_reflector_client_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Reflector client\n")

/* neighbor route-server-client. */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_RSERVER_CLIENT);
}

ALIAS_HIDDEN(neighbor_route_server_client,
	     neighbor_route_server_client_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Server client\n")

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_RSERVER_CLIENT);
}

ALIAS_HIDDEN(no_neighbor_route_server_client,
	     no_neighbor_route_server_client_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Server client\n")

DEFUN (neighbor_nexthop_local_unchanged,
       neighbor_nexthop_local_unchanged_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> nexthop-local unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

DEFUN (no_neighbor_nexthop_local_unchanged,
       no_neighbor_nexthop_local_unchanged_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> nexthop-local unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local-nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

DEFUN (neighbor_attr_unchanged,
       neighbor_attr_unchanged_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
	int idx = 0;
	char *peer_str = argv[1]->arg;
	struct peer *peer;
	uint16_t flags = 0;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (argv_find(argv, argc, "as-path", &idx))
		SET_FLAG(flags, PEER_FLAG_AS_PATH_UNCHANGED);
	idx = 0;
	if (argv_find(argv, argc, "next-hop", &idx))
		SET_FLAG(flags, PEER_FLAG_NEXTHOP_UNCHANGED);
	idx = 0;
	if (argv_find(argv, argc, "med", &idx))
		SET_FLAG(flags, PEER_FLAG_MED_UNCHANGED);

	/* no flags means all of them! */
	if (!flags) {
		SET_FLAG(flags, PEER_FLAG_AS_PATH_UNCHANGED);
		SET_FLAG(flags, PEER_FLAG_NEXTHOP_UNCHANGED);
		SET_FLAG(flags, PEER_FLAG_MED_UNCHANGED);
	} else {
		if (!CHECK_FLAG(flags, PEER_FLAG_AS_PATH_UNCHANGED)
		    && peer_af_flag_check(peer, afi, safi,
					  PEER_FLAG_AS_PATH_UNCHANGED)) {
			peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					       PEER_FLAG_AS_PATH_UNCHANGED);
		}

		if (!CHECK_FLAG(flags, PEER_FLAG_NEXTHOP_UNCHANGED)
		    && peer_af_flag_check(peer, afi, safi,
					  PEER_FLAG_NEXTHOP_UNCHANGED)) {
			peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					       PEER_FLAG_NEXTHOP_UNCHANGED);
		}

		if (!CHECK_FLAG(flags, PEER_FLAG_MED_UNCHANGED)
		    && peer_af_flag_check(peer, afi, safi,
					  PEER_FLAG_MED_UNCHANGED)) {
			peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					       PEER_FLAG_MED_UNCHANGED);
		}
	}

	return peer_af_flag_set_vty(vty, peer_str, afi, safi, flags);
}

ALIAS_HIDDEN(
	neighbor_attr_unchanged, neighbor_attr_unchanged_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n")

DEFUN (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
	int idx = 0;
	char *peer = argv[2]->arg;
	uint16_t flags = 0;

	if (argv_find(argv, argc, "as-path", &idx))
		SET_FLAG(flags, PEER_FLAG_AS_PATH_UNCHANGED);
	idx = 0;
	if (argv_find(argv, argc, "next-hop", &idx))
		SET_FLAG(flags, PEER_FLAG_NEXTHOP_UNCHANGED);
	idx = 0;
	if (argv_find(argv, argc, "med", &idx))
		SET_FLAG(flags, PEER_FLAG_MED_UNCHANGED);

	if (!flags) // no flags means all of them!
	{
		SET_FLAG(flags, PEER_FLAG_AS_PATH_UNCHANGED);
		SET_FLAG(flags, PEER_FLAG_NEXTHOP_UNCHANGED);
		SET_FLAG(flags, PEER_FLAG_MED_UNCHANGED);
	}

	return peer_af_flag_unset_vty(vty, peer, bgp_node_afi(vty),
				      bgp_node_safi(vty), flags);
}

ALIAS_HIDDEN(
	no_neighbor_attr_unchanged, no_neighbor_attr_unchanged_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n")

/* EBGP multihop configuration. */
static int peer_ebgp_multihop_set_vty(struct vty *vty, const char *ip_str,
				      const char *ttl_str)
{
	struct peer *peer;
	unsigned int ttl;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->conf_if)
		return bgp_vty_return(vty, BGP_ERR_INVALID_FOR_DIRECT_PEER);

	if (!ttl_str)
		ttl = MAXTTL;
	else
		ttl = strtoul(ttl_str, NULL, 10);

	return bgp_vty_return(vty, peer_ebgp_multihop_set(peer, ttl));
}

static int peer_ebgp_multihop_unset_vty(struct vty *vty, const char *ip_str)
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return bgp_vty_return(vty, peer_ebgp_multihop_unset(peer));
}

/* neighbor ebgp-multihop. */
DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
	int idx_peer = 1;
	return peer_ebgp_multihop_set_vty(vty, argv[idx_peer]->arg, NULL);
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop (1-255)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_ebgp_multihop_set_vty(vty, argv[idx_peer]->arg,
					  argv[idx_number]->arg);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop [(1-255)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
	int idx_peer = 2;
	return peer_ebgp_multihop_unset_vty(vty, argv[idx_peer]->arg);
}


/* disable-connected-check */
DEFUN (neighbor_disable_connected_check,
       neighbor_disable_connected_check_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> <disable-connected-check|enforce-multihop>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n"
       "Enforce EBGP neighbors perform multihop\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

DEFUN (no_neighbor_disable_connected_check,
       no_neighbor_disable_connected_check_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> <disable-connected-check|enforce-multihop>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n"
       "Enforce EBGP neighbors perform multihop\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DISABLE_CONNECTED_CHECK);
}


/* enforce-first-as */
DEFUN (neighbor_enforce_first_as,
       neighbor_enforce_first_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> enforce-first-as",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce the first AS for EBGP routes\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_ENFORCE_FIRST_AS);
}

DEFUN (no_neighbor_enforce_first_as,
       no_neighbor_enforce_first_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> enforce-first-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce the first AS for EBGP routes\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_ENFORCE_FIRST_AS);
}


DEFUN (neighbor_description,
       neighbor_description_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> description LINE...",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
	int idx_peer = 1;
	int idx_line = 3;
	struct peer *peer;
	char *str;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	str = argv_concat(argv, argc, idx_line);

	peer_description_set(peer, str);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> description",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer_description_unset(peer);

	return CMD_SUCCESS;
}

ALIAS(no_neighbor_description, no_neighbor_description_comment_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> description LINE...",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Neighbor specific description\n"
      "Up to 80 characters describing this neighbor\n")

/* Neighbor update-source. */
static int peer_update_source_vty(struct vty *vty, const char *peer_str,
				  const char *source_str)
{
	struct peer *peer;
	struct prefix p;
	union sockunion su;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->conf_if)
		return CMD_WARNING;

	if (source_str) {
		if (str2sockunion(source_str, &su) == 0)
			peer_update_source_addr_set(peer, &su);
		else {
			if (str2prefix(source_str, &p)) {
				vty_out(vty,
					"%% Invalid update-source, remove prefix length \n");
				return CMD_WARNING_CONFIG_FAILED;
			} else
				peer_update_source_if_set(peer, source_str);
		}
	} else
		peer_update_source_unset(peer);

	return CMD_SUCCESS;
}

#define BGP_UPDATE_SOURCE_HELP_STR                                             \
	"IPv4 address\n"                                                       \
	"IPv6 address\n"                                                       \
	"Interface name (requires zebra to be running)\n"

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> update-source <A.B.C.D|X:X::X:X|WORD>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
	int idx_peer = 1;
	int idx_peer_2 = 3;
	return peer_update_source_vty(vty, argv[idx_peer]->arg,
				      argv[idx_peer_2]->arg);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> update-source [<A.B.C.D|X:X::X:X|WORD>]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
	int idx_peer = 2;
	return peer_update_source_vty(vty, argv[idx_peer]->arg, NULL);
}

static int peer_default_originate_set_vty(struct vty *vty, const char *peer_str,
					  afi_t afi, safi_t safi,
					  const char *rmap, int set)
{
	int ret;
	struct peer *peer;
	struct route_map *route_map = NULL;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (set) {
		if (rmap)
			route_map = route_map_lookup_warn_noexist(vty, rmap);
		ret = peer_default_originate_set(peer, afi, safi,
						 rmap, route_map);
	} else
		ret = peer_default_originate_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

/* neighbor default-originate. */
DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
	int idx_peer = 1;
	return peer_default_originate_set_vty(vty, argv[idx_peer]->arg,
					      bgp_node_afi(vty),
					      bgp_node_safi(vty), NULL, 1);
}

ALIAS_HIDDEN(neighbor_default_originate, neighbor_default_originate_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Originate default route to this neighbor\n")

DEFUN (neighbor_default_originate_rmap,
       neighbor_default_originate_rmap_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate route-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
	int idx_peer = 1;
	int idx_word = 4;
	return peer_default_originate_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, 1);
}

ALIAS_HIDDEN(
	neighbor_default_originate_rmap,
	neighbor_default_originate_rmap_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> default-originate route-map WORD",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n")

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> default-originate [route-map WORD]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
	int idx_peer = 2;
	return peer_default_originate_set_vty(vty, argv[idx_peer]->arg,
					      bgp_node_afi(vty),
					      bgp_node_safi(vty), NULL, 0);
}

ALIAS_HIDDEN(
	no_neighbor_default_originate, no_neighbor_default_originate_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> default-originate [route-map WORD]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n")


/* Set neighbor's BGP port.  */
static int peer_port_vty(struct vty *vty, const char *ip_str, int afi,
			 const char *port_str)
{
	struct peer *peer;
	uint16_t port;
	struct servent *sp;

	peer = peer_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!port_str) {
		sp = getservbyname("bgp", "tcp");
		port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);
	} else {
		port = strtoul(port_str, NULL, 10);
	}

	peer_port_set(peer, port);

	return CMD_SUCCESS;
}

/* Set specified peer's BGP port.  */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       "neighbor <A.B.C.D|X:X::X:X> port (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
	int idx_ip = 1;
	int idx_number = 3;
	return peer_port_vty(vty, argv[idx_ip]->arg, AFI_IP,
			     argv[idx_number]->arg);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       "no neighbor <A.B.C.D|X:X::X:X> port [(0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
	int idx_ip = 2;
	return peer_port_vty(vty, argv[idx_ip]->arg, AFI_IP, NULL);
}


/* neighbor weight. */
static int peer_weight_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi, const char *weight_str)
{
	int ret;
	struct peer *peer;
	unsigned long weight;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	weight = strtoul(weight_str, NULL, 10);

	ret = peer_weight_set(peer, afi, safi, weight);
	return bgp_vty_return(vty, ret);
}

static int peer_weight_unset_vty(struct vty *vty, const char *ip_str, afi_t afi,
				 safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_weight_unset(peer, afi, safi);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> weight (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_weight_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				   bgp_node_safi(vty), argv[idx_number]->arg);
}

ALIAS_HIDDEN(neighbor_weight, neighbor_weight_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> weight (0-65535)",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Set default weight for routes from this neighbor\n"
	     "default weight\n")

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> weight [(0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
	int idx_peer = 2;
	return peer_weight_unset_vty(vty, argv[idx_peer]->arg,
				     bgp_node_afi(vty), bgp_node_safi(vty));
}

ALIAS_HIDDEN(no_neighbor_weight, no_neighbor_weight_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> weight [(0-65535)]",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Set default weight for routes from this neighbor\n"
	     "default weight\n")


/* Override capability negotiation. */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Strict capability negotiation match\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_STRICT_CAP_MATCH);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Strict capability negotiation match\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_STRICT_CAP_MATCH);
}

static int peer_timers_set_vty(struct vty *vty, const char *ip_str,
			       const char *keep_str, const char *hold_str)
{
	int ret;
	struct peer *peer;
	uint32_t keepalive;
	uint32_t holdtime;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	keepalive = strtoul(keep_str, NULL, 10);
	holdtime = strtoul(hold_str, NULL, 10);

	ret = peer_timers_set(peer, keepalive, holdtime);

	return bgp_vty_return(vty, ret);
}

static int peer_timers_unset_vty(struct vty *vty, const char *ip_str)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_timers_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_timers,
       neighbor_timers_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> timers (0-65535) (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	return peer_timers_set_vty(vty, argv[idx_peer]->arg,
				   argv[idx_number]->arg,
				   argv[idx_number_2]->arg);
}

DEFUN (no_neighbor_timers,
       no_neighbor_timers_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> timers [(0-65535) (0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	int idx_peer = 2;
	return peer_timers_unset_vty(vty, argv[idx_peer]->arg);
}


static int peer_timers_connect_set_vty(struct vty *vty, const char *ip_str,
				       const char *time_str)
{
	int ret;
	struct peer *peer;
	uint32_t connect;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	connect = strtoul(time_str, NULL, 10);

	ret = peer_timers_connect_set(peer, connect);

	return bgp_vty_return(vty, ret);
}

static int peer_timers_connect_unset_vty(struct vty *vty, const char *ip_str)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_timers_connect_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> timers connect (1-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
	int idx_peer = 1;
	int idx_number = 4;
	return peer_timers_connect_set_vty(vty, argv[idx_peer]->arg,
					   argv[idx_number]->arg);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> timers connect [(1-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
	int idx_peer = 2;
	return peer_timers_connect_unset_vty(vty, argv[idx_peer]->arg);
}


static int peer_advertise_interval_vty(struct vty *vty, const char *ip_str,
				       const char *time_str, int set)
{
	int ret;
	struct peer *peer;
	uint32_t routeadv = 0;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (time_str)
		routeadv = strtoul(time_str, NULL, 10);

	if (set)
		ret = peer_advertise_interval_set(peer, routeadv);
	else
		ret = peer_advertise_interval_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_advertise_interval,
       neighbor_advertise_interval_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> advertisement-interval (0-600)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_advertise_interval_vty(vty, argv[idx_peer]->arg,
					   argv[idx_number]->arg, 1);
}

DEFUN (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> advertisement-interval [(0-600)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
	int idx_peer = 2;
	return peer_advertise_interval_vty(vty, argv[idx_peer]->arg, NULL, 0);
}


/* Time to wait before processing route-map updates */
DEFUN (bgp_set_route_map_delay_timer,
       bgp_set_route_map_delay_timer_cmd,
       "bgp route-map delay-timer (0-600)",
       SET_STR
       "BGP route-map delay timer\n"
       "Time in secs to wait before processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{
	int idx_number = 3;
	uint32_t rmap_delay_timer;

	if (argv[idx_number]->arg) {
		rmap_delay_timer = strtoul(argv[idx_number]->arg, NULL, 10);
		bm->rmap_update_timer = rmap_delay_timer;

		/* if the dynamic update handling is being disabled, and a timer
		 * is
		 * running, stop the timer and act as if the timer has already
		 * fired.
		 */
		if (!rmap_delay_timer && bm->t_rmap_update) {
			BGP_TIMER_OFF(bm->t_rmap_update);
			thread_execute(bm->master, bgp_route_map_update_timer,
				       NULL, 0);
		}
		return CMD_SUCCESS;
	} else {
		vty_out(vty, "%% BGP invalid route-map delay-timer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
}

DEFUN (no_bgp_set_route_map_delay_timer,
       no_bgp_set_route_map_delay_timer_cmd,
       "no bgp route-map delay-timer [(0-600)]",
       NO_STR
       BGP_STR
       "Default BGP route-map delay timer\n"
       "Reset to default time to wait for processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;

	return CMD_SUCCESS;
}


/* neighbor interface */
static int peer_interface_vty(struct vty *vty, const char *ip_str,
			      const char *str)
{
	struct peer *peer;

	peer = peer_lookup_vty(vty, ip_str);
	if (!peer || peer->conf_if) {
		vty_out(vty, "%% BGP invalid peer %s\n", ip_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (str)
		peer_interface_set(peer, str);
	else
		peer_interface_unset(peer);

	return CMD_SUCCESS;
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       "neighbor <A.B.C.D|X:X::X:X> interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
	int idx_ip = 1;
	int idx_word = 3;
	return peer_interface_vty(vty, argv[idx_ip]->arg, argv[idx_word]->arg);
}

DEFUN (no_neighbor_interface,
       no_neighbor_interface_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Interface\n"
       "Interface name\n")
{
	int idx_peer = 2;
	return peer_interface_vty(vty, argv[idx_peer]->arg, NULL);
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list <(1-199)|(1300-2699)|WORD> <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 1;
	int idx_acl = 3;
	int direct, ret;
	struct peer *peer;

	const char *pstr = argv[idx_peer]->arg;
	const char *acl = argv[idx_acl]->arg;
	const char *inout = argv[argc - 1]->text;

	peer = peer_and_group_lookup_vty(vty, pstr);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	direct = strmatch(inout, "in") ? FILTER_IN : FILTER_OUT;
	ret = peer_distribute_set(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  direct, acl);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	neighbor_distribute_list, neighbor_distribute_list_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list <(1-199)|(1300-2699)|WORD> <in|out>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list <(1-199)|(1300-2699)|WORD> <in|out>",
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
	int idx_peer = 2;
	int direct, ret;
	struct peer *peer;

	const char *pstr = argv[idx_peer]->arg;
	const char *inout = argv[argc - 1]->text;

	peer = peer_and_group_lookup_vty(vty, pstr);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	direct = strmatch(inout, "in") ? FILTER_IN : FILTER_OUT;
	ret = peer_distribute_unset(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				    direct);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	no_neighbor_distribute_list, no_neighbor_distribute_list_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list <(1-199)|(1300-2699)|WORD> <in|out>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")

/* Set prefix list to the peer. */
static int peer_prefix_list_set_vty(struct vty *vty, const char *ip_str,
				    afi_t afi, safi_t safi,
				    const char *name_str,
				    const char *direct_str)
{
	int ret;
	int direct = FILTER_IN;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_prefix_list_set(peer, afi, safi, direct, name_str);

	return bgp_vty_return(vty, ret);
}

static int peer_prefix_list_unset_vty(struct vty *vty, const char *ip_str,
				      afi_t afi, safi_t safi,
				      const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_prefix_list_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_prefix_list_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_prefix_list, neighbor_prefix_list_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Filter updates to/from this neighbor\n"
	     "Name of a prefix list\n"
	     "Filter incoming updates\n"
	     "Filter outgoing updates\n")

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_prefix_list_unset_vty(vty, argv[idx_peer]->arg,
					  bgp_node_afi(vty), bgp_node_safi(vty),
					  argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_prefix_list, no_neighbor_prefix_list_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Filter updates to/from this neighbor\n"
	     "Name of a prefix list\n"
	     "Filter incoming updates\n"
	     "Filter outgoing updates\n")

static int peer_aslist_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi, const char *name_str,
			       const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_aslist_set(peer, afi, safi, direct, name_str);

	return bgp_vty_return(vty, ret);
}

static int peer_aslist_unset_vty(struct vty *vty, const char *ip_str, afi_t afi,
				 safi_t safi, const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_aslist_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> filter-list WORD <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_aslist_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				   bgp_node_safi(vty), argv[idx_word]->arg,
				   argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_filter_list, neighbor_filter_list_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> filter-list WORD <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Establish BGP filters\n"
	     "AS path access-list name\n"
	     "Filter incoming routes\n"
	     "Filter outgoing routes\n")

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> filter-list WORD <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_aslist_unset_vty(vty, argv[idx_peer]->arg,
				     bgp_node_afi(vty), bgp_node_safi(vty),
				     argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_filter_list, no_neighbor_filter_list_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> filter-list WORD <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Establish BGP filters\n"
	     "AS path access-list name\n"
	     "Filter incoming routes\n"
	     "Filter outgoing routes\n")

/* Set route-map to the peer. */
static int peer_route_map_set_vty(struct vty *vty, const char *ip_str,
				  afi_t afi, safi_t safi, const char *name_str,
				  const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = RMAP_IN;
	struct route_map *route_map;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "in", 2) == 0)
		direct = RMAP_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = RMAP_OUT;

	route_map = route_map_lookup_warn_noexist(vty, name_str);
	ret = peer_route_map_set(peer, afi, safi, direct, name_str, route_map);

	return bgp_vty_return(vty, ret);
}

static int peer_route_map_unset_vty(struct vty *vty, const char *ip_str,
				    afi_t afi, safi_t safi,
				    const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = RMAP_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "in", 2) == 0)
		direct = RMAP_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = RMAP_OUT;

	ret = peer_route_map_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-map WORD <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_route_map_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_route_map, neighbor_route_map_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-map WORD <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Apply route map to neighbor\n"
	     "Name of route map\n"
	     "Apply map to incoming routes\n"
	     "Apply map to outbound routes\n")

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-map WORD <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_route_map_unset_vty(vty, argv[idx_peer]->arg,
					bgp_node_afi(vty), bgp_node_safi(vty),
					argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_route_map, no_neighbor_route_map_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-map WORD <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Apply route map to neighbor\n"
	     "Name of route map\n"
	     "Apply map to incoming routes\n"
	     "Apply map to outbound routes\n")

/* Set unsuppress-map to the peer. */
static int peer_unsuppress_map_set_vty(struct vty *vty, const char *ip_str,
				       afi_t afi, safi_t safi,
				       const char *name_str)
{
	int ret;
	struct peer *peer;
	struct route_map *route_map;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	route_map = route_map_lookup_warn_noexist(vty, name_str);
	ret = peer_unsuppress_map_set(peer, afi, safi, name_str, route_map);

	return bgp_vty_return(vty, ret);
}

/* Unset route-map from the peer. */
static int peer_unsuppress_map_unset_vty(struct vty *vty, const char *ip_str,
					 afi_t afi, safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_unsuppress_map_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_unsuppress_map,
       neighbor_unsuppress_map_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	return peer_unsuppress_map_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg);
}

ALIAS_HIDDEN(neighbor_unsuppress_map, neighbor_unsuppress_map_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Route-map to selectively unsuppress suppressed routes\n"
	     "Name of route map\n")

DEFUN (no_neighbor_unsuppress_map,
       no_neighbor_unsuppress_map_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
	int idx_peer = 2;
	return peer_unsuppress_map_unset_vty(vty, argv[idx_peer]->arg,
					     bgp_node_afi(vty),
					     bgp_node_safi(vty));
}

ALIAS_HIDDEN(no_neighbor_unsuppress_map, no_neighbor_unsuppress_map_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Route-map to selectively unsuppress suppressed routes\n"
	     "Name of route map\n")

static int peer_maximum_prefix_set_vty(struct vty *vty, const char *ip_str,
				       afi_t afi, safi_t safi,
				       const char *num_str,
				       const char *threshold_str, int warning,
				       const char *restart_str)
{
	int ret;
	struct peer *peer;
	uint32_t max;
	uint8_t threshold;
	uint16_t restart;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	max = strtoul(num_str, NULL, 10);
	if (threshold_str)
		threshold = atoi(threshold_str);
	else
		threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

	if (restart_str)
		restart = atoi(restart_str);
	else
		restart = 0;

	ret = peer_maximum_prefix_set(peer, afi, safi, max, threshold, warning,
				      restart);

	return bgp_vty_return(vty, ret);
}

static int peer_maximum_prefix_unset_vty(struct vty *vty, const char *ip_str,
					 afi_t afi, safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_maximum_prefix_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 0, NULL);
}

ALIAS_HIDDEN(neighbor_maximum_prefix, neighbor_maximum_prefix_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295)",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Maximum number of prefix accept from this peer\n"
	     "maximum no. of prefix limit\n")

DEFUN (neighbor_maximum_prefix_threshold,
       neighbor_maximum_prefix_threshold_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 0, NULL);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold,
	neighbor_maximum_prefix_threshold_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100)",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n")

DEFUN (neighbor_maximum_prefix_warning,
       neighbor_maximum_prefix_warning_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 1, NULL);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_warning,
	neighbor_maximum_prefix_warning_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) warning-only",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Only give warning message when limit is exceeded\n")

DEFUN (neighbor_maximum_prefix_threshold_warning,
       neighbor_maximum_prefix_threshold_warning_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 1, NULL);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold_warning,
	neighbor_maximum_prefix_threshold_warning_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) warning-only",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Only give warning message when limit is exceeded\n")

DEFUN (neighbor_maximum_prefix_restart,
       neighbor_maximum_prefix_restart_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) restart (1-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 5;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 0, argv[idx_number_2]->arg);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_restart,
	neighbor_maximum_prefix_restart_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) restart (1-65535)",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n")

DEFUN (neighbor_maximum_prefix_threshold_restart,
       neighbor_maximum_prefix_threshold_restart_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) restart (1-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefixes to accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 0,
		argv[idx_number_3]->arg);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold_restart,
	neighbor_maximum_prefix_threshold_restart_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) restart (1-65535)",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n")

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only]]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefixes to accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n"
       "Only give warning message when limit is exceeded\n")
{
	int idx_peer = 2;
	return peer_maximum_prefix_unset_vty(vty, argv[idx_peer]->arg,
					     bgp_node_afi(vty),
					     bgp_node_safi(vty));
}

ALIAS_HIDDEN(
	no_neighbor_maximum_prefix, no_neighbor_maximum_prefix_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only]]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Only give warning message when limit is exceeded\n")


/* "neighbor allowas-in" */
DEFUN (neighbor_allowas_in,
       neighbor_allowas_in_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n"
       "Number of occurrences of AS number\n"
       "Only accept my AS in the as-path if the route was originated in my AS\n")
{
	int idx_peer = 1;
	int idx_number_origin = 3;
	int ret;
	int origin = 0;
	struct peer *peer;
	int allow_num = 0;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (argc <= idx_number_origin)
		allow_num = 3;
	else {
		if (argv[idx_number_origin]->type == WORD_TKN)
			origin = 1;
		else
			allow_num = atoi(argv[idx_number_origin]->arg);
	}

	ret = peer_allowas_in_set(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  allow_num, origin);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	neighbor_allowas_in, neighbor_allowas_in_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Accept as-path with my AS present in it\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n")

DEFUN (no_neighbor_allowas_in,
       no_neighbor_allowas_in_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n"
       "Number of occurrences of AS number\n"
       "Only accept my AS in the as-path if the route was originated in my AS\n")
{
	int idx_peer = 2;
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_allowas_in_unset(peer, bgp_node_afi(vty),
				    bgp_node_safi(vty));

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	no_neighbor_allowas_in, no_neighbor_allowas_in_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"allow local ASN appears in aspath attribute\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n")

DEFUN (neighbor_ttl_security,
       neighbor_ttl_security_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ttl-security hops (1-254)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP ttl-security parameters\n"
       "Specify the maximum number of hops to the BGP peer\n"
       "Number of hops to BGP peer\n")
{
	int idx_peer = 1;
	int idx_number = 4;
	struct peer *peer;
	int gtsm_hops;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	gtsm_hops = strtoul(argv[idx_number]->arg, NULL, 10);

	/*
	 * If 'neighbor swpX', then this is for directly connected peers,
	 * we should not accept a ttl-security hops value greater than 1.
	 */
	if (peer->conf_if && (gtsm_hops > 1)) {
		vty_out(vty,
			"%s is directly connected peer, hops cannot exceed 1\n",
			argv[idx_peer]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_vty_return(vty, peer_ttl_security_hops_set(peer, gtsm_hops));
}

DEFUN (no_neighbor_ttl_security,
       no_neighbor_ttl_security_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> ttl-security hops (1-254)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP ttl-security parameters\n"
       "Specify the maximum number of hops to the BGP peer\n"
       "Number of hops to BGP peer\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return bgp_vty_return(vty, peer_ttl_security_hops_unset(peer));
}

DEFUN (neighbor_addpath_tx_all_paths,
       neighbor_addpath_tx_all_paths_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				 BGP_ADDPATH_ALL);
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(neighbor_addpath_tx_all_paths,
	     neighbor_addpath_tx_all_paths_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise all paths to a neighbor\n")

DEFUN (no_neighbor_addpath_tx_all_paths,
       no_neighbor_addpath_tx_all_paths_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->addpath_type[bgp_node_afi(vty)][bgp_node_safi(vty)]
	    != BGP_ADDPATH_ALL) {
		vty_out(vty,
			"%% Peer not currently configured to transmit all paths.");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				 BGP_ADDPATH_NONE);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(no_neighbor_addpath_tx_all_paths,
	     no_neighbor_addpath_tx_all_paths_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise all paths to a neighbor\n")

DEFUN (neighbor_addpath_tx_bestpath_per_as,
       neighbor_addpath_tx_bestpath_per_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				 BGP_ADDPATH_BEST_PER_AS);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(neighbor_addpath_tx_bestpath_per_as,
	     neighbor_addpath_tx_bestpath_per_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise the bestpath per each neighboring AS\n")

DEFUN (no_neighbor_addpath_tx_bestpath_per_as,
       no_neighbor_addpath_tx_bestpath_per_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->addpath_type[bgp_node_afi(vty)][bgp_node_safi(vty)]
	    != BGP_ADDPATH_BEST_PER_AS) {
		vty_out(vty,
			"%% Peer not currently configured to transmit all best path per as.");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				 BGP_ADDPATH_NONE);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(no_neighbor_addpath_tx_bestpath_per_as,
	     no_neighbor_addpath_tx_bestpath_per_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise the bestpath per each neighboring AS\n")

DEFPY(
	neighbor_aspath_loop_detection, neighbor_aspath_loop_detection_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer->as_path_loop_detection = true;

	return CMD_SUCCESS;
}

DEFPY(
	no_neighbor_aspath_loop_detection,
	no_neighbor_aspath_loop_detection_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer->as_path_loop_detection = false;

	return CMD_SUCCESS;
}

static int set_ecom_list(struct vty *vty, int argc, struct cmd_token **argv,
			 struct ecommunity **list)
{
	struct ecommunity *ecom = NULL;
	struct ecommunity *ecomadd;

	for (; argc; --argc, ++argv) {

		ecomadd = ecommunity_str2com(argv[0]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "Malformed community-list value\n");
			if (ecom)
				ecommunity_free(&ecom);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (ecom) {
			ecommunity_merge(ecom, ecomadd);
			ecommunity_free(&ecomadd);
		} else {
			ecom = ecomadd;
		}
	}

	if (*list) {
		ecommunity_free(&*list);
	}
	*list = ecom;

	return CMD_SUCCESS;
}

/*
 * v2vimport is true if we are handling a `import vrf ...` command
 */
static afi_t vpn_policy_getafi(struct vty *vty, struct bgp *bgp, bool v2vimport)
{
	afi_t afi;

	switch (vty->node) {
	case BGP_IPV4_NODE:
		afi = AFI_IP;
		break;
	case BGP_IPV6_NODE:
		afi = AFI_IP6;
		break;
	default:
		vty_out(vty,
			"%% context error: valid only in address-family <ipv4|ipv6> unicast block\n");
		return AFI_MAX;
	}

	if (!v2vimport) {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure import vrf commands before using vpn commands\n");
			return AFI_MAX;
		}
	} else {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure vpn to vrf commands before using import vrf commands\n");
			return AFI_MAX;
		}
	}
	return afi;
}

DEFPY (af_rd_vpn_export,
       af_rd_vpn_export_cmd,
       "[no] rd vpn export ASN:NN_OR_IP-ADDRESS:NN$rd_str",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix_rd prd;
	int ret;
	afi_t afi;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	if (yes) {
		ret = str2prefix_rd(rd_str, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (yes) {
		bgp->vpn_policy[afi].tovpn_rd = prd;
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_RD_SET);
	} else {
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_RD_SET);
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS (af_rd_vpn_export,
       af_no_rd_vpn_export_cmd,
       "no rd vpn export",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n")

DEFPY (af_label_vpn_export,
       af_label_vpn_export_cmd,
       "[no] label vpn export <(0-1048575)$label_val|auto$label_auto>",
       NO_STR
       "label value for VRF\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "Label Value <0-1048575>\n"
       "Automatically assign a label\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	mpls_label_t label = MPLS_LABEL_NONE;
	afi_t afi;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	/* If "no ...", squash trailing parameter */
	if (!yes)
		label_auto = NULL;

	if (yes) {
		if (!label_auto)
			label = label_val; /* parser should force unsigned */
	}

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;


	if (label_auto && CHECK_FLAG(bgp->vpn_policy[afi].flags,
				     BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		/* no change */
		return CMD_SUCCESS;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (!label_auto && CHECK_FLAG(bgp->vpn_policy[afi].flags,
				      BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {

		if (bgp->vpn_policy[afi].tovpn_label != MPLS_LABEL_NONE) {

			/*
			 * label has previously been automatically
			 * assigned by labelpool: release it
			 *
			 * NB if tovpn_label == MPLS_LABEL_NONE it
			 * means the automatic assignment is in flight
			 * and therefore the labelpool callback must
			 * detect that the auto label is not needed.
			 */

			bgp_lp_release(LP_TYPE_VRF,
				       &bgp->vpn_policy[afi],
				       bgp->vpn_policy[afi].tovpn_label);
		}
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	}

	bgp->vpn_policy[afi].tovpn_label = label;
	if (label_auto) {
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
		bgp_lp_get(LP_TYPE_VRF, &bgp->vpn_policy[afi],
			   vpn_leak_label_callback);
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS (af_label_vpn_export,
       af_no_label_vpn_export_cmd,
       "no label vpn export",
       NO_STR
       "label value for VRF\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n")

DEFPY (af_nexthop_vpn_export,
       af_nexthop_vpn_export_cmd,
       "[no] nexthop vpn export <A.B.C.D|X:X::X:X>$nexthop_str",
       NO_STR
       "Specify next hop to use for VRF advertised prefixes\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	struct prefix p;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	if (yes) {
		if (!sockunion2hostprefix(nexthop_str, &p))
			return CMD_WARNING_CONFIG_FAILED;
	}

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (yes) {
		bgp->vpn_policy[afi].tovpn_nexthop = p;
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	} else {
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS (af_nexthop_vpn_export,
       af_no_nexthop_vpn_export_cmd,
       "no nexthop vpn export",
       NO_STR
       "Specify next hop to use for VRF advertised prefixes\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n")

static int vpn_policy_getdirs(struct vty *vty, const char *dstr, int *dodir)
{
	if (!strcmp(dstr, "import")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
	} else if (!strcmp(dstr, "export")) {
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else if (!strcmp(dstr, "both")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else {
		vty_out(vty, "%% direction parse error\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFPY (af_rt_vpn_imexport,
       af_rt_vpn_imexport_cmd,
       "[no] <rt|route-target> vpn <import|export|both>$direction_str RTLIST...",
       NO_STR
       "Specify route target list\n"
       "Specify route target list\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family: match any\n"
       "For routes leaked from current address-family to vpn: set\n"
       "both import: match any and export: set\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct ecommunity *ecom = NULL;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	vpn_policy_direction_t dir;
	afi_t afi;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	ret = vpn_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!argv_find(argv, argc, "RTLIST", &idx)) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = set_ecom_list(vty, argc - idx, argv + idx, &ecom);
		if (ret != CMD_SUCCESS) {
			return ret;
		}
	}

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (yes) {
			if (bgp->vpn_policy[afi].rtlist[dir])
				ecommunity_free(
						&bgp->vpn_policy[afi].rtlist[dir]);
			bgp->vpn_policy[afi].rtlist[dir] =
				ecommunity_dup(ecom);
		} else {
			if (bgp->vpn_policy[afi].rtlist[dir])
				ecommunity_free(
						&bgp->vpn_policy[afi].rtlist[dir]);
			bgp->vpn_policy[afi].rtlist[dir] = NULL;
		}

		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	if (ecom)
		ecommunity_free(&ecom);

	return CMD_SUCCESS;
}

ALIAS (af_rt_vpn_imexport,
       af_no_rt_vpn_imexport_cmd,
       "no <rt|route-target> vpn <import|export|both>$direction_str",
       NO_STR
       "Specify route target list\n"
       "Specify route target list\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n"
       "both import and export\n")

DEFPY (af_route_map_vpn_imexport,
       af_route_map_vpn_imexport_cmd,
/* future: "route-map <vpn|evpn|vrf NAME> <import|export> RMAP" */
       "[no] route-map vpn <import|export>$direction_str RMAP$rmap_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n"
       "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	vpn_policy_direction_t dir;
	afi_t afi;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	ret = vpn_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (yes) {
			if (bgp->vpn_policy[afi].rmap_name[dir])
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp->vpn_policy[afi].rmap_name[dir]);
			bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(
								      MTYPE_ROUTE_MAP_NAME, rmap_str);
			bgp->vpn_policy[afi].rmap[dir] =
				route_map_lookup_warn_noexist(vty, rmap_str);
			if (!bgp->vpn_policy[afi].rmap[dir])
				return CMD_SUCCESS;
		} else {
			if (bgp->vpn_policy[afi].rmap_name[dir])
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp->vpn_policy[afi].rmap_name[dir]);
			bgp->vpn_policy[afi].rmap_name[dir] = NULL;
			bgp->vpn_policy[afi].rmap[dir] = NULL;
		}

		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	return CMD_SUCCESS;
}

ALIAS (af_route_map_vpn_imexport,
       af_no_route_map_vpn_imexport_cmd,
       "no route-map vpn <import|export>$direction_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n")

DEFPY(af_import_vrf_route_map, af_import_vrf_route_map_cmd,
      "[no] import vrf route-map RMAP$rmap_str",
      NO_STR
      "Import routes from another VRF\n"
      "Vrf routes being filtered\n"
      "Specify route map\n"
      "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	vpn_policy_direction_t dir = BGP_VPN_POLICY_DIR_FROMVPN;
	afi_t afi;
	int idx = 0;
	int yes = 1;
	struct bgp *bgp_default;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	afi = vpn_policy_getafi(vty, bgp, true);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		int32_t ret;
		as_t as = bgp->as;

		/* Auto-create assuming the same AS */
		ret = bgp_get(&bgp_default, &as, NULL,
			      BGP_INSTANCE_TYPE_DEFAULT);

		if (ret) {
			vty_out(vty,
				"VRF default is not configured as a bgp instance\n");
			return CMD_WARNING;
		}
	}

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	if (yes) {
		if (bgp->vpn_policy[afi].rmap_name[dir])
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      bgp->vpn_policy[afi].rmap_name[dir]);
		bgp->vpn_policy[afi].rmap_name[dir] =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);
		bgp->vpn_policy[afi].rmap[dir] =
			route_map_lookup_warn_noexist(vty, rmap_str);
		if (!bgp->vpn_policy[afi].rmap[dir])
			return CMD_SUCCESS;
	} else {
		if (bgp->vpn_policy[afi].rmap_name[dir])
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      bgp->vpn_policy[afi].rmap_name[dir]);
		bgp->vpn_policy[afi].rmap_name[dir] = NULL;
		bgp->vpn_policy[afi].rmap[dir] = NULL;
	}

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS(af_import_vrf_route_map, af_no_import_vrf_route_map_cmd,
      "no import vrf route-map",
      NO_STR
      "Import routes from another VRF\n"
      "Vrf routes being filtered\n"
      "Specify route map\n")

DEFPY(bgp_imexport_vrf, bgp_imexport_vrf_cmd,
      "[no] import vrf VIEWVRFNAME$import_name",
      NO_STR
      "Import routes from another VRF\n"
      "VRF to import from\n"
      "The name of the VRF\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node;
	struct bgp *vrf_bgp, *bgp_default;
	int32_t ret = 0;
	as_t as = bgp->as;
	bool remove = false;
	int32_t idx = 0;
	char *vname;
	enum bgp_instance_type bgp_type = BGP_INSTANCE_TYPE_VRF;
	safi_t safi;
	afi_t afi;

	if (import_name == NULL) {
		vty_out(vty, "%% Missing import name\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "no", &idx))
		remove = true;

	afi = vpn_policy_getafi(vty, bgp, true);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	safi = bgp_node_safi(vty);

	if (((BGP_INSTANCE_TYPE_DEFAULT == bgp->inst_type)
	     && (strcmp(import_name, VRF_DEFAULT_NAME) == 0))
	    || (bgp->name && (strcmp(import_name, bgp->name) == 0))) {
		vty_out(vty, "%% Cannot %s vrf %s into itself\n",
			remove ? "unimport" : "import", import_name);
		return CMD_WARNING;
	}

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		/* Auto-create assuming the same AS */
		ret = bgp_get(&bgp_default, &as, NULL,
			      BGP_INSTANCE_TYPE_DEFAULT);

		if (ret) {
			vty_out(vty,
				"VRF default is not configured as a bgp instance\n");
			return CMD_WARNING;
		}
	}

	vrf_bgp = bgp_lookup_by_name(import_name);
	if (!vrf_bgp) {
		if (strcmp(import_name, VRF_DEFAULT_NAME) == 0)
			vrf_bgp = bgp_default;
		else
			/* Auto-create assuming the same AS */
			ret = bgp_get(&vrf_bgp, &as, import_name, bgp_type);

		if (ret) {
			vty_out(vty,
				"VRF %s is not configured as a bgp instance\n",
				import_name);
			return CMD_WARNING;
		}
	}

	if (remove) {
		vrf_unimport_from_vrf(bgp, vrf_bgp, afi, safi);
	} else {
		/* Already importing from "import_vrf"? */
		for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].import_vrf, node,
					  vname)) {
			if (strcmp(vname, import_name) == 0)
				return CMD_WARNING;
		}

		vrf_import_from_vrf(bgp, vrf_bgp, afi, safi);
	}

	return CMD_SUCCESS;
}

/* This command is valid only in a bgp vrf instance or the default instance */
DEFPY (bgp_imexport_vpn,
       bgp_imexport_vpn_cmd,
       "[no] <import|export>$direction_str vpn",
       NO_STR
       "Import routes to this address-family\n"
       "Export routes from this address-family\n"
       "to/from default instance VPN RIB\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int previous_state;
	afi_t afi;
	safi_t safi;
	int idx = 0;
	int yes = 1;
	int flag;
	vpn_policy_direction_t dir;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	if (BGP_INSTANCE_TYPE_VRF != bgp->inst_type &&
		BGP_INSTANCE_TYPE_DEFAULT != bgp->inst_type) {

		vty_out(vty, "%% import|export vpn valid only for bgp vrf or default instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);
	if ((SAFI_UNICAST != safi) || ((AFI_IP != afi) && (AFI_IP6 != afi))) {
		vty_out(vty, "%% import|export vpn valid only for unicast ipv4|ipv6\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!strcmp(direction_str, "import")) {
		flag = BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT;
		dir = BGP_VPN_POLICY_DIR_FROMVPN;
	} else if (!strcmp(direction_str, "export")) {
		flag = BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT;
		dir = BGP_VPN_POLICY_DIR_TOVPN;
	} else {
		vty_out(vty, "%% unknown direction %s\n", direction_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	previous_state = CHECK_FLAG(bgp->af_flags[afi][safi], flag);

	if (yes) {
		SET_FLAG(bgp->af_flags[afi][safi], flag);
		if (!previous_state) {
			/* trigger export current vrf */
			vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
		}
	} else {
		if (previous_state) {
			/* trigger un-export current vrf */
			vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);
		}
		UNSET_FLAG(bgp->af_flags[afi][safi], flag);
	}

	return CMD_SUCCESS;
}

DEFPY (af_routetarget_import,
       af_routetarget_import_cmd,
       "[no] <rt|route-target> redirect import RTLIST...",
       NO_STR
       "Specify route target list\n"
       "Specify route target list\n"
       "Flow-spec redirect type route target\n"
       "Import routes to this address-family\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct ecommunity *ecom = NULL;
	afi_t afi;
	int idx = 0;
	int yes = 1;

	if (argv_find(argv, argc, "no", &idx))
		yes = 0;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	if (yes) {
		if (!argv_find(argv, argc, "RTLIST", &idx)) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = set_ecom_list(vty, argc - idx, argv + idx, &ecom);
		if (ret != CMD_SUCCESS)
			return ret;
	}

	if (yes) {
		if (bgp->vpn_policy[afi].import_redirect_rtlist)
			ecommunity_free(&bgp->vpn_policy[afi]
					.import_redirect_rtlist);
		bgp->vpn_policy[afi].import_redirect_rtlist =
			ecommunity_dup(ecom);
	} else {
		if (bgp->vpn_policy[afi].import_redirect_rtlist)
			ecommunity_free(&bgp->vpn_policy[afi]
					.import_redirect_rtlist);
		bgp->vpn_policy[afi].import_redirect_rtlist = NULL;
	}

	if (ecom)
		ecommunity_free(&ecom);

	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_ipv4_safi,
	address_family_ipv4_safi_cmd,
	"address-family ipv4 [<unicast|multicast|vpn|labeled-unicast|flowspec>]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	BGP_SAFI_WITH_LABEL_HELP_STR)
{

	if (argc == 3) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		safi_t safi = bgp_vty_safi_from_str(argv[2]->text);
		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
		    && safi != SAFI_UNICAST && safi != SAFI_MULTICAST
		    && safi != SAFI_EVPN) {
			vty_out(vty,
				"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		vty->node = bgp_node_type(AFI_IP, safi);
	} else
		vty->node = BGP_IPV4_NODE;

	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_ipv6_safi,
	address_family_ipv6_safi_cmd,
	"address-family ipv6 [<unicast|multicast|vpn|labeled-unicast|flowspec>]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	BGP_SAFI_WITH_LABEL_HELP_STR)
{
	if (argc == 3) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		safi_t safi = bgp_vty_safi_from_str(argv[2]->text);
		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
		    && safi != SAFI_UNICAST && safi != SAFI_MULTICAST
		    && safi != SAFI_EVPN) {
			vty_out(vty,
				"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		vty->node = bgp_node_type(AFI_IP6, safi);
	} else
		vty->node = BGP_IPV6_NODE;

	return CMD_SUCCESS;
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN_NOSH (address_family_vpnv4,
       address_family_vpnv4_cmd,
       "address-family vpnv4 [unicast]",
       "Enter Address Family command mode\n"
       "Address Family\n"
       "Address Family modifier\n")
{
	vty->node = BGP_VPNV4_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_vpnv6,
       address_family_vpnv6_cmd,
       "address-family vpnv6 [unicast]",
       "Enter Address Family command mode\n"
       "Address Family\n"
       "Address Family modifier\n")
{
	vty->node = BGP_VPNV6_NODE;
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFUN_NOSH (address_family_evpn,
       address_family_evpn_cmd,
       "address-family l2vpn evpn",
       "Enter Address Family command mode\n"
       "Address Family\n"
       "Address Family modifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (exit_address_family,
       exit_address_family_cmd,
       "exit-address-family",
       "Exit from Address Family configuration mode\n")
{
	if (vty->node == BGP_IPV4_NODE || vty->node == BGP_IPV4M_NODE
	    || vty->node == BGP_IPV4L_NODE || vty->node == BGP_VPNV4_NODE
	    || vty->node == BGP_IPV6_NODE || vty->node == BGP_IPV6M_NODE
	    || vty->node == BGP_IPV6L_NODE || vty->node == BGP_VPNV6_NODE
	    || vty->node == BGP_EVPN_NODE
	    || vty->node == BGP_FLOWSPECV4_NODE
	    || vty->node == BGP_FLOWSPECV6_NODE)
		vty->node = BGP_NODE;
	return CMD_SUCCESS;
}

/* Recalculate bestpath and re-advertise a prefix */
static int bgp_clear_prefix(struct vty *vty, const char *view_name,
			    const char *ip_str, afi_t afi, safi_t safi,
			    struct prefix_rd *prd)
{
	int ret;
	struct prefix match;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_table *rib;

	/* BGP structure lookup. */
	if (view_name) {
		bgp = bgp_lookup_by_name(view_name);
		if (bgp == NULL) {
			vty_out(vty, "%% Can't find BGP instance %s\n",
				view_name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	/* Check IP address argument. */
	ret = str2prefix(ip_str, &match);
	if (!ret) {
		vty_out(vty, "%% address is malformed\n");
		return CMD_WARNING;
	}

	match.family = afi2family(afi);
	rib = bgp->rib[afi][safi];

	if (safi == SAFI_MPLS_VPN) {
		for (rn = bgp_table_top(rib); rn; rn = bgp_route_next(rn)) {
			if (prd && memcmp(rn->p.u.val, prd->val, 8) != 0)
				continue;

			table = bgp_node_get_bgp_table_info(rn);
			if (table != NULL) {

				if ((rm = bgp_node_match(table, &match))
				    != NULL) {
					if (rm->p.prefixlen
					    == match.prefixlen) {
						SET_FLAG(rm->flags,
							 BGP_NODE_USER_CLEAR);
						bgp_process(bgp, rm, afi, safi);
					}
					bgp_unlock_node(rm);
				}
			}
		}
	} else {
		if ((rn = bgp_node_match(rib, &match)) != NULL) {
			if (rn->p.prefixlen == match.prefixlen) {
				SET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);
				bgp_process(bgp, rn, afi, safi);
			}
			bgp_unlock_node(rn);
		}
	}

	return CMD_SUCCESS;
}

/* one clear bgp command to rule them all */
DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6|l2vpn> [<unicast|multicast|vpn|labeled-unicast|flowspec|evpn>]] <*|A.B.C.D|X:X::X:X|WORD|(1-4294967295)|external|peer-group PGNAME> [<soft [<in|out>]|in [prefix-filter]|out>]",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       "Address Family\n"
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Address Family modifier\n"
       "Clear all peers\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       "Clear peers with the AS number\n"
       "Clear all external peers\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR
       BGP_SOFT_OUT_STR
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n"
       BGP_SOFT_OUT_STR)
{
	char *vrf = NULL;

	afi_t afi = AFI_UNSPEC;
	safi_t safi = SAFI_UNSPEC;
	enum clear_sort clr_sort = clear_peer;
	enum bgp_clear_type clr_type;
	char *clr_arg = NULL;

	int idx = 0;

	/* clear [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi))
		argv_find_and_parse_safi(argv, argc, &idx, &safi);

	/* <*|A.B.C.D|X:X::X:X|WORD|(1-4294967295)|external|peer-group PGNAME> */
	if (argv_find(argv, argc, "*", &idx)) {
		clr_sort = clear_all;
	} else if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "X:X::X:X", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "peer-group", &idx)) {
		clr_sort = clear_group;
		idx++;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "PGNAME", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "WORD", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "(1-4294967295)", &idx)) {
		clr_sort = clear_as;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "external", &idx)) {
		clr_sort = clear_external;
	}

	/* [<soft [<in|out>]|in [prefix-filter]|out>] */
	if (argv_find(argv, argc, "soft", &idx)) {
		if (argv_find(argv, argc, "in", &idx)
		    || argv_find(argv, argc, "out", &idx))
			clr_type = strmatch(argv[idx]->text, "in")
					   ? BGP_CLEAR_SOFT_IN
					   : BGP_CLEAR_SOFT_OUT;
		else
			clr_type = BGP_CLEAR_SOFT_BOTH;
	} else if (argv_find(argv, argc, "in", &idx)) {
		clr_type = argv_find(argv, argc, "prefix-filter", &idx)
				   ? BGP_CLEAR_SOFT_IN_ORF_PREFIX
				   : BGP_CLEAR_SOFT_IN;
	} else if (argv_find(argv, argc, "out", &idx)) {
		clr_type = BGP_CLEAR_SOFT_OUT;
	} else
		clr_type = BGP_CLEAR_SOFT_NONE;

	return bgp_clear_vty(vty, vrf, afi, safi, clr_sort, clr_type, clr_arg);
}

DEFUN (clear_ip_bgp_prefix,
       clear_ip_bgp_prefix_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] prefix A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv4 prefix\n")
{
	char *vrf = NULL;
	char *prefix = NULL;

	int idx = 0;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}

	prefix = argv[argc - 1]->arg;

	return bgp_clear_prefix(vty, vrf, prefix, AFI_IP, SAFI_UNICAST, NULL);
}

DEFUN (clear_bgp_ipv6_safi_prefix,
       clear_bgp_ipv6_safi_prefix_cmd,
       "clear [ip] bgp ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;

	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);
	return bgp_clear_prefix(
		vty, NULL, prefix, AFI_IP6,
		safi, NULL);
}

DEFUN (clear_bgp_instance_ipv6_safi_prefix,
       clear_bgp_instance_ipv6_safi_prefix_cmd,
       "clear [ip] bgp <view|vrf> VIEWVRFNAME ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_vrfview = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;
	char *vrfview = NULL;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx_vrfview)) {
		vrfview = argv[idx_vrfview + 1]->arg;
		if (vrfview && strmatch(vrfview, VRF_DEFAULT_NAME))
			vrfview = NULL;
	} else if (argv_find(argv, argc, "view", &idx_vrfview)) {
		/* [<view> VIEWVRFNAME] */
		vrfview = argv[idx_vrfview + 1]->arg;
	}
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);

	return bgp_clear_prefix(
		vty, vrfview, prefix,
		AFI_IP6, safi, NULL);
}

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show [ip] bgp views",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show the defined BGP views\n")
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;

	vty_out(vty, "Defined BGP views:\n");
	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		/* Skip VRFs. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
			continue;
		vty_out(vty, "\t%s (AS%u)\n", bgp->name ? bgp->name : "(null)",
			bgp->as);
	}

	return CMD_SUCCESS;
}

DEFUN (show_bgp_vrfs,
       show_bgp_vrfs_cmd,
       "show [ip] bgp vrfs [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show BGP VRFs\n"
       JSON_STR)
{
	char buf[ETHER_ADDR_STRLEN];
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	int count = 0;

	if (uj) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		const char *name, *type;
		struct peer *peer;
		struct listnode *node2, *nnode2;
		int peers_cfg, peers_estb;
		json_object *json_vrf = NULL;

		/* Skip Views. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
			continue;

		count++;
		if (!uj && count == 1) {
			vty_out(vty,
				"%4s  %-5s  %-16s  %9s  %10s  %-37s\n",
				"Type", "Id", "routerId", "#PeersVfg",
				"#PeersEstb", "Name");
			vty_out(vty, "%11s  %-16s  %-21s  %-6s\n", " ",
				"L3-VNI", "RouterMAC", "Interface");
		}

		peers_cfg = peers_estb = 0;
		if (uj)
			json_vrf = json_object_new_object();


		for (ALL_LIST_ELEMENTS(bgp->peer, node2, nnode2, peer)) {
			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;
			peers_cfg++;
			if (peer->status == Established)
				peers_estb++;
		}

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			name = VRF_DEFAULT_NAME;
			type = "DFLT";
		} else {
			name = bgp->name;
			type = "VRF";
		}


		if (uj) {
			int64_t vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
						    ? -1
						    : (int64_t)bgp->vrf_id;
			json_object_string_add(json_vrf, "type", type);
			json_object_int_add(json_vrf, "vrfId", vrf_id_ui);
			json_object_string_add(json_vrf, "routerId",
					       inet_ntoa(bgp->router_id));
			json_object_int_add(json_vrf, "numConfiguredPeers",
					    peers_cfg);
			json_object_int_add(json_vrf, "numEstablishedPeers",
					    peers_estb);

			json_object_int_add(json_vrf, "l3vni", bgp->l3vni);
			json_object_string_add(
				json_vrf, "rmac",
				prefix_mac2str(&bgp->rmac, buf, sizeof(buf)));
			json_object_string_add(json_vrf, "interface",
				ifindex2ifname(bgp->l3vni_svi_ifindex,
					       bgp->vrf_id));
			json_object_object_add(json_vrfs, name, json_vrf);
		} else {
			vty_out(vty,
				"%4s  %-5d  %-16s  %-9u  %-10u  %-37s\n",
				type,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id,
				inet_ntoa(bgp->router_id), peers_cfg,
				peers_estb, name);
			vty_out(vty,"%11s  %-16u  %-21s  %-20s\n", " ",
				bgp->l3vni,
				prefix_mac2str(&bgp->rmac, buf, sizeof(buf)),
				ifindex2ifname(bgp->l3vni_svi_ifindex,
					       bgp->vrf_id));
		}
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);

		json_object_int_add(json, "totalVrfs", count);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		if (count)
			vty_out(vty,
				"\nTotal number of VRFs (including default): %d\n",
				count);
	}

	return CMD_SUCCESS;
}

DEFUN (show_bgp_mac_hash,
       show_bgp_mac_hash_cmd,
       "show bgp mac hash",
       SHOW_STR
       BGP_STR
       "Mac Address\n"
       "Mac Address database\n")
{
	bgp_mac_dump_table(vty);

	return CMD_SUCCESS;
}

static void show_tip_entry(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct tip_addr *tip = (struct tip_addr *)bucket->data;

	vty_out(vty, "addr: %s, count: %d\n", inet_ntoa(tip->addr),
		tip->refcnt);
}

static void bgp_show_martian_nexthops(struct vty *vty, struct bgp *bgp)
{
	vty_out(vty, "self nexthop database:\n");
	bgp_nexthop_show_address_hash(vty, bgp);

	vty_out(vty, "Tunnel-ip database:\n");
	hash_iterate(bgp->tip_hash,
		     (void (*)(struct hash_bucket *, void *))show_tip_entry,
		     vty);
}

DEFUN(show_bgp_martian_nexthop_db, show_bgp_martian_nexthop_db_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] martian next-hop",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "martian next-hops\n"
      "martian next-hop database\n")
{
	struct bgp *bgp = NULL;
	int idx = 0;
	char *name = NULL;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		name = argv[idx + 1]->arg;
		if (name && strmatch(name, VRF_DEFAULT_NAME))
			name = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		name = argv[idx + 1]->arg;
	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (!bgp) {
		vty_out(vty, "%% No BGP process is configured\n");
		return CMD_WARNING;
	}
	bgp_show_martian_nexthops(vty, bgp);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_memory,
       show_bgp_memory_cmd,
       "show [ip] bgp memory",
       SHOW_STR
       IP_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
	char memstrbuf[MTYPE_MEMSTR_LEN];
	unsigned long count;

	/* RIB related usage stats */
	count = mtype_stats_alloc(MTYPE_BGP_NODE);
	vty_out(vty, "%ld RIB nodes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_node)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE);
	vty_out(vty, "%ld BGP routes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_path_info)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA)))
		vty_out(vty, "%ld BGP route ancillaries, using %s of memory\n",
			count,
			mtype_memstr(
				memstrbuf, sizeof(memstrbuf),
				count * sizeof(struct bgp_path_info_extra)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_STATIC)))
		vty_out(vty, "%ld Static routes, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_static)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_PACKET)))
		vty_out(vty, "%ld Packets, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bpacket)));

	/* Adj-In/Out */
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_IN)))
		vty_out(vty, "%ld Adj-In entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_in)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_OUT)))
		vty_out(vty, "%ld Adj-Out entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_out)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_NEXTHOP_CACHE)))
		vty_out(vty, "%ld Nexthop cache entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_nexthop_cache)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_DAMP_INFO)))
		vty_out(vty, "%ld Dampening entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_damp_info)));

	/* Attributes */
	count = attr_count();
	vty_out(vty, "%ld BGP attributes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct attr)));

	if ((count = attr_unknown_count()))
		vty_out(vty, "%ld unknown attributes\n", count);

	/* AS_PATH attributes */
	count = aspath_count();
	vty_out(vty, "%ld BGP AS-PATH entries, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct aspath)));

	count = mtype_stats_alloc(MTYPE_AS_SEG);
	vty_out(vty, "%ld BGP AS-PATH segments, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct assegment)));

	/* Other attributes */
	if ((count = community_count()))
		vty_out(vty, "%ld BGP community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct community)));
	if ((count = mtype_stats_alloc(MTYPE_ECOMMUNITY)))
		vty_out(vty, "%ld BGP community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct ecommunity)));
	if ((count = mtype_stats_alloc(MTYPE_LCOMMUNITY)))
		vty_out(vty,
			"%ld BGP large-community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct lcommunity)));

	if ((count = mtype_stats_alloc(MTYPE_CLUSTER)))
		vty_out(vty, "%ld Cluster lists, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct cluster_list)));

	/* Peer related usage */
	count = mtype_stats_alloc(MTYPE_BGP_PEER);
	vty_out(vty, "%ld peers, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct peer)));

	if ((count = mtype_stats_alloc(MTYPE_PEER_GROUP)))
		vty_out(vty, "%ld peer groups, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct peer_group)));

	/* Other */
	if ((count = mtype_stats_alloc(MTYPE_BGP_REGEXP)))
		vty_out(vty, "%ld compiled regexes, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(regex_t)));
	return CMD_SUCCESS;
}

static void bgp_show_bestpath_json(struct bgp *bgp, json_object *json)
{
	json_object *bestpath = json_object_new_object();

	if (bgp_flag_check(bgp, BGP_FLAG_ASPATH_IGNORE))
		json_object_string_add(bestpath, "asPath", "ignore");

	if (bgp_flag_check(bgp, BGP_FLAG_ASPATH_CONFED))
		json_object_string_add(bestpath, "asPath", "confed");

	if (bgp_flag_check(bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
		if (bgp_flag_check(bgp, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
			json_object_string_add(bestpath, "multiPathRelax",
					       "as-set");
		else
			json_object_string_add(bestpath, "multiPathRelax",
					       "true");
	} else
		json_object_string_add(bestpath, "multiPathRelax", "false");

	if (bgp_flag_check(bgp, BGP_FLAG_COMPARE_ROUTER_ID))
		json_object_string_add(bestpath, "compareRouterId", "true");
	if (bgp_flag_check(bgp, BGP_FLAG_MED_CONFED)
	    || bgp_flag_check(bgp, BGP_FLAG_MED_MISSING_AS_WORST)) {
		if (bgp_flag_check(bgp, BGP_FLAG_MED_CONFED))
			json_object_string_add(bestpath, "med", "confed");
		if (bgp_flag_check(bgp, BGP_FLAG_MED_MISSING_AS_WORST))
			json_object_string_add(bestpath, "med",
					       "missing-as-worst");
		else
			json_object_string_add(bestpath, "med", "true");
	}

	json_object_object_add(json, "bestPath", bestpath);
}

/* Print the error code/subcode for why the peer is down */
static void bgp_show_peer_reset(struct vty * vty, struct peer *peer,
				json_object *json_peer, bool use_json)
{
	const char *code_str;
	const char *subcode_str;

	if (use_json) {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			char errorcodesubcode_hexstr[5];
			char errorcodesubcode_str[256];

			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str = bgp_notify_subcode_str(
					 peer->notify.code,
					 peer->notify.subcode);

			sprintf(errorcodesubcode_hexstr, "%02X%02X",
				peer->notify.code, peer->notify.subcode);
			json_object_string_add(json_peer,
					       "lastErrorCodeSubcode",
					       errorcodesubcode_hexstr);
			snprintf(errorcodesubcode_str, 255, "%s%s",
				 code_str, subcode_str);
			json_object_string_add(json_peer,
					       "lastNotificationReason",
					       errorcodesubcode_str);
			if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED
			    && peer->notify.code == BGP_NOTIFY_CEASE
			    && (peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN
				|| peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_RESET)
			    && peer->notify.length) {
				char msgbuf[1024];
				const char *msg_str;

				msg_str = bgp_notify_admin_message(
					     msgbuf, sizeof(msgbuf),
					     (uint8_t *)peer->notify.data,
					     peer->notify.length);
				if (msg_str)
					json_object_string_add(
					   json_peer,
					   "lastShutdownDescription",
					   msg_str);
			}

		}
		json_object_string_add(json_peer, "lastResetDueTo",
				       peer_down_str[(int)peer->last_reset]);
		json_object_int_add(json_peer, "lastResetCode",
				    peer->last_reset);
	} else {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str =
				bgp_notify_subcode_str(peer->notify.code,
						       peer->notify.subcode);
			vty_out(vty, "  Notification %s (%s%s)\n",
				peer->last_reset == PEER_DOWN_NOTIFY_SEND
				? "sent"
				: "received",
				code_str, subcode_str);
		} else {
			vty_out(vty, "  %s\n",
				peer_down_str[(int)peer->last_reset]);
		}
	}
}

static inline bool bgp_has_peer_failed(struct peer *peer, afi_t afi,
				       safi_t safi)
{
	return ((peer->status != Established) ||
		!peer->afc_recv[afi][safi]);
}

static void bgp_show_failed_summary(struct vty *vty, struct bgp *bgp,
				    struct peer *peer, json_object *json_peer,
				    int max_neighbor_width, bool use_json)
{
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	int len;

	if (use_json) {
		if (peer_dynamic_neighbor(peer))
			json_object_boolean_true_add(json_peer,
						     "dynamicPeer");
		if (peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       peer->hostname);

		if (peer->domainname)
			json_object_string_add(json_peer, "domainname",
					       peer->domainname);
		json_object_int_add(json_peer, "connectionsEstablished",
				    peer->established);
		json_object_int_add(json_peer, "connectionsDropped",
				    peer->dropped);
		peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
			    use_json, json_peer);
		if (peer->status == Established)
			json_object_string_add(json_peer, "lastResetDueTo",
					       "AFI/SAFI Not Negotiated");
		else
			bgp_show_peer_reset(NULL, peer, json_peer, true);
	} else {
		dn_flag[1] = '\0';
		dn_flag[0] = peer_dynamic_neighbor(peer) ? '*' : '\0';
		if (peer->hostname
		    && bgp_flag_check(bgp, BGP_FLAG_SHOW_HOSTNAME))
			len = vty_out(vty, "%s%s(%s)", dn_flag,
				      peer->hostname, peer->host);
		else
			len = vty_out(vty, "%s%s", dn_flag, peer->host);

		/* pad the neighbor column with spaces */
		if (len < max_neighbor_width)
			vty_out(vty, "%*s", max_neighbor_width - len,
				" ");
		vty_out(vty, "%7d %7d %8s", peer->established,
			peer->dropped,
			peer_uptime(peer->uptime, timebuf,
				    BGP_UPTIME_LEN, 0, NULL));
		if (peer->status == Established)
			vty_out(vty, "  AFI/SAFI Not Negotiated\n");
		else
			bgp_show_peer_reset(vty, peer, NULL,
					    false);
	}
}


/* Show BGP peer's summary information. */
static int bgp_show_summary(struct vty *vty, struct bgp *bgp, int afi, int safi,
			    bool show_failed, bool use_json)
{
	struct peer *peer;
	struct listnode *node, *nnode;
	unsigned int count = 0, dn_count = 0;
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	char neighbor_buf[VTY_BUFSIZ];
	int neighbor_col_default_width = 16;
	int len, failed_count = 0;
	int max_neighbor_width = 0;
	int pfx_rcd_safi;
	json_object *json = NULL;
	json_object *json_peer = NULL;
	json_object *json_peers = NULL;
	struct peer_af *paf;

	/* labeled-unicast routes are installed in the unicast table so in order
	 * to
	 * display the correct PfxRcd value we must look at SAFI_UNICAST
	 */

	if (safi == SAFI_LABELED_UNICAST)
		pfx_rcd_safi = SAFI_UNICAST;
	else
		pfx_rcd_safi = safi;

	if (use_json) {
		json = json_object_new_object();
		json_peers = json_object_new_object();
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;

			if (peer->afc[afi][safi]) {
				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
			if (peer_dynamic_neighbor(peer))
				dn_count++;
		}

	} else {
		/* Loop over all neighbors that will be displayed to determine
		 * how many
		 * characters are needed for the Neighbor column
		 */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;

			if (peer->afc[afi][safi]) {
				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer))
					dn_flag[0] = '*';

				if (peer->hostname
				    && bgp_flag_check(bgp,
						      BGP_FLAG_SHOW_HOSTNAME))
					sprintf(neighbor_buf, "%s%s(%s) ",
						dn_flag, peer->hostname,
						peer->host);
				else
					sprintf(neighbor_buf, "%s%s ", dn_flag,
						peer->host);

				len = strlen(neighbor_buf);

				if (len > max_neighbor_width)
					max_neighbor_width = len;

				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
		}

		/* Originally we displayed the Neighbor column as 16
		 * characters wide so make that the default
		 */
		if (max_neighbor_width < neighbor_col_default_width)
			max_neighbor_width = neighbor_col_default_width;
	}

	if (show_failed && !failed_count) {
		if (use_json) {
			json_object_int_add(json, "failedPeersCount", 0);
			json_object_int_add(json, "dynamicPeers", dn_count);
			json_object_int_add(json, "totalPeers", count);

			vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		} else {
			vty_out(vty, "%% No failed BGP neighbors found\n");
			vty_out(vty, "\nTotal number of neighbors %d\n", count);
		}
		return CMD_SUCCESS;
	}

	count = 0;		/* Reset the value as its used again */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (!peer->afc[afi][safi])
			continue;

		if (!count) {
			unsigned long ents;
			char memstrbuf[MTYPE_MEMSTR_LEN];
			int64_t vrf_id_ui;

			vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;

			/* Usage summary and header */
			if (use_json) {
				json_object_string_add(
					json, "routerId",
					inet_ntoa(bgp->router_id));
				json_object_int_add(json, "as", bgp->as);
				json_object_int_add(json, "vrfId", vrf_id_ui);
				json_object_string_add(
					json, "vrfName",
					(bgp->inst_type
					 == BGP_INSTANCE_TYPE_DEFAULT)
						? VRF_DEFAULT_NAME
						: bgp->name);
			} else {
				vty_out(vty,
					"BGP router identifier %s, local AS number %u vrf-id %d",
					inet_ntoa(bgp->router_id), bgp->as,
					bgp->vrf_id == VRF_UNKNOWN
						? -1
						: (int)bgp->vrf_id);
				vty_out(vty, "\n");
			}

			if (bgp_update_delay_configured(bgp)) {
				if (use_json) {
					json_object_int_add(
						json, "updateDelayLimit",
						bgp->v_update_delay);

					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						json_object_int_add(
							json,
							"updateDelayEstablishWait",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						json_object_string_add(
							json,
							"updateDelayFirstNeighbor",
							bgp->update_delay_begin_time);
						json_object_boolean_true_add(
							json,
							"updateDelayInProgress");
					} else {
						if (bgp->update_delay_over) {
							json_object_string_add(
								json,
								"updateDelayFirstNeighbor",
								bgp->update_delay_begin_time);
							json_object_string_add(
								json,
								"updateDelayBestpathResumed",
								bgp->update_delay_end_time);
							json_object_string_add(
								json,
								"updateDelayZebraUpdateResume",
								bgp->update_delay_zebra_resume_time);
							json_object_string_add(
								json,
								"updateDelayPeerUpdateResume",
								bgp->update_delay_peers_resume_time);
						}
					}
				} else {
					vty_out(vty,
						"Read-only mode update-delay limit: %d seconds\n",
						bgp->v_update_delay);
					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						vty_out(vty,
							"                   Establish wait: %d seconds\n",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						vty_out(vty,
							"  First neighbor established: %s\n",
							bgp->update_delay_begin_time);
						vty_out(vty,
							"  Delay in progress\n");
					} else {
						if (bgp->update_delay_over) {
							vty_out(vty,
								"  First neighbor established: %s\n",
								bgp->update_delay_begin_time);
							vty_out(vty,
								"          Best-paths resumed: %s\n",
								bgp->update_delay_end_time);
							vty_out(vty,
								"        zebra update resumed: %s\n",
								bgp->update_delay_zebra_resume_time);
							vty_out(vty,
								"        peers update resumed: %s\n",
								bgp->update_delay_peers_resume_time);
						}
					}
				}
			}

			if (use_json) {
				if (bgp_maxmed_onstartup_configured(bgp)
				    && bgp->maxmed_active)
					json_object_boolean_true_add(
						json, "maxMedOnStartup");
				if (bgp->v_maxmed_admin)
					json_object_boolean_true_add(
						json, "maxMedAdministrative");

				json_object_int_add(
					json, "tableVersion",
					bgp_table_version(bgp->rib[afi][safi]));

				ents = bgp_table_count(bgp->rib[afi][safi]);
				json_object_int_add(json, "ribCount", ents);
				json_object_int_add(
					json, "ribMemory",
					ents * sizeof(struct bgp_node));

				ents = bgp->af_peer_count[afi][safi];
				json_object_int_add(json, "peerCount", ents);
				json_object_int_add(json, "peerMemory",
						    ents * sizeof(struct peer));

				if ((ents = listcount(bgp->group))) {
					json_object_int_add(
						json, "peerGroupCount", ents);
					json_object_int_add(
						json, "peerGroupMemory",
						ents * sizeof(struct
							      peer_group));
				}

				if (CHECK_FLAG(bgp->af_flags[afi][safi],
					       BGP_CONFIG_DAMPENING))
					json_object_boolean_true_add(
						json, "dampeningEnabled");
			} else {
				if (bgp_maxmed_onstartup_configured(bgp)
				    && bgp->maxmed_active)
					vty_out(vty,
						"Max-med on-startup active\n");
				if (bgp->v_maxmed_admin)
					vty_out(vty,
						"Max-med administrative active\n");

				vty_out(vty, "BGP table version %" PRIu64 "\n",
					bgp_table_version(bgp->rib[afi][safi]));

				ents = bgp_table_count(bgp->rib[afi][safi]);
				vty_out(vty,
					"RIB entries %ld, using %s of memory\n",
					ents,
					mtype_memstr(memstrbuf,
						     sizeof(memstrbuf),
						     ents * sizeof(struct
								   bgp_node)));

				/* Peer related usage */
				ents = bgp->af_peer_count[afi][safi];
				vty_out(vty, "Peers %ld, using %s of memory\n",
					ents,
					mtype_memstr(
						memstrbuf, sizeof(memstrbuf),
						ents * sizeof(struct peer)));

				if ((ents = listcount(bgp->group)))
					vty_out(vty,
						"Peer groups %ld, using %s of memory\n",
						ents,
						mtype_memstr(
							memstrbuf,
							sizeof(memstrbuf),
							ents * sizeof(struct
								      peer_group)));

				if (CHECK_FLAG(bgp->af_flags[afi][safi],
					       BGP_CONFIG_DAMPENING))
					vty_out(vty, "Dampening enabled.\n");
				vty_out(vty, "\n");

				/* Subtract 8 here because 'Neighbor' is
				 * 8 characters */
				vty_out(vty, "Neighbor");
				vty_out(vty, "%*s", max_neighbor_width - 8,
					" ");
				if (show_failed)
					vty_out(vty, "EstdCnt DropCnt ResetTime Reason\n");
				else
					vty_out(vty,
					"V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd\n");
			}
		}

		count++;
		/* Works for both failed & successful cases */
		if (peer_dynamic_neighbor(peer))
			dn_count++;

		if (use_json) {
			json_peer = NULL;

			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				json_peer = json_object_new_object();
				bgp_show_failed_summary(vty, bgp, peer,
							json_peer, 0, use_json);
			} else if (!show_failed) {
				json_peer = json_object_new_object();
				if (peer_dynamic_neighbor(peer)) {
					json_object_boolean_true_add(json_peer,
								     "dynamicPeer");
				}

				if (peer->hostname)
					json_object_string_add(json_peer, "hostname",
							       peer->hostname);

				if (peer->domainname)
					json_object_string_add(json_peer, "domainname",
							       peer->domainname);

				json_object_int_add(json_peer, "remoteAs", peer->as);
				json_object_int_add(json_peer, "version", 4);
				json_object_int_add(json_peer, "msgRcvd",
						    PEER_TOTAL_RX(peer));
				json_object_int_add(json_peer, "msgSent",
						    PEER_TOTAL_TX(peer));

				json_object_int_add(json_peer, "tableVersion",
						    peer->version[afi][safi]);
				json_object_int_add(json_peer, "outq",
						    peer->obuf->count);
				json_object_int_add(json_peer, "inq", 0);
				peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
					    use_json, json_peer);

				/*
				 * Adding "pfxRcd" field to match with the corresponding
				 * CLI. "prefixReceivedCount" will be deprecated in
				 * future.
				 */
				json_object_int_add(json_peer, "prefixReceivedCount",
						    peer->pcount[afi][pfx_rcd_safi]);
				json_object_int_add(json_peer, "pfxRcd",
						    peer->pcount[afi][pfx_rcd_safi]);

				paf = peer_af_find(peer, afi, pfx_rcd_safi);
				if (paf && PAF_SUBGRP(paf))
					json_object_int_add(json_peer,
							    "pfxSnt",
							    (PAF_SUBGRP(paf))->scount);
				if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
					json_object_string_add(json_peer, "state",
							       "Idle (Admin)");
				else if (peer->afc_recv[afi][safi])
					json_object_string_add(
							       json_peer, "state",
							       lookup_msg(bgp_status_msg, peer->status,
									  NULL));
				else if (CHECK_FLAG(peer->sflags,
						    PEER_STATUS_PREFIX_OVERFLOW))
					json_object_string_add(json_peer, "state",
							       "Idle (PfxCt)");
				else
					json_object_string_add(
							       json_peer, "state",
							       lookup_msg(bgp_status_msg, peer->status,
									  NULL));
				json_object_int_add(json_peer, "connectionsEstablished",
						    peer->established);
				json_object_int_add(json_peer, "connectionsDropped",
						    peer->dropped);
			}
			/* Avoid creating empty peer dicts in JSON */
			if (json_peer == NULL)
				continue;

			if (peer->conf_if)
				json_object_string_add(json_peer, "idType",
						       "interface");
			else if (peer->su.sa.sa_family == AF_INET)
				json_object_string_add(json_peer, "idType",
						       "ipv4");
			else if (peer->su.sa.sa_family == AF_INET6)
				json_object_string_add(json_peer, "idType",
						       "ipv6");
			json_object_object_add(json_peers, peer->host,
					       json_peer);
		} else {
			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				bgp_show_failed_summary(vty, bgp, peer, NULL,
							max_neighbor_width,
							use_json);
			} else if (!show_failed) {
				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer)) {
					dn_flag[0] = '*';
				}

				if (peer->hostname
				    && bgp_flag_check(bgp, BGP_FLAG_SHOW_HOSTNAME))
					len = vty_out(vty, "%s%s(%s)", dn_flag,
						      peer->hostname, peer->host);
				else
					len = vty_out(vty, "%s%s", dn_flag, peer->host);

				/* pad the neighbor column with spaces */
				if (len < max_neighbor_width)
					vty_out(vty, "%*s", max_neighbor_width - len,
						" ");

				vty_out(vty, "4 %10u %7u %7u %8" PRIu64 " %4d %4zd %8s",
					peer->as, PEER_TOTAL_RX(peer),
					PEER_TOTAL_TX(peer), peer->version[afi][safi],
					0, peer->obuf->count,
					peer_uptime(peer->uptime, timebuf,
						    BGP_UPTIME_LEN, 0, NULL));

				if (peer->status == Established)
					if (peer->afc_recv[afi][safi])
						vty_out(vty, " %12" PRIu32,
							peer->pcount
								[afi]
								[pfx_rcd_safi]);
					else
						vty_out(vty, " NoNeg");
				else {
					if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
						vty_out(vty, " Idle (Admin)");
					else if (CHECK_FLAG(
							    peer->sflags,
							    PEER_STATUS_PREFIX_OVERFLOW))
						vty_out(vty, " Idle (PfxCt)");
					else
						vty_out(vty, " %12s",
							lookup_msg(bgp_status_msg,
								   peer->status, NULL));
				}
				vty_out(vty, "\n");
			}

		}
	}

	if (use_json) {
		json_object_object_add(json, "peers", json_peers);
		json_object_int_add(json, "failedPeers", failed_count);
		json_object_int_add(json, "totalPeers", count);
		json_object_int_add(json, "dynamicPeers", dn_count);

		if (!show_failed)
			bgp_show_bestpath_json(bgp, json);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		if (count)
			vty_out(vty, "\nTotal number of neighbors %d\n", count);
		else {
			vty_out(vty, "No %s neighbor is configured\n",
				get_afi_safi_str(afi, safi, false));
		}

		if (dn_count) {
			vty_out(vty, "* - dynamic neighbor\n");
			vty_out(vty, "%d dynamic neighbor(s), limit %d\n",
				dn_count, bgp->dynamic_neighbors_limit);
		}
	}

	return CMD_SUCCESS;
}

static void bgp_show_summary_afi_safi(struct vty *vty, struct bgp *bgp, int afi,
				      int safi, bool show_failed, bool use_json)
{
	int is_first = 1;
	int afi_wildcard = (afi == AFI_MAX);
	int safi_wildcard = (safi == SAFI_MAX);
	int is_wildcard = (afi_wildcard || safi_wildcard);
	bool nbr_output = false;

	if (use_json && is_wildcard)
		vty_out(vty, "{\n");
	if (afi_wildcard)
		afi = 1; /* AFI_IP */
	while (afi < AFI_MAX) {
		if (safi_wildcard)
			safi = 1; /* SAFI_UNICAST */
		while (safi < SAFI_MAX) {
			if (bgp_afi_safi_peer_exists(bgp, afi, safi)) {
				nbr_output = true;

				if (is_wildcard) {
					/*
					 * So limit output to those afi/safi
					 * pairs that
					 * actualy have something interesting in
					 * them
					 */
					if (use_json) {
						if (!is_first)
							vty_out(vty, ",\n");
						else
							is_first = 0;

						vty_out(vty, "\"%s\":",
							get_afi_safi_str(afi,
									 safi,
									 true));
					} else {
						vty_out(vty, "\n%s Summary:\n",
							get_afi_safi_str(afi,
									 safi,
									 false));
					}
				}
				bgp_show_summary(vty, bgp, afi, safi, show_failed,
						 use_json);
			}
			safi++;
			if (!safi_wildcard)
				safi = SAFI_MAX;
		}
		afi++;
		if (!afi_wildcard)
			afi = AFI_MAX;
	}

	if (use_json && is_wildcard)
		vty_out(vty, "}\n");
	else if (!nbr_output) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No BGP neighbors found\n");
	}
}

static void bgp_show_all_instances_summary_vty(struct vty *vty, afi_t afi,
					       safi_t safi, bool show_failed,
					       bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	int is_first = 1;
	bool nbr_output = false;

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		nbr_output = true;
		if (use_json) {
			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, show_failed,
					  use_json);
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

int bgp_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, bool show_failed, bool use_json)
{
	struct bgp *bgp;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_summary_vty(vty, afi, safi,
							   show_failed,
							   use_json);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);

			if (!bgp) {
				if (use_json)
					vty_out(vty, "{}\n");
				else
					vty_out(vty,
						"%% BGP instance not found\n");
				return CMD_WARNING;
			}

			bgp_show_summary_afi_safi(vty, bgp, afi, safi,
						  show_failed, use_json);
			return CMD_SUCCESS;
		}
	}

	bgp = bgp_get_default();

	if (bgp)
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, show_failed,
					  use_json);
	else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* `show [ip] bgp summary' commands. */
DEFUN (show_ip_bgp_summary,
       show_ip_bgp_summary_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] summary [failed] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Summary of BGP neighbor status\n"
       "Show only sessions not in Established state\n"
       JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;
	bool show_failed = false;

	int idx = 0;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	if (argv_find(argv, argc, "failed", &idx))
		show_failed = true;

	bool uj = use_json(argc, argv);

	return bgp_show_summary_vty(vty, vrf, afi, safi, show_failed, uj);
}

const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json)
{
	if (for_json)
		return get_afi_safi_json_str(afi, safi);
	else
		return get_afi_safi_vty_str(afi, safi);
}

/* Show BGP peer's information. */
enum show_type { show_all, show_peer, show_ipv4_all, show_ipv6_all, show_ipv4_peer, show_ipv6_peer };

static void bgp_show_peer_afi_orf_cap(struct vty *vty, struct peer *p,
				      afi_t afi, safi_t safi,
				      uint16_t adv_smcap, uint16_t adv_rmcap,
				      uint16_t rcv_smcap, uint16_t rcv_rmcap,
				      bool use_json, json_object *json_pref)
{
	/* Send-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "received");
		} else {
			vty_out(vty, "      Send-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_smcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}

	/* Receive-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "received");
		} else {
			vty_out(vty, "      Receive-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_rmcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}
}

static void bgp_show_peer_afi(struct vty *vty, struct peer *p, afi_t afi,
			      safi_t safi, bool use_json,
			      json_object *json_neigh)
{
	struct bgp_filter *filter;
	struct peer_af *paf;
	char orf_pfx_name[BUFSIZ];
	int orf_pfx_count;
	json_object *json_af = NULL;
	json_object *json_prefA = NULL;
	json_object *json_prefB = NULL;
	json_object *json_addr = NULL;

	if (use_json) {
		json_addr = json_object_new_object();
		json_af = json_object_new_object();
		filter = &p->filter[afi][safi];

		if (peer_group_active(p))
			json_object_string_add(json_addr, "peerGroupMember",
					       p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			json_object_int_add(json_addr, "updateGroupId",
					    PAF_UPDGRP(paf)->id);
			json_object_int_add(json_addr, "subGroupId",
					    PAF_SUBGRP(paf)->id);
			json_object_int_add(json_addr, "packetQueueLength",
					    bpacket_queue_virtual_length(paf));
		}

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			json_object_int_add(json_af, "orfType",
					    ORF_TYPE_PREFIX);
			json_prefA = json_object_new_object();
			bgp_show_peer_afi_orf_cap(vty, p, afi, safi,
						  PEER_CAP_ORF_PREFIX_SM_ADV,
						  PEER_CAP_ORF_PREFIX_RM_ADV,
						  PEER_CAP_ORF_PREFIX_SM_RCV,
						  PEER_CAP_ORF_PREFIX_RM_RCV,
						  use_json, json_prefA);
			json_object_object_add(json_af, "orfPrefixList",
					       json_prefA);
		}

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_OLD_RCV)) {
			json_object_int_add(json_af, "orfOldType",
					    ORF_TYPE_PREFIX_OLD);
			json_prefB = json_object_new_object();
			bgp_show_peer_afi_orf_cap(
				vty, p, afi, safi, PEER_CAP_ORF_PREFIX_SM_ADV,
				PEER_CAP_ORF_PREFIX_RM_ADV,
				PEER_CAP_ORF_PREFIX_SM_OLD_RCV,
				PEER_CAP_ORF_PREFIX_RM_OLD_RCV, use_json,
				json_prefB);
			json_object_object_add(json_af, "orfOldPrefixList",
					       json_prefB);
		}

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
			json_object_object_add(json_addr, "afDependentCap",
					       json_af);
		else
			json_object_free(json_af);

		sprintf(orf_pfx_name, "%s.%d.%d", p->host, afi, safi);
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				json_object_boolean_true_add(json_neigh,
							     "orfSent");
			if (orf_pfx_count)
				json_object_int_add(json_addr, "orfRecvCounter",
						    orf_pfx_count);
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			json_object_string_add(
				json_addr, "orfFirstUpdate",
				"deferredUntilORFOrRouteRefreshRecvd");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeReflectorClient");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeServerClient");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			json_object_boolean_true_add(json_addr,
						     "inboundSoftConfigPermit");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllRemovedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsRemovedInUpdatesToNbr");

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			json_object_boolean_true_add(
				json_addr,
				bgp_addpath_names(p->addpath_type[afi][safi])
					->type_json_name);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			json_object_string_add(json_addr,
					       "overrideASNsInOutboundUpdates",
					       "ifAspathEqualRemoteAs");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF))
			json_object_boolean_true_add(json_addr,
						     "routerAlwaysNextHop");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedAsPathPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedNextHopPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedMedPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_EXT_COMMUNITY)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_SEND_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_EXT_COMMUNITY))
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "extendedAndStandard");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_EXT_COMMUNITY))
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "extended");
			else
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "standard");
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			if (p->default_rmap[afi][safi].name)
				json_object_string_add(
					json_addr, "defaultRouteMap",
					p->default_rmap[afi][safi].name);

			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
				json_object_boolean_true_add(json_addr,
							     "defaultSent");
			else
				json_object_boolean_true_add(json_addr,
							     "defaultNotSent");
		}

		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				json_object_boolean_true_add(
					json_addr, "advertiseAllVnis");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			json_object_boolean_true_add(json_addr,
						     "inboundPathPolicyConfig");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			json_object_boolean_true_add(
				json_addr, "outboundPathPolicyConfig");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdatePrefixFilterList",
					       filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdatePrefixFilterList",
					       filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			json_object_string_add(
				json_addr, "incomingUpdateNetworkFilterList",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			json_object_string_add(
				json_addr, "outgoingUpdateNetworkFilterList",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdateAsPathFilterList",
					       filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdateAsPathFilterList",
					       filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			json_object_string_add(
				json_addr, "routeMapForIncomingAdvertisements",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			json_object_string_add(
				json_addr, "routeMapForOutgoingAdvertisements",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (p->bgp->ebgp_requires_policy == DEFAULT_EBGP_POLICY_ENABLED
		    && !bgp_inbound_policy_exists(p, filter))
			json_object_string_add(
				json_addr, "inboundEbgpRequiresPolicy",
				"Inbound updates discarded due to missing policy");

		/* ebgp-requires-policy (outbound) */
		if (p->bgp->ebgp_requires_policy == DEFAULT_EBGP_POLICY_ENABLED
		    && (!bgp_outbound_policy_exists(p, filter)))
			json_object_string_add(
				json_addr, "outboundEbgpRequiresPolicy",
				"Outbound updates discarded due to missing policy");

		/* unsuppress-map */
		if (filter->usmap.name)
			json_object_string_add(json_addr,
					       "selectiveUnsuppressRouteMap",
					       filter->usmap.name);

		/* Receive prefix count */
		json_object_int_add(json_addr, "acceptedPrefixCounter",
				    p->pcount[afi][safi]);
		if (paf && PAF_SUBGRP(paf))
			json_object_int_add(json_addr, "sentPrefixCounter",
						(PAF_SUBGRP(paf))->scount);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			json_object_int_add(json_addr, "prefixAllowedMax",
					    p->pmax[afi][safi]);
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_MAX_PREFIX_WARNING))
				json_object_boolean_true_add(
					json_addr, "prefixAllowedMaxWarning");
			json_object_int_add(json_addr,
					    "prefixAllowedWarningThresh",
					    p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				json_object_int_add(
					json_addr,
					"prefixAllowedRestartIntervalMsecs",
					p->pmax_restart[afi][safi] * 60000);
		}
		json_object_object_add(json_neigh, get_afi_safi_str(afi, safi, true),
				       json_addr);

	} else {
		filter = &p->filter[afi][safi];

		vty_out(vty, " For address family: %s\n",
			get_afi_safi_str(afi, safi, false));

		if (peer_group_active(p))
			vty_out(vty, "  %s peer-group member\n",
				p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			vty_out(vty, "  Update group %" PRIu64
				     ", subgroup %" PRIu64 "\n",
				PAF_UPDGRP(paf)->id, PAF_SUBGRP(paf)->id);
			vty_out(vty, "  Packet Queue length %d\n",
				bpacket_queue_virtual_length(paf));
		} else {
			vty_out(vty, "  Not part of any update group\n");
		}
		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
			vty_out(vty, "  AF-dependant capabilities:\n");

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			vty_out(vty,
				"    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
				ORF_TYPE_PREFIX);
			bgp_show_peer_afi_orf_cap(
				vty, p, afi, safi, PEER_CAP_ORF_PREFIX_SM_ADV,
				PEER_CAP_ORF_PREFIX_RM_ADV,
				PEER_CAP_ORF_PREFIX_SM_RCV,
				PEER_CAP_ORF_PREFIX_RM_RCV, use_json, NULL);
		}
		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_OLD_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_OLD_RCV)) {
			vty_out(vty,
				"    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
				ORF_TYPE_PREFIX_OLD);
			bgp_show_peer_afi_orf_cap(
				vty, p, afi, safi, PEER_CAP_ORF_PREFIX_SM_ADV,
				PEER_CAP_ORF_PREFIX_RM_ADV,
				PEER_CAP_ORF_PREFIX_SM_OLD_RCV,
				PEER_CAP_ORF_PREFIX_RM_OLD_RCV, use_json, NULL);
		}

		sprintf(orf_pfx_name, "%s.%d.%d", p->host, afi, safi);
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			vty_out(vty, "  Outbound Route Filter (ORF):");
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				vty_out(vty, " sent;");
			if (orf_pfx_count)
				vty_out(vty, " received (%d entries)",
					orf_pfx_count);
			vty_out(vty, "\n");
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			vty_out(vty,
				"  First update is deferred until ORF or ROUTE-REFRESH is received\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			vty_out(vty, "  Route-Reflector Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			vty_out(vty, "  Route-Server Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			vty_out(vty,
				"  Inbound soft reconfiguration allowed\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			vty_out(vty,
				"  Private AS numbers (all) replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			vty_out(vty,
				"  Private AS numbers replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			vty_out(vty,
				"  Private AS numbers (all) removed in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			vty_out(vty,
				"  Private AS numbers removed in updates to this neighbor\n");

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			vty_out(vty, "  %s\n",
				bgp_addpath_names(p->addpath_type[afi][safi])
					->human_description);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			vty_out(vty,
				"  Override ASNs in outbound updates if aspath equals remote-as\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF))
			vty_out(vty, "  NEXT_HOP is always this router\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			vty_out(vty,
				"  AS_PATH is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			vty_out(vty,
				"  NEXT_HOP is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			vty_out(vty,
				"  MED is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_EXT_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_LARGE_COMMUNITY)) {
			vty_out(vty,
				"  Community attribute sent to this neighbor");
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_SEND_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_EXT_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(all)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(large)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_EXT_COMMUNITY))
				vty_out(vty, "(extended)\n");
			else
				vty_out(vty, "(standard)\n");
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			vty_out(vty, "  Default information originate,");

			if (p->default_rmap[afi][safi].name)
				vty_out(vty, " default route-map %s%s,",
					p->default_rmap[afi][safi].map ? "*"
								       : "",
					p->default_rmap[afi][safi].name);
			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
				vty_out(vty, " default sent\n");
			else
				vty_out(vty, " default not sent\n");
		}

		/* advertise-vni-all */
		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				vty_out(vty, "  advertise-all-vni\n");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			vty_out(vty, "  Inbound path policy configured\n");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			vty_out(vty, "  Outbound path policy configured\n");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update prefix filter list is %s%s\n",
				filter->plist[FILTER_IN].plist ? "*" : "",
				filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update prefix filter list is %s%s\n",
				filter->plist[FILTER_OUT].plist ? "*" : "",
				filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update network filter list is %s%s\n",
				filter->dlist[FILTER_IN].alist ? "*" : "",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update network filter list is %s%s\n",
				filter->dlist[FILTER_OUT].alist ? "*" : "",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update AS path filter list is %s%s\n",
				filter->aslist[FILTER_IN].aslist ? "*" : "",
				filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update AS path filter list is %s%s\n",
				filter->aslist[FILTER_OUT].aslist ? "*" : "",
				filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			vty_out(vty,
				"  Route map for incoming advertisements is %s%s\n",
				filter->map[RMAP_IN].map ? "*" : "",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			vty_out(vty,
				"  Route map for outgoing advertisements is %s%s\n",
				filter->map[RMAP_OUT].map ? "*" : "",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (p->bgp->ebgp_requires_policy == DEFAULT_EBGP_POLICY_ENABLED
		    && !bgp_inbound_policy_exists(p, filter))
			vty_out(vty,
				"  Inbound updates discarded due to missing policy\n");

		/* ebgp-requires-policy (outbound) */
		if (p->bgp->ebgp_requires_policy == DEFAULT_EBGP_POLICY_ENABLED
		    && !bgp_outbound_policy_exists(p, filter))
			vty_out(vty,
				"  Outbound updates discarded due to missing policy\n");

		/* unsuppress-map */
		if (filter->usmap.name)
			vty_out(vty,
				"  Route map for selective unsuppress is %s%s\n",
				filter->usmap.map ? "*" : "",
				filter->usmap.name);

		/* Receive prefix count */
		vty_out(vty, "  %" PRIu32 " accepted prefixes\n",
			p->pcount[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			vty_out(vty,
				"  Maximum prefixes allowed %" PRIu32 "%s\n",
				p->pmax[afi][safi],
				CHECK_FLAG(p->af_flags[afi][safi],
					   PEER_FLAG_MAX_PREFIX_WARNING)
					? " (warning-only)"
					: "");
			vty_out(vty, "  Threshold for warning message %d%%",
				p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				vty_out(vty, ", restart interval %d min",
					p->pmax_restart[afi][safi]);
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}
}

static void bgp_show_peer(struct vty *vty, struct peer *p, bool use_json,
			  json_object *json)
{
	struct bgp *bgp;
	char buf1[PREFIX2STR_BUFFER], buf[SU_ADDRSTRLEN];
	char timebuf[BGP_UPTIME_LEN];
	char dn_flag[2];
	afi_t afi;
	safi_t safi;
	uint16_t i;
	uint8_t *msg;
	json_object *json_neigh = NULL;
	time_t epoch_tbuf;

	bgp = p->bgp;

	if (use_json)
		json_neigh = json_object_new_object();

	memset(dn_flag, '\0', sizeof(dn_flag));
	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (!use_json) {
		if (p->conf_if) /* Configured interface name. */
			vty_out(vty, "BGP neighbor on %s: %s, ", p->conf_if,
				BGP_PEER_SU_UNSPEC(p)
					? "None"
					: sockunion2str(&p->su, buf,
							SU_ADDRSTRLEN));
		else /* Configured IP address. */
			vty_out(vty, "BGP neighbor is %s%s, ", dn_flag,
				p->host);
	}

	if (use_json) {
		if (p->conf_if && BGP_PEER_SU_UNSPEC(p))
			json_object_string_add(json_neigh, "bgpNeighborAddr",
					       "none");
		else if (p->conf_if && !BGP_PEER_SU_UNSPEC(p))
			json_object_string_add(
				json_neigh, "bgpNeighborAddr",
				sockunion2str(&p->su, buf, SU_ADDRSTRLEN));

		json_object_int_add(json_neigh, "remoteAs", p->as);

		if (p->change_local_as)
			json_object_int_add(json_neigh, "localAs",
					    p->change_local_as);
		else
			json_object_int_add(json_neigh, "localAs", p->local_as);

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
			json_object_boolean_true_add(json_neigh,
						     "localAsNoPrepend");

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS))
			json_object_boolean_true_add(json_neigh,
						     "localAsReplaceAs");
	} else {
		if ((p->as_type == AS_SPECIFIED) || (p->as_type == AS_EXTERNAL)
		    || (p->as_type == AS_INTERNAL))
			vty_out(vty, "remote AS %u, ", p->as);
		else
			vty_out(vty, "remote AS Unspecified, ");
		vty_out(vty, "local AS %u%s%s, ",
			p->change_local_as ? p->change_local_as : p->local_as,
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND)
				? " no-prepend"
				: "",
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS)
				? " replace-as"
				: "");
	}
	/* peer type internal or confed-internal */
	if ((p->as == p->local_as) || (p->as_type == AS_INTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedInternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrInternalLink");
		} else {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				vty_out(vty, "confed-internal link\n");
			else
				vty_out(vty, "internal link\n");
		}
	/* peer type external or confed-external */
	} else if (p->as || (p->as_type == AS_EXTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedExternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrExternalLink");
		} else {
			if (bgp_confederation_peers_check(bgp, p->as))
				vty_out(vty, "confed-external link\n");
			else
				vty_out(vty, "external link\n");
		}
	} else {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "nbrUnspecifiedLink");
		else
			vty_out(vty, "unspecified link\n");
	}

	/* Description. */
	if (p->desc) {
		if (use_json)
			json_object_string_add(json_neigh, "nbrDesc", p->desc);
		else
			vty_out(vty, " Description: %s\n", p->desc);
	}

	if (p->hostname) {
		if (use_json) {
			if (p->hostname)
				json_object_string_add(json_neigh, "hostname",
						       p->hostname);

			if (p->domainname)
				json_object_string_add(json_neigh, "domainname",
						       p->domainname);
		} else {
			if (p->domainname && (p->domainname[0] != '\0'))
				vty_out(vty, "Hostname: %s.%s\n", p->hostname,
					p->domainname);
			else
				vty_out(vty, "Hostname: %s\n", p->hostname);
		}
	}

	/* Peer-group */
	if (p->group) {
		if (use_json) {
			json_object_string_add(json_neigh, "peerGroup",
					       p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				sockunion2hostprefix(&(p->su), &prefix);
				range = peer_group_lookup_dynamic_neighbor_range(
					p->group, &prefix);

				if (range) {
					prefix2str(range, buf1, sizeof(buf1));
					json_object_string_add(
						json_neigh,
						"peerSubnetRangeGroup", buf1);
				}
			}
		} else {
			vty_out(vty,
				" Member of peer-group %s for session parameters\n",
				p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				sockunion2hostprefix(&(p->su), &prefix);
				range = peer_group_lookup_dynamic_neighbor_range(
					p->group, &prefix);

				if (range) {
					prefix2str(range, buf1, sizeof(buf1));
					vty_out(vty,
						" Belongs to the subnet range group: %s\n",
						buf1);
				}
			}
		}
	}

	if (use_json) {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN))
			json_object_boolean_true_add(json_neigh,
						     "adminShutDown");

		/* BGP Version. */
		json_object_int_add(json_neigh, "bgpVersion", 4);
		json_object_string_add(
			json_neigh, "remoteRouterId",
			inet_ntop(AF_INET, &p->remote_id, buf1, sizeof(buf1)));
		json_object_string_add(
			json_neigh, "localRouterId",
			inet_ntop(AF_INET, &bgp->router_id, buf1,
					sizeof(buf1)));

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			json_object_boolean_true_add(json_neigh,
						     "nbrCommonAdmin");

		/* Status. */
		json_object_string_add(
			json_neigh, "bgpState",
			lookup_msg(bgp_status_msg, p->status, NULL));

		if (p->status == Established) {
			time_t uptime;

			uptime = bgp_clock();
			uptime -= p->uptime;
			epoch_tbuf = time(NULL) - uptime;

#if CONFDATE > 20200101
			CPP_NOTICE(
				"bgpTimerUp should be deprecated and can be removed now");
#endif
			/*
			 * bgpTimerUp was miliseconds that was accurate
			 * up to 1 day, then the value returned
			 * became garbage.  So in order to provide
			 * some level of backwards compatability,
			 * we still provde the data, but now
			 * we are returning the correct value
			 * and also adding a new bgpTimerUpMsec
			 * which will allow us to deprecate
			 * this eventually
			 */
			json_object_int_add(json_neigh, "bgpTimerUp",
					    uptime * 1000);
			json_object_int_add(json_neigh, "bgpTimerUpMsec",
					    uptime * 1000);
			json_object_string_add(json_neigh, "bgpTimerUpString",
					       peer_uptime(p->uptime, timebuf,
							   BGP_UPTIME_LEN, 0,
							   NULL));
			json_object_int_add(json_neigh,
					    "bgpTimerUpEstablishedEpoch",
					    epoch_tbuf);
		}

		else if (p->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passive");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passiveNSF");
		}

		/* read timer */
		time_t uptime;
		struct tm *tm;

		uptime = bgp_clock();
		uptime -= p->readtime;
		tm = gmtime(&uptime);
		json_object_int_add(json_neigh, "bgpTimerLastRead",
				    (tm->tm_sec * 1000) + (tm->tm_min * 60000)
					    + (tm->tm_hour * 3600000));

		uptime = bgp_clock();
		uptime -= p->last_write;
		tm = gmtime(&uptime);
		json_object_int_add(json_neigh, "bgpTimerLastWrite",
				    (tm->tm_sec * 1000) + (tm->tm_min * 60000)
					    + (tm->tm_hour * 3600000));

		uptime = bgp_clock();
		uptime -= p->update_time;
		tm = gmtime(&uptime);
		json_object_int_add(json_neigh, "bgpInUpdateElapsedTimeMsecs",
				    (tm->tm_sec * 1000) + (tm->tm_min * 60000)
					    + (tm->tm_hour * 3600000));

		/* Configured timer values. */
		json_object_int_add(json_neigh, "bgpTimerHoldTimeMsecs",
				    p->v_holdtime * 1000);
		json_object_int_add(json_neigh,
				    "bgpTimerKeepAliveIntervalMsecs",
				    p->v_keepalive * 1000);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER)) {
			json_object_int_add(json_neigh,
					    "bgpTimerConfiguredHoldTimeMsecs",
					    p->holdtime * 1000);
			json_object_int_add(
				json_neigh,
				"bgpTimerConfiguredKeepAliveIntervalMsecs",
				p->keepalive * 1000);
		} else if ((bgp->default_holdtime != BGP_DEFAULT_HOLDTIME)
			   || (bgp->default_keepalive
			       != BGP_DEFAULT_KEEPALIVE)) {
			json_object_int_add(json_neigh,
					    "bgpTimerConfiguredHoldTimeMsecs",
					    bgp->default_holdtime);
			json_object_int_add(
				json_neigh,
				"bgpTimerConfiguredKeepAliveIntervalMsecs",
				bgp->default_keepalive);
		}
	} else {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN))
			vty_out(vty, " Administratively shut down\n");

		/* BGP Version. */
		vty_out(vty, "  BGP version 4");
		vty_out(vty, ", remote router ID %s",
			inet_ntop(AF_INET, &p->remote_id, buf1, sizeof(buf1)));
		vty_out(vty, ", local router ID %s\n",
			inet_ntop(AF_INET, &bgp->router_id, buf1,
					sizeof(buf1)));

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			vty_out(vty,
				"  Neighbor under common administration\n");

		/* Status. */
		vty_out(vty, "  BGP state = %s",
			lookup_msg(bgp_status_msg, p->status, NULL));

		if (p->status == Established)
			vty_out(vty, ", up for %8s",
				peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN,
					    0, NULL));

		else if (p->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				vty_out(vty, " (passive)");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				vty_out(vty, " (NSF passive)");
		}
		vty_out(vty, "\n");

		/* read timer */
		vty_out(vty, "  Last read %s",
			peer_uptime(p->readtime, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));
		vty_out(vty, ", Last write %s\n",
			peer_uptime(p->last_write, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));

		/* Configured timer values. */
		vty_out(vty,
			"  Hold time is %d, keepalive interval is %d seconds\n",
			p->v_holdtime, p->v_keepalive);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER)) {
			vty_out(vty, "  Configured hold time is %d",
				p->holdtime);
			vty_out(vty, ", keepalive interval is %d seconds\n",
				p->keepalive);
		} else if ((bgp->default_holdtime != BGP_DEFAULT_HOLDTIME)
			   || (bgp->default_keepalive
			       != BGP_DEFAULT_KEEPALIVE)) {
			vty_out(vty, "  Configured hold time is %d",
				bgp->default_holdtime);
			vty_out(vty, ", keepalive interval is %d seconds\n",
				bgp->default_keepalive);
		}
	}
	/* Capability. */
	if (p->status == Established) {
		if (p->cap || p->afc_adv[AFI_IP][SAFI_UNICAST]
		    || p->afc_recv[AFI_IP][SAFI_UNICAST]
		    || p->afc_adv[AFI_IP][SAFI_MULTICAST]
		    || p->afc_recv[AFI_IP][SAFI_MULTICAST]
		    || p->afc_adv[AFI_IP6][SAFI_UNICAST]
		    || p->afc_recv[AFI_IP6][SAFI_UNICAST]
		    || p->afc_adv[AFI_IP6][SAFI_MULTICAST]
		    || p->afc_recv[AFI_IP6][SAFI_MULTICAST]
		    || p->afc_adv[AFI_IP6][SAFI_MPLS_VPN]
		    || p->afc_recv[AFI_IP6][SAFI_MPLS_VPN]
		    || p->afc_adv[AFI_IP6][SAFI_ENCAP]
		    || p->afc_recv[AFI_IP6][SAFI_ENCAP]
		    || p->afc_adv[AFI_IP6][SAFI_FLOWSPEC]
		    || p->afc_recv[AFI_IP6][SAFI_FLOWSPEC]
		    || p->afc_adv[AFI_IP][SAFI_ENCAP]
		    || p->afc_recv[AFI_IP][SAFI_ENCAP]
		    || p->afc_adv[AFI_IP][SAFI_FLOWSPEC]
		    || p->afc_recv[AFI_IP][SAFI_FLOWSPEC]
		    || p->afc_adv[AFI_IP][SAFI_MPLS_VPN]
		    || p->afc_recv[AFI_IP][SAFI_MPLS_VPN]) {
			if (use_json) {
				json_object *json_cap = NULL;

				json_cap = json_object_new_object();

				/* AS4 */
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV)
				    || CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
					if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)
					    && CHECK_FLAG(p->cap,
							  PEER_CAP_AS4_RCV))
						json_object_string_add(
							json_cap, "4byteAs",
							"advertisedAndReceived");
					else if (CHECK_FLAG(p->cap,
							    PEER_CAP_AS4_ADV))
						json_object_string_add(
							json_cap, "4byteAs",
							"advertised");
					else if (CHECK_FLAG(p->cap,
							    PEER_CAP_AS4_RCV))
						json_object_string_add(
							json_cap, "4byteAs",
							"received");
				}

				/* AddPath */
				if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_ADDPATH_ADV)) {
					json_object *json_add = NULL;
					const char *print_store;

					json_add = json_object_new_object();

					FOREACH_AFI_SAFI (afi, safi) {
						json_object *json_sub = NULL;
						json_sub =
							json_object_new_object();
						print_store = get_afi_safi_str(
							afi, safi, true);

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_TX_RCV)) {
							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_TX_ADV)
							    && CHECK_FLAG(
								       p->af_cap
									       [afi]
									       [safi],
								       PEER_CAP_ADDPATH_AF_TX_RCV))
								json_object_boolean_true_add(
									json_sub,
									"txAdvertisedAndReceived");
							else if (
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_TX_ADV))
								json_object_boolean_true_add(
									json_sub,
									"txAdvertised");
							else if (
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_TX_RCV))
								json_object_boolean_true_add(
									json_sub,
									"txReceived");
						}

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_RX_RCV)) {
							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_RX_ADV)
							    && CHECK_FLAG(
								       p->af_cap
									       [afi]
									       [safi],
								       PEER_CAP_ADDPATH_AF_RX_RCV))
								json_object_boolean_true_add(
									json_sub,
									"rxAdvertisedAndReceived");
							else if (
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_RX_ADV))
								json_object_boolean_true_add(
									json_sub,
									"rxAdvertised");
							else if (
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_RX_RCV))
								json_object_boolean_true_add(
									json_sub,
									"rxReceived");
						}

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_TX_RCV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_RX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_RX_RCV))
							json_object_object_add(
								json_add,
								print_store,
								json_sub);
						else
							json_object_free(
								json_sub);
					}

					json_object_object_add(
						json_cap, "addPath", json_add);
				}

				/* Dynamic */
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_DYNAMIC_ADV)) {
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_DYNAMIC_ADV)
					    && CHECK_FLAG(p->cap,
							  PEER_CAP_DYNAMIC_RCV))
						json_object_string_add(
							json_cap, "dynamic",
							"advertisedAndReceived");
					else if (CHECK_FLAG(
							 p->cap,
							 PEER_CAP_DYNAMIC_ADV))
						json_object_string_add(
							json_cap, "dynamic",
							"advertised");
					else if (CHECK_FLAG(
							 p->cap,
							 PEER_CAP_DYNAMIC_RCV))
						json_object_string_add(
							json_cap, "dynamic",
							"received");
				}

				/* Extended nexthop */
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)
				    || CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
					json_object *json_nxt = NULL;
					const char *print_store;


					if (CHECK_FLAG(p->cap,
						       PEER_CAP_ENHE_ADV)
					    && CHECK_FLAG(p->cap,
							  PEER_CAP_ENHE_RCV))
						json_object_string_add(
							json_cap,
							"extendedNexthop",
							"advertisedAndReceived");
					else if (CHECK_FLAG(p->cap,
							    PEER_CAP_ENHE_ADV))
						json_object_string_add(
							json_cap,
							"extendedNexthop",
							"advertised");
					else if (CHECK_FLAG(p->cap,
							    PEER_CAP_ENHE_RCV))
						json_object_string_add(
							json_cap,
							"extendedNexthop",
							"received");

					if (CHECK_FLAG(p->cap,
						       PEER_CAP_ENHE_RCV)) {
						json_nxt =
							json_object_new_object();

						for (safi = SAFI_UNICAST;
						     safi < SAFI_MAX; safi++) {
							if (CHECK_FLAG(
								    p->af_cap
									    [AFI_IP]
									    [safi],
								    PEER_CAP_ENHE_AF_RCV)) {
								print_store = get_afi_safi_str(
									AFI_IP,
									safi, true);
								json_object_string_add(
									json_nxt,
									print_store,
									"recieved"); /* misspelled for compatibility */
							}
						}
						json_object_object_add(
							json_cap,
							"extendedNexthopFamililesByPeer",
							json_nxt);
					}
				}

				/* Route Refresh */
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_REFRESH_NEW_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_REFRESH_OLD_RCV)) {
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_REFRESH_ADV)
					    && (CHECK_FLAG(
							p->cap,
							PEER_CAP_REFRESH_NEW_RCV)
						|| CHECK_FLAG(
							   p->cap,
							   PEER_CAP_REFRESH_OLD_RCV))) {
						if (CHECK_FLAG(
							    p->cap,
							    PEER_CAP_REFRESH_OLD_RCV)
						    && CHECK_FLAG(
							       p->cap,
							       PEER_CAP_REFRESH_NEW_RCV))
							json_object_string_add(
								json_cap,
								"routeRefresh",
								"advertisedAndReceivedOldNew");
						else {
							if (CHECK_FLAG(
								    p->cap,
								    PEER_CAP_REFRESH_OLD_RCV))
								json_object_string_add(
									json_cap,
									"routeRefresh",
									"advertisedAndReceivedOld");
							else
								json_object_string_add(
									json_cap,
									"routeRefresh",
									"advertisedAndReceivedNew");
						}
					} else if (
						CHECK_FLAG(
							p->cap,
							PEER_CAP_REFRESH_ADV))
						json_object_string_add(
							json_cap,
							"routeRefresh",
							"advertised");
					else if (
						CHECK_FLAG(
							p->cap,
							PEER_CAP_REFRESH_NEW_RCV)
						|| CHECK_FLAG(
							   p->cap,
							   PEER_CAP_REFRESH_OLD_RCV))
						json_object_string_add(
							json_cap,
							"routeRefresh",
							"received");
				}

				/* Multiprotocol Extensions */
				json_object *json_multi = NULL;
				json_multi = json_object_new_object();

				FOREACH_AFI_SAFI (afi, safi) {
					if (p->afc_adv[afi][safi]
					    || p->afc_recv[afi][safi]) {
						json_object *json_exten = NULL;
						json_exten =
							json_object_new_object();

						if (p->afc_adv[afi][safi]
						    && p->afc_recv[afi][safi])
							json_object_boolean_true_add(
								json_exten,
								"advertisedAndReceived");
						else if (p->afc_adv[afi][safi])
							json_object_boolean_true_add(
								json_exten,
								"advertised");
						else if (p->afc_recv[afi][safi])
							json_object_boolean_true_add(
								json_exten,
								"received");

						json_object_object_add(
							json_multi,
							get_afi_safi_str(afi,
									 safi,
									 true),
							json_exten);
					}
				}
				json_object_object_add(
					json_cap, "multiprotocolExtensions",
					json_multi);

				/* Hostname capabilities */
				json_object *json_hname = NULL;

				json_hname = json_object_new_object();

				if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
					json_object_string_add(
						json_hname, "advHostName",
						bgp->peer_self->hostname
							? bgp->peer_self
								  ->hostname
							: "n/a");
					json_object_string_add(
						json_hname, "advDomainName",
						bgp->peer_self->domainname
							? bgp->peer_self
								  ->domainname
							: "n/a");
				}


				if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
					json_object_string_add(
						json_hname, "rcvHostName",
						p->hostname ? p->hostname
							    : "n/a");
					json_object_string_add(
						json_hname, "rcvDomainName",
						p->domainname ? p->domainname
							      : "n/a");
				}

				json_object_object_add(json_cap, "hostName",
						       json_hname);

				/* Gracefull Restart */
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_RESTART_ADV)) {
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_RESTART_ADV)
					    && CHECK_FLAG(p->cap,
							  PEER_CAP_RESTART_RCV))
						json_object_string_add(
							json_cap,
							"gracefulRestart",
							"advertisedAndReceived");
					else if (CHECK_FLAG(
							 p->cap,
							 PEER_CAP_RESTART_ADV))
						json_object_string_add(
							json_cap,
							"gracefulRestartCapability",
							"advertised");
					else if (CHECK_FLAG(
							 p->cap,
							 PEER_CAP_RESTART_RCV))
						json_object_string_add(
							json_cap,
							"gracefulRestartCapability",
							"received");

					if (CHECK_FLAG(p->cap,
						       PEER_CAP_RESTART_RCV)) {
						int restart_af_count = 0;
						json_object *json_restart =
							NULL;
						json_restart =
							json_object_new_object();

						json_object_int_add(
							json_cap,
							"gracefulRestartRemoteTimerMsecs",
							p->v_gr_restart * 1000);

						FOREACH_AFI_SAFI (afi, safi) {
							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_RESTART_AF_RCV)) {
								json_object *
									json_sub =
										NULL;
								json_sub =
									json_object_new_object();

								if (CHECK_FLAG(
									    p->af_cap
										    [afi]
										    [safi],
									    PEER_CAP_RESTART_AF_PRESERVE_RCV))
									json_object_boolean_true_add(
										json_sub,
										"preserved");
								restart_af_count++;
								json_object_object_add(
									json_restart,
									get_afi_safi_str(
										afi,
										safi,
										true),
									json_sub);
							}
						}
						if (!restart_af_count) {
							json_object_string_add(
								json_cap,
								"addressFamiliesByPeer",
								"none");
							json_object_free(
								json_restart);
						} else
							json_object_object_add(
								json_cap,
								"addressFamiliesByPeer",
								json_restart);
					}
				}
				json_object_object_add(json_neigh,
						       "neighborCapabilities",
						       json_cap);
			} else {
				vty_out(vty, "  Neighbor capabilities:\n");

				/* AS4 */
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV)
				    || CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
					vty_out(vty, "    4 Byte AS:");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_AS4_ADV))
						vty_out(vty, " advertised");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_AS4_RCV))
						vty_out(vty, " %sreceived",
							CHECK_FLAG(
								p->cap,
								PEER_CAP_AS4_ADV)
								? "and "
								: "");
					vty_out(vty, "\n");
				}

				/* AddPath */
				if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_ADDPATH_ADV)) {
					vty_out(vty, "    AddPath:\n");

					FOREACH_AFI_SAFI (afi, safi) {
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_TX_RCV)) {
							vty_out(vty,
								"      %s: TX ",
								get_afi_safi_str(
									afi,
									safi,
									false));

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_TX_ADV))
								vty_out(vty,
									"advertised %s",
									get_afi_safi_str(
										afi,
										safi,
										false));

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_TX_RCV))
								vty_out(vty,
									"%sreceived",
									CHECK_FLAG(
										p->af_cap
											[afi]
											[safi],
										PEER_CAP_ADDPATH_AF_TX_ADV)
										? " and "
										: "");

							vty_out(vty, "\n");
						}

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_ADV)
						    || CHECK_FLAG(
							       p->af_cap[afi]
									[safi],
							       PEER_CAP_ADDPATH_AF_RX_RCV)) {
							vty_out(vty,
								"      %s: RX ",
								get_afi_safi_str(
									afi,
									safi,
									false));

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_RX_ADV))
								vty_out(vty,
									"advertised %s",
									get_afi_safi_str(
										afi,
										safi,
										false));

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_ADDPATH_AF_RX_RCV))
								vty_out(vty,
									"%sreceived",
									CHECK_FLAG(
										p->af_cap
											[afi]
											[safi],
										PEER_CAP_ADDPATH_AF_RX_ADV)
										? " and "
										: "");

							vty_out(vty, "\n");
						}
					}
				}

				/* Dynamic */
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_DYNAMIC_ADV)) {
					vty_out(vty, "    Dynamic:");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_DYNAMIC_ADV))
						vty_out(vty, " advertised");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_DYNAMIC_RCV))
						vty_out(vty, " %sreceived",
							CHECK_FLAG(
								p->cap,
								PEER_CAP_DYNAMIC_ADV)
								? "and "
								: "");
					vty_out(vty, "\n");
				}

				/* Extended nexthop */
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)
				    || CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
					vty_out(vty, "    Extended nexthop:");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_ENHE_ADV))
						vty_out(vty, " advertised");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_ENHE_RCV))
						vty_out(vty, " %sreceived",
							CHECK_FLAG(
								p->cap,
								PEER_CAP_ENHE_ADV)
								? "and "
								: "");
					vty_out(vty, "\n");

					if (CHECK_FLAG(p->cap,
						       PEER_CAP_ENHE_RCV)) {
						vty_out(vty,
							"      Address families by peer:\n        ");
						for (safi = SAFI_UNICAST;
						     safi < SAFI_MAX; safi++)
							if (CHECK_FLAG(
								    p->af_cap
									    [AFI_IP]
									    [safi],
								    PEER_CAP_ENHE_AF_RCV))
								vty_out(vty,
									"           %s\n",
									get_afi_safi_str(
										AFI_IP,
										safi,
										false));
					}
				}

				/* Route Refresh */
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_REFRESH_NEW_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_REFRESH_OLD_RCV)) {
					vty_out(vty, "    Route refresh:");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_REFRESH_ADV))
						vty_out(vty, " advertised");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_REFRESH_NEW_RCV)
					    || CHECK_FLAG(
						       p->cap,
						       PEER_CAP_REFRESH_OLD_RCV))
						vty_out(vty, " %sreceived(%s)",
							CHECK_FLAG(
								p->cap,
								PEER_CAP_REFRESH_ADV)
								? "and "
								: "",
							(CHECK_FLAG(
								 p->cap,
								 PEER_CAP_REFRESH_OLD_RCV)
							 && CHECK_FLAG(
								    p->cap,
								    PEER_CAP_REFRESH_NEW_RCV))
								? "old & new"
								: CHECK_FLAG(
									  p->cap,
									  PEER_CAP_REFRESH_OLD_RCV)
									  ? "old"
									  : "new");

					vty_out(vty, "\n");
				}

				/* Multiprotocol Extensions */
				FOREACH_AFI_SAFI (afi, safi)
					if (p->afc_adv[afi][safi]
					    || p->afc_recv[afi][safi]) {
						vty_out(vty,
							"    Address Family %s:",
							get_afi_safi_str(
								   afi,
								   safi,
								   false));
						if (p->afc_adv[afi][safi])
							vty_out(vty,
								" advertised");
						if (p->afc_recv[afi][safi])
							vty_out(vty,
								" %sreceived",
								p->afc_adv[afi]
									  [safi]
									? "and "
									: "");
						vty_out(vty, "\n");
					}

				/* Hostname capability */
				vty_out(vty, "    Hostname Capability:");

				if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
					vty_out(vty,
						" advertised (name: %s,domain name: %s)",
						bgp->peer_self->hostname
							? bgp->peer_self
								  ->hostname
							: "n/a",
						bgp->peer_self->domainname
							? bgp->peer_self
								  ->domainname
							: "n/a");
				} else {
					vty_out(vty, " not advertised");
				}

				if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
					vty_out(vty,
						" received (name: %s,domain name: %s)",
						p->hostname ? p->hostname
							    : "n/a",
						p->domainname ? p->domainname
							      : "n/a");
				} else {
					vty_out(vty, " not received");
				}

				vty_out(vty, "\n");

				/* Gracefull Restart */
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)
				    || CHECK_FLAG(p->cap,
						  PEER_CAP_RESTART_ADV)) {
					vty_out(vty,
						"    Graceful Restart Capabilty:");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_RESTART_ADV))
						vty_out(vty, " advertised");
					if (CHECK_FLAG(p->cap,
						       PEER_CAP_RESTART_RCV))
						vty_out(vty, " %sreceived",
							CHECK_FLAG(
								p->cap,
								PEER_CAP_RESTART_ADV)
								? "and "
								: "");
					vty_out(vty, "\n");

					if (CHECK_FLAG(p->cap,
						       PEER_CAP_RESTART_RCV)) {
						int restart_af_count = 0;

						vty_out(vty,
							"      Remote Restart timer is %d seconds\n",
							p->v_gr_restart);
						vty_out(vty,
							"      Address families by peer:\n        ");

						FOREACH_AFI_SAFI (afi, safi)
							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_RESTART_AF_RCV)) {
								vty_out(vty,
									"%s%s(%s)",
									restart_af_count
										? ", "
										: "",
									get_afi_safi_str(
										afi,
										safi,
										false),
									CHECK_FLAG(
										p->af_cap
											[afi]
											[safi],
										PEER_CAP_RESTART_AF_PRESERVE_RCV)
										? "preserved"
										: "not preserved");
								restart_af_count++;
							}
						if (!restart_af_count)
							vty_out(vty, "none");
						vty_out(vty, "\n");
					}
				}
			}
		}
	}

	/* graceful restart information */
	if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) || p->t_gr_restart
	    || p->t_gr_stale) {
		json_object *json_grace = NULL;
		json_object *json_grace_send = NULL;
		json_object *json_grace_recv = NULL;
		int eor_send_af_count = 0;
		int eor_receive_af_count = 0;

		if (use_json) {
			json_grace = json_object_new_object();
			json_grace_send = json_object_new_object();
			json_grace_recv = json_object_new_object();

			if (p->status == Established) {
				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(p->af_sflags[afi][safi],
						       PEER_STATUS_EOR_SEND)) {
						json_object_boolean_true_add(
							json_grace_send,
							get_afi_safi_str(afi,
									 safi,
									 true));
						eor_send_af_count++;
					}
				}
				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(
						    p->af_sflags[afi][safi],
						    PEER_STATUS_EOR_RECEIVED)) {
						json_object_boolean_true_add(
							json_grace_recv,
							get_afi_safi_str(afi,
									 safi,
									 true));
						eor_receive_af_count++;
					}
				}
			}

			json_object_object_add(json_grace, "endOfRibSend",
					       json_grace_send);
			json_object_object_add(json_grace, "endOfRibRecv",
					       json_grace_recv);

			if (p->t_gr_restart)
				json_object_int_add(json_grace,
						    "gracefulRestartTimerMsecs",
						    thread_timer_remain_second(
							    p->t_gr_restart)
							    * 1000);

			if (p->t_gr_stale)
				json_object_int_add(
					json_grace,
					"gracefulStalepathTimerMsecs",
					thread_timer_remain_second(
						p->t_gr_stale)
						* 1000);

			json_object_object_add(
				json_neigh, "gracefulRestartInfo", json_grace);
		} else {
			vty_out(vty, "  Graceful restart information:\n");
			if (p->status == Established) {
				vty_out(vty, "    End-of-RIB send: ");
				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(p->af_sflags[afi][safi],
						       PEER_STATUS_EOR_SEND)) {
						vty_out(vty, "%s%s",
							eor_send_af_count ? ", "
									  : "",
							get_afi_safi_str(afi,
								         safi,
									 false));
						eor_send_af_count++;
					}
				}
				vty_out(vty, "\n");
				vty_out(vty, "    End-of-RIB received: ");
				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(
						    p->af_sflags[afi][safi],
						    PEER_STATUS_EOR_RECEIVED)) {
						vty_out(vty, "%s%s",
							eor_receive_af_count
								? ", "
								: "",
							get_afi_safi_str(afi,
									 safi,
									 false));
						eor_receive_af_count++;
					}
				}
				vty_out(vty, "\n");
			}

			if (p->t_gr_restart)
				vty_out(vty,
					"    The remaining time of restart timer is %ld\n",
					thread_timer_remain_second(
						p->t_gr_restart));

			if (p->t_gr_stale)
				vty_out(vty,
					"    The remaining time of stalepath timer is %ld\n",
					thread_timer_remain_second(
						p->t_gr_stale));
		}
	}
	if (use_json) {
		json_object *json_stat = NULL;
		json_stat = json_object_new_object();
		/* Packet counts. */
		json_object_int_add(json_stat, "depthInq", 0);
		json_object_int_add(json_stat, "depthOutq",
				    (unsigned long)p->obuf->count);
		json_object_int_add(json_stat, "opensSent",
				    atomic_load_explicit(&p->open_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "opensRecv",
				    atomic_load_explicit(&p->open_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsSent",
				    atomic_load_explicit(&p->notify_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsRecv",
				    atomic_load_explicit(&p->notify_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesSent",
				    atomic_load_explicit(&p->update_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesRecv",
				    atomic_load_explicit(&p->update_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesSent",
				    atomic_load_explicit(&p->keepalive_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesRecv",
				    atomic_load_explicit(&p->keepalive_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshSent",
				    atomic_load_explicit(&p->refresh_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshRecv",
				    atomic_load_explicit(&p->refresh_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilitySent",
				    atomic_load_explicit(&p->dynamic_cap_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilityRecv",
				    atomic_load_explicit(&p->dynamic_cap_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "totalSent", PEER_TOTAL_TX(p));
		json_object_int_add(json_stat, "totalRecv", PEER_TOTAL_RX(p));
		json_object_object_add(json_neigh, "messageStats", json_stat);
	} else {
		/* Packet counts. */
		vty_out(vty, "  Message statistics:\n");
		vty_out(vty, "    Inq depth is 0\n");
		vty_out(vty, "    Outq depth is %lu\n",
			(unsigned long)p->obuf->count);
		vty_out(vty, "                         Sent       Rcvd\n");
		vty_out(vty, "    Opens:         %10d %10d\n",
			atomic_load_explicit(&p->open_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->open_in,
					     memory_order_relaxed));
		vty_out(vty, "    Notifications: %10d %10d\n",
			atomic_load_explicit(&p->notify_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->notify_in,
					     memory_order_relaxed));
		vty_out(vty, "    Updates:       %10d %10d\n",
			atomic_load_explicit(&p->update_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->update_in,
					     memory_order_relaxed));
		vty_out(vty, "    Keepalives:    %10d %10d\n",
			atomic_load_explicit(&p->keepalive_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->keepalive_in,
					     memory_order_relaxed));
		vty_out(vty, "    Route Refresh: %10d %10d\n",
			atomic_load_explicit(&p->refresh_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->refresh_in,
					     memory_order_relaxed));
		vty_out(vty, "    Capability:    %10d %10d\n",
			atomic_load_explicit(&p->dynamic_cap_out,
					     memory_order_relaxed),
			atomic_load_explicit(&p->dynamic_cap_in,
					     memory_order_relaxed));
		vty_out(vty, "    Total:         %10d %10d\n", PEER_TOTAL_TX(p),
			PEER_TOTAL_RX(p));
	}

	if (use_json) {
		/* advertisement-interval */
		json_object_int_add(json_neigh,
				    "minBtwnAdvertisementRunsTimerMsecs",
				    p->v_routeadv * 1000);

		/* Update-source. */
		if (p->update_if || p->update_source) {
			if (p->update_if)
				json_object_string_add(json_neigh,
						       "updateSource",
						       p->update_if);
			else if (p->update_source)
				json_object_string_add(
					json_neigh, "updateSource",
					sockunion2str(p->update_source, buf1,
						      SU_ADDRSTRLEN));
		}
	} else {
		/* advertisement-interval */
		vty_out(vty,
			"  Minimum time between advertisement runs is %d seconds\n",
			p->v_routeadv);

		/* Update-source. */
		if (p->update_if || p->update_source) {
			vty_out(vty, "  Update source is ");
			if (p->update_if)
				vty_out(vty, "%s", p->update_if);
			else if (p->update_source)
				vty_out(vty, "%s",
					sockunion2str(p->update_source, buf1,
						      SU_ADDRSTRLEN));
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}

	/* Address Family Information */
	json_object *json_hold = NULL;

	if (use_json)
		json_hold = json_object_new_object();

	FOREACH_AFI_SAFI (afi, safi)
		if (p->afc[afi][safi])
			bgp_show_peer_afi(vty, p, afi, safi, use_json,
					  json_hold);

	if (use_json) {
		json_object_object_add(json_neigh, "addressFamilyInfo",
				       json_hold);
		json_object_int_add(json_neigh, "connectionsEstablished",
				    p->established);
		json_object_int_add(json_neigh, "connectionsDropped",
				    p->dropped);
	} else
		vty_out(vty, "  Connections established %d; dropped %d\n",
			p->established, p->dropped);

	if (!p->last_reset) {
		if (use_json)
			json_object_string_add(json_neigh, "lastReset",
					       "never");
		else
			vty_out(vty, "  Last reset never\n");
	} else {
		if (use_json) {
			time_t uptime;
			struct tm *tm;

			uptime = bgp_clock();
			uptime -= p->resettime;
			tm = gmtime(&uptime);
			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (tm->tm_sec * 1000)
						    + (tm->tm_min * 60000)
						    + (tm->tm_hour * 3600000));
			bgp_show_peer_reset(NULL, p, json_neigh, true);
		} else {
			vty_out(vty, "  Last reset %s, ",
				peer_uptime(p->resettime, timebuf,
					    BGP_UPTIME_LEN, 0, NULL));

			bgp_show_peer_reset(vty, p, NULL, false);
			if (p->last_reset_cause_size) {
				msg = p->last_reset_cause;
				vty_out(vty,
					"  Message received that caused BGP to send a NOTIFICATION:\n    ");
				for (i = 1; i <= p->last_reset_cause_size;
				     i++) {
					vty_out(vty, "%02X", *msg++);

					if (i != p->last_reset_cause_size) {
						if (i % 16 == 0) {
							vty_out(vty, "\n    ");
						} else if (i % 4 == 0) {
							vty_out(vty, " ");
						}
					}
				}
				vty_out(vty, "\n");
			}
		}
	}

	if (CHECK_FLAG(p->sflags, PEER_STATUS_PREFIX_OVERFLOW)) {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "prefixesConfigExceedMax");
		else
			vty_out(vty,
				"  Peer had exceeded the max. no. of prefixes configured.\n");

		if (p->t_pmax_restart) {
			if (use_json) {
				json_object_boolean_true_add(
					json_neigh, "reducePrefixNumFrom");
				json_object_int_add(json_neigh,
						    "restartInTimerMsec",
						    thread_timer_remain_second(
							    p->t_pmax_restart)
							    * 1000);
			} else
				vty_out(vty,
					"  Reduce the no. of prefix from %s, will restart in %ld seconds\n",
					p->host, thread_timer_remain_second(
							 p->t_pmax_restart));
		} else {
			if (use_json)
				json_object_boolean_true_add(
					json_neigh,
					"reducePrefixNumAndClearIpBgp");
			else
				vty_out(vty,
					"  Reduce the no. of prefix and clear ip bgp %s to restore peering\n",
					p->host);
		}
	}

	/* EBGP Multihop and GTSM */
	if (p->sort != BGP_PEER_IBGP) {
		if (use_json) {
			if (p->gtsm_hops > 0)
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else if (p->ttl > BGP_DEFAULT_TTL)
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->ttl);
		} else {
			if (p->gtsm_hops > 0)
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
			else if (p->ttl > BGP_DEFAULT_TTL)
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->ttl);
		}
	} else {
		if (p->gtsm_hops > 0) {
			if (use_json)
				json_object_int_add(json_neigh,
						    "internalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else
				vty_out(vty,
					"  Internal BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
		}
	}

	/* Local address. */
	if (p->su_local) {
		if (use_json) {
			json_object_string_add(json_neigh, "hostLocal",
					       sockunion2str(p->su_local, buf1,
							     SU_ADDRSTRLEN));
			json_object_int_add(json_neigh, "portLocal",
					    ntohs(p->su_local->sin.sin_port));
		} else
			vty_out(vty, "Local host: %s, Local port: %d\n",
				sockunion2str(p->su_local, buf1, SU_ADDRSTRLEN),
				ntohs(p->su_local->sin.sin_port));
	}

	/* Remote address. */
	if (p->su_remote) {
		if (use_json) {
			json_object_string_add(json_neigh, "hostForeign",
					       sockunion2str(p->su_remote, buf1,
							     SU_ADDRSTRLEN));
			json_object_int_add(json_neigh, "portForeign",
					    ntohs(p->su_remote->sin.sin_port));
		} else
			vty_out(vty, "Foreign host: %s, Foreign port: %d\n",
				sockunion2str(p->su_remote, buf1,
					      SU_ADDRSTRLEN),
				ntohs(p->su_remote->sin.sin_port));
	}

	/* Nexthop display. */
	if (p->su_local) {
		if (use_json) {
			json_object_string_add(json_neigh, "nexthop",
					       inet_ntop(AF_INET,
							 &p->nexthop.v4, buf1,
							 sizeof(buf1)));
			json_object_string_add(json_neigh, "nexthopGlobal",
					       inet_ntop(AF_INET6,
							 &p->nexthop.v6_global,
							 buf1, sizeof(buf1)));
			json_object_string_add(json_neigh, "nexthopLocal",
					       inet_ntop(AF_INET6,
							 &p->nexthop.v6_local,
							 buf1, sizeof(buf1)));
			if (p->shared_network)
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "sharedNetwork");
			else
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "nonSharedNetwork");
		} else {
			vty_out(vty, "Nexthop: %s\n",
				inet_ntop(AF_INET, &p->nexthop.v4, buf1,
					  sizeof(buf1)));
			vty_out(vty, "Nexthop global: %s\n",
				inet_ntop(AF_INET6, &p->nexthop.v6_global, buf1,
					  sizeof(buf1)));
			vty_out(vty, "Nexthop local: %s\n",
				inet_ntop(AF_INET6, &p->nexthop.v6_local, buf1,
					  sizeof(buf1)));
			vty_out(vty, "BGP connection: %s\n",
				p->shared_network ? "shared network"
						  : "non shared network");
		}
	}

	/* Timer information. */
	if (use_json) {
		json_object_int_add(json_neigh, "connectRetryTimer",
				    p->v_connect);
		if (p->status == Established && p->rtt)
			json_object_int_add(json_neigh, "estimatedRttInMsecs",
					    p->rtt);
		if (p->t_start)
			json_object_int_add(
				json_neigh, "nextStartTimerDueInMsecs",
				thread_timer_remain_second(p->t_start) * 1000);
		if (p->t_connect)
			json_object_int_add(
				json_neigh, "nextConnectTimerDueInMsecs",
				thread_timer_remain_second(p->t_connect)
					* 1000);
		if (p->t_routeadv) {
			json_object_int_add(json_neigh, "mraiInterval",
					    p->v_routeadv);
			json_object_int_add(
				json_neigh, "mraiTimerExpireInMsecs",
				thread_timer_remain_second(p->t_routeadv)
					* 1000);
		}
		if (p->password)
			json_object_int_add(json_neigh, "authenticationEnabled",
					    1);

		if (p->t_read)
			json_object_string_add(json_neigh, "readThread", "on");
		else
			json_object_string_add(json_neigh, "readThread", "off");

		if (CHECK_FLAG(p->thread_flags, PEER_THREAD_WRITES_ON))
			json_object_string_add(json_neigh, "writeThread", "on");
		else
			json_object_string_add(json_neigh, "writeThread",
					       "off");
	} else {
		vty_out(vty, "BGP Connect Retry Timer in Seconds: %d\n",
			p->v_connect);
		if (p->status == Established && p->rtt)
			vty_out(vty, "Estimated round trip time: %d ms\n",
				p->rtt);
		if (p->t_start)
			vty_out(vty, "Next start timer due in %ld seconds\n",
				thread_timer_remain_second(p->t_start));
		if (p->t_connect)
			vty_out(vty, "Next connect timer due in %ld seconds\n",
				thread_timer_remain_second(p->t_connect));
		if (p->t_routeadv)
			vty_out(vty,
				"MRAI (interval %u) timer expires in %ld seconds\n",
				p->v_routeadv,
				thread_timer_remain_second(p->t_routeadv));
		if (p->password)
			vty_out(vty, "Peer Authentication Enabled\n");

		vty_out(vty, "Read thread: %s  Write thread: %s  FD used: %d\n",
			p->t_read ? "on" : "off",
			CHECK_FLAG(p->thread_flags, PEER_THREAD_WRITES_ON)
				? "on"
				: "off", p->fd);
	}

	if (p->notify.code == BGP_NOTIFY_OPEN_ERR
	    && p->notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
		bgp_capability_vty_out(vty, p, use_json, json_neigh);

	if (!use_json)
		vty_out(vty, "\n");

	/* BFD information. */
	bgp_bfd_show_info(vty, p, use_json, json_neigh);

	if (use_json) {
		if (p->conf_if) /* Configured interface name. */
			json_object_object_add(json, p->conf_if, json_neigh);
		else /* Configured IP address. */
			json_object_object_add(json, p->host, json_neigh);
	}
}

static int bgp_show_neighbor(struct vty *vty, struct bgp *bgp,
			     enum show_type type, union sockunion *su,
			     const char *conf_if, bool use_json,
			     json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	int find = 0;
	bool nbr_output = false;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	if (type == show_ipv4_peer || type == show_ipv4_all) {
		afi = AFI_IP;
	} else if (type == show_ipv6_peer || type == show_ipv6_all) {
		afi = AFI_IP6;
	}

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		switch (type) {
		case show_all:
			bgp_show_peer(vty, peer, use_json, json);
			nbr_output = true;
			break;
		case show_peer:
			if (conf_if) {
				if ((peer->conf_if
				     && !strcmp(peer->conf_if, conf_if))
				    || (peer->hostname
					&& !strcmp(peer->hostname, conf_if))) {
					find = 1;
					bgp_show_peer(vty, peer, use_json,
						      json);
				}
			} else {
				if (sockunion_same(&peer->su, su)) {
					find = 1;
					bgp_show_peer(vty, peer, use_json,
						      json);
				}
			}
			break;
		case show_ipv4_peer:
		case show_ipv6_peer:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					if (conf_if) {
						if ((peer->conf_if
						     && !strcmp(peer->conf_if, conf_if))
						    || (peer->hostname
							&& !strcmp(peer->hostname, conf_if))) {
							find = 1;
							bgp_show_peer(vty, peer, use_json,
								      json);
							break;
						}
					} else {
						if (sockunion_same(&peer->su, su)) {
							find = 1;
							bgp_show_peer(vty, peer, use_json,
								      json);
							break;
						}
					}
				}
			}
			break;
		case show_ipv4_all:
		case show_ipv6_all:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					bgp_show_peer(vty, peer, use_json, json);
					nbr_output = true;
					break;
				}
			}
			break;
		}
	}

	if ((type == show_peer || type == show_ipv4_peer ||
	     type == show_ipv6_peer) && !find) {
		if (use_json)
			json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
		else
			vty_out(vty, "%% No such neighbor in this view/vrf\n");
	}

	if (type != show_peer && type != show_ipv4_peer &&
	    type != show_ipv6_peer && !nbr_output && !use_json)
		vty_out(vty, "%% No BGP neighbors found\n");

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

static void bgp_show_all_instances_neighbors_vty(struct vty *vty,
						 enum show_type type,
						 const char *ip_str,
						 bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;
	int ret, is_first = 1;
	bool nbr_output = false;

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		nbr_output = true;
		if (use_json) {
			if (!(json = json_object_new_object())) {
				flog_err(
					EC_BGP_JSON_MEM_ERROR,
					"Unable to allocate memory for JSON object");
				vty_out(vty,
					"{\"error\": {\"message:\": \"Unable to allocate memory for JSON object\"}}}\n");
				return;
			}

			json_object_int_add(json, "vrfId",
					    (bgp->vrf_id == VRF_UNKNOWN)
						    ? -1
						    : (int64_t)bgp->vrf_id);
			json_object_string_add(
				json, "vrfName",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);

			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}

		if (type == show_peer || type == show_ipv4_peer ||
		    type == show_ipv6_peer) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL,
					  use_json, json);
		}
		json_object_free(json);
	}

	if (use_json) {
		vty_out(vty, "}\n");
		json_object_free(json);
	}
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

static int bgp_show_neighbor_vty(struct vty *vty, const char *name,
				 enum show_type type, const char *ip_str,
				 bool use_json)
{
	int ret;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_neighbors_vty(vty, type, ip_str,
							     use_json);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
			if (!bgp) {
				if (use_json) {
					json = json_object_new_object();
					vty_out(vty, "%s\n",
						json_object_to_json_string_ext(
							json,
							JSON_C_TO_STRING_PRETTY));
					json_object_free(json);
				} else
					vty_out(vty,
						"%% BGP instance not found\n");

				return CMD_WARNING;
			}
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp) {
		json = json_object_new_object();
		if (ip_str) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL, use_json,
					  json);
		}
		json_object_free(json);
	} else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp neighbors" commands.  */
DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>] neighbors [<A.B.C.D|X:X::X:X|WORD>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       JSON_STR)
{
	char *vrf = NULL;
	char *sh_arg = NULL;
	enum show_type sh_type;
	afi_t afi = AFI_MAX;

	bool uj = use_json(argc, argv);

	int idx = 0;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;

	idx++;

	if (argv_find(argv, argc, "ipv4", &idx)) {
		sh_type = show_ipv4_all;
		afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", &idx)) {
		sh_type = show_ipv6_all;
		afi = AFI_IP6;
	} else {
		sh_type = show_all;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)
	    || argv_find(argv, argc, "X:X::X:X", &idx)
	    || argv_find(argv, argc, "WORD", &idx)) {
		sh_type = show_peer;
		sh_arg = argv[idx]->arg;
	}

	if (sh_type == show_peer && afi == AFI_IP) {
		sh_type = show_ipv4_peer;
	} else if (sh_type == show_peer && afi == AFI_IP6) {
		sh_type = show_ipv6_peer;
	}

	return bgp_show_neighbor_vty(vty, vrf, sh_type, sh_arg, uj);
}

/* Show BGP's AS paths internal data.  There are both `show [ip] bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths,
       show_ip_bgp_paths_cmd,
       "show [ip] bgp ["BGP_SAFI_CMD_STR"] paths",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_SAFI_HELP_STR
       "Path information\n")
{
	vty_out(vty, "Address Refcnt Path\n");
	aspath_print_all_vty(vty);
	return CMD_SUCCESS;
}

#include "hash.h"

static void community_show_all_iterator(struct hash_bucket *bucket,
					struct vty *vty)
{
	struct community *com;

	com = (struct community *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)com, com->refcnt,
		community_str(com, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info,
       show_ip_bgp_community_info_cmd,
       "show [ip] bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
	vty_out(vty, "Address Refcnt Community\n");

	hash_iterate(community_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))community_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}

static void lcommunity_show_all_iterator(struct hash_bucket *bucket,
					 struct vty *vty)
{
	struct lcommunity *lcom;

	lcom = (struct lcommunity *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)lcom, lcom->refcnt,
		lcommunity_str(lcom, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_lcommunity_info,
       show_ip_bgp_lcommunity_info_cmd,
       "show ip bgp large-community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp large-community information\n")
{
	vty_out(vty, "Address Refcnt Large-community\n");

	hash_iterate(lcommunity_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))lcommunity_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}


DEFUN (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show [ip] bgp attribute-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")
{
	attr_show_all(vty);
	return CMD_SUCCESS;
}

static int bgp_show_route_leak_vty(struct vty *vty, const char *name,
				   afi_t afi, safi_t safi,
				   bool use_json, json_object *json)
{
	struct bgp *bgp;
	struct listnode *node;
	char *vname;
	char buf1[INET6_ADDRSTRLEN];
	char *ecom_str;
	vpn_policy_direction_t dir;

	if (json) {
		json_object *json_import_vrfs = NULL;
		json_object *json_export_vrfs = NULL;

		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json,
					JSON_C_TO_STRING_PRETTY));
			json_object_free(json);

			return CMD_WARNING;
		}

		/* Provide context for the block */
		json_object_string_add(json, "vrf", name ? name : "default");
		json_object_string_add(json, "afiSafi",
				       get_afi_safi_str(afi, safi, true));

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			json_object_string_add(json, "importFromVrfs", "none");
			json_object_string_add(json, "importRts", "none");
		} else {
			json_import_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				json_object_array_add(json_import_vrfs,
						json_object_new_string(vname));

			json_object_object_add(json, "importFromVrfs",
						       json_import_vrfs);
			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "importRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "importRts",
						       "none");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			json_object_string_add(json, "exportToVrfs", "none");
			json_object_string_add(json, "routeDistinguisher",
					       "none");
			json_object_string_add(json, "exportRts", "none");
		} else {
			json_export_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				json_object_array_add(json_export_vrfs,
						json_object_new_string(vname));
			json_object_object_add(json, "exportToVrfs",
					       json_export_vrfs);
			json_object_string_add(json, "routeDistinguisher",
				   prefix_rd2str(&bgp->vpn_policy[afi].tovpn_rd,
						 buf1, RD_ADDRSTRLEN));

			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "exportRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "exportRts",
						       "none");
		}

		if (use_json) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(json,
						      JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		}
	} else {
		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_out(vty, "%% No such BGP instance exist\n");
			return CMD_WARNING;
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT))
			vty_out(vty,
		     "This VRF is not importing %s routes from any other VRF\n",
		      get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		   "This VRF is importing %s routes from the following VRFs:\n",
		    get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			ecom_str = NULL;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Import RT(s): %s\n", ecom_str);

				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT))
			vty_out(vty,
		       "This VRF is not exporting %s routes to any other VRF\n",
			get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		       "This VRF is exporting %s routes to the following VRFs:\n",
			get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			vty_out(vty, "RD: %s\n",
				prefix_rd2str(&bgp->vpn_policy[afi].tovpn_rd,
					      buf1, RD_ADDRSTRLEN));

			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Export RT: %s\n", ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}
	}

	return CMD_SUCCESS;
}

static int bgp_show_all_instance_route_leak_vty(struct vty *vty, afi_t afi,
						safi_t safi, bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	char *vrf_name = NULL;
	json_object *json = NULL;
	json_object *json_vrf = NULL;
	json_object *json_vrfs = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {

		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
			vrf_name = bgp->name;

		if (use_json) {
			json_vrf = json_object_new_object();
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? VRF_DEFAULT_NAME : bgp->name);
		}
		bgp_show_route_leak_vty(vty, vrf_name, afi, safi, 0, json_vrf);
		if (use_json) {
			if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				json_object_object_add(json_vrfs,
						VRF_DEFAULT_NAME, json_vrf);
			else
				json_object_object_add(json_vrfs, vrf_name,
						       json_vrf);
		}
	}

	if (use_json) {
		json_object_object_add(json, "vrfs", json_vrfs);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(json,
						JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp route-leak" command.  */
DEFUN (show_ip_bgp_route_leak,
	show_ip_bgp_route_leak_cmd,
	"show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] route-leak  [json]",
	SHOW_STR
	IP_STR
	BGP_STR
	BGP_INSTANCE_HELP_STR
	BGP_AFI_HELP_STR
	BGP_SAFI_HELP_STR
	"Route leaking information\n"
	JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	bool uj = use_json(argc, argv);
	int idx = 0;
	json_object *json = NULL;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
	}
	/* [vrf VIEWVRFNAME] */
	if (argv_find(argv, argc, "view", &idx)) {
		vty_out(vty,
			"%% This command is not applicable to BGP views\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	if (!((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)) {
		vty_out(vty,
			"%% This command is applicable only for unicast ipv4|ipv6\n");
		return CMD_WARNING;
	}

	if (vrf && strmatch(vrf, "all"))
		return bgp_show_all_instance_route_leak_vty(vty, afi, safi, uj);

	if (uj)
		json = json_object_new_object();

	return bgp_show_route_leak_vty(vty, vrf, afi, safi, uj, json);
}

static void bgp_show_all_instances_updgrps_vty(struct vty *vty, afi_t afi,
					       safi_t safi)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		vty_out(vty, "\nInstance %s:\n",
			(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? VRF_DEFAULT_NAME
				: bgp->name);
		update_group_show(bgp, afi, safi, vty, 0);
	}
}

static int bgp_show_update_groups(struct vty *vty, const char *name, int afi,
				  int safi, uint64_t subgrp_id)
{
	struct bgp *bgp;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_updgrps_vty(vty, afi, safi);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp)
		update_group_show(bgp, afi, safi, vty, subgrp_id);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_updgrps,
       show_ip_bgp_updgrps_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] update-groups [SUBGROUP-ID]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Specific subgroup to display detailed info for\n")
{
	char *vrf = NULL;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	uint64_t subgrp_id = 0;

	int idx = 0;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	/* get subgroup id, if provided */
	idx = argc - 1;
	if (argv[idx]->type == VARIABLE_TKN)
		subgrp_id = strtoull(argv[idx]->arg, NULL, 10);

	return (bgp_show_update_groups(vty, vrf, afi, safi, subgrp_id));
}

DEFUN (show_bgp_instance_all_ipv6_updgrps,
       show_bgp_instance_all_ipv6_updgrps_cmd,
       "show [ip] bgp <view|vrf> all update-groups",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed info about dynamic update groups\n")
{
	bgp_show_all_instances_updgrps_vty(vty, AFI_IP6, SAFI_UNICAST);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_l2vpn_evpn_updgrps,
	show_bgp_l2vpn_evpn_updgrps_cmd,
	"show [ip] bgp l2vpn evpn update-groups",
	SHOW_STR
	IP_STR
	BGP_STR
	"l2vpn address family\n"
	"evpn sub-address family\n"
	"Detailed info about dynamic update groups\n")
{
	char *vrf = NULL;
	uint64_t subgrp_id = 0;

	bgp_show_update_groups(vty, vrf, AFI_L2VPN, SAFI_EVPN, subgrp_id);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_stats,
       show_bgp_updgrps_stats_cmd,
       "show [ip] bgp update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed info about dynamic update groups\n"
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
       "show [ip] bgp <view|vrf> VIEWVRFNAME update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Statistics\n")
{
	int idx_word = 3;
	struct bgp *bgp;

	bgp = bgp_lookup_by_name(argv[idx_word]->arg);
	if (bgp)
		update_group_show_stats(bgp, vty);

	return CMD_SUCCESS;
}

static void show_bgp_updgrps_adj_info_aux(struct vty *vty, const char *name,
					  afi_t afi, safi_t safi,
					  const char *what, uint64_t subgrp_id)
{
	struct bgp *bgp;

	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (bgp) {
		if (!strcmp(what, "advertise-queue"))
			update_group_show_adj_queue(bgp, afi, safi, vty,
						    subgrp_id);
		else if (!strcmp(what, "advertised-routes"))
			update_group_show_advertised(bgp, afi, safi, vty,
						     subgrp_id);
		else if (!strcmp(what, "packet-queue"))
			update_group_show_packet_queue(bgp, afi, safi, vty,
						       subgrp_id);
	}
}

DEFPY(show_ip_bgp_instance_updgrps_adj_s,
      show_ip_bgp_instance_updgrps_adj_s_cmd,
      "show [ip]$ip bgp [<view|vrf> VIEWVRFNAME$vrf] [<ipv4|ipv6>$afi <unicast|multicast|vpn>$safi] update-groups [SUBGROUP-ID]$sgid <advertise-queue|advertised-routes|packet-queue>$rtq",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_HELP_STR
      "Detailed info about dynamic update groups\n"
      "Specific subgroup to display info for\n"
      "Advertisement queue\n"
      "Announced routes\n"
      "Packet queue\n")
{
	uint64_t subgrp_id = 0;
	afi_t afiz;
	safi_t safiz;
	if (sgid)
		subgrp_id = strtoull(sgid, NULL, 10);

	if (!ip && !afi)
		afiz = AFI_IP6;
	if (!ip && afi)
		afiz = bgp_vty_afi_from_str(afi);
	if (ip && !afi)
		afiz = AFI_IP;
	if (ip && afi) {
		afiz = bgp_vty_afi_from_str(afi);
		if (afiz != AFI_IP)
			vty_out(vty,
				"%% Cannot specify both 'ip' and 'ipv6'\n");
		return CMD_WARNING;
	}

	safiz = safi ? bgp_vty_safi_from_str(safi) : SAFI_UNICAST;

	show_bgp_updgrps_adj_info_aux(vty, vrf, afiz, safiz, rtq, subgrp_id);
	return CMD_SUCCESS;
}

static int bgp_show_one_peer_group(struct vty *vty, struct peer_group *group)
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

	if (conf->as_type == AS_SPECIFIED || conf->as_type == AS_EXTERNAL) {
		vty_out(vty, "\nBGP peer-group %s, remote AS %" PRIu32 "\n",
			group->name, conf->as);
	} else if (conf->as_type == AS_INTERNAL) {
		vty_out(vty, "\nBGP peer-group %s, remote AS %" PRIu32 "\n",
			group->name, group->bgp->as);
	} else {
		vty_out(vty, "\nBGP peer-group %s\n", group->name);
	}

	if ((group->bgp->as == conf->as) || (conf->as_type == AS_INTERNAL))
		vty_out(vty, "  Peer-group type is internal\n");
	else
		vty_out(vty, "  Peer-group type is external\n");

	/* Display AFs configured. */
	vty_out(vty, "  Configured address-families:");
	FOREACH_AFI_SAFI (afi, safi) {
		if (conf->afc[afi][safi]) {
			af_cfgd = 1;
			vty_out(vty, " %s;", get_afi_safi_str(afi, safi, false));
		}
	}
	if (!af_cfgd)
		vty_out(vty, " none\n");
	else
		vty_out(vty, "\n");

	/* Display listen ranges (for dynamic neighbors), if any */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (afi == AFI_IP)
			af_str = "IPv4";
		else if (afi == AFI_IP6)
			af_str = "IPv6";
		else
			af_str = "???";
		lr_count = listcount(group->listen_range[afi]);
		if (lr_count) {
			vty_out(vty, "  %d %s listen range(s)\n", lr_count,
				af_str);


			for (ALL_LIST_ELEMENTS(group->listen_range[afi], node,
					       nnode, range)) {
				prefix2str(range, buf, sizeof(buf));
				vty_out(vty, "    %s\n", buf);
			}
		}
	}

	/* Display group members and their status */
	if (listcount(group->peer)) {
		vty_out(vty, "  Peer-group members:\n");
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
				peer_status = "Idle (Admin)";
			else if (CHECK_FLAG(peer->sflags,
					    PEER_STATUS_PREFIX_OVERFLOW))
				peer_status = "Idle (PfxCt)";
			else
				peer_status = lookup_msg(bgp_status_msg,
							 peer->status, NULL);

			dynamic = peer_dynamic_neighbor(peer);
			vty_out(vty, "    %s %s %s \n", peer->host,
				dynamic ? "(dynamic)" : "", peer_status);
		}
	}

	return CMD_SUCCESS;
}

static int bgp_show_peer_group_vty(struct vty *vty, const char *name,
				   const char *group_name)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer_group *group;
	bool found = false;

	bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

	if (!bgp) {
		vty_out(vty, "%% BGP instance not found\n");
		return CMD_WARNING;
	}

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		if (group_name) {
			if (strmatch(group->name, group_name)) {
				bgp_show_one_peer_group(vty, group);
				found = true;
				break;
			}
		} else {
			bgp_show_one_peer_group(vty, group);
		}
	}

	if (group_name && !found)
		vty_out(vty, "%% No such peer-group\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_peer_groups,
       show_ip_bgp_peer_groups_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] peer-group [PGNAME]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on BGP peer groups\n"
       "Peer group name\n")
{
	char *vrf, *pg;
	int idx = 0;

	vrf = argv_find(argv, argc, "VIEWVRFNAME", &idx) ? argv[idx]->arg
							 : NULL;
	pg = argv_find(argv, argc, "PGNAME", &idx) ? argv[idx]->arg : NULL;

	return bgp_show_peer_group_vty(vty, vrf, pg);
}


/* Redistribute VTY commands.  */

DEFUN (bgp_redistribute_ipv4,
       bgp_redistribute_ipv4_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int type;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redist_add(bgp, AFI_IP, type, 0);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, false);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4, bgp_redistribute_ipv4_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD,
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD)

DEFUN (bgp_redistribute_ipv4_rmap,
       bgp_redistribute_ipv4_rmap_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int type;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map = route_map_lookup_warn_noexist(
		vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_rmap, bgp_redistribute_ipv4_rmap_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD " route-map WORD",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_metric,
       bgp_redistribute_ipv4_metric_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_metric, bgp_redistribute_ipv4_metric_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295)",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_rmap_metric,
       bgp_redistribute_ipv4_rmap_metric_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " route-map WORD metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int idx_number = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_rmap_metric,
	bgp_redistribute_ipv4_rmap_metric_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD
	" route-map WORD metric (0-4294967295)",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Route map reference\n"
	"Pointer to route-map entries\n"
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_metric_rmap,
       bgp_redistribute_ipv4_metric_rmap_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295) route-map WORD",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int idx_word = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_metric_rmap,
	bgp_redistribute_ipv4_metric_rmap_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD
	" metric (0-4294967295) route-map WORD",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_ospf,
       bgp_redistribute_ipv4_ospf_cmd,
       "redistribute <ospf|table> (1-65535)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	unsigned short instance;
	unsigned short protocol;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	bgp_redist_add(bgp, AFI_IP, protocol, instance);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, false);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf, bgp_redistribute_ipv4_ospf_hidden_cmd,
	     "redistribute <ospf|table> (1-65535)",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Instance ID/Table ID\n")

DEFUN (bgp_redistribute_ipv4_ospf_rmap,
       bgp_redistribute_ipv4_ospf_rmap_cmd,
       "redistribute <ospf|table> (1-65535) route-map WORD",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_word = 4;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf_rmap,
	     bgp_redistribute_ipv4_ospf_rmap_hidden_cmd,
	     "redistribute <ospf|table> (1-65535) route-map WORD",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Instance ID/Table ID\n"
	     "Route map reference\n"
	     "Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_ospf_metric,
       bgp_redistribute_ipv4_ospf_metric_cmd,
       "redistribute <ospf|table> (1-65535) metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_number_2 = 4;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf_metric,
	     bgp_redistribute_ipv4_ospf_metric_hidden_cmd,
	     "redistribute <ospf|table> (1-65535) metric (0-4294967295)",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Instance ID/Table ID\n"
	     "Metric for redistributed routes\n"
	     "Default metric\n")

DEFUN (bgp_redistribute_ipv4_ospf_rmap_metric,
       bgp_redistribute_ipv4_ospf_rmap_metric_cmd,
       "redistribute <ospf|table> (1-65535) route-map WORD metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_word = 4;
	int idx_number_2 = 6;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_ospf_rmap_metric,
	bgp_redistribute_ipv4_ospf_rmap_metric_hidden_cmd,
	"redistribute <ospf|table> (1-65535) route-map WORD metric (0-4294967295)",
	"Redistribute information from another routing protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Non-main Kernel Routing Table\n"
	"Instance ID/Table ID\n"
	"Route map reference\n"
	"Pointer to route-map entries\n"
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_ospf_metric_rmap,
       bgp_redistribute_ipv4_ospf_metric_rmap_cmd,
       "redistribute <ospf|table> (1-65535) metric (0-4294967295) route-map WORD",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_number_2 = 4;
	int idx_word = 6;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_ospf_metric_rmap,
	bgp_redistribute_ipv4_ospf_metric_rmap_hidden_cmd,
	"redistribute <ospf|table> (1-65535) metric (0-4294967295) route-map WORD",
	"Redistribute information from another routing protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Non-main Kernel Routing Table\n"
	"Instance ID/Table ID\n"
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_cmd,
       "no redistribute <ospf|table> (1-65535) [{metric (0-4294967295)|route-map WORD}]",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 2;
	int idx_number = 3;
	unsigned short instance;
	int protocol;

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else
		protocol = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	return bgp_redistribute_unset(bgp, AFI_IP, protocol, instance);
}

ALIAS_HIDDEN(
	no_bgp_redistribute_ipv4_ospf, no_bgp_redistribute_ipv4_ospf_hidden_cmd,
	"no redistribute <ospf|table> (1-65535) [{metric (0-4294967295)|route-map WORD}]",
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
       "no redistribute " FRR_IP_REDIST_STR_BGPD " [{metric (0-4294967295)|route-map WORD}]",
       NO_STR
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 2;
	int type;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return bgp_redistribute_unset(bgp, AFI_IP, type, 0);
}

ALIAS_HIDDEN(
	no_bgp_redistribute_ipv4, no_bgp_redistribute_ipv4_hidden_cmd,
	"no redistribute " FRR_IP_REDIST_STR_BGPD
	" [{metric (0-4294967295)|route-map WORD}]",
	NO_STR
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv6,
       bgp_redistribute_ipv6_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int type;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redist_add(bgp, AFI_IP6, type, 0);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, false);
}

DEFUN (bgp_redistribute_ipv6_rmap,
       bgp_redistribute_ipv6_rmap_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int type;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (bgp_redistribute_ipv6_metric,
       bgp_redistribute_ipv6_metric_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP6, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (bgp_redistribute_ipv6_rmap_metric,
       bgp_redistribute_ipv6_rmap_metric_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " route-map WORD metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int idx_number = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP6, type,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (bgp_redistribute_ipv6_metric_rmap,
       bgp_redistribute_ipv6_metric_rmap_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " metric (0-4294967295) route-map WORD",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int idx_word = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP6, SAFI_UNICAST,
						metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_cmd,
       "no redistribute " FRR_IP6_REDIST_STR_BGPD " [{metric (0-4294967295)|route-map WORD}]",
       NO_STR
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 2;
	int type;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_redistribute_unset(bgp, AFI_IP6, type, 0);
}

void bgp_config_write_redistribute(struct vty *vty, struct bgp *bgp, afi_t afi,
				   safi_t safi)
{
	int i;

	/* Unicast redistribution only.  */
	if (safi != SAFI_UNICAST)
		return;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		/* Redistribute BGP does not make sense.  */
		if (i != ZEBRA_ROUTE_BGP) {
			struct list *red_list;
			struct listnode *node;
			struct bgp_redist *red;

			red_list = bgp->redist[afi][i];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				/* "redistribute" configuration.  */
				vty_out(vty, "  redistribute %s",
					zebra_route_string(i));
				if (red->instance)
					vty_out(vty, " %d", red->instance);
				if (red->redist_metric_flag)
					vty_out(vty, " metric %u",
						red->redist_metric);
				if (red->rmap.name)
					vty_out(vty, " route-map %s",
						red->rmap.name);
				vty_out(vty, "\n");
			}
		}
	}
}

/* This is part of the address-family block (unicast only) */
void bgp_vpn_policy_config_write_afi(struct vty *vty, struct bgp *bgp,
					    afi_t afi)
{
	int indent = 2;

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]) {
		if (listcount(bgp->vpn_policy[afi].import_vrf))
			vty_out(vty, "%*simport vrf route-map %s\n", indent, "",
				bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
		else
			vty_out(vty, "%*sroute-map vpn import %s\n", indent, "",
				bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	}
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		       BGP_CONFIG_VRF_TO_VRF_IMPORT)
	    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			  BGP_CONFIG_VRF_TO_VRF_EXPORT))
		return;

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {

		vty_out(vty, "%*slabel vpn export %s\n", indent, "", "auto");

	} else {
		if (bgp->vpn_policy[afi].tovpn_label != MPLS_LABEL_NONE) {
			vty_out(vty, "%*slabel vpn export %u\n", indent, "",
				bgp->vpn_policy[afi].tovpn_label);
		}
	}
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_RD_SET)) {
		char buf[RD_ADDRSTRLEN];
		vty_out(vty, "%*srd vpn export %s\n", indent, "",
			prefix_rd2str(&bgp->vpn_policy[afi].tovpn_rd, buf,
				      sizeof(buf)));
	}
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_NEXTHOP_SET)) {

		char buf[PREFIX_STRLEN];
		if (inet_ntop(bgp->vpn_policy[afi].tovpn_nexthop.family,
			      &bgp->vpn_policy[afi].tovpn_nexthop.u.prefix, buf,
			      sizeof(buf))) {

			vty_out(vty, "%*snexthop vpn export %s\n",
				indent, "", buf);
		}
	}
	if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN]
	    && bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN]
	    && ecommunity_cmp(
		       bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
		       bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN])) {

		char *b = ecommunity_ecom2str(
			bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN],
			ECOMMUNITY_FORMAT_ROUTE_MAP, ECOMMUNITY_ROUTE_TARGET);
		vty_out(vty, "%*srt vpn both %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	} else {
		if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN]) {
			char *b = ecommunity_ecom2str(
				bgp->vpn_policy[afi]
					.rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%*srt vpn import %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
		if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN]) {
			char *b = ecommunity_ecom2str(
				bgp->vpn_policy[afi]
					.rtlist[BGP_VPN_POLICY_DIR_TOVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%*srt vpn export %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
	}

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_TOVPN])
		vty_out(vty, "%*sroute-map vpn export %s\n", indent, "",
			bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_TOVPN]);

	if (bgp->vpn_policy[afi].import_redirect_rtlist) {
		char *b = ecommunity_ecom2str(
					bgp->vpn_policy[afi]
					.import_redirect_rtlist,
					ECOMMUNITY_FORMAT_ROUTE_MAP,
					ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "%*srt redirect import %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	}
}


/* BGP node structure. */
static struct cmd_node bgp_node = {
	BGP_NODE, "%s(config-router)# ", 1,
};

static struct cmd_node bgp_ipv4_unicast_node = {
	BGP_IPV4_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_ipv4_multicast_node = {
	BGP_IPV4M_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_ipv4_labeled_unicast_node = {
	BGP_IPV4L_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_ipv6_unicast_node = {
	BGP_IPV6_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_ipv6_multicast_node = {
	BGP_IPV6M_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_ipv6_labeled_unicast_node = {
	BGP_IPV6L_NODE, "%s(config-router-af)# ", 1,
};

static struct cmd_node bgp_vpnv4_node = {BGP_VPNV4_NODE,
					 "%s(config-router-af)# ", 1};

static struct cmd_node bgp_vpnv6_node = {BGP_VPNV6_NODE,
					 "%s(config-router-af-vpnv6)# ", 1};

static struct cmd_node bgp_evpn_node = {BGP_EVPN_NODE,
					"%s(config-router-evpn)# ", 1};

static struct cmd_node bgp_evpn_vni_node = {BGP_EVPN_VNI_NODE,
					    "%s(config-router-af-vni)# ", 1};

static struct cmd_node bgp_flowspecv4_node = {BGP_FLOWSPECV4_NODE,
					 "%s(config-router-af)# ", 1};

static struct cmd_node bgp_flowspecv6_node = {BGP_FLOWSPECV6_NODE,
					 "%s(config-router-af-vpnv6)# ", 1};

static void community_list_vty(void);

static void bgp_ac_neighbor(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, lnpeer, peer)) {
			/* only provide suggestions on the appropriate input
			 * token type,
			 * they'll otherwise show up multiple times */
			enum cmd_token_type match_type;
			char *name = peer->host;

			if (peer->conf_if) {
				match_type = VARIABLE_TKN;
				name = peer->conf_if;
			} else if (strchr(peer->host, ':'))
				match_type = IPV6_TKN;
			else
				match_type = IPV4_TKN;

			if (token->type != match_type)
				continue;

			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, name));
		}
	}
}

static const struct cmd_variable_handler bgp_var_neighbor[] = {
	{.varname = "neighbor", .completions = bgp_ac_neighbor},
	{.varname = "neighbors", .completions = bgp_ac_neighbor},
	{.varname = "peer", .completions = bgp_ac_neighbor},
	{.completions = NULL}};

static void bgp_ac_peergroup(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer_group *group;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->group, lnpeer, group))
			vector_set(comps, XSTRDUP(MTYPE_COMPLETION,
						  group->name));
	}
}

static const struct cmd_variable_handler bgp_var_peergroup[] = {
	{.tokenname = "PGNAME", .completions = bgp_ac_peergroup},
	{.completions = NULL} };

void bgp_vty_init(void)
{
	cmd_variable_handler_register(bgp_var_neighbor);
	cmd_variable_handler_register(bgp_var_peergroup);

	/* Install bgp top node. */
	install_node(&bgp_node, bgp_config_write);
	install_node(&bgp_ipv4_unicast_node, NULL);
	install_node(&bgp_ipv4_multicast_node, NULL);
	install_node(&bgp_ipv4_labeled_unicast_node, NULL);
	install_node(&bgp_ipv6_unicast_node, NULL);
	install_node(&bgp_ipv6_multicast_node, NULL);
	install_node(&bgp_ipv6_labeled_unicast_node, NULL);
	install_node(&bgp_vpnv4_node, NULL);
	install_node(&bgp_vpnv6_node, NULL);
	install_node(&bgp_evpn_node, NULL);
	install_node(&bgp_evpn_vni_node, NULL);
	install_node(&bgp_flowspecv4_node, NULL);
	install_node(&bgp_flowspecv6_node, NULL);

	/* Install default VTY commands to new nodes.  */
	install_default(BGP_NODE);
	install_default(BGP_IPV4_NODE);
	install_default(BGP_IPV4M_NODE);
	install_default(BGP_IPV4L_NODE);
	install_default(BGP_IPV6_NODE);
	install_default(BGP_IPV6M_NODE);
	install_default(BGP_IPV6L_NODE);
	install_default(BGP_VPNV4_NODE);
	install_default(BGP_VPNV6_NODE);
	install_default(BGP_FLOWSPECV4_NODE);
	install_default(BGP_FLOWSPECV6_NODE);
	install_default(BGP_EVPN_NODE);
	install_default(BGP_EVPN_VNI_NODE);

	/* "bgp local-mac" hidden commands. */
	install_element(CONFIG_NODE, &bgp_local_mac_cmd);
	install_element(CONFIG_NODE, &no_bgp_local_mac_cmd);

	/* bgp route-map delay-timer commands. */
	install_element(CONFIG_NODE, &bgp_set_route_map_delay_timer_cmd);
	install_element(CONFIG_NODE, &no_bgp_set_route_map_delay_timer_cmd);

	/* Dummy commands (Currently not supported) */
	install_element(BGP_NODE, &no_synchronization_cmd);
	install_element(BGP_NODE, &no_auto_summary_cmd);

	/* "router bgp" commands. */
	install_element(CONFIG_NODE, &router_bgp_cmd);

	/* "no router bgp" commands. */
	install_element(CONFIG_NODE, &no_router_bgp_cmd);

	/* "bgp router-id" commands. */
	install_element(BGP_NODE, &bgp_router_id_cmd);
	install_element(BGP_NODE, &no_bgp_router_id_cmd);

	/* "bgp cluster-id" commands. */
	install_element(BGP_NODE, &bgp_cluster_id_cmd);
	install_element(BGP_NODE, &no_bgp_cluster_id_cmd);

	/* "bgp confederation" commands. */
	install_element(BGP_NODE, &bgp_confederation_identifier_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_identifier_cmd);

	/* "bgp confederation peers" commands. */
	install_element(BGP_NODE, &bgp_confederation_peers_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_peers_cmd);

	/* bgp max-med command */
	install_element(BGP_NODE, &bgp_maxmed_admin_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_admin_cmd);
	install_element(BGP_NODE, &bgp_maxmed_admin_medv_cmd);
	install_element(BGP_NODE, &bgp_maxmed_onstartup_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_onstartup_cmd);

	/* bgp disable-ebgp-connected-nh-check */
	install_element(BGP_NODE, &bgp_disable_connected_route_check_cmd);
	install_element(BGP_NODE, &no_bgp_disable_connected_route_check_cmd);

	/* bgp update-delay command */
	install_element(BGP_NODE, &bgp_update_delay_cmd);
	install_element(BGP_NODE, &no_bgp_update_delay_cmd);
	install_element(BGP_NODE, &bgp_update_delay_establish_wait_cmd);

	install_element(BGP_NODE, &bgp_wpkt_quanta_cmd);
	install_element(BGP_NODE, &bgp_rpkt_quanta_cmd);

	install_element(BGP_NODE, &bgp_coalesce_time_cmd);
	install_element(BGP_NODE, &no_bgp_coalesce_time_cmd);

	/* "maximum-paths" commands. */
	install_element(BGP_NODE, &bgp_maxpaths_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_maxpaths_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_ibgp_hidden_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_ibgp_cluster_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_maxpaths_ibgp_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_maxpaths_ibgp_cmd);

	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV6L_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV6L_NODE, &no_bgp_maxpaths_ibgp_cmd);

	/* "timers bgp" commands. */
	install_element(BGP_NODE, &bgp_timers_cmd);
	install_element(BGP_NODE, &no_bgp_timers_cmd);

	/* route-map delay-timer commands - per instance for backwards compat.
	 */
	install_element(BGP_NODE, &bgp_set_route_map_delay_timer_cmd);
	install_element(BGP_NODE, &no_bgp_set_route_map_delay_timer_cmd);

	/* "bgp client-to-client reflection" commands */
	install_element(BGP_NODE, &no_bgp_client_to_client_reflection_cmd);
	install_element(BGP_NODE, &bgp_client_to_client_reflection_cmd);

	/* "bgp always-compare-med" commands */
	install_element(BGP_NODE, &bgp_always_compare_med_cmd);
	install_element(BGP_NODE, &no_bgp_always_compare_med_cmd);

	/* bgp ebgp-requires-policy */
	install_element(BGP_NODE, &bgp_ebgp_requires_policy_cmd);
	install_element(BGP_NODE, &no_bgp_ebgp_requires_policy_cmd);

	/* "bgp deterministic-med" commands */
	install_element(BGP_NODE, &bgp_deterministic_med_cmd);
	install_element(BGP_NODE, &no_bgp_deterministic_med_cmd);

	/* "bgp graceful-restart" commands */
	install_element(BGP_NODE, &bgp_graceful_restart_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_stalepath_time_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_stalepath_time_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_restart_time_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_restart_time_cmd);

	install_element(BGP_NODE, &bgp_graceful_restart_preserve_fw_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_preserve_fw_cmd);

	/* "bgp graceful-shutdown" commands */
	install_element(BGP_NODE, &bgp_graceful_shutdown_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_shutdown_cmd);

	/* "bgp fast-external-failover" commands */
	install_element(BGP_NODE, &bgp_fast_external_failover_cmd);
	install_element(BGP_NODE, &no_bgp_fast_external_failover_cmd);

	/* "bgp bestpath compare-routerid" commands */
	install_element(BGP_NODE, &bgp_bestpath_compare_router_id_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_compare_router_id_cmd);

	/* "bgp bestpath as-path ignore" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_ignore_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_ignore_cmd);

	/* "bgp bestpath as-path confed" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_confed_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_confed_cmd);

	/* "bgp bestpath as-path multipath-relax" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_multipath_relax_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_multipath_relax_cmd);

	/* "bgp log-neighbor-changes" commands */
	install_element(BGP_NODE, &bgp_log_neighbor_changes_cmd);
	install_element(BGP_NODE, &no_bgp_log_neighbor_changes_cmd);

	/* "bgp bestpath med" commands */
	install_element(BGP_NODE, &bgp_bestpath_med_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_med_cmd);

	/* "no bgp default ipv4-unicast" commands. */
	install_element(BGP_NODE, &no_bgp_default_ipv4_unicast_cmd);
	install_element(BGP_NODE, &bgp_default_ipv4_unicast_cmd);

	/* "bgp network import-check" commands. */
	install_element(BGP_NODE, &bgp_network_import_check_cmd);
	install_element(BGP_NODE, &bgp_network_import_check_exact_cmd);
	install_element(BGP_NODE, &no_bgp_network_import_check_cmd);

	/* "bgp default local-preference" commands. */
	install_element(BGP_NODE, &bgp_default_local_preference_cmd);
	install_element(BGP_NODE, &no_bgp_default_local_preference_cmd);

	/* bgp default show-hostname */
	install_element(BGP_NODE, &bgp_default_show_hostname_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_hostname_cmd);

	/* "bgp default subgroup-pkt-queue-max" commands. */
	install_element(BGP_NODE, &bgp_default_subgroup_pkt_queue_max_cmd);
	install_element(BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_cmd);

	/* bgp ibgp-allow-policy-mods command */
	install_element(BGP_NODE, &bgp_rr_allow_outbound_policy_cmd);
	install_element(BGP_NODE, &no_bgp_rr_allow_outbound_policy_cmd);

	/* "bgp listen limit" commands. */
	install_element(BGP_NODE, &bgp_listen_limit_cmd);
	install_element(BGP_NODE, &no_bgp_listen_limit_cmd);

	/* "bgp listen range" commands. */
	install_element(BGP_NODE, &bgp_listen_range_cmd);
	install_element(BGP_NODE, &no_bgp_listen_range_cmd);

	/* "bgp default shutdown" command */
	install_element(BGP_NODE, &bgp_default_shutdown_cmd);

	/* "neighbor remote-as" commands. */
	install_element(BGP_NODE, &neighbor_remote_as_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_v6only_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_remote_as_cmd);
	install_element(BGP_NODE,
			&neighbor_interface_v6only_config_remote_as_cmd);
	install_element(BGP_NODE, &no_neighbor_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_config_cmd);

	/* "neighbor peer-group" commands. */
	install_element(BGP_NODE, &neighbor_peer_group_cmd);
	install_element(BGP_NODE, &no_neighbor_peer_group_cmd);
	install_element(BGP_NODE,
			&no_neighbor_interface_peer_group_remote_as_cmd);

	/* "neighbor local-as" commands. */
	install_element(BGP_NODE, &neighbor_local_as_cmd);
	install_element(BGP_NODE, &neighbor_local_as_no_prepend_cmd);
	install_element(BGP_NODE, &neighbor_local_as_no_prepend_replace_as_cmd);
	install_element(BGP_NODE, &no_neighbor_local_as_cmd);

	/* "neighbor solo" commands. */
	install_element(BGP_NODE, &neighbor_solo_cmd);
	install_element(BGP_NODE, &no_neighbor_solo_cmd);

	/* "neighbor password" commands. */
	install_element(BGP_NODE, &neighbor_password_cmd);
	install_element(BGP_NODE, &no_neighbor_password_cmd);

	/* "neighbor activate" commands. */
	install_element(BGP_NODE, &neighbor_activate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_activate_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_activate_cmd);

	/* "no neighbor activate" commands. */
	install_element(BGP_NODE, &no_neighbor_activate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_activate_cmd);

	/* "neighbor peer-group" set commands. */
	install_element(BGP_NODE, &neighbor_set_peer_group_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_set_peer_group_hidden_cmd);

	/* "no neighbor peer-group unset" commands. */
	install_element(BGP_NODE, &no_neighbor_set_peer_group_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_set_peer_group_hidden_cmd);

	/* "neighbor softreconfiguration inbound" commands.*/
	install_element(BGP_NODE, &neighbor_soft_reconfiguration_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_soft_reconfiguration_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_soft_reconfiguration_cmd);

	/* "neighbor attribute-unchanged" commands.  */
	install_element(BGP_NODE, &neighbor_attr_unchanged_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_attr_unchanged_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_attr_unchanged_cmd);

	install_element(BGP_EVPN_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_attr_unchanged_cmd);

	/* "nexthop-local unchanged" commands */
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_nexthop_local_unchanged_cmd);

	/* "neighbor next-hop-self" commands. */
	install_element(BGP_NODE, &neighbor_nexthop_self_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_nexthop_self_cmd);

	/* "neighbor next-hop-self force" commands. */
	install_element(BGP_NODE, &neighbor_nexthop_self_force_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_force_hidden_cmd);
	install_element(BGP_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);

	/* "neighbor as-override" commands. */
	install_element(BGP_NODE, &neighbor_as_override_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_as_override_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_as_override_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_as_override_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_as_override_cmd);

	/* "neighbor remove-private-AS" commands. */
	install_element(BGP_NODE, &neighbor_remove_private_as_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_remove_private_as_hidden_cmd);
	install_element(BGP_NODE, &neighbor_remove_private_as_all_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_remove_private_as_all_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_remove_private_as_replace_as_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_remove_private_as_replace_as_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_remove_private_as_all_replace_as_hidden_cmd);
	install_element(
		BGP_NODE,
		&no_neighbor_remove_private_as_all_replace_as_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);

	/* "neighbor send-community" commands.*/
	install_element(BGP_NODE, &neighbor_send_community_hidden_cmd);
	install_element(BGP_NODE, &neighbor_send_community_type_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_send_community_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_send_community_type_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_send_community_type_cmd);

	/* "neighbor route-reflector" commands.*/
	install_element(BGP_NODE, &neighbor_route_reflector_client_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_route_reflector_client_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_reflector_client_cmd);

	/* "neighbor route-server" commands.*/
	install_element(BGP_NODE, &neighbor_route_server_client_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_route_server_client_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_route_server_client_cmd);

	/* "neighbor addpath-tx-all-paths" commands.*/
	install_element(BGP_NODE, &neighbor_addpath_tx_all_paths_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_addpath_tx_all_paths_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_addpath_tx_all_paths_cmd);

	/* "neighbor addpath-tx-bestpath-per-AS" commands.*/
	install_element(BGP_NODE,
			&neighbor_addpath_tx_bestpath_per_as_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_hidden_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);

	/* "neighbor sender-as-path-loop-detection" commands. */
	install_element(BGP_NODE, &neighbor_aspath_loop_detection_cmd);
	install_element(BGP_NODE, &no_neighbor_aspath_loop_detection_cmd);

	/* "neighbor passive" commands. */
	install_element(BGP_NODE, &neighbor_passive_cmd);
	install_element(BGP_NODE, &no_neighbor_passive_cmd);


	/* "neighbor shutdown" commands. */
	install_element(BGP_NODE, &neighbor_shutdown_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_msg_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_msg_cmd);

	/* "neighbor capability extended-nexthop" commands.*/
	install_element(BGP_NODE, &neighbor_capability_enhe_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_enhe_cmd);

	/* "neighbor capability orf prefix-list" commands.*/
	install_element(BGP_NODE, &neighbor_capability_orf_prefix_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_capability_orf_prefix_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_capability_orf_prefix_cmd);

	/* "neighbor capability dynamic" commands.*/
	install_element(BGP_NODE, &neighbor_capability_dynamic_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_dynamic_cmd);

	/* "neighbor dont-capability-negotiate" commands. */
	install_element(BGP_NODE, &neighbor_dont_capability_negotiate_cmd);
	install_element(BGP_NODE, &no_neighbor_dont_capability_negotiate_cmd);

	/* "neighbor ebgp-multihop" commands. */
	install_element(BGP_NODE, &neighbor_ebgp_multihop_cmd);
	install_element(BGP_NODE, &neighbor_ebgp_multihop_ttl_cmd);
	install_element(BGP_NODE, &no_neighbor_ebgp_multihop_cmd);

	/* "neighbor disable-connected-check" commands.  */
	install_element(BGP_NODE, &neighbor_disable_connected_check_cmd);
	install_element(BGP_NODE, &no_neighbor_disable_connected_check_cmd);

	/* "neighbor enforce-first-as" commands. */
	install_element(BGP_NODE, &neighbor_enforce_first_as_cmd);
	install_element(BGP_NODE, &no_neighbor_enforce_first_as_cmd);

	/* "neighbor description" commands. */
	install_element(BGP_NODE, &neighbor_description_cmd);
	install_element(BGP_NODE, &no_neighbor_description_cmd);
	install_element(BGP_NODE, &no_neighbor_description_comment_cmd);

	/* "neighbor update-source" commands. "*/
	install_element(BGP_NODE, &neighbor_update_source_cmd);
	install_element(BGP_NODE, &no_neighbor_update_source_cmd);

	/* "neighbor default-originate" commands. */
	install_element(BGP_NODE, &neighbor_default_originate_hidden_cmd);
	install_element(BGP_NODE, &neighbor_default_originate_rmap_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_default_originate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_default_originate_cmd);

	/* "neighbor port" commands. */
	install_element(BGP_NODE, &neighbor_port_cmd);
	install_element(BGP_NODE, &no_neighbor_port_cmd);

	/* "neighbor weight" commands. */
	install_element(BGP_NODE, &neighbor_weight_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_weight_hidden_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_weight_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_weight_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_weight_cmd);

	/* "neighbor override-capability" commands. */
	install_element(BGP_NODE, &neighbor_override_capability_cmd);
	install_element(BGP_NODE, &no_neighbor_override_capability_cmd);

	/* "neighbor strict-capability-match" commands. */
	install_element(BGP_NODE, &neighbor_strict_capability_cmd);
	install_element(BGP_NODE, &no_neighbor_strict_capability_cmd);

	/* "neighbor timers" commands. */
	install_element(BGP_NODE, &neighbor_timers_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_cmd);

	/* "neighbor timers connect" commands. */
	install_element(BGP_NODE, &neighbor_timers_connect_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_connect_cmd);

	/* "neighbor advertisement-interval" commands. */
	install_element(BGP_NODE, &neighbor_advertise_interval_cmd);
	install_element(BGP_NODE, &no_neighbor_advertise_interval_cmd);

	/* "neighbor interface" commands. */
	install_element(BGP_NODE, &neighbor_interface_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_cmd);

	/* "neighbor distribute" commands. */
	install_element(BGP_NODE, &neighbor_distribute_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_distribute_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_distribute_list_cmd);

	/* "neighbor prefix-list" commands. */
	install_element(BGP_NODE, &neighbor_prefix_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_prefix_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_prefix_list_cmd);

	/* "neighbor filter-list" commands. */
	install_element(BGP_NODE, &neighbor_filter_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_filter_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_filter_list_cmd);

	/* "neighbor route-map" commands. */
	install_element(BGP_NODE, &neighbor_route_map_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_route_map_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_map_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_map_cmd);

	/* "neighbor unsuppress-map" commands. */
	install_element(BGP_NODE, &neighbor_unsuppress_map_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_unsuppress_map_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_unsuppress_map_cmd);

	/* "neighbor maximum-prefix" commands. */
	install_element(BGP_NODE, &neighbor_maximum_prefix_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_hidden_cmd);
	install_element(BGP_NODE, &neighbor_maximum_prefix_warning_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_warning_hidden_cmd);
	install_element(BGP_NODE, &neighbor_maximum_prefix_restart_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_restart_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_maximum_prefix_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_maximum_prefix_cmd);

	/* "neighbor allowas-in" */
	install_element(BGP_NODE, &neighbor_allowas_in_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_allowas_in_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_allowas_in_cmd);

	/* address-family commands. */
	install_element(BGP_NODE, &address_family_ipv4_safi_cmd);
	install_element(BGP_NODE, &address_family_ipv6_safi_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(BGP_NODE, &address_family_vpnv4_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */

	install_element(BGP_NODE, &address_family_evpn_cmd);

	/* "exit-address-family" command. */
	install_element(BGP_IPV4_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4M_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4L_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6M_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6L_NODE, &exit_address_family_cmd);
	install_element(BGP_VPNV4_NODE, &exit_address_family_cmd);
	install_element(BGP_VPNV6_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &exit_address_family_cmd);
	install_element(BGP_EVPN_NODE, &exit_address_family_cmd);

	/* "clear ip bgp commands" */
	install_element(ENABLE_NODE, &clear_ip_bgp_all_cmd);

	/* clear ip bgp prefix  */
	install_element(ENABLE_NODE, &clear_ip_bgp_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_ipv6_safi_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_instance_ipv6_safi_prefix_cmd);

	/* "show [ip] bgp summary" commands. */
	install_element(VIEW_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_instance_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_bgp_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_summary_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_updgrps_cmd);

	/* "show [ip] bgp neighbors" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_neighbors_cmd);

	/* "show [ip] bgp peer-group" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_peer_groups_cmd);

	/* "show [ip] bgp paths" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_paths_cmd);

	/* "show [ip] bgp community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_community_info_cmd);

	/* "show ip bgp large-community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_lcommunity_info_cmd);
	/* "show [ip] bgp attribute-info" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_attr_info_cmd);
	/* "show [ip] bgp route-leak" command */
	install_element(VIEW_NODE, &show_ip_bgp_route_leak_cmd);

	/* "redistribute" commands.  */
	install_element(BGP_NODE, &bgp_redistribute_ipv4_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_redistribute_ipv4_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_rmap_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_rmap_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_metric_rmap_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_ospf_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_redistribute_ipv4_ospf_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_ospf_rmap_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_rmap_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_metric_rmap_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_metric_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_metric_cmd);
	install_element(BGP_IPV4_NODE,
			&bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
	install_element(BGP_IPV4_NODE,
			&bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_metric_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_rmap_cmd);

	/* import|export vpn [route-map WORD] */
	install_element(BGP_IPV4_NODE, &bgp_imexport_vpn_cmd);
	install_element(BGP_IPV6_NODE, &bgp_imexport_vpn_cmd);

	install_element(BGP_IPV4_NODE, &bgp_imexport_vrf_cmd);
	install_element(BGP_IPV6_NODE, &bgp_imexport_vrf_cmd);

	/* ttl_security commands */
	install_element(BGP_NODE, &neighbor_ttl_security_cmd);
	install_element(BGP_NODE, &no_neighbor_ttl_security_cmd);

	/* "show [ip] bgp memory" commands. */
	install_element(VIEW_NODE, &show_bgp_memory_cmd);

	/* "show bgp martian next-hop" */
	install_element(VIEW_NODE, &show_bgp_martian_nexthop_db_cmd);

	install_element(VIEW_NODE, &show_bgp_mac_hash_cmd);

	/* "show [ip] bgp views" commands. */
	install_element(VIEW_NODE, &show_bgp_views_cmd);

	/* "show [ip] bgp vrfs" commands. */
	install_element(VIEW_NODE, &show_bgp_vrfs_cmd);

	/* Community-list. */
	community_list_vty();

	/* vpn-policy commands */
	install_element(BGP_IPV4_NODE, &af_rd_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_rd_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_label_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_label_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_nexthop_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_nexthop_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_rt_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_rt_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_import_vrf_route_map_cmd);
	install_element(BGP_IPV6_NODE, &af_import_vrf_route_map_cmd);

	install_element(BGP_IPV4_NODE, &af_routetarget_import_cmd);
	install_element(BGP_IPV6_NODE, &af_routetarget_import_cmd);

	install_element(BGP_IPV4_NODE, &af_no_rd_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rd_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_label_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_label_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_nexthop_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_nexthop_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rt_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rt_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_no_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_no_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_no_import_vrf_route_map_cmd);
	install_element(BGP_IPV6_NODE, &af_no_import_vrf_route_map_cmd);
}

#include "memory.h"
#include "bgp_regex.h"
#include "bgp_clist.h"
#include "bgp_ecommunity.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *community_direct_str(int direct)
{
	switch (direct) {
	case COMMUNITY_DENY:
		return "deny";
	case COMMUNITY_PERMIT:
		return "permit";
	default:
		return "unknown";
	}
}

/* Display error string.  */
static void community_list_perror(struct vty *vty, int ret)
{
	switch (ret) {
	case COMMUNITY_LIST_ERR_CANT_FIND_LIST:
		vty_out(vty, "%% Can't find community-list\n");
		break;
	case COMMUNITY_LIST_ERR_MALFORMED_VAL:
		vty_out(vty, "%% Malformed community-list value\n");
		break;
	case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as standard community\n");
		break;
	case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as expanded community\n");
		break;
	}
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"

/*community-list standard */
DEFUN (community_list_standard,
       bgp_community_list_standard_cmd,
       "bgp community-list <(1-99)|standard WORD> <deny|permit> AA:NN...",
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Add an standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_STANDARD;
	int idx = 0;

	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_name_or_number = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = community_list_set(bgp_clist, cl_name_or_number, str, direct,
				     style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		/* Display error string.  */
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_community_list_standard_all,
       no_bgp_community_list_standard_all_cmd,
       "no bgp community-list <(1-99)|standard WORD> <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Add an standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *str = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_STANDARD;

	int idx = 0;

	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_name_or_number = argv[idx]->arg;

	int ret = community_list_unset(bgp_clist, cl_name_or_number, str,
				       direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

ALIAS(no_community_list_standard_all, no_bgp_community_list_standard_all_list_cmd,
      "no bgp community-list <(1-99)|standard WORD>",
      NO_STR BGP_STR COMMUNITY_LIST_STR
      "Community list number (standard)\n"
      "Add an standard community-list entry\n"
      "Community list name\n")

/*community-list expanded */
DEFUN (community_list_expanded_all,
       bgp_community_list_expanded_all_cmd,
       "bgp community-list <(100-500)|expanded WORD> <deny|permit> AA:NN...",
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_EXPANDED;

	int idx = 0;

	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_name_or_number = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = community_list_set(bgp_clist, cl_name_or_number, str, direct,
				     style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		/* Display error string.  */
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_community_list_expanded_all,
       no_bgp_community_list_expanded_all_cmd,
       "no bgp community-list <(100-500)|expanded WORD> <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *str = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_EXPANDED;

	int idx = 0;

	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_name_or_number = argv[idx]->arg;

	int ret = community_list_unset(bgp_clist, cl_name_or_number, str,
				       direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

ALIAS(no_community_list_expanded_all, no_bgp_community_list_expanded_all_list_cmd,
      "no bgp community-list <(100-500)|expanded WORD>",
      NO_STR IP_STR COMMUNITY_LIST_STR
      "Community list number (expanded)\n"
      "Add an expanded community-list entry\n"
      "Community list name\n")

/* Return configuration string of community-list entry.  */
static const char *community_list_config_str(struct community_entry *entry)
{
	const char *str;

	if (entry->any)
		str = "";
	else {
		if (entry->style == COMMUNITY_LIST_STANDARD)
			str = community_str(entry->u.com, false);
		else if (entry->style == LARGE_COMMUNITY_LIST_STANDARD)
			str = lcommunity_str(entry->u.lcom, false);
		else
			str = entry->config;
	}
	return str;
}

static void community_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty, "Named Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		if (entry->any)
			vty_out(vty, "    %s\n",
				community_direct_str(entry->direct));
		else
			vty_out(vty, "    %s %s\n",
				community_direct_str(entry->direct),
				community_list_config_str(entry));
	}
}

DEFUN (show_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list",
       SHOW_STR
       BGP_STR
       "List community-list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		community_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		community_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_community_list_arg,
       show_bgp_community_list_arg_cmd,
       "show bgp community-list <(1-500)|WORD> detail",
       SHOW_STR
       BGP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n"
       "Detailed information on community-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find community-list\n");
		return CMD_WARNING;
	}

	community_list_show(vty, list);

	return CMD_SUCCESS;
}

/*
 * Large Community code.
 */
static int lcommunity_list_set_vty(struct vty *vty, int argc,
				   struct cmd_token **argv, int style,
				   int reject_all_digit_name)
{
	int ret;
	int direct;
	char *str;
	int idx = 0;
	char *cl_name;

	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;

	/* All digit name check.  */
	idx = 0;
	argv_find(argv, argc, "WORD", &idx);
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "(100-500)", &idx);
	cl_name = argv[idx]->arg;
	if (reject_all_digit_name && all_digit(cl_name)) {
		vty_out(vty, "%% Community name cannot have all digits\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	idx = 0;
	argv_find(argv, argc, "AA:BB:CC", &idx);
	argv_find(argv, argc, "LINE", &idx);
	/* Concat community string argument. */
	if (idx)
		str = argv_concat(argv, argc, idx);
	else
		str = NULL;

	ret = lcommunity_list_set(bgp_clist, cl_name, str, direct, style);

	/* Free temporary community list string allocated by
	   argv_concat().  */
	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

static int lcommunity_list_unset_vty(struct vty *vty, int argc,
				     struct cmd_token **argv, int style)
{
	int ret;
	int direct = 0;
	char *str = NULL;
	int idx = 0;

	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		/* Check the list direct. */
		if (strncmp(argv[idx]->arg, "p", 1) == 0)
			direct = COMMUNITY_PERMIT;
		else
			direct = COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "LINE", &idx);
		argv_find(argv, argc, "AA:AA:NN", &idx);
		/* Concat community string argument.  */
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "WORD", &idx);

	/* Unset community list.  */
	ret = lcommunity_list_unset(bgp_clist, argv[idx]->arg, str, direct,
				    style);

	/* Free temporary community list string allocated by
	   argv_concat().  */
	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* "large-community-list" keyword help string.  */
#define LCOMMUNITY_LIST_STR "Add a large community list entry\n"
#define LCOMMUNITY_VAL_STR  "large community in 'aa:bb:cc' format\n"

DEFUN (lcommunity_list_standard,
       bgp_lcommunity_list_standard_cmd,
       "bgp large-community-list (1-99) <deny|permit> AA:BB:CC...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_STANDARD, 0);
}

DEFUN (lcommunity_list_expanded,
       bgp_lcommunity_list_expanded_cmd,
       "bgp large-community-list (100-500) <deny|permit> LINE...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (expanded)\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (lcommunity_list_name_standard,
       bgp_lcommunity_list_name_standard_cmd,
       "bgp large-community-list standard WORD <deny|permit> AA:BB:CC...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify standard large-community-list\n"
       "Large Community list name\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_STANDARD, 1);
}

DEFUN (lcommunity_list_name_expanded,
       bgp_lcommunity_list_name_expanded_cmd,
       "bgp large-community-list expanded WORD <deny|permit> LINE...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large Community list name\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_lcommunity_list_standard_all,
       no_bgp_lcommunity_list_standard_all_cmd,
       "no bgp large-community-list <(1-99)|(100-500)|WORD>",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Large Community list number (expanded)\n"
       "Large Community list name\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_name_expanded_all,
       no_bgp_lcommunity_list_name_expanded_all_cmd,
       "no bgp large-community-list expanded WORD",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large Community list name\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

DEFUN (no_lcommunity_list_standard,
       no_bgp_lcommunity_list_standard_cmd,
       "no bgp large-community-list (1-99) <deny|permit> AA:AA:NN...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_expanded,
       no_bgp_lcommunity_list_expanded_cmd,
       "no bgp large-community-list (100-500) <deny|permit> LINE...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (expanded)\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

DEFUN (no_lcommunity_list_name_standard,
       no_bgp_lcommunity_list_name_standard_cmd,
       "no bgp large-community-list standard WORD <deny|permit> AA:AA:NN...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify standard large-community-list\n"
       "Large Community list name\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_name_expanded,
       no_bgp_lcommunity_list_name_expanded_cmd,
       "no bgp large-community-list expanded WORD <deny|permit> LINE...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large community list name\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

static void lcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		if (entry->any)
			vty_out(vty, "    %s\n",
				community_direct_str(entry->direct));
		else
			vty_out(vty, "    %s %s\n",
				community_direct_str(entry->direct),
				community_list_config_str(entry));
	}
}

DEFUN (show_lcommunity_list,
       show_bgp_lcommunity_list_cmd,
       "show bgp large-community-list",
       SHOW_STR
       BGP_STR
       "List large-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_lcommunity_list_arg,
       show_bgp_lcommunity_list_arg_cmd,
       "show bgp large-community-list <(1-500)|WORD> detail",
       SHOW_STR
       BGP_STR
       "List large-community list\n"
       "Large-community-list number\n"
       "Large-community-list name\n"
       "Detailed information on large-community-list\n")
{
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[3]->arg, 0,
				     LARGE_COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find large-community-list\n");
		return CMD_WARNING;
	}

	lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in 'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

DEFUN (extcommunity_list_standard,
       bgp_extcommunity_list_standard_cmd,
       "bgp extcommunity-list <(1-99)|standard WORD> <deny|permit> AA:NN...",
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify standard extcommunity-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
	int style = EXTCOMMUNITY_LIST_STANDARD;
	int direct = 0;
	char *cl_number_or_name = NULL;

	int idx = 0;

	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_number_or_name = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = extcommunity_list_set(bgp_clist, cl_number_or_name, str,
					direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (extcommunity_list_name_expanded,
       bgp_extcommunity_list_name_expanded_cmd,
       "bgp extcommunity-list <(100-500)|expanded WORD> <deny|permit> LINE...",
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
	int style = EXTCOMMUNITY_LIST_EXPANDED;
	int direct = 0;
	char *cl_number_or_name = NULL;
	int idx = 0;

	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_number_or_name = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "LINE", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = extcommunity_list_set(bgp_clist, cl_number_or_name, str,
					direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_extcommunity_list_standard_all,
       no_bgp_extcommunity_list_standard_all_cmd,
       "no bgp extcommunity-list <(1-99)|standard WORD> <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify standard extcommunity-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
	int style = EXTCOMMUNITY_LIST_STANDARD;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *str = NULL;
	int idx = 0;

	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_number_or_name = argv[idx]->arg;

	int ret = extcommunity_list_unset(bgp_clist, cl_number_or_name, str,
					  direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

ALIAS(no_extcommunity_list_standard_all,
      no_bgp_extcommunity_list_standard_all_list_cmd,
      "no bgp extcommunity-list <(1-99)|standard WORD>",
      NO_STR IP_STR EXTCOMMUNITY_LIST_STR
      "Extended Community list number (standard)\n"
      "Specify standard extcommunity-list\n"
      "Community list name\n")

DEFUN (no_extcommunity_list_expanded_all,
       no_bgp_extcommunity_list_expanded_all_cmd,
       "no bgp extcommunity-list <(100-500)|expanded WORD> <deny|permit> LINE...",
       NO_STR
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
	int style = EXTCOMMUNITY_LIST_EXPANDED;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *str = NULL;
	int idx = 0;

	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "LINE", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "WORD", &idx);
	cl_number_or_name = argv[idx]->arg;

	int ret = extcommunity_list_unset(bgp_clist, cl_number_or_name, str,
					  direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

ALIAS(no_extcommunity_list_expanded_all,
      no_bgp_extcommunity_list_expanded_all_list_cmd,
      "no bgp extcommunity-list <(100-500)|expanded WORD>",
      NO_STR IP_STR EXTCOMMUNITY_LIST_STR
      "Extended Community list number (expanded)\n"
      "Specify expanded extcommunity-list\n"
      "Extended Community list name\n")

static void extcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		if (entry->any)
			vty_out(vty, "    %s\n",
				community_direct_str(entry->direct));
		else
			vty_out(vty, "    %s %s\n",
				community_direct_str(entry->direct),
				community_list_config_str(entry));
	}
}

DEFUN (show_extcommunity_list,
       show_bgp_extcommunity_list_cmd,
       "show bgp extcommunity-list",
       SHOW_STR
       BGP_STR
       "List extended-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_extcommunity_list_arg,
       show_bgp_extcommunity_list_arg_cmd,
       "show bgp extcommunity-list <(1-500)|WORD> detail",
       SHOW_STR
       BGP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n"
       "Detailed information on extcommunity-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     EXTCOMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find extcommunity-list\n");
		return CMD_WARNING;
	}

	extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* Display community-list and extcommunity-list configuration.  */
static int community_list_config_write(struct vty *vty)
{
	struct community_list *list;
	struct community_entry *entry;
	struct community_list_master *cm;
	int write = 0;

	/* Community-list.  */
	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp community-list %s %s %s\n", list->name,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp community-list %s %s %s %s\n",
				entry->style == COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	/* Extcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp extcommunity-list %s %s %s\n",
				list->name, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp extcommunity-list %s %s %s %s\n",
				entry->style == EXTCOMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}


	/* lcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp large-community-list %s %s %s\n",
				list->name, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty, "bgp large-community-list %s %s %s %s\n",
				entry->style == LARGE_COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	return write;
}

static struct cmd_node community_list_node = {
	COMMUNITY_LIST_NODE, "", 1 /* Export to vtysh.  */
};

static void community_list_vty(void)
{
	install_node(&community_list_node, community_list_config_write);

	/* Community-list.  */
	install_element(CONFIG_NODE, &bgp_community_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_community_list_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_list_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_arg_cmd);

	/* Extcommunity-list.  */
	install_element(CONFIG_NODE, &bgp_extcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_extcommunity_list_name_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_extcommunity_list_standard_all_list_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_extcommunity_list_expanded_all_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_arg_cmd);

	/* Large Community List */
	install_element(CONFIG_NODE, &bgp_lcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_expanded_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_name_standard_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_name_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_lcommunity_list_name_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_name_standard_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_name_expanded_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_arg_cmd);
}
