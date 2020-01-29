/*
 * Copyright (C) 2020 Cumulus Networks, Inc.
 *                    Chirag Shah
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
#include "northbound.h"
#include "libfrr.h"

#include "zebra/zebra_nb.h"

/*
 * XPath: /frr-zebra:get-route-information
 */
int get_route_information_rpc(const char *xpath, const struct list *input,
			      struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-v6-mroute-info
 */
int get_v6_mroute_info_rpc(const char *xpath, const struct list *input,
			   struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vrf-info
 */
int get_vrf_info_rpc(const char *xpath, const struct list *input,
		     struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vrf-vni-info
 */
int get_vrf_vni_info_rpc(const char *xpath, const struct list *input,
			 struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-info
 */
int get_evpn_info_rpc(const char *xpath, const struct list *input,
		      struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vni-info
 */
int get_vni_info_rpc(const char *xpath, const struct list *input,
		     struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-vni-rmac
 */
int get_evpn_vni_rmac_rpc(const char *xpath, const struct list *input,
			  struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-vni-nexthops
 */
int get_evpn_vni_nexthops_rpc(const char *xpath, const struct list *input,
			      struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:clear-evpn-dup-addr
 */
int clear_evpn_dup_addr_rpc(const char *xpath, const struct list *input,
			    struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-macs
 */
int get_evpn_macs_rpc(const char *xpath, const struct list *input,
		      struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-arp-cache
 */
int get_evpn_arp_cache_rpc(const char *xpath, const struct list *input,
			   struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-pbr-ipset
 */
int get_pbr_ipset_rpc(const char *xpath, const struct list *input,
		      struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-pbr-iptable
 */
int get_pbr_iptable_rpc(const char *xpath, const struct list *input,
			struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-debugs
 */
int get_debugs_rpc(const char *xpath, const struct list *input,
		   struct list *output)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}
