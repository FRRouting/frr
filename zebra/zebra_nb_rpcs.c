// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Cumulus Networks, Inc.
 *                    Chirag Shah
 */

#include <zebra.h>
#include "northbound.h"
#include "libfrr.h"

#include "zebra/zebra_nb.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn.h"

/*
 * XPath: /frr-zebra:clear-evpn-dup-addr
 */
int clear_evpn_dup_addr_rpc(struct nb_cb_rpc_args *args)
{
	struct zebra_vrf *zvrf;
	int ret = NB_OK;

	if (!is_evpn_enabled()) {
		snprintf(args->errmsg, args->errmsg_len,
			 "%% EVPN not enabled\n");
		return NB_ERR_VALIDATION;
	}
	zvrf = zebra_vrf_get_evpn();

	if (yang_dnode_exists(args->input, "all-vnis")) {
		zebra_vxlan_clear_dup_detect_vni_all(zvrf);
	} else {
		vni_t vni = yang_dnode_get_uint32(args->input, "vni-id");
		struct ipaddr host_ip = {.ipa_type = IPADDR_NONE};
		struct ethaddr mac;

		if (!zebra_evpn_lookup(vni)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% VNI %u does not exist\n", vni);
			return NB_ERR_VALIDATION;
		}

		if (yang_dnode_exists(args->input, "mac-addr")) {
			yang_dnode_get_mac(&mac, args->input, "mac-addr");
			ret = zebra_vxlan_clear_dup_detect_vni_mac(zvrf, vni,
								   &mac,
								   args->errmsg,
								   args->errmsg_len);
		} else if (yang_dnode_exists(args->input, "vni-ipaddr")) {
			yang_dnode_get_ip(&host_ip, args->input, "vni-ipaddr");
			ret = zebra_vxlan_clear_dup_detect_vni_ip(zvrf, vni,
								  &host_ip,
								  args->errmsg,
								  args->errmsg_len);
		} else {
			ret = zebra_vxlan_clear_dup_detect_vni(zvrf, vni);
		}
	}
	if (ret < 0)
		return NB_ERR;

	return NB_OK;
}

/*
 * XPath: /frr-zebra:get-route-information
 */
int get_route_information_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-v6-mroute-info
 */
int get_v6_mroute_info_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vrf-info
 */
int get_vrf_info_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vrf-vni-info
 */
int get_vrf_vni_info_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-info
 */
int get_evpn_info_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-vni-info
 */
int get_vni_info_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-vni-rmac
 */
int get_evpn_vni_rmac_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-vni-nexthops
 */
int get_evpn_vni_nexthops_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-macs
 */
int get_evpn_macs_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-evpn-arp-cache
 */
int get_evpn_arp_cache_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-pbr-ipset
 */
int get_pbr_ipset_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-pbr-iptable
 */
int get_pbr_iptable_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}

/*
 * XPath: /frr-zebra:get-debugs
 */
int get_debugs_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_ERR_NOT_FOUND;
}
