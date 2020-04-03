/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "pimd/pim_nb.h"

static int pim_null_create(enum nb_event event,
                const struct lyd_node *dnode,
                union nb_resource *resource)
{
        return NB_OK;
}

static int pim_null_destroy(enum nb_event event,
                                const struct lyd_node *dnode)
{
        return NB_OK;
}

/*static int pim_null_modify(enum nb_event event,
                                           const struct lyd_node *dnode,
                                             union nb_resource *resource)
{
        return NB_OK;
}
*/

const struct frr_yang_module_info frr_routing_info = {
	.name = "frr-routing",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol",
			.cbs.create = pim_null_create,
			.cbs.destroy = pim_null_destroy,
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_pim_info = {
	.name = "frr-pim",
	.nodes = {
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim",
                        .cbs.create = pim_instance_create,
                        .cbs.destroy = pim_instance_destroy,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp",
                        .cbs.create = pim_instance_ecmp_create,
                        .cbs.destroy = pim_instance_ecmp_destroy,
                },
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp-rebalance",
			.cbs.create = pim_instance_ecmp_rebalance_create,
			.cbs.destroy = pim_instance_ecmp_rebalance_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/join-prune-interval",
			.cbs.modify = pim_instance_join_prune_interval_modify,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/keep-alive-timer",
			.cbs.modify = pim_instance_keep_alive_timer_modify,
		},
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/rp-keep-alive-timer",
                        .cbs.modify = pim_instance_rp_ka_timer_modify,
                },
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/packets",
			.cbs.modify = pim_instance_packets_modify,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/register-suppress-time",
			.cbs.modify = pim_instance_register_suppress_time_modify,
		},
                {       
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family",
                        .cbs.create = pim_instance_af_create,
                        .cbs.destroy = pim_instance_af_destroy,
                },
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary",
			.cbs.create = pim_instance_send_v6_secondary_create,
			.cbs.destroy = pim_instance_send_v6_secondary_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-action",
			.cbs.modify = pim_instance_spt_switch_action_modify,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list",
			.cbs.modify = pim_instance_spt_switch_infinity_prefix_list_modify,
			.cbs.destroy = pim_instance_spt_switch_infinity_prefix_list_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm/prefix-list",
                        .cbs.modify = pim_instance_ssm_prefix_list_modify,
                        .cbs.destroy = pim_instance_ssm_prefix_list_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd/source-ip",
			.cbs.create = pim_instance_ssm_pingd_source_ip_create,
			.cbs.destroy = pim_instance_ssm_pingd_source_ip_destroy,
		},
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/mesh-group-name",
                        .cbs.modify = pim_instance_msdp_mesh_group_create,
                        .cbs.destroy = pim_instance_msdp_mesh_group_destroy,
                },
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/member-ip",
                        .cbs.create = pim_instance_msdp_mesh_group_member_create,
                        .cbs.destroy = pim_instance_msdp_mesh_group_member_destroy,
                },
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/source-ip",
                        .cbs.modify = pim_instance_msdp_mesh_group_source_modify,
                        .cbs.destroy = pim_instance_msdp_mesh_group_source_destroy,
                },
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer",
			.cbs.create = pim_instance_msdp_peer_create,
                        .cbs.destroy = pim_instance_msdp_peer_destroy,
                },		
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer/source-ip",
                        .cbs.modify = pim_instance_msdp_peer_ip_create,
                        .cbs.destroy = pim_instance_msdp_peer_ip_destroy,
                },
                {
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag",
                        .cbs.apply_finish = pim_instance_mlag_apply_finish,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif",
                        .cbs.modify = pim_instance_mlag_peerlink_rif_modify,
                        .cbs.destroy = pim_instance_mlag_peerlink_rif_destroy,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address",
                        .cbs.modify = pim_instance_mlag_reg_address_modify,
                        .cbs.destroy = pim_instance_mlag_reg_address_destroy,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/my-role",
                        .cbs.modify = pim_instance_mlag_my_role_modify,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peer-state",
                        .cbs.modify = pim_instance_mlag_peer_state_modify,
                },
                {
                        .xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list",
                        .cbs.modify = pim_instance_register_accept_list_modify,
                        .cbs.destroy = pim_instance_register_accept_list_destroy,
                },
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim",
			.cbs.create = pim_interface_create,
			.cbs.destroy = pim_interface_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/dr-priority",
			.cbs.modify = pim_interface_dr_priority_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/hello-interval",
			.cbs.modify = pim_interface_hello_interval_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/hello-holdtime",
			.cbs.modify = pim_interface_hello_holdtime_modify,
			.cbs.destroy = pim_interface_hello_holdtime_destroy,
		},
                {
                        .xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd",
			.cbs.create = pim_interface_bfd_create,
			.cbs.destroy = pim_interface_bfd_destroy,
			.cbs.apply_finish = pim_interface_bfd_apply_finish,
                },
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/min-rx-interval",
			.cbs.modify = pim_interface_bfd_min_rx_interval_modify,
		},
                {
                        .xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/min-tx-interval",
                        .cbs.modify = pim_interface_bfd_min_tx_interval_modify,
                },
                {
                        .xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/detect_mult",
                        .cbs.modify = pim_interface_bfd_detect_mult_modify,
                },
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bsm",
			.cbs.create = pim_interface_bsm_create,
			.cbs.destroy = pim_interface_bsm_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/unicast-bsm",
			.cbs.create = pim_interface_unicast_bsm_create,
			.cbs.destroy = pim_interface_unicast_bsm_destroy,
		},
                {
                        .xpath = "/frr-interface:lib/interface/frr-pim:pim/active-active",
                        .cbs.create = pim_interface_active_active_create,
			.cbs.destroy = pim_interface_active_active_destroy,
                },
                {
                        .xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family",
                        .cbs.create = pim_interface_af_create,
                        .cbs.destroy = pim_interface_af_destroy,
                },
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/use-source",
			.cbs.modify = pim_interface_use_source_modify,
			.cbs.destroy = pim_interface_use_source_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil",
			.cbs.modify = pim_interface_multicast_boundary_oil_modify,
			.cbs.destroy = pim_interface_multicast_boundary_oil_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute",
			.cbs.create = pim_interface_mroute_create,
			.cbs.destroy = pim_interface_mroute_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute/oif",
			.cbs.modify = pim_interface_mroute_oif_modify,
			.cbs.destroy = pim_interface_mroute_oif_destroy,
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info frr_pim_rp_info = {
	.name = "frr-pim-rp",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list",
			.cbs.create = pim_instance_rp_list_create,
			.cbs.destroy = pim_null_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/group-list",
			.cbs.create = pim_instance_rp_group_list_create,
			.cbs.destroy = pim_instance_rp_group_list_destroy,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list",
			.cbs.modify = pim_instance_rp_prefix_list_modify,
			.cbs.destroy = pim_null_destroy,
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info frr_igmp_info = {
        .name = "frr-igmp",
        .nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/igmp-enable",
                        .cbs.modify = pim_interface_igmp_enable_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/version",
			.cbs.modify = pim_interface_igmp_version_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/query-interval",
			.cbs.modify = pim_interface_query_interval_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/query-max-response-time",
			.cbs.modify = pim_interface_query_max_response_time_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/last-member-query-interval",
			.cbs.modify = pim_interface_last_member_query_interval_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/robustness-variable",
			.cbs.modify = pim_interface_robustness_variable_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/address-family",
			.cbs.create = pim_null_create,
			.cbs.destroy = pim_null_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/address-family/static-group",
			.cbs.create = pim_null_create, 
			.cbs.destroy = pim_null_destroy,
		},
		{
			.xpath = NULL,
		},
	}
};

