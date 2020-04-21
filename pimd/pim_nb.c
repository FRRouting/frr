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
#include "vrf.h"
#include "pimd/pim_nb.h"

// Remove this once routing_nb.c is merged.
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol
 */
static int routing_control_plane_protocols_control_plane_protocol_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct vrf *vrf;
	const char *vrfname;

	switch (event) {
	case NB_EV_VALIDATE:
		vrfname = yang_dnode_get_string(dnode, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf) {
			zlog_warn("vrf is not configured\n");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrfname = yang_dnode_get_string(dnode, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		nb_running_set_entry(dnode, vrf);
		break;
	};

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct vrf *vrf;

	if (event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_unset_entry(dnode);
	(void)vrf;
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_routing_info = {
	.name = "frr-routing",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_destroy,
			}
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_ecmp_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_ecmp_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp-rebalance",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/join-prune-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_join_prune_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/keep-alive-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_keep_alive_timer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/rp-keep-alive-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_rp_keep_alive_timer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/packets",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_packets_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/register-suppress-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_register_suppress_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-action",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd-source-ip",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/mesh-group-name",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/member-ip",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/source-ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/source-ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/my-role",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peer-state",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/pim-enable",
			.cbs = {
				.create = lib_interface_pim_pim_enable_create,
				.destroy = lib_interface_pim_pim_enable_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/dr-priority",
			.cbs = {
				.modify = lib_interface_pim_dr_priority_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/hello-interval",
			.cbs = {
				.modify = lib_interface_pim_hello_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/hello-holdtime",
			.cbs = {
				.modify = lib_interface_pim_hello_holdtime_modify,
				.destroy = lib_interface_pim_hello_holdtime_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd",
			.cbs = {
				.create = lib_interface_pim_bfd_create,
				.destroy = lib_interface_pim_bfd_destroy,
				.apply_finish = lib_interface_pim_bfd_apply_finish,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/min-rx-interval",
			.cbs = {
				.modify = lib_interface_pim_bfd_min_rx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/min-tx-interval",
			.cbs = {
				.modify = lib_interface_pim_bfd_min_tx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bfd/detect_mult",
			.cbs = {
				.modify = lib_interface_pim_bfd_detect_mult_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/bsm",
			.cbs = {
				.create = lib_interface_pim_bsm_create,
				.destroy = lib_interface_pim_bsm_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/unicast-bsm",
			.cbs = {
				.create = lib_interface_pim_unicast_bsm_create,
				.destroy = lib_interface_pim_unicast_bsm_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/active-active",
			.cbs = {
				.create = lib_interface_pim_active_active_create,
				.destroy = lib_interface_pim_active_active_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family",
			.cbs = {
				.create = lib_interface_pim_address_family_create,
				.destroy = lib_interface_pim_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/use-source",
			.cbs = {
				.modify = lib_interface_pim_address_family_use_source_modify,
				.destroy = lib_interface_pim_address_family_use_source_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil",
			.cbs = {
				.modify = lib_interface_pim_address_family_multicast_boundary_oil_modify,
				.destroy = lib_interface_pim_address_family_multicast_boundary_oil_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute",
			.cbs = {
				.create = lib_interface_pim_address_family_mroute_create,
				.destroy = lib_interface_pim_address_family_mroute_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute/oif",
			.cbs = {
				.modify = lib_interface_pim_address_family_mroute_oif_modify,
				.destroy = lib_interface_pim_address_family_mroute_oif_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_pim_rp_info = {
	.name = "frr-pim-rp",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/group-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_igmp_info = {
	.name = "frr-igmp",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/igmp-enable",
			.cbs = {
				.modify = lib_interface_igmp_igmp_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/version",
			.cbs = {
				.modify = lib_interface_igmp_version_modify,
				.destroy = lib_interface_igmp_version_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/query-interval",
			.cbs = {
				.modify = lib_interface_igmp_query_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/query-max-response-time",
			.cbs = {
				.modify = lib_interface_igmp_query_max_response_time_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/last-member-query-interval",
			.cbs = {
				.modify = lib_interface_igmp_last_member_query_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/robustness-variable",
			.cbs = {
				.modify = lib_interface_igmp_robustness_variable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/address-family",
			.cbs = {
				.create = lib_interface_igmp_address_family_create,
				.destroy = lib_interface_igmp_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-igmp:igmp/address-family/static-group",
			.cbs = {
				.create = lib_interface_igmp_address_family_static_group_create,
				.destroy = lib_interface_igmp_address_family_static_group_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
