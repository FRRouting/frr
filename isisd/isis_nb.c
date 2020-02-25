/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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

#include "isisd/isis_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_isisd_info = {
	.name = "frr-isisd",
	.nodes = {
		{
			.xpath = "/frr-isisd:isis/instance",
			.cbs = {
				.cli_show = cli_show_router_isis,
				.create = isis_instance_create,
				.destroy = isis_instance_destroy,
			},
			.priority = NB_DFLT_PRIORITY - 1,
		},
		{
			.xpath = "/frr-isisd:isis/instance/is-type",
			.cbs = {
				.cli_show = cli_show_isis_is_type,
				.modify = isis_instance_is_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-address",
			.cbs = {
				.cli_show = cli_show_isis_area_address,
				.create = isis_instance_area_address_create,
				.destroy = isis_instance_area_address_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/dynamic-hostname",
			.cbs = {
				.cli_show = cli_show_isis_dynamic_hostname,
				.modify = isis_instance_dynamic_hostname_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/attached",
			.cbs = {
				.cli_show = cli_show_isis_attached,
				.modify = isis_instance_attached_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/overload",
			.cbs = {
				.cli_show = cli_show_isis_overload,
				.modify = isis_instance_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/metric-style",
			.cbs = {
				.cli_show = cli_show_isis_metric_style,
				.modify = isis_instance_metric_style_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/purge-originator",
			.cbs = {
				.cli_show = cli_show_isis_purge_origin,
				.modify = isis_instance_purge_originator_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/mtu",
			.cbs = {
				.cli_show = cli_show_isis_lsp_mtu,
				.modify = isis_instance_lsp_mtu_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval",
			.cbs = {
				.cli_show = cli_show_isis_lsp_ref_interval,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval/level-1",
			.cbs = {
				.modify = isis_instance_lsp_refresh_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval/level-2",
			.cbs = {
				.modify = isis_instance_lsp_refresh_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime",
			.cbs = {
				.cli_show = cli_show_isis_lsp_max_lifetime,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-1",
			.cbs = {
				.modify = isis_instance_lsp_maximum_lifetime_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-2",
			.cbs = {
				.modify = isis_instance_lsp_maximum_lifetime_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval",
			.cbs = {
				.cli_show = cli_show_isis_lsp_gen_interval,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval/level-1",
			.cbs = {
				.modify = isis_instance_lsp_generation_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval/level-2",
			.cbs = {
				.modify = isis_instance_lsp_generation_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay",
			.cbs = {
				.apply_finish = ietf_backoff_delay_apply_finish,
				.cli_show = cli_show_isis_spf_ietf_backoff,
				.create = isis_instance_spf_ietf_backoff_delay_create,
				.destroy = isis_instance_spf_ietf_backoff_delay_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_init_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_short_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_long_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_hold_down_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_time_to_learn_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval",
			.cbs = {
				.cli_show = cli_show_isis_spf_min_interval,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-1",
			.cbs = {
				.modify = isis_instance_spf_minimum_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-2",
			.cbs = {
				.modify = isis_instance_spf_minimum_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password",
			.cbs = {
				.apply_finish = area_password_apply_finish,
				.cli_show = cli_show_isis_area_pwd,
				.create = isis_instance_area_password_create,
				.destroy = isis_instance_area_password_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password",
			.cbs = {
				.modify = isis_instance_area_password_password_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password-type",
			.cbs = {
				.modify = isis_instance_area_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/authenticate-snp",
			.cbs = {
				.modify = isis_instance_area_password_authenticate_snp_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password",
			.cbs = {
				.apply_finish = domain_password_apply_finish,
				.cli_show = cli_show_isis_domain_pwd,
				.create = isis_instance_domain_password_create,
				.destroy = isis_instance_domain_password_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password",
			.cbs = {
				.modify = isis_instance_domain_password_password_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password-type",
			.cbs = {
				.modify = isis_instance_domain_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/authenticate-snp",
			.cbs = {
				.modify = isis_instance_domain_password_authenticate_snp_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4",
			.cbs = {
				.apply_finish = default_info_origin_ipv4_apply_finish,
				.cli_show = cli_show_isis_def_origin_ipv4,
				.create = isis_instance_default_information_originate_ipv4_create,
				.destroy = isis_instance_default_information_originate_ipv4_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/always",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv4_always_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/route-map",
			.cbs = {
				.destroy = isis_instance_default_information_originate_ipv4_route_map_destroy,
				.modify = isis_instance_default_information_originate_ipv4_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/metric",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv4_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6",
			.cbs = {
				.apply_finish = default_info_origin_ipv6_apply_finish,
				.cli_show = cli_show_isis_def_origin_ipv6,
				.create = isis_instance_default_information_originate_ipv6_create,
				.destroy = isis_instance_default_information_originate_ipv6_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/always",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv6_always_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/route-map",
			.cbs = {
				.destroy = isis_instance_default_information_originate_ipv6_route_map_destroy,
				.modify = isis_instance_default_information_originate_ipv6_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/metric",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv6_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4",
			.cbs = {
				.apply_finish = redistribute_ipv4_apply_finish,
				.cli_show = cli_show_isis_redistribute_ipv4,
				.create = isis_instance_redistribute_ipv4_create,
				.destroy = isis_instance_redistribute_ipv4_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv4_route_map_destroy,
				.modify = isis_instance_redistribute_ipv4_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/metric",
			.cbs = {
				.modify = isis_instance_redistribute_ipv4_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6",
			.cbs = {
				.apply_finish = redistribute_ipv6_apply_finish,
				.cli_show = cli_show_isis_redistribute_ipv6,
				.create = isis_instance_redistribute_ipv6_create,
				.destroy = isis_instance_redistribute_ipv6_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv6_route_map_destroy,
				.modify = isis_instance_redistribute_ipv6_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/metric",
			.cbs = {
				.modify = isis_instance_redistribute_ipv6_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv4_multicast,
				.create = isis_instance_multi_topology_ipv4_multicast_create,
				.destroy = isis_instance_multi_topology_ipv4_multicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv4_multicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv4_mgmt,
				.create = isis_instance_multi_topology_ipv4_management_create,
				.destroy = isis_instance_multi_topology_ipv4_management_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv4_management_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_unicast,
				.create = isis_instance_multi_topology_ipv6_unicast_create,
				.destroy = isis_instance_multi_topology_ipv6_unicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_unicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_multicast,
				.create = isis_instance_multi_topology_ipv6_multicast_create,
				.destroy = isis_instance_multi_topology_ipv6_multicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_multicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_mgmt,
				.create = isis_instance_multi_topology_ipv6_management_create,
				.destroy = isis_instance_multi_topology_ipv6_management_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_management_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_dstsrc,
				.create = isis_instance_multi_topology_ipv6_dstsrc_create,
				.destroy = isis_instance_multi_topology_ipv6_dstsrc_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_dstsrc_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/log-adjacency-changes",
			.cbs = {
				.cli_show = cli_show_isis_log_adjacency,
				.modify = isis_instance_log_adjacency_changes_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te,
				.create = isis_instance_mpls_te_create,
				.destroy = isis_instance_mpls_te_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te/router-address",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te_router_addr,
				.destroy = isis_instance_mpls_te_router_address_destroy,
				.modify = isis_instance_mpls_te_router_address_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis",
			.cbs = {
				.create = lib_interface_isis_create,
				.destroy = lib_interface_isis_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/area-tag",
			.cbs = {
				.modify = lib_interface_isis_area_tag_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/circuit-type",
			.cbs = {
				.cli_show = cli_show_ip_isis_circ_type,
				.modify = lib_interface_isis_circuit_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv4-routing",
			.cbs = {
				.cli_show = cli_show_ip_isis_ipv4,
				.modify = lib_interface_isis_ipv4_routing_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv6-routing",
			.cbs = {
				.cli_show = cli_show_ip_isis_ipv6,
				.modify = lib_interface_isis_ipv6_routing_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring",
			.cbs = {
				.modify = lib_interface_isis_bfd_monitoring_modify,
				.cli_show = cli_show_ip_isis_bfd_monitoring,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_csnp_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_csnp_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_csnp_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_psnp_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_psnp_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_psnp_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/padding",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_padding,
				.modify = lib_interface_isis_hello_padding_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_hello_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_hello_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_multi,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1",
			.cbs = {
				.modify = lib_interface_isis_hello_multiplier_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2",
			.cbs = {
				.modify = lib_interface_isis_hello_multiplier_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric",
			.cbs = {
				.cli_show = cli_show_ip_isis_metric,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-1",
			.cbs = {
				.modify = lib_interface_isis_metric_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-2",
			.cbs = {
				.modify = lib_interface_isis_metric_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority",
			.cbs = {
				.cli_show = cli_show_ip_isis_priority,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-1",
			.cbs = {
				.modify = lib_interface_isis_priority_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-2",
			.cbs = {
				.modify = lib_interface_isis_priority_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/network-type",
			.cbs = {
				.cli_show = cli_show_ip_isis_network_type,
				.modify = lib_interface_isis_network_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/passive",
			.cbs = {
				.cli_show = cli_show_ip_isis_passive,
				.modify = lib_interface_isis_passive_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password",
			.cbs = {
				.cli_show = cli_show_ip_isis_password,
				.create = lib_interface_isis_password_create,
				.destroy = lib_interface_isis_password_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password",
			.cbs = {
				.modify = lib_interface_isis_password_password_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password-type",
			.cbs = {
				.modify = lib_interface_isis_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake",
			.cbs = {
				.cli_show = cli_show_ip_isis_threeway_shake,
				.modify = lib_interface_isis_disable_three_way_handshake_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv4_unicast,
				.modify = lib_interface_isis_multi_topology_ipv4_unicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv4_multicast,
				.modify = lib_interface_isis_multi_topology_ipv4_multicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv4_mgmt,
				.modify = lib_interface_isis_multi_topology_ipv4_management_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_unicast,
				.modify = lib_interface_isis_multi_topology_ipv6_unicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_multicast,
				.modify = lib_interface_isis_multi_topology_ipv6_multicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_mgmt,
				.modify = lib_interface_isis_multi_topology_ipv6_management_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_dstsrc,
				.modify = lib_interface_isis_multi_topology_ipv6_dstsrc_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency",
			.cbs = {
				.get_next = lib_interface_isis_adjacencies_adjacency_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-sys-type",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_neighbor_sys_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-sysid",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_neighbor_sysid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-extended-circuit-id",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-snpa",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_neighbor_snpa_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/hold-timer",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_hold_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-priority",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_neighbor_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/state",
			.cbs = {
				.get_elem = lib_interface_isis_adjacencies_adjacency_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-changes",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_adjacency_changes_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-number",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_adjacency_number_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/init-fails",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_init_fails_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-rejects",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_adjacency_rejects_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/id-len-mismatch",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_id_len_mismatch_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/max-area-addresses-mismatch",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_max_area_addresses_mismatch_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/authentication-type-fails",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_authentication_type_fails_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/event-counters/authentication-fails",
			.cbs = {
				.get_elem = lib_interface_isis_event_counters_authentication_fails_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
