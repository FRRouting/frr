/*
 * BFD daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"

#include "bfdd_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bfdd_info = {
	.name = "frr-bfdd",
	.nodes = {
		{
			.xpath = "/frr-bfdd:bfdd/bfd",
			.cbs = {
				.create = bfdd_bfd_create,
				.destroy = bfdd_bfd_destroy,
				.cli_show = bfd_cli_show_header,
				.cli_show_end = bfd_cli_show_header_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_single_hop_create,
				.destroy = bfdd_bfd_sessions_single_hop_destroy,
				.get_next = bfdd_bfd_sessions_single_hop_get_next,
				.get_keys = bfdd_bfd_sessions_single_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_single_hop_lookup_entry,
				.cli_show = bfd_cli_show_single_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_source_addr_modify,
				.destroy = bfdd_bfd_sessions_single_hop_source_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_echo_mode_modify,
				.cli_show = bfd_cli_show_echo,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify,
				.cli_show = bfd_cli_show_echo_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_multi_hop_create,
				.destroy = bfdd_bfd_sessions_multi_hop_destroy,
				.get_next = bfdd_bfd_sessions_multi_hop_get_next,
				.get_keys = bfdd_bfd_sessions_multi_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_multi_hop_lookup_entry,
				.cli_show = bfd_cli_show_multi_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
