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

#ifndef _FRR_BFDD_NB_H_
#define _FRR_BFDD_NB_H_

extern const struct frr_yang_module_info frr_bfdd_info;

/* Mandatory callbacks. */
int bfdd_bfd_create(enum nb_event event, const struct lyd_node *dnode,
		    union nb_resource *resource);
int bfdd_bfd_destroy(enum nb_event event, const struct lyd_node *dnode);
int bfdd_bfd_sessions_single_hop_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
const void *bfdd_bfd_sessions_single_hop_get_next(const void *parent_list_entry,
						  const void *list_entry);
int bfdd_bfd_sessions_single_hop_get_keys(const void *list_entry,
					  struct yang_list_keys *keys);
const void *
bfdd_bfd_sessions_single_hop_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys);
int bfdd_bfd_sessions_single_hop_source_addr_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_source_addr_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int bfdd_bfd_sessions_single_hop_detection_multiplier_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_required_receive_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_administrative_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_echo_mode_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_state_get_elem(const char *xpath,
							const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem(
	const char *xpath, const void *list_entry);
int bfdd_bfd_sessions_multi_hop_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource);
int bfdd_bfd_sessions_multi_hop_destroy(enum nb_event event,
					const struct lyd_node *dnode);
const void *bfdd_bfd_sessions_multi_hop_get_next(const void *parent_list_entry,
						 const void *list_entry);
int bfdd_bfd_sessions_multi_hop_get_keys(const void *list_entry,
					 struct yang_list_keys *keys);
const void *
bfdd_bfd_sessions_multi_hop_lookup_entry(const void *parent_list_entry,
					 const struct yang_list_keys *keys);
int bfdd_bfd_sessions_multi_hop_detection_multiplier_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_multi_hop_desired_transmission_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_multi_hop_required_receive_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int bfdd_bfd_sessions_multi_hop_administrative_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_local_discriminator_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_local_state_get_elem(const char *xpath,
						       const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_local_diagnostic_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_local_multiplier_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_remote_discriminator_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_remote_state_get_elem(const char *xpath,
							const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_remote_diagnostic_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_remote_multiplier_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_negotiated_transmission_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_negotiated_receive_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_detection_mode_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_last_down_time_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_last_up_time_get_elem(const char *xpath,
							const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_session_down_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *bfdd_bfd_sessions_multi_hop_stats_session_up_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_control_packet_input_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_control_packet_output_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_negotiated_echo_transmission_interval_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_echo_packet_input_count_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
bfdd_bfd_sessions_multi_hop_stats_echo_packet_output_count_get_elem(
	const char *xpath, const void *list_entry);

/* Optional 'cli_show' callbacks. */
void bfd_cli_show_header(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults);
void bfd_cli_show_header_end(struct vty *vty, struct lyd_node *dnode);
void bfd_cli_show_single_hop_peer(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void bfd_cli_show_multi_hop_peer(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);
void bfd_cli_show_peer_end(struct vty *vty, struct lyd_node *dnode);
void bfd_cli_show_mult(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults);
void bfd_cli_show_tx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults);
void bfd_cli_show_rx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults);
void bfd_cli_show_shutdown(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void bfd_cli_show_echo(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults);
void bfd_cli_show_echo_interval(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);

#endif /* _FRR_BFDD_NB_H_ */
