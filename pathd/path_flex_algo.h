/* Flex-algo candidate paths
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PATHD_PATH_FLEX_ALGO_H
#define _PATHD_PATH_FLEX_ALGO_H

#include <zebra.h>
#include "pathd/pathd.h"
#include "lib/zapi_client.h"
#include "lib/zapi_fae.h"
#include "lib/printfrr.h"

#define PATH_DEBUG_FA 0x01
#define PATH_DEBUG_FA_DETAILED 0x02
#define PATH_DEBUG_FA_IGP_DEFAULTS 0x04

#define IS_PATH_DEBUG_FA (path_debug_fa & PATH_DEBUG_FA)
#define IS_PATH_DEBUG_FA_DETAILED (path_debug_fa & PATH_DEBUG_FA_DETAILED)
#define IS_PATH_DEBUG_FA_IGP_DEFAULTS                                          \
	(path_debug_fa & PATH_DEBUG_FA_IGP_DEFAULTS)

extern unsigned long path_debug_fa;

#define FA_DEBUG                                                               \
	if (IS_PATH_DEBUG_FA & path_debug_fa)                                  \
	zlog_debug
#define FA_D_DEBUG                                                             \
	if (IS_PATH_DEBUG_FA_DETAILED & path_debug_fa)                         \
	zlog_debug
#define FA_IGPDEF_DEBUG                                                        \
	if (IS_PATH_DEBUG_FA_IGP_DEFAULTS & path_debug_fa)                     \
	zlog_debug

extern const struct frr_yang_module_info frr_pathd_flexalgo_info;

extern void path_flex_algo_init(void);

extern void path_flex_algo_finish(void);

extern int fa_check_default_igp_proto(uint8_t proto);

extern int fa_set_default_igp_proto(uint8_t proto);

extern int fa_set_default_igp_instance(uint16_t instance);

extern int fa_set_default_igp_vrf_id(vrf_id_t vrf_id);

extern int fa_set_default_igp_isis_area_tag(const char *area_tag);


extern void fa_candidate_endpoint_add(struct srte_candidate *candidate);

extern void fa_candidate_endpoint_del(struct srte_candidate *candidate);

extern void fa_igp_handle_ready(struct zapi_client_daemon_id *di,
				struct zapi_fae_igp_discriminator *d);

extern void fa_igp_handle_notready(struct zapi_client_daemon_id *di,
				   struct zapi_fae_igp_discriminator *d);

extern void fa_handle_update(struct zapi_client_daemon_id *di,
			     struct zapi_fae_igp_discriminator *d,
			     struct zapi_fae_query *query,
			     struct zapi_fae_answer *answer);

extern void fa_vty_igp_show_all(struct vty *vty);

extern void fa_vty_endpoint_show_all(struct vty *vty, bool detail);
extern void fa_vty_igp_defaults_show(struct vty *vty);

/* zebra API */
extern void path_zebra_fae_register(bool do_register, struct ipaddr *endpoint,
				    uint8_t algorithm, uint8_t protocol,
				    uint16_t instance, uint32_t session_id,
				    vrf_id_t vrf_id, uint32_t isis_z_area_id);
extern int path_zebra_debug_send_fae_ready(bool do_ready, uint8_t proto,
					   vrf_id_t vrf_id,
					   const char *area_tag,
					   uint32_t z_area_id);

extern int path_zebra_debug_send_fae_update(uint8_t protocol, vrf_id_t vrf_id,
					    uint32_t z_area_id,
					    struct ipaddr *endpoint,
					    uint8_t algorithm,
					    struct zapi_srte_tunnel *sid_list);

extern int path_zebra_handle_fae_update(struct stream *s);
extern int path_zebra_handle_fae_ready(bool ready, struct stream *s);

/* cli initialisation */
extern void path_flex_algo_cli_init(void);

/* northbound config API */
int pathd_srte_flex_algo_default_protocol_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_flex_algo_default_protocol_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_flex_algo_default_vrf_modify(struct nb_cb_modify_args *args);
int pathd_srte_flex_algo_default_vrf_destroy(struct nb_cb_destroy_args *args);
int pathd_srte_flex_algo_default_instance_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_flex_algo_default_instance_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_flex_algo_default_isis_area_tag_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_flex_algo_default_isis_area_tag_destroy(
	struct nb_cb_destroy_args *args);
void cli_show_flex_algo_igp_defaults(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
/* show flex algo debugging */
void path_flex_algo_show_debugging(struct vty *vty);

#endif /* _PATHD_PATH_FLEX_ALGO_H */
