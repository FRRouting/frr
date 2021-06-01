/*
 * CMGD VTY interface.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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

#ifndef _CMGD_VTY_H
#define _CMGD_VTY_H

#if 0
#include "cmgd/cmgd.h"
#include "stream.h"
struct cmgd;

#define CMGD_INSTANCE_HELP_STR "CMGD view\nCMGD VRF\nView/VRF name\n"
#define CMGD_INSTANCE_ALL_HELP_STR "CMGD view\nCMGD VRF\nAll Views/VRFs\n"

#define CMGD_AFI_CMD_STR         "<ipv4|ipv6>"
#define CMGD_AFI_HELP_STR        "Address Family\nAddress Family\n"
#define CMGD_SAFI_CMD_STR        "<unicast|multicast|vpn>"
#define CMGD_SAFI_HELP_STR                                                      \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"
#define CMGD_AFI_SAFI_CMD_STR    CMGD_AFI_CMD_STR" "CMGD_SAFI_CMD_STR
#define CMGD_AFI_SAFI_HELP_STR   CMGD_AFI_HELP_STR CMGD_SAFI_HELP_STR

#define CMGD_SAFI_WITH_LABEL_CMD_STR  "<unicast|multicast|vpn|labeled-unicast|flowspec>"
#define CMGD_SAFI_WITH_LABEL_HELP_STR                                           \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"

#define SHOW_GR_HEADER \
	"Codes: GR - Graceful Restart," \
	" * -  Inheriting Global GR Config,\n" \
	"       Restart - GR Mode-Restarting," \
	" Helper - GR Mode-Helper,\n" \
	"       Disable - GR Mode-Disable.\n\n"

#define CMGD_SHOW_PEER_GR_CAPABILITY( \
			vty, p, use_json, json) \
	do {			\
		cmgd_show_neighbor_graceful_restart_local_mode( \
				vty, p, use_json, json);		\
		cmgd_show_neighbor_graceful_restart_remote_mode( \
				vty, p, use_json, json); \
		cmgd_show_neighnor_graceful_restart_rbit( \
				vty, p, use_json, json);	\
		cmgd_show_neighbor_graceful_restart_time( \
				vty, p, use_json, json);	\
		cmgd_show_neighbor_graceful_restart_capability_per_afi_safi(\
						vty, p, use_json, json); \
	} while (0)

#define VTY_CMGD_GR_DEFINE_LOOP_VARIABLE                                        \
	struct peer *peer_loop = NULL;                                         \
	struct listnode *node = NULL;                                          \
	struct listnode *nnode = NULL;                                         \
	bool gr_router_detected = false

#define VTY_CMGD_GR_ROUTER_DETECT(_cmgd, _peer, _peer_list)                      \
	do {                                                                   \
		if (_peer->cmgd->t_startup)                                     \
			cmgd_peer_gr_flags_update(_peer);                       \
		for (ALL_LIST_ELEMENTS(_peer_list, node, nnode, peer_loop)) {  \
			if (CHECK_FLAG(peer_loop->flags,                       \
				       PEER_FLAG_GRACEFUL_RESTART))            \
				gr_router_detected = true;                     \
		}                                                              \
	} while (0)


#define VTY_SEND_CMGD_GR_CAPABILITY_TO_ZEBRA(_cmgd, _ret)                        \
	do {                                                                   \
		if (gr_router_detected                                         \
		    && _cmgd->present_zebra_gr_state == ZEBRA_GR_DISABLE) {     \
			if (cmgd_zebra_send_capabilities(_cmgd, false))          \
				_ret = CMGD_ERR_INVALID_VALUE;                  \
		} else if (!gr_router_detected                                 \
			   && _cmgd->present_zebra_gr_state                     \
				      == ZEBRA_GR_ENABLE) {                    \
			if (cmgd_zebra_send_capabilities(_cmgd, true))           \
				_ret = CMGD_ERR_INVALID_VALUE;                  \
		}                                                              \
	} while (0)

#define VTY_CMGD_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(                 \
	_cmgd, _peer_list, _ret)                                                \
	do {                                                                   \
		struct peer *peer_loop;                                        \
		bool gr_router_detected = false;                               \
		struct listnode *node = {0};                                   \
		struct listnode *nnode = {0};                                  \
		for (ALL_LIST_ELEMENTS(_peer_list, node, nnode, peer_loop)) {  \
			if (peer_loop->cmgd->t_startup)                         \
				cmgd_peer_gr_flags_update(peer_loop);           \
			if (CHECK_FLAG(peer_loop->flags,                       \
				       PEER_FLAG_GRACEFUL_RESTART))            \
				gr_router_detected = true;                     \
		}                                                              \
		if (gr_router_detected                                         \
		    && _cmgd->present_zebra_gr_state == ZEBRA_GR_DISABLE) {     \
			if (cmgd_zebra_send_capabilities(_cmgd, false))          \
				_ret = CMGD_ERR_INVALID_VALUE;                  \
		} else if (!gr_router_detected                                 \
			   && _cmgd->present_zebra_gr_state                     \
				      == ZEBRA_GR_ENABLE) {                    \
			if (cmgd_zebra_send_capabilities(_cmgd, true))           \
				_ret = CMGD_ERR_INVALID_VALUE;                  \
		}                                                              \
	} while (0)


#define PRINT_EOR(_eor_flag)                                                   \
	do {                                                                   \
		if (eor_flag)                                                  \
			vty_out(vty, "Yes\n");                                 \
		else                                                           \
			vty_out(vty, "No\n");                                  \
	} while (0)

#define PRINT_EOR_JSON(_eor_flag)                                              \
	do {                                                                   \
		if (eor_flag)                                                  \
			json_object_boolean_true_add(                          \
				json_endofrib_status,                          \
				"endOfRibSentAfterUpdate");                    \
		else                                                           \
			json_object_boolean_false_add(                         \
				json_endofrib_status,                          \
				"endOfRibSentAfterUpdate");                    \
	} while (0)
#endif

extern void cmgd_vty_init(void);
extern void cmgd_init_bcknd_cmd(void);

#if 0
extern const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json);
extern int cmgd_get_vty(struct cmgd **cmgd, as_t *as, const char *name,
		       enum cmgd_instance_type inst_type);
extern void cmgd_config_write_update_delay(struct vty *vty, struct cmgd *cmgd);
extern void cmgd_config_write_wpkt_quanta(struct vty *vty, struct cmgd *cmgd);
extern void cmgd_config_write_rpkt_quanta(struct vty *vty, struct cmgd *cmgd);
extern void cmgd_config_write_listen(struct vty *vty, struct cmgd *cmgd);
extern void cmgd_config_write_coalesce_time(struct vty *vty, struct cmgd *cmgd);
extern int cmgd_vty_return(struct vty *vty, int ret);
extern struct peer *peer_and_group_lookup_vty(struct vty *vty,
					      const char *peer_str);

extern afi_t cmgd_vty_afi_from_str(const char *afi_str);

extern safi_t cmgd_vty_safi_from_str(const char *safi_str);

extern int argv_find_and_parse_afi(struct cmd_token **argv, int argc,
				   int *index, afi_t *afi);

extern int argv_find_and_parse_safi(struct cmd_token **argv, int argc,
				    int *index, safi_t *safi);

extern int cmgd_vty_find_and_parse_afi_safi_cmgd(struct vty *vty,
					       struct cmd_token **argv,
					       int argc, int *idx, afi_t *afi,
					       safi_t *safi, struct cmgd **cmgd,
					       bool use_json);
int cmgd_vty_find_and_parse_cmgd(struct vty *vty, struct cmd_token **argv,
			       int argc, struct cmgd **cmgd, bool use_json);
extern int cmgd_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
				safi_t safi, bool show_failed,
				bool show_established, bool use_json);
extern int cmgd_clear_star_soft_in(const char *name, char *errmsg,
				  size_t errmsg_len);
extern int cmgd_clear_star_soft_out(const char *name, char *errmsg,
				   size_t errmsg_len);
int cmgd_wpkt_quanta_config_vty(struct cmgd *cmgd, uint32_t quanta, bool set);
int cmgd_rpkt_quanta_config_vty(struct cmgd *cmgd, uint32_t quanta, bool set);
extern int cmgd_maxpaths_config_vty(struct cmgd *cmgd, afi_t afi, safi_t safi,
				   int peer_type, uint16_t maxpaths,
				   uint16_t options, int set, char *errmsg,
				   size_t errmsg_len);
extern const char *cmgd_afi_safi_get_container_str(afi_t afi, safi_t safi);
extern bool vpn_policy_check_import(struct cmgd *cmgd, afi_t afi, safi_t safi,
				    bool v2vimport, char *errmsg,
				    size_t errmsg_len);
extern int cmgd_nb_errmsg_return(char *errmsg, size_t errmsg_len, int ret);
extern bool peer_address_self_check(struct cmgd *cmgd, union sockunion *su);
extern int peer_local_interface_cfg(struct cmgd *cmgd, const char *ip_str,
				    const char *str, char *errmsg,
				    size_t errmsg_len);
extern int peer_conf_interface_create(struct cmgd *cmgd, const char *conf_if,
				      afi_t afi, safi_t safi, bool v6only,
				      const char *peer_group_name, int as_type,
				      as_t as, char *errmsg, size_t errmsg_len);
extern int peer_flag_modify_nb(struct cmgd *cmgd, const char *ip_str,
			       struct peer *peer, uint32_t flag, bool set,
			       char *errmsg, size_t errmsg_len);
extern int peer_af_flag_modify_nb(struct peer *peer, afi_t afi, safi_t safi,
				  uint32_t flag, int set, char *errmsg,
				  size_t errmsg_len);
#endif

#endif /* _CMGD_VTY_H */
