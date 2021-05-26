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

#ifndef _QUAGGA_BGP_VTY_H
#define _QUAGGA_BGP_VTY_H

#include "bgpd/bgpd.h"
#include "stream.h"
struct bgp;

#define BGP_INSTANCE_HELP_STR "BGP view\nBGP VRF\nView/VRF name\n"
#define BGP_INSTANCE_ALL_HELP_STR "BGP view\nBGP VRF\nAll Views/VRFs\n"

#define BGP_AFI_CMD_STR         "<ipv4|ipv6>"
#define BGP_AFI_HELP_STR        "Address Family\nAddress Family\n"
#define BGP_SAFI_CMD_STR        "<unicast|multicast|vpn>"
#define BGP_SAFI_HELP_STR                                                      \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"
#define BGP_AFI_SAFI_CMD_STR    BGP_AFI_CMD_STR" "BGP_SAFI_CMD_STR
#define BGP_AFI_SAFI_HELP_STR   BGP_AFI_HELP_STR BGP_SAFI_HELP_STR

#define BGP_SAFI_WITH_LABEL_CMD_STR  "<unicast|multicast|vpn|labeled-unicast|flowspec>"
#define BGP_SAFI_WITH_LABEL_HELP_STR                                           \
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

#define BGP_SHOW_SUMMARY_HEADER_ALL                                            \
	"V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc\n"
#define BGP_SHOW_SUMMARY_HEADER_ALL_WIDE                                       \
	"V         AS    LocalAS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc\n"
#define BGP_SHOW_SUMMARY_HEADER_FAILED "EstdCnt DropCnt ResetTime Reason\n"

#define BGP_SHOW_PEER_GR_CAPABILITY( \
			vty, p, use_json, json) \
	do {			\
		bgp_show_neighbor_graceful_restart_local_mode( \
				vty, p, use_json, json);		\
		bgp_show_neighbor_graceful_restart_remote_mode( \
				vty, p, use_json, json); \
		bgp_show_neighnor_graceful_restart_rbit( \
				vty, p, use_json, json);	\
		bgp_show_neighbor_graceful_restart_time( \
				vty, p, use_json, json);	\
		bgp_show_neighbor_graceful_restart_capability_per_afi_safi(\
						vty, p, use_json, json); \
	} while (0)

#define VTY_BGP_GR_DEFINE_LOOP_VARIABLE                                        \
	struct peer *peer_loop = NULL;                                         \
	struct listnode *node = NULL;                                          \
	struct listnode *nnode = NULL;                                         \
	bool gr_router_detected = false

#define VTY_BGP_GR_ROUTER_DETECT(_bgp, _peer, _peer_list)                      \
	do {                                                                   \
		if (_peer->bgp->t_startup)                                     \
			bgp_peer_gr_flags_update(_peer);                       \
		for (ALL_LIST_ELEMENTS(_peer_list, node, nnode, peer_loop)) {  \
			if (CHECK_FLAG(peer_loop->flags,                       \
				       PEER_FLAG_GRACEFUL_RESTART))            \
				gr_router_detected = true;                     \
		}                                                              \
	} while (0)


#define VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(_bgp, _ret)                        \
	do {                                                                   \
		if (gr_router_detected                                         \
		    && _bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {     \
			if (bgp_zebra_send_capabilities(_bgp, false))          \
				_ret = BGP_ERR_INVALID_VALUE;                  \
		} else if (!gr_router_detected                                 \
			   && _bgp->present_zebra_gr_state                     \
				      == ZEBRA_GR_ENABLE) {                    \
			if (bgp_zebra_send_capabilities(_bgp, true))           \
				_ret = BGP_ERR_INVALID_VALUE;                  \
		}                                                              \
	} while (0)

#define VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(                 \
	_bgp, _peer_list, _ret)                                                \
	do {                                                                   \
		struct peer *peer_loop;                                        \
		bool gr_router_detected = false;                               \
		struct listnode *node = {0};                                   \
		struct listnode *nnode = {0};                                  \
		for (ALL_LIST_ELEMENTS(_peer_list, node, nnode, peer_loop)) {  \
			if (peer_loop->bgp->t_startup)                         \
				bgp_peer_gr_flags_update(peer_loop);           \
			if (CHECK_FLAG(peer_loop->flags,                       \
				       PEER_FLAG_GRACEFUL_RESTART))            \
				gr_router_detected = true;                     \
		}                                                              \
		if (gr_router_detected                                         \
		    && _bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {     \
			if (bgp_zebra_send_capabilities(_bgp, false))          \
				_ret = BGP_ERR_INVALID_VALUE;                  \
		} else if (!gr_router_detected                                 \
			   && _bgp->present_zebra_gr_state                     \
				      == ZEBRA_GR_ENABLE) {                    \
			if (bgp_zebra_send_capabilities(_bgp, true))           \
				_ret = BGP_ERR_INVALID_VALUE;                  \
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

extern void bgp_vty_init(void);
extern void community_alias_vty(void);
extern const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json);
extern int bgp_get_vty(struct bgp **bgp, as_t *as, const char *name,
		       enum bgp_instance_type inst_type);
extern void bgp_config_write_update_delay(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_rpkt_quanta(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_listen(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp);
extern int bgp_vty_return(struct vty *vty, int ret);
extern struct peer *peer_and_group_lookup_vty(struct vty *vty,
					      const char *peer_str);

extern afi_t bgp_vty_afi_from_str(const char *afi_str);

extern safi_t bgp_vty_safi_from_str(const char *safi_str);

extern int argv_find_and_parse_afi(struct cmd_token **argv, int argc,
				   int *index, afi_t *afi);

extern int argv_find_and_parse_safi(struct cmd_token **argv, int argc,
				    int *index, safi_t *safi);

extern int bgp_vty_find_and_parse_afi_safi_bgp(struct vty *vty,
					       struct cmd_token **argv,
					       int argc, int *idx, afi_t *afi,
					       safi_t *safi, struct bgp **bgp,
					       bool use_json);
int bgp_vty_find_and_parse_bgp(struct vty *vty, struct cmd_token **argv,
			       int argc, struct bgp **bgp, bool use_json);
extern int bgp_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
				safi_t safi, uint8_t show_flags);
extern int bgp_clear_star_soft_in(const char *name, char *errmsg,
				  size_t errmsg_len);
extern int bgp_clear_star_soft_out(const char *name, char *errmsg,
				   size_t errmsg_len);
int bgp_wpkt_quanta_config_vty(struct bgp *bgp, uint32_t quanta, bool set);
int bgp_rpkt_quanta_config_vty(struct bgp *bgp, uint32_t quanta, bool set);
extern int bgp_maxpaths_config_vty(struct bgp *bgp, afi_t afi, safi_t safi,
				   int peer_type, uint16_t maxpaths,
				   uint16_t options, int set, char *errmsg,
				   size_t errmsg_len);
extern const char *bgp_afi_safi_get_container_str(afi_t afi, safi_t safi);
extern bool vpn_policy_check_import(struct bgp *bgp, afi_t afi, safi_t safi,
				    bool v2vimport, char *errmsg,
				    size_t errmsg_len);
extern int bgp_nb_errmsg_return(char *errmsg, size_t errmsg_len, int ret);
extern bool peer_address_self_check(struct bgp *bgp, union sockunion *su);
extern int peer_local_interface_cfg(struct bgp *bgp, const char *ip_str,
				    const char *str, char *errmsg,
				    size_t errmsg_len);
extern int peer_conf_interface_create(struct bgp *bgp, const char *conf_if,
				      bool v6only, const char *peer_group_name,
				      int as_type, as_t as, char *errmsg,
				      size_t errmsg_len);
extern int peer_flag_modify_nb(struct bgp *bgp, const char *ip_str,
			       struct peer *peer, uint32_t flag, bool set,
			       char *errmsg, size_t errmsg_len);
extern int peer_af_flag_modify_nb(struct peer *peer, afi_t afi, safi_t safi,
				  uint32_t flag, int set, char *errmsg,
				  size_t errmsg_len);

#endif /* _QUAGGA_BGP_VTY_H */
