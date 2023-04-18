// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ospf_ldp_sync.h: OSPF LDP-IGP Sync  handling routines
 * Copyright (C) 2020 Volta Networks, Inc.
 */

#ifndef _ZEBRA_OSPF_LDP_SYNC_H
#define _ZEBRA_OSPF_LDP_SYNC_H

#define LDP_OSPF_LSINFINITY 65535

/* Macro to log debug message */
#define ols_debug(...)                                                         \
	do {                                                                   \
		if (IS_DEBUG_OSPF_LDP_SYNC)                                    \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)


extern void ospf_if_set_ldp_sync_enable(struct ospf *ospf,
					struct interface *ifp);
extern void ospf_if_set_ldp_sync_holddown(struct ospf *ospf,
					  struct interface *ifp);
extern void ospf_ldp_sync_if_init(struct ospf_interface *ospf);
extern void ospf_ldp_sync_if_start(struct interface *ifp, bool send_state_req);
extern void ospf_ldp_sync_if_remove(struct interface *ifp, bool remove);
extern void ospf_ldp_sync_if_down(struct interface *ifp);
extern void ospf_ldp_sync_if_complete(struct interface *ifp);
extern void ospf_ldp_sync_holddown_timer_add(struct interface *ifp);
extern void ospf_ldp_sync_ldp_fail(struct interface *ifp);
extern void ospf_ldp_sync_show_info(struct vty *vty, struct ospf *ospf,
				    json_object *json_vrf, bool use_json);
extern void ospf_ldp_sync_write_config(struct vty *vty, struct ospf *ospf);
extern void ospf_ldp_sync_if_write_config(struct vty *vty,
					  struct ospf_if_params *params);
extern int ospf_ldp_sync_state_update(struct ldp_igp_sync_if_state state);
extern int ospf_ldp_sync_announce_update(struct ldp_igp_sync_announce announce);
extern void
ospf_ldp_sync_handle_client_close(struct zapi_client_close_info *info);
extern void ospf_ldp_sync_state_req_msg(struct interface *ifp);
extern void ospf_ldp_sync_init(void);
extern void ospf_ldp_sync_gbl_exit(struct ospf *ospf, bool remove);
#endif /* _ZEBRA_OSPF_LDP_SYNC_H */
