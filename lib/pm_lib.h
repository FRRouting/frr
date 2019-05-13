/*
 * header for path monitoring general services
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __LIB_PM_H__
#define __LIB_PM_H__

#include "lib/json.h"
#include "lib/zclient.h"

#define PM_GBL_FLAG_IN_SHUTDOWN (1 << 0) /* The daemon in shutdown */
struct pm_gbl {
	uint16_t flags;
};

#define PM_FLAG_PM_REG   (1 << 1) /* Peer registered with PM */

#define PM_STATUS_UNKNOWN (1 << 0) /* PM session status never received */
#define PM_STATUS_DOWN    (1 << 1) /* PM session status is down */
#define PM_STATUS_UP      (1 << 2) /* PM session status is up */

#define PM_DEF_INTERVAL 5000
#define PM_DEF_PACKET_SIZE 100
#define PM_DEF_IPV6_PACKET_SIZE 100
#define PM_DEF_TOS_VAL 0xc0  /* Inter Network Control */
#define PM_DEF_TIMEOUT 5000

struct pm_info {
	uint16_t flags;
	uint32_t interval;
	uint32_t timeout;
	uint16_t packet_size;
	uint8_t tos_val;
	time_t last_update;
	uint8_t status;
};

extern struct pm_info *pm_info_create(void);

extern void pm_info_free(struct pm_info **pm_info);

extern void pm_set_param(struct pm_info **pm_info, uint32_t interval,
			 uint32_t timeout, uint16_t packet_size,
			 uint8_t tos_val, int *command);
extern void pm_peer_sendmsg(struct zclient *zclient, struct pm_info *pm_info,
			    int family, void *dst_ip, void *src_ip,
			    char *if_name, int command,
			    int set_flag, vrf_id_t vrf_id);

extern const char *pm_get_command_dbg_str(int command);

extern struct interface *pm_get_peer_info(struct stream *s,
					  struct prefix *dp,
					  struct prefix *sp,
					  int *status,
					  vrf_id_t vrf_id);
const char *pm_get_status_str(int status);

extern void pm_show_info(struct vty *vty, struct pm_info *pm_info,
			  int extra_space, bool use_json,
			  json_object *json_obj);

extern void pm_client_sendmsg(struct zclient *zclient, int command,
			       vrf_id_t vrf_id);

extern void pm_gbl_init(void);

extern void pm_gbl_exit(void);

#endif /* __LIB_PM_H__ */
