/* mlag header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __MLAG_H__
#define __MLAG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/stream.h"

#define MLAG_MSG_NULL_PAYLOAD 0
#define MLAG_MSG_NO_BATCH 1
#define MLAG_BUF_LIMIT 2048

enum mlag_role {
	MLAG_ROLE_NONE,
	MLAG_ROLE_PRIMARY,
	MLAG_ROLE_SECONDARY
};

enum mlag_state {
	MLAG_STATE_DOWN,
	MLAG_STATE_RUNNING,
};

enum mlag_frr_state {
	MLAG_FRR_STATE_NONE,
	MLAG_FRR_STATE_DOWN,
	MLAG_FRR_STATE_UP,
};

enum mlag_owner {
	MLAG_OWNER_NONE,
	MLAG_OWNER_INTERFACE,
	MLAG_OWNER_VXLAN,
};

/*
 * This message definition should match mlag.proto
 * Because message registration is based on this
 */
enum mlag_msg_type {
	MLAG_MSG_NONE = 0,
	MLAG_REGISTER = 1,
	MLAG_DEREGISTER = 2,
	MLAG_STATUS_UPDATE = 3,
	MLAG_MROUTE_ADD = 4,
	MLAG_MROUTE_DEL = 5,
	MLAG_DUMP = 6,
	MLAG_MROUTE_ADD_BULK = 7,
	MLAG_MROUTE_DEL_BULK = 8,
	MLAG_PIM_CFG_DUMP = 10,
	MLAG_VXLAN_UPDATE = 11,
	MLAG_PEER_FRR_STATUS = 12,
};

struct mlag_frr_status {
	enum mlag_frr_state frr_state;
};

struct mlag_status {
	char peerlink_rif[INTERFACE_NAMSIZ];
	enum mlag_role my_role;
	enum mlag_state peer_state;
};

#define MLAG_ROLE_STRSIZE 16

struct mlag_vxlan {
	uint32_t anycast_ip;
	uint32_t local_ip;
};

struct mlag_mroute_add {
	char vrf_name[VRF_NAMSIZ];
	uint32_t source_ip;
	uint32_t group_ip;
	uint32_t cost_to_rp;
	enum mlag_owner owner_id;
	bool am_i_dr;
	bool am_i_dual_active;
	vrf_id_t vrf_id;
	char intf_name[INTERFACE_NAMSIZ];
};

struct mlag_mroute_del {
	char vrf_name[VRF_NAMSIZ];
	uint32_t source_ip;
	uint32_t group_ip;
	enum mlag_owner owner_id;
	vrf_id_t vrf_id;
	char intf_name[INTERFACE_NAMSIZ];
};

struct mlag_msg {
	enum mlag_msg_type msg_type;
	uint16_t data_len;
	uint16_t msg_cnt;
	uint8_t data[0];
} __attribute__((packed));


extern char *mlag_role2str(enum mlag_role role, char *buf, size_t size);
extern char *mlag_lib_msgid_to_str(enum mlag_msg_type msg_type, char *buf,
				   size_t size);
extern int mlag_lib_decode_mlag_hdr(struct stream *s, struct mlag_msg *msg);
extern int mlag_lib_decode_mroute_add(struct stream *s,
				      struct mlag_mroute_add *msg);
extern int mlag_lib_decode_mroute_del(struct stream *s,
				      struct mlag_mroute_del *msg);
extern int mlag_lib_decode_mlag_status(struct stream *s,
				       struct mlag_status *msg);
extern int mlag_lib_decode_vxlan_update(struct stream *s,
					struct mlag_vxlan *msg);
extern int mlag_lib_decode_frr_status(struct stream *s,
				      struct mlag_frr_status *msg);
#ifdef __cplusplus
}
#endif

#endif
