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

#define MLAG_BUF_LIMIT 2048

enum mlag_role {
	MLAG_ROLE_NONE,
	MLAG_ROLE_PRIMARY,
	MLAG_ROLE_SECONDARY
};

/*
 * This message definition should match mlag.proto
 * Beacuse mesasge registartion is based on this
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

extern char *mlag_role2str(enum mlag_role role, char *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif
