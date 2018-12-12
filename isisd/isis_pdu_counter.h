/*
 * IS-IS Routing protocol - isis_pdu_counter.c
 * Copyright (C) 2018 Christian Franke, for NetDEF Inc.
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
#ifndef ISIS_PDU_COUNTER_H
#define ISIS_PDU_COUNTER_H

enum pdu_counter_index {
	L1_LAN_HELLO_INDEX = 0,
	L2_LAN_HELLO_INDEX,
	P2P_HELLO_INDEX,
	L1_LINK_STATE_INDEX,
	L2_LINK_STATE_INDEX,
	FS_LINK_STATE_INDEX,
	L1_COMPLETE_SEQ_NUM_INDEX,
	L2_COMPLETE_SEQ_NUM_INDEX,
	L1_PARTIAL_SEQ_NUM_INDEX,
	L2_PARTIAL_SEQ_NUM_INDEX,
	PDU_COUNTER_SIZE
};
typedef uint64_t pdu_counter_t[PDU_COUNTER_SIZE];

void pdu_counter_print(struct vty *vty, const char *prefix,
		       pdu_counter_t counter);
void pdu_counter_count(pdu_counter_t counter, uint8_t pdu_type);

#endif
