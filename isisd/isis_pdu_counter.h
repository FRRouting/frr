// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Routing protocol - isis_pdu_counter.c
 * Copyright (C) 2018 Christian Franke, for NetDEF Inc.
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
void pdu_counter_count_drop(struct isis_area *area, uint8_t pdu_type);
uint64_t pdu_counter_get_count(pdu_counter_t counter, uint8_t pdu_type);

#endif
