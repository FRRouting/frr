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

#include <zebra.h>

#include "vty.h"

#include "isisd/isis_pdu_counter.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_pdu.h"

static int pdu_type_to_counter_index(uint8_t pdu_type)
{
	switch (pdu_type) {
	case L1_LAN_HELLO:
		return L1_LAN_HELLO_INDEX;
	case L2_LAN_HELLO:
		return L2_LAN_HELLO_INDEX;
	case P2P_HELLO:
		return P2P_HELLO_INDEX;
	case L1_LINK_STATE:
		return L1_LINK_STATE_INDEX;
	case L2_LINK_STATE:
		return L2_LINK_STATE_INDEX;
	case FS_LINK_STATE:
		return FS_LINK_STATE_INDEX;
	case L1_COMPLETE_SEQ_NUM:
		return L1_COMPLETE_SEQ_NUM_INDEX;
	case L2_COMPLETE_SEQ_NUM:
		return L2_COMPLETE_SEQ_NUM_INDEX;
	case L1_PARTIAL_SEQ_NUM:
		return L1_PARTIAL_SEQ_NUM_INDEX;
	case L2_PARTIAL_SEQ_NUM:
		return L2_PARTIAL_SEQ_NUM_INDEX;
	default:
		return -1;
	}
}

static const char *pdu_counter_index_to_name(enum pdu_counter_index index)
{
	switch (index) {
	case L1_LAN_HELLO_INDEX:
		return " L1 IIH";
	case L2_LAN_HELLO_INDEX:
		return " L2 IIH";
	case P2P_HELLO_INDEX:
		return "P2P IIH";
	case L1_LINK_STATE_INDEX:
		return " L1 LSP";
	case L2_LINK_STATE_INDEX:
		return " L2 LSP";
	case FS_LINK_STATE_INDEX:
		return " FS LSP";
	case L1_COMPLETE_SEQ_NUM_INDEX:
		return "L1 CSNP";
	case L2_COMPLETE_SEQ_NUM_INDEX:
		return "L2 CSNP";
	case L1_PARTIAL_SEQ_NUM_INDEX:
		return "L1 PSNP";
	case L2_PARTIAL_SEQ_NUM_INDEX:
		return "L2 PSNP";
	default:
		return "???????";
	}
}

void pdu_counter_count(pdu_counter_t counter, uint8_t pdu_type)
{
	int index = pdu_type_to_counter_index(pdu_type);

	if (index < 0)
		return;

	counter[index]++;
}

void pdu_counter_print(struct vty *vty, const char *prefix,
		       pdu_counter_t counter)
{
	for (int i = 0; i < PDU_COUNTER_SIZE; i++) {
		if (!counter[i])
			continue;
		vty_out(vty, "%s%s: %" PRIu64 "\n", prefix,
			pdu_counter_index_to_name(i), counter[i]);
	}
}
