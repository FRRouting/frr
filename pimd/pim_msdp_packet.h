/*
 * IP MSDP packet helpers
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef PIM_MSDP_PACKET_H
#define PIM_MSDP_PACKET_H

/* type and length of a single tlv can be consider packet header */
#define PIM_MSDP_HEADER_SIZE 3

/* Keepalive TLV
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       4      |              3                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define PIM_MSDP_KA_TLV_MAX_SIZE PIM_MSDP_HEADER_SIZE

/* Source-Active TLV (x=8, y=12xEntryCount)
 0 1 2 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       1       |           x + y               |  Entry Count  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         RP Address                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Reserved             |  Sprefix Len  | \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  \
|                        Group Address                          |   ) z
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  /
|                        Source Address                         | /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define PIM_MSDP_SA_TLV_MAX_SIZE 9192
#define PIM_MSDP_SA_X_SIZE 8
#define PIM_MSDP_SA_ONE_ENTRY_SIZE 12
#define PIM_MSDP_SA_Y_SIZE(entry_cnt) (PIM_MSDP_SA_ONE_ENTRY_SIZE * entry_cnt)
#define PIM_MSDP_SA_ENTRY_CNT2SIZE(entry_cnt)                                  \
	(PIM_MSDP_SA_X_SIZE + PIM_MSDP_SA_Y_SIZE(entry_cnt))
/* SA TLV has to have atleast only one entry in it so x=8 + y=12 */
#define PIM_MSDP_SA_TLV_MIN_SIZE PIM_MSDP_SA_ENTRY_CNT2SIZE(1)
/* XXX: theoretically we can fix a max of 255 but that may result in packet
 * fragmentation */
#define PIM_MSDP_SA_MAX_ENTRY_CNT 120

#define PIM_MSDP_MAX_PACKET_SIZE max(PIM_MSDP_SA_TLV_MAX_SIZE, PIM_MSDP_KA_TLV_MAX_SIZE)

#define PIM_MSDP_PKT_TYPE_STRLEN 16

void pim_msdp_pkt_ka_tx(struct pim_msdp_peer *mp);
int pim_msdp_read(struct thread *thread);
void pim_msdp_pkt_sa_tx(struct pim_instance *pim);
void pim_msdp_pkt_sa_tx_one(struct pim_msdp_sa *sa);
void pim_msdp_pkt_sa_tx_to_one_peer(struct pim_msdp_peer *mp);

#endif
