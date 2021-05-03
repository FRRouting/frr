// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP packet helpers
 * Copyright (C) 2016 Cumulus Networks, Inc.
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

#define PIM_MSDP_MAX_PACKET_SIZE                                               \
	MAX(PIM_MSDP_SA_TLV_MAX_SIZE, PIM_MSDP_KA_TLV_MAX_SIZE)

#define PIM_MSDP_PKT_TYPE_STRLEN 16

void pim_msdp_pkt_ka_tx(struct pim_msdp_peer *mp);
void pim_msdp_read(struct event *thread);
void pim_msdp_pkt_sa_tx(struct pim_instance *pim);
void pim_msdp_pkt_sa_tx_one(struct pim_msdp_sa *sa);
void pim_msdp_pkt_sa_tx_to_one_peer(struct pim_msdp_peer *mp);
void pim_msdp_pkt_sa_tx_one_to_one_peer(struct pim_msdp_peer *mp,
					struct in_addr rp, pim_sgaddr sg);
bool msdp_peer_sa_filter(const struct pim_msdp_peer *mp,
			 const struct pim_msdp_sa *sa);

#endif
