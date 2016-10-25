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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef PIM_MSDP_PACKET_H
#define PIM_MSDP_PACKET_H

/* type and length of a single tlv can be consider packet header */
#define PIM_MSDP_HEADER_SIZE 3
#define PIM_MSDP_SA_TLV_MAX_SIZE 9192
#define PIM_MSDP_KA_TLV_MAX_SIZE PIM_MSDP_HEADER_SIZE
/* XXX: this is just a guesstimate - need to revist */
#define PIM_MSDP_MAX_PACKET_SIZE (PIM_MSDP_SA_TLV_MAX_SIZE + PIM_MSDP_KA_TLV_MAX_SIZE)

#define PIM_MSDP_PKT_TYPE_STRLEN 16

void pim_msdp_pkt_ka_tx(struct pim_msdp_peer *mp);
int pim_msdp_read(struct thread *thread);
#endif
