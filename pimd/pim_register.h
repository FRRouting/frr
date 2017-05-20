/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
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
#ifndef PIM_REGISTER_H
#define PIM_REGISTER_H

#include <zebra.h>

#include "if.h"

#define PIM_REGISTER_BORDER_BIT 0x80000000
#define PIM_REGISTER_NR_BIT     0x40000000

#define PIM_MSG_REGISTER_LEN   (8)
#define PIM_MSG_REGISTER_STOP_LEN (4)

int pim_register_stop_recv(struct interface *ifp, uint8_t *buf, int buf_size);

int pim_register_recv(struct interface *ifp, struct in_addr dest_addr,
		      struct in_addr src_addr, uint8_t *tlv_buf,
		      int tlv_buf_size);

void pim_register_send(const uint8_t *buf, int buf_size, struct in_addr src,
		       struct pim_rpf *rpg, int null_register,
		       struct pim_upstream *up);
void pim_register_stop_send(struct interface *ifp, struct prefix_sg *sg,
			    struct in_addr src, struct in_addr originator);
void pim_register_join(struct pim_upstream *up);

#endif
