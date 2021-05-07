/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#ifndef PIM_UTIL_H
#define PIM_UTIL_H

#include <stdint.h>

#include <zebra.h>

#include "checksum.h"
#include "pimd.h"
#include "pim_iface.h"

uint8_t igmp_msg_encode16to8(uint16_t value);
uint16_t igmp_msg_decode8to16(uint8_t code);

void pim_pkt_dump(const char *label, const uint8_t *buf, int size);

int pim_is_group_224_0_0_0_24(struct in_addr group_addr);
int pim_is_group_224_4(struct in_addr group_addr);
bool pim_is_group_filtered(struct pim_interface *pim_ifp, struct in_addr *grp);

/*
 * For 'ip pim allow-rp'. This checks if a given RP address is allowed by the
 * configured RP-filtering prefix list.
 *
 * Asserts that accept_rp is enabled; if it's not, there's no reason to call
 * this.
 *
 * pim_ifp
 *    The PIM interface the (*,G) JOIN with the RP address being checked was
 *    received on.
 *
 * rp
 *    The RP address that was received.
 */
bool pim_is_rp_allowed(struct pim_interface *pim_ifp, struct in_addr *rp);

#endif /* PIM_UTIL_H */
