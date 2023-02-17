// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp);
int pim_get_all_mcast_group(struct prefix *prefix);
bool pim_addr_is_multicast(pim_addr addr);
#endif /* PIM_UTIL_H */
