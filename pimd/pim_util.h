// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_UTIL_H
#define PIM_UTIL_H

#include <stdint.h>

#include <zebra.h>
#include "lib/filter.h"

#include "checksum.h"
#include "pimd.h"
#include "pim_iface.h"

uint8_t igmp_msg_encode16to8(uint16_t value);
uint16_t igmp_msg_decode8to16(uint8_t code);

void pim_pkt_dump(const char *label, const uint8_t *buf, int size);

int pim_is_group_224_0_0_0_24(struct in_addr group_addr);
int pim_is_group_224_4(struct in_addr group_addr);
bool pim_is_group_ff00_8(struct in6_addr group_address);
enum filter_type pim_access_list_apply(struct access_list *access, const struct in_addr *source,
				       const struct in_addr *group);
bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp, pim_addr *src);
void pim_get_all_mcast_group(struct prefix *prefix);
bool pim_addr_is_multicast(pim_addr addr);

/*
 * For 'ip pim allow-rp'. This checks if a given RP address is allowed.
 *
 * Returns false if allow-rp is not enabled on the interface.
 * Returns true if allow-rp is enabled and no prefix-list is configured.
 * Returns true/false based on prefix-list match if one is configured.
 *
 * pim_ifp
 *    The PIM interface the (*,G) JOIN with the RP address being checked was
 *    received on.
 *
 * rp
 *    The RP address that was received.
 */
bool pim_is_rp_allowed(struct pim_interface *pim_ifp, pim_addr *rp);

#endif /* PIM_UTIL_H */
