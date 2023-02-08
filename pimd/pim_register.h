// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
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

int pim_register_recv(struct interface *ifp, pim_addr dest_addr,
		      pim_addr src_addr, uint8_t *tlv_buf, int tlv_buf_size);
#if PIM_IPV == 6
struct in6_addr pim_register_get_unicast_v6_addr(struct pim_interface *p_ifp);
#endif
void pim_register_send(const uint8_t *buf, int buf_size, pim_addr src,
		       struct pim_rpf *rpg, int null_register,
		       struct pim_upstream *up);
void pim_register_stop_send(struct interface *ifp, pim_sgaddr *sg, pim_addr src,
			    pim_addr originator);
void pim_register_join(struct pim_upstream *up);
void pim_null_register_send(struct pim_upstream *up);
void pim_reg_del_on_couldreg_fail(struct interface *ifp);

#endif
