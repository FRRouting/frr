// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_HELLO_H
#define PIM_HELLO_H

#include <zebra.h>

#include "if.h"

int pim_hello_recv(struct interface *ifp, pim_addr src_addr, uint8_t *tlv_buf,
		   int tlv_buf_size);

int pim_hello_build_tlv(struct interface *ifp, uint8_t *tlv_buf,
			int tlv_buf_size, uint16_t holdtime,
			uint32_t dr_priority, uint32_t generation_id,
			uint16_t propagation_delay, uint16_t override_interval,
			int can_disable_join_suppression);

void pim_hello_require(struct interface *ifp);

#endif /* PIM_HELLO_H */
