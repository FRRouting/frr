// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_JOIN_H
#define PIM_JOIN_H

#include <zebra.h>

#include "if.h"

#include "pim_neighbor.h"

int pim_joinprune_recv(struct interface *ifp, struct pim_neighbor *neigh,
		       pim_addr src_addr, uint8_t *tlv_buf, int tlv_buf_size);

int pim_joinprune_send(struct pim_rpf *nexthop, struct list *groups);

#endif /* PIM_JOIN_H */
