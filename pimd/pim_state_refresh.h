// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_state_refresh.h: PIM Dense Mode State Refresh
 *
 * Copyright (C) 2024 ATCorp
 * Jafar Al-Gharaibeh
 */

#ifndef PIM_SATREFRESH_H
#define PIM_SATREFRESH_H

#include <zebra.h>

#include "if.h"
#include "pim_addr.h"
#include "pimd.h"
#include "pim_pim.h"
#include "pim_upstream.h"

int pim_staterefresh_build_msg(uint8_t *pim_msg, int buf_size, struct interface *ifp,
			       pim_addr group_addr, pim_addr source_addr, pim_addr originator_addr,
			       uint32_t metric_preference, uint32_t route_metric,
			       uint32_t rpt_bit_flag, uint8_t masklen, uint8_t ttl, bool p, bool n,
			       bool o, uint8_t reserved, uint8_t Interval);

int pim_staterefresh_recv(struct interface *ifp, pim_addr src_addr, uint8_t *buf, int buf_size);

/*
 * pim_msg_hdr
 * =========================
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |PIM Ver| Type  |   Reserved    |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Multicast Group Address (Encoded Group Format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Source Address (Encoded Unicast Format)           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Originator Address (Encoded Unicast Format)         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|                     Metric Preference                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             Metric                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Masklen    |    TTL        |P|N|O|Reserved |   Interval    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  P :
 *    Prune indicator flag. This MUST be set to 1 if the State Refresh
 *    is to be sent on a Pruned interface. Otherwise, it MUST be set to
 *    0.
 *
 *  N :
 *    Prune Now flag. This SHOULD be set to 1 by the State Refresh
 *    originator on every third State Refresh message and SHOULD be
 *    ignored upon receipt. This is for compatibility with earlier
 *    versions of state refresh.
 *
 *  O :
 *    Assert Override flag. This SHOULD be set to 1 by upstream routers
 *    on a LAN if the Assert Timer (AT(S,G)) is not running and SHOULD be
 *    ignored upon receipt. This is for compatibility with earlier
 *    versions of state refresh.
 */

struct pim_staterefresh_header {
	uint8_t masklen;
	uint8_t ttl;

#if (BYTE_ORDER == BIG_ENDIAN)
	uint8_t p : 1;
	uint8_t n : 1;
	uint8_t o : 1;
	uint8_t reserved : 5;
#elif (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t reserved : 5;
	uint8_t o : 1;
	uint8_t n : 1;
	uint8_t p : 1;
#else
#error "Please set byte order"
#endif
	uint8_t Interval;
};


void pim_send_staterefresh(struct pim_upstream *up);

#endif /* PIM_SATREFRESH_H*/
