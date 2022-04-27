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

#ifndef PIM_ASSERT_H
#define PIM_ASSERT_H

#include <zebra.h>

#include "if.h"

struct pim_ifchannel;
struct pim_neighbor;

enum pim_ifassert_state {
	PIM_IFASSERT_NOINFO,
	PIM_IFASSERT_I_AM_WINNER,
	PIM_IFASSERT_I_AM_LOSER
};

struct pim_assert_metric {
	uint32_t rpt_bit_flag;
	uint32_t metric_preference;
	uint32_t route_metric;
	pim_addr ip_address; /* neighbor router that sourced the Assert
				      message */
};

/*
  RFC 4601: 4.11.  Timer Values

  Note that for historical reasons, the Assert message lacks a
  Holdtime field.  Thus, changing the Assert Time from the default
  value is not recommended.
 */
#define PIM_ASSERT_OVERRIDE_INTERVAL (3)   /* seconds */
#define PIM_ASSERT_TIME              (180) /* seconds */

#define PIM_ASSERT_METRIC_PREFERENCE_MAX (0xFFFFFFFF)
#define PIM_ASSERT_ROUTE_METRIC_MAX      (0xFFFFFFFF)

void pim_ifassert_winner_set(struct pim_ifchannel *ch,
			     enum pim_ifassert_state new_state, pim_addr winner,
			     struct pim_assert_metric winner_metric);

int pim_assert_recv(struct interface *ifp, struct pim_neighbor *neigh,
		    pim_addr src_addr, uint8_t *buf, int buf_size);

int pim_assert_metric_better(const struct pim_assert_metric *m1,
			     const struct pim_assert_metric *m2);
int pim_assert_metric_match(const struct pim_assert_metric *m1,
			    const struct pim_assert_metric *m2);

int pim_assert_build_msg(uint8_t *pim_msg, int buf_size, struct interface *ifp,
			 pim_addr group_addr, pim_addr source_addr,
			 uint32_t metric_preference, uint32_t route_metric,
			 uint32_t rpt_bit_flag);

int pim_assert_send(struct pim_ifchannel *ch);

int assert_action_a1(struct pim_ifchannel *ch);
void assert_action_a4(struct pim_ifchannel *ch);
void assert_action_a5(struct pim_ifchannel *ch);

#endif /* PIM_ASSERT_H */
