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

#ifndef PIM_OIL_H
#define PIM_OIL_H

#include "pim_mroute.h"

/*
 * Where did we get this (S,G) from?
 *
 * IGMP - Learned from IGMP
 * PIM - Learned from PIM
 * SOURCE - Learned from Source multicast packet received
 * STAR - Inherited
 */
#define PIM_OIF_FLAG_PROTO_IGMP   (1 << 0)
#define PIM_OIF_FLAG_PROTO_PIM    (1 << 1)
#define PIM_OIF_FLAG_PROTO_SOURCE (1 << 2)
#define PIM_OIF_FLAG_PROTO_STAR   (1 << 3)
#define PIM_OIF_FLAG_PROTO_ANY                                                 \
	(PIM_OIF_FLAG_PROTO_IGMP | PIM_OIF_FLAG_PROTO_PIM                      \
	 | PIM_OIF_FLAG_PROTO_SOURCE | PIM_OIF_FLAG_PROTO_STAR)

/*
 * We need a pimreg vif id from the kernel.
 * Since ifindex == vif id for most cases and the number
 * of expected interfaces is at most 100, using MAXVIFS -1
 * is probably ok.
 * Don't come running to me if this assumption is bad,
 * fix it.
 */
#define PIM_OIF_PIM_REGISTER_VIF   0
#define PIM_MAX_USABLE_VIFS        (MAXVIFS - 1)

struct channel_counts {
	unsigned long long lastused;
	unsigned long pktcnt;
	unsigned long oldpktcnt;
	unsigned long bytecnt;
	unsigned long oldbytecnt;
	unsigned long wrong_if;
	unsigned long oldwrong_if;
};

/*
  qpim_channel_oil_list holds a list of struct channel_oil.

  Each channel_oil.oil is used to control an (S,G) entry in the Kernel
  Multicast Forwarding Cache.
*/

struct channel_oil {
	struct pim_instance *pim;

	struct mfcctl oil;
	int installed;
	int oil_inherited_rescan;
	int oil_size;
	int oil_ref_count;
	time_t oif_creation[MAXVIFS];
	uint32_t oif_flags[MAXVIFS];
	struct channel_counts cc;
	struct pim_upstream *up;
};

extern struct list *pim_channel_oil_list;

void pim_oil_init(struct pim_instance *pim);
void pim_oil_terminate(struct pim_instance *pim);

void pim_channel_oil_free(struct channel_oil *c_oil);
struct channel_oil *pim_find_channel_oil(struct pim_instance *pim,
					 struct prefix_sg *sg);
struct channel_oil *pim_channel_oil_add(struct pim_instance *pim,
					struct prefix_sg *sg,
					int input_vif_index);
void pim_channel_oil_del(struct channel_oil *c_oil);

int pim_channel_add_oif(struct channel_oil *c_oil, struct interface *oif,
			uint32_t proto_mask);
int pim_channel_del_oif(struct channel_oil *c_oil, struct interface *oif,
			uint32_t proto_mask);

int pim_channel_oil_empty(struct channel_oil *c_oil);

char *pim_channel_oil_dump(struct channel_oil *c_oil, char *buf, size_t size);
#endif /* PIM_OIL_H */
