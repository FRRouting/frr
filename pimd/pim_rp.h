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
#ifndef PIM_RP_H
#define PIM_RP_H

#include <zebra.h>
#include "prefix.h"
#include "vty.h"
#include "plist.h"
#include "pim_iface.h"
#include "pim_rpf.h"

struct rp_info {
	struct prefix group;
	struct pim_rpf rp;
	int i_am_rp;
	char *plist;
};

void pim_rp_init(struct pim_instance *pim);
void pim_rp_free(struct pim_instance *pim);

void pim_rp_list_hash_clean(void *data);

int pim_rp_new(struct pim_instance *pim, const char *rp, const char *group,
	       const char *plist);
int pim_rp_del(struct pim_instance *pim, const char *rp, const char *group,
	       const char *plist);
void pim_rp_prefix_list_update(struct pim_instance *pim,
			       struct prefix_list *plist);

int pim_rp_config_write(struct pim_instance *pim, struct vty *vty,
			const char *spaces);

void pim_rp_setup(struct pim_instance *pim);

int pim_rp_i_am_rp(struct pim_instance *pim, struct in_addr group);
void pim_rp_check_on_if_add(struct pim_interface *pim_ifp);
void pim_i_am_rp_re_evaluate(struct pim_instance *pim);

int pim_rp_check_is_my_ip_address(struct pim_instance *pim,
				  struct in_addr group,
				  struct in_addr dest_addr);

int pim_rp_set_upstream_addr(struct pim_instance *pim, struct in_addr *up,
			     struct in_addr source, struct in_addr group);

struct pim_rpf *pim_rp_g(struct pim_instance *pim, struct in_addr group);

#define I_am_RP(P, G)  pim_rp_i_am_rp ((P), (G))
#define RP(P, G)       pim_rp_g ((P), (G))

void pim_rp_show_information(struct pim_instance *pim, struct vty *vty,
			     uint8_t uj);
void pim_resolve_rp_nh(struct pim_instance *pim);
int pim_rp_list_cmp(void *v1, void *v2);
#endif
