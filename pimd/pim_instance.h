/*
 * PIM for FRR - PIM Instance
 * Copyright (C) 2017 Cumulus Networks, Inc.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef __PIM_INSTANCE_H__
#define __PIM_INSTANCE_H__

#include "pim_str.h"
#include "pim_msdp.h"

#if defined(HAVE_LINUX_MROUTE_H)
#include <linux/mroute.h>
#else
/*
  Below: from <linux/mroute.h>
*/

#ifndef MAXVIFS
#define MAXVIFS (256)
#endif
#endif
extern struct pim_instance *pimg; // Pim Global Instance

enum pim_spt_switchover {
	PIM_SPT_IMMEDIATE,
	PIM_SPT_INFINITY,
};

/* Per VRF PIM DB */
struct pim_instance {
	vrf_id_t vrf_id;
	struct vrf *vrf;

	struct {
		enum pim_spt_switchover switchover;
		char *plist;
	} spt;

	struct hash *rpf_hash;

	void *ssm_info; /* per-vrf SSM configuration */

	int send_v6_secondary;

	struct thread *thread;
	int mroute_socket;
	int64_t mroute_socket_creation;
	int64_t mroute_add_events;
	int64_t mroute_add_last;
	int64_t mroute_del_events;
	int64_t mroute_del_last;

	struct interface *regiface;

	// List of static routes;
	struct list *static_routes;

	// Upstream vrf specific information
	struct list *upstream_list;
	struct hash *upstream_hash;
	struct timer_wheel *upstream_sg_wheel;

	/*
	 * RP information
	 */
	struct list *rp_list;
	struct route_table *rp_table;

	int iface_vif_index[MAXVIFS];

	struct list *channel_oil_list;
	struct hash *channel_oil_hash;

	struct pim_msdp msdp;

	struct list *ssmpingd_list;
	struct in_addr ssmpingd_group_addr;

	unsigned int keep_alive_time;
	unsigned int rp_keep_alive_time;

	bool ecmp_enable;
	bool ecmp_rebalance_enable;

	/* If we need to rescan all our upstreams */
	struct thread *rpf_cache_refresher;
	int64_t rpf_cache_refresh_requests;
	int64_t rpf_cache_refresh_events;
	int64_t rpf_cache_refresh_last;
	int64_t scan_oil_events;
	int64_t scan_oil_last;

	int64_t nexthop_lookups;
	int64_t nexthop_lookups_avoided;
	int64_t last_route_change_time;
};

void pim_vrf_init(void);
void pim_vrf_terminate(void);

struct pim_instance *pim_get_pim_instance(vrf_id_t vrf_id);

#endif
