// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_NEIGHBOR_H
#define PIM_NEIGHBOR_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "prefix.h"

#include "pim_tlv.h"
#include "pim_iface.h"
#include "pim_str.h"

struct pim_neighbor {
	int64_t creation; /* timestamp of creation */
	pim_addr source_addr;
	pim_hello_options hello_options;
	uint16_t holdtime;
	uint16_t propagation_delay_msec;
	uint16_t override_interval_msec;
	uint32_t dr_priority;
	uint32_t generation_id;
	struct list *prefix_list; /* list of struct prefix */
	struct event *t_expire_timer;
	struct interface *interface;

	struct event *jp_timer;
	struct list *upstream_jp_agg;
	struct bfd_session_params *bfd_session;
};

void pim_neighbor_timer_reset(struct pim_neighbor *neigh, uint16_t holdtime);
void pim_neighbor_free(struct pim_neighbor *neigh);
struct pim_neighbor *pim_neighbor_find(struct interface *ifp,
				       pim_addr source_addr, bool secondary);
struct pim_neighbor *pim_neighbor_find_by_secondary(struct interface *ifp,
						    struct prefix *src);
struct pim_neighbor *pim_neighbor_find_if(struct interface *ifp);


#define PIM_NEIGHBOR_SEND_DELAY 0
#define PIM_NEIGHBOR_SEND_NOW   1
struct pim_neighbor *
pim_neighbor_add(struct interface *ifp, pim_addr source_addr,
		 pim_hello_options hello_options, uint16_t holdtime,
		 uint16_t propagation_delay, uint16_t override_interval,
		 uint32_t dr_priority, uint32_t generation_id,
		 struct list *addr_list, int send_hello_now);
void pim_neighbor_delete(struct interface *ifp, struct pim_neighbor *neigh,
			 const char *delete_message);
void pim_neighbor_delete_all(struct interface *ifp, const char *delete_message);
void pim_neighbor_update(struct pim_neighbor *neigh,
			 pim_hello_options hello_options, uint16_t holdtime,
			 uint32_t dr_priority, struct list *addr_list);
struct prefix *pim_neighbor_find_secondary(struct pim_neighbor *neigh,
					   struct prefix *addr);
int pim_if_dr_election(struct interface *ifp);

#endif /* PIM_NEIGHBOR_H */
