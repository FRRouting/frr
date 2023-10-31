// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra neighbor table management
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 */

#ifndef _ZEBRA_NEIGH_H
#define _ZEBRA_NEIGH_H

#include <zebra.h>

#include "if.h"

#define zneigh_info zrouter.neigh_info

struct zebra_neigh_ent {
	ifindex_t ifindex;
	struct ipaddr ip;

	struct ethaddr mac;

	uint32_t flags;
#define ZEBRA_NEIGH_ENT_ACTIVE (1 << 0) /* can be used for traffic */

	/* memory used for adding the neigt entry to zneigh_info->es_rb_tree */
	RB_ENTRY(zebra_neigh_ent) rb_node;

	/* list of pbr rules associated with this neigh */
	struct list *pbr_rule_list;
};
RB_HEAD(zebra_neigh_rb_head, zebra_neigh_ent);
RB_PROTOTYPE(zebra_neigh_rb_head, zebra_neigh_ent, rb_node, zebra_es_rb_cmp);

struct zebra_neigh_info {
	/* RB tree of neighbor entries  */
	struct zebra_neigh_rb_head neigh_rb_tree;
};


/****************************************************************************/
extern void zebra_neigh_add(struct interface *ifp, struct ipaddr *ip,
			    struct ethaddr *mac);
extern void zebra_neigh_del(struct interface *ifp, struct ipaddr *ip);
extern void zebra_neigh_del_all(struct interface *ifp);
extern void zebra_neigh_show(struct vty *vty);
extern void zebra_neigh_init(void);
extern void zebra_neigh_terminate(void);
extern void zebra_neigh_deref(struct zebra_pbr_rule *rule);
extern void zebra_neigh_ref(int ifindex, struct ipaddr *ip,
			    struct zebra_pbr_rule *rule);

#endif /* _ZEBRA_NEIGH_H */
