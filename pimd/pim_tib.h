// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TIB (Tree Information Base) - just PIM <> IGMP/MLD glue for now
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

#ifndef _FRR_PIM_GLUE_H
#define _FRR_PIM_GLUE_H

#include "if.h"
#include "typesafe.h"
#include "pim_addr.h"

struct pim_instance;
struct channel_oil;

PREDECL_RBTREE_UNIQ(gm_proxy_rpf);

/*
 * RPF proxy mode: per-(S,G) proxy state.  The proxy join for sg is placed
 * only on the proxy interface that is the RPF interface toward sg.src.
 */
struct gm_proxy_rpf {
	struct gm_proxy_rpf_item item;

	pim_sgaddr sg;

	/* Proxy interface currently carrying the join, IFINDEX_INTERNAL if none */
	ifindex_t proxy_ifindex;

	/* Downstream interfaces with GM interest in sg */
	ifindex_t *ds_ifindex;
	unsigned int ds_count;
	unsigned int ds_alloc;
};

extern bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg,
			   struct interface *oif, struct channel_oil **oilp);
extern void tib_sg_gm_prune(struct pim_instance *pim, pim_sgaddr sg,
			    struct interface *oif, struct channel_oil **oilp);
extern void tib_sg_proxy_join_prune_check(struct pim_instance *pim,
					  pim_sgaddr sg, struct interface *oif,
					  bool join);
/*
 * Invoke cb for each non-proxy interface with GM interest in sg that
 * proxy_ifp's proxy route-map would accept. skip_ifp is excluded (may be NULL).
 */
extern void tib_sg_downstream_ifaces_foreach(struct pim_instance *pim, pim_sgaddr sg,
					     struct interface *proxy_ifp,
					     struct interface *skip_ifp,
					     void (*cb)(struct interface *ifp, void *arg),
					     void *arg);


/* True when sg is handled by RPF proxy mode (enabled, and sg is an (S,G)) */
extern bool tib_sg_proxy_rpf_applies(struct pim_instance *pim, pim_sgaddr sg);
/* Switch RPF proxy mode on/off, rebuilding proxy joins on all proxy ifaces */
extern void tib_sg_proxy_rpf_set(struct pim_instance *pim, bool enable);
/* Re-evaluate the proxy interface of every (S,G) with source src */
extern void tib_sg_proxy_rpf_nht_update(struct pim_instance *pim, pim_addr src);
/* Re-evaluate the proxy interface of every (S,G) */
extern void tib_sg_proxy_rpf_update_all(struct pim_instance *pim);
/* ifp gained or lost PIM or IGMP/MLD: re-evaluate */
extern void tib_sg_proxy_rpf_if_changed(struct interface *ifp);
extern void tib_sg_proxy_rpf_init(struct pim_instance *pim);
extern void tib_sg_proxy_rpf_fini(struct pim_instance *pim);

#endif /* _FRR_PIM_GLUE_H */
