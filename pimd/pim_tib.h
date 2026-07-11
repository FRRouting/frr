// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TIB (Tree Information Base) - just PIM <> IGMP/MLD glue for now
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

#ifndef _FRR_PIM_GLUE_H
#define _FRR_PIM_GLUE_H

#include "pim_addr.h"

struct pim_instance;
struct channel_oil;

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

#endif /* _FRR_PIM_GLUE_H */
