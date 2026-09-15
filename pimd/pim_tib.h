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

/*
 * Which of the two subscribers that share PIM_OIF_FLAG_PROTO_GM on an OIF is
 * dropping its subscription.  The flag is a single bit per (channel_oil, vif)
 * and is not reference counted, so the OIF may only be removed once both are
 * gone.
 */
enum tib_sg_gm_sub {
	/* IGMP/MLD membership learned on the interface */
	TIB_GM_SUB_DYNAMIC,
	/* "ip igmp static-group" / "ipv6 mld static-group" */
	TIB_GM_SUB_STATIC,
};

extern bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg,
			   struct interface *oif, struct channel_oil **oilp);
/*
 * Drop one subscriber's (S,G) subscription on oif.  The OIF, the PIM local
 * membership and the upstream proxy join are only torn down when the other
 * subscriber named by "leaving" is gone as well.
 */
extern void tib_sg_gm_prune(struct pim_instance *pim, pim_sgaddr sg, struct interface *oif,
			    enum tib_sg_gm_sub leaving, struct channel_oil **oilp);
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
