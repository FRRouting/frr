// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * ospf_bfd.h: OSPF BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_OSPF_BFD_H
#define _ZEBRA_OSPF_BFD_H

#include "ospfd/ospf_interface.h"
#include "json.h"

extern void ospf_bfd_init(struct event_loop *tm);

extern void ospf_bfd_write_config(struct vty *vty,
				  const struct ospf_if_params *params);

extern void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state,
				   int state);

/**
 * Legacy information: it is the peers who actually have this information
 * and the protocol should not need to know about timers.
 */
extern void ospf_interface_bfd_show(struct vty *vty,
				    const struct interface *ifp,
				    struct json_object *json);

/* Disable interface BFD sessions while preserving configured parameters. */
extern void ospf_interface_disable_bfd(struct interface *ifp,
				       struct ospf_if_params *oip);

/* Free interface BFD configuration during interface parameter teardown. */
extern void ospf_interface_bfd_free_config(struct interface *ifp,
					   struct ospf_if_params *oip);

/* Allocate interface BFD configuration with FRR defaults if needed. */
extern struct bfd_configuration *ospf_interface_bfd_config_get(struct interface *ifp);

/*
 * Enables interface BFD sessions, allocating `bfd_config` with FRR defaults
 * on first call.  `quick` controls FRR's quick-establishment
 * mode (no YANG counterpart; the RFC 9129 northbound only flips the
 * `enabled` leaf, so it always passes `false`).  Promoted from static
 * to extern so the RFC 9129 `/bfd/enabled` callback and the legacy
 * `ip ospf bfd` CLI share the same allocation path.
 */
extern void ospf_interface_enable_bfd(struct interface *ifp, bool quick);

/*
 * Push BFD configuration changes to live sessions on this interface.
 * Idempotent.
 */
extern void ospf_interface_bfd_apply(struct interface *ifp);

/**
 * Create/update BFD session for this OSPF neighbor.
 */
extern void ospf_neighbor_bfd_apply(struct ospf_neighbor *nbr);

/* Remove BFD session associated with a neighbor (interface-owned). */
extern void ospf_neighbor_bfd_clear(struct ospf_neighbor *nbr);

/* Flush all per-interface BFD session entries. */
extern void ospf_bfd_if_flush(struct ospf_interface *oi);

#endif /* _ZEBRA_OSPF_BFD_H */
