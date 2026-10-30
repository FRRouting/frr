// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN-MH bridge-port protection
 * Copyright (C) 2026 Cisco Systems, Inc.
 * Patrice Brissette
 */

#ifndef _ZEBRA_EVPN_BPP_H
#define _ZEBRA_EVPN_BPP_H

#include <stdbool.h>

#include "lib/prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vty;
struct zebra_if;
struct zebra_evpn_es;
struct zapi_evpn_bpp_peer;
struct zebra_dplane_ctx;

/*
 * A protection entry is kept per (ES bond, VLAN) while the bond has
 * "evpn mh bridge-port-protection" configured.
 */
extern void zebra_evpn_bpp_init(void);
extern void zebra_evpn_bpp_terminate(void);

/* Sync the entries of an interface with its config, VLANs and ES. */
extern void zebra_evpn_bpp_if_update(struct zebra_if *zif);

/* Remove all the entries of an interface that is going away. */
extern void zebra_evpn_bpp_if_del(struct zebra_if *zif);

/*
 * Re-evaluate every entry from the event loop, after a change to a BD,
 * SVI, VRF, L3VNI or the l3vni-neigh setting.
 */
extern void zebra_evpn_bpp_re_eval_schedule(void);

/* The ES became known to BGP or not; sync its L3VNI ES-EVIs. */
extern void zebra_evpn_bpp_es_update(struct zebra_evpn_es *es);

/* Replay (add) or withdraw (del) the L3VNI ES-EVIs sent for the ES. */
extern void zebra_evpn_bpp_es_send_all(struct zebra_evpn_es *es, bool add);

/* One row per entry; ifname (may be NULL) filters on the ES bond. */
extern void zebra_evpn_bpp_show(struct vty *vty, const char *ifname, bool detail, bool uj);

/* One block per protected ES; esi (may be NULL) filters on the ES. */
extern void zebra_evpn_bpp_show_member(struct vty *vty, const esi_t *esi, bool uj);

/* Install or remove a Member from the ES Group. zebra does not re-check
 * eligibility or RMAC; bgpd is the only sender of BPP_PEER.
 */
extern void zebra_evpn_bpp_peer_update(const struct zapi_evpn_bpp_peer *peer, bool add);

/* Bound while ≥ 1 entry is ready and the Group has ≥ 1 Member. */
extern bool zebra_evpn_bpp_es_bound(const struct zebra_evpn_es *es);

/* Record a protection Binding enqueue; is_del clears the export table. */
extern void zebra_evpn_bpp_export_br_port(struct zebra_evpn_es *es, bool is_del);

/* Complete an export-log entry when the dplane result arrives. */
extern void zebra_evpn_bpp_dplane_result(struct zebra_dplane_ctx *ctx);

/* Last state sent and the enqueue ring. */
extern void zebra_evpn_bpp_show_export(struct vty *vty, bool uj);

/* Re-enqueue Members, Groups, Bindings, then REPLAY_DONE. */
extern void zebra_evpn_bpp_replay(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_EVPN_BPP_H */
