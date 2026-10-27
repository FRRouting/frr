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

/* One row per entry; ifname (may be NULL) filters on the ES bond. */
extern void zebra_evpn_bpp_show(struct vty *vty, const char *ifname, bool detail, bool uj);

/* One block per protected ES; esi (may be NULL) filters on the ES. */
extern void zebra_evpn_bpp_show_member(struct vty *vty, const esi_t *esi, bool uj);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_EVPN_BPP_H */
