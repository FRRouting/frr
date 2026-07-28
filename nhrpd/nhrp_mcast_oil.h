// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP multicast OIL -- per-NBMA subscriber cache
 *
 * Built by snooping inbound PIM Join/Prune messages on the NHRP
 * interface (captured via the same NFLOG group as outbound multicast;
 * see nhrp_multicast.c). For each PIM Join seen, the sender's tunnel
 * IP is mapped to its NBMA via the NHRP cache, and (source, group,
 * ifindex, NBMA) is recorded with a hold-time-driven expiry.
 *
 * The replication path in nhrp_multicast_forward_cache() consults this
 * cache before forwarding user-data multicast: only NBMAs listed in
 * the OIL for the current (S, G, ifindex) receive a copy.
 *
 * Link-local multicast (224.0.0.0/24 -- PIM, OSPF, IGMP, etc.) bypasses
 * the filter and is always fanned out to every registered peer.
 *
 * Copyright (c) 2026 Onyx Networks.
 */
#ifndef NHRP_MCAST_OIL_H
#define NHRP_MCAST_OIL_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "sockunion.h"

struct interface;

/* Hold-time bounds. If a PIM Join carries a holdtime of zero (prune)
 * we remove the entry immediately. For Joins with a non-zero
 * holdtime, the entry persists for that long and is refreshed by
 * subsequent Joins. RFC 7761 sect.4.11 puts the default at 210 s.
 */
#define NHRP_MCAST_OIL_DEFAULT_HOLDTIME 210
#define NHRP_MCAST_OIL_MAX_HOLDTIME     65535

/* Initialise + teardown. Called once from nhrp_main.c at startup / shutdown. */
void nhrp_mcast_oil_init(void);
void nhrp_mcast_oil_terminate(void);

/* Record a PIM Join for (source, group) arriving on ifp, sent by the
 * PIM neighbor whose tunnel-IP is sender_tunnel_ip. The neighbor's
 * NBMA is resolved via nhrp_cache_get(). holdtime is in seconds.
 * wc_bit = true for (*,G) Joins (wildcard), false for (S,G).
 *
 * On prune (holdtime 0) the matching entry is removed.
 */
void nhrp_mcast_oil_join(struct interface *ifp,
			 union sockunion *src_addr,
			 union sockunion *grp_addr,
			 union sockunion *sender_tunnel_ip,
			 uint16_t holdtime,
			 bool wc_bit);

void nhrp_mcast_oil_prune(struct interface *ifp,
			  union sockunion *src_addr,
			  union sockunion *grp_addr,
			  union sockunion *sender_tunnel_ip,
			  bool wc, bool rpt);

/* Query whether a given peer NBMA is in the OIL for (source, group,
 * ifp). Returns true if:
 *   (a) an exact (S, G, ifp) entry exists and nbma is in its set, OR
 *   (b) a (*, G, ifp) entry exists and nbma is in its set (shared-tree
 *       fallback per PIM-SM semantics).
 *
 * If NO OIL entry exists for the (S, G, ifp) or (*, G, ifp) pair, the
 * function returns `default_fanout` -- letting the caller decide the
 * fail-open vs fail-closed stance per interface.
 */
bool nhrp_mcast_oil_contains(struct interface *ifp,
			     union sockunion *src_addr,
			     union sockunion *grp_addr,
			     union sockunion *peer_nbma,
			     bool default_fanout);

/* Returns true if grp_addr is in 224.0.0.0/24 (link-local control).
 * These are always fanned out -- filtering them would break PIM/OSPF/IGMP.
 */
bool nhrp_mcast_is_linklocal(union sockunion *grp_addr);

/* Pretty-print the OIL cache -- used by `show nhrp multicast oil` vty. */
void nhrp_mcast_oil_show(struct vty *vty);

#endif /* NHRP_MCAST_OIL_H */
