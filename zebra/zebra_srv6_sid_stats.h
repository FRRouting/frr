// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 per-SID tx/rx statistics DB.
 *
 * Cisco-style model: counters live in the dataplane (kernel), the control
 * plane polls them into a SID-keyed cache on a timer and surfaces them via
 * show/clear.  rx = local decap (SEG6_LOCAL_COUNTERS on the seg6local route);
 * tx = encap toward a remote SID (the srl2 netdev that wraps for that SID).
 */
#ifndef _ZEBRA_SRV6_SID_STATS_H
#define _ZEBRA_SRV6_SID_STATS_H

#include <zebra.h>
#include "lib/if.h"
#include "lib/typesafe.h"

PREDECL_HASH(sid_stat_htab);

struct zebra_srv6_sid_stat {
	struct sid_stat_htab_item htab_item;
	struct in6_addr sid;

	uint32_t k_action;    /* kernel SEG6_LOCAL_ACTION (for local SIDs) */
	bool is_local;	      /* we decap this SID (rx) */
	bool is_encap;	      /* an srl2 encaps toward this SID (tx) */
	ifindex_t tx_ifindex; /* srl2 ifindex providing tx */

	/* raw cumulative kernel values from the latest poll */
	uint64_t rx_pkts, rx_bytes;
	uint64_t tx_pkts, tx_bytes;

	/* baselines captured by `clear`, subtracted on display */
	uint64_t rx_pkts_base, rx_bytes_base;
	uint64_t tx_pkts_base, tx_bytes_base;

	bool seen; /* set each poll; unseen entries are pruned */
};

void zebra_srv6_sid_stats_init(void);
void zebra_srv6_sid_stats_fini(void);

void zebra_srv6_sid_stats_poll(void);			     /* one refresh now */
void zebra_srv6_sid_stats_clear(const struct in6_addr *sid); /* NULL = all */

void zebra_srv6_sid_stats_walk(void (*cb)(const struct zebra_srv6_sid_stat *srl2, void *arg),
			       void *arg);

#endif /* _ZEBRA_SRV6_SID_STATS_H */
