// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing over IPv6 (SRv6) for IS-IS
 * as per RFC 9352
 * https://datatracker.ietf.org/doc/html/rfc9352
 *
 * Copyright (C) 2023 Carmine Scarpitta - University of Rome Tor Vergata
 */

#ifndef _FRR_ISIS_SRV6_H
#define _FRR_ISIS_SRV6_H

#include "lib/srv6.h"

/* Maximum SRv6 SID Depths supported by the router */
#define SRV6_MAX_SEG_LEFT 3
#define SRV6_MAX_END_POP 3
#define SRV6_MAX_H_ENCAPS 2
#define SRV6_MAX_END_D 5

/* Name of the interface used for installing SRv6 SIDs into the data plane */
#define SRV6_IFNAME "sr0"

/* SRv6 SID structure */
struct isis_srv6_sid_structure {
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
};

/* SRv6 SID not bound to any adjacency */
struct isis_srv6_sid {
	struct isis_srv6_sid *next;

	/* SID flags */
	uint8_t flags;

	/* SID value */
	struct in6_addr sid;

	/* Endpoint behavior bound to the SID */
	enum srv6_endpoint_behavior_codepoint behavior;

	/* SRv6 SID structure */
	struct isis_srv6_sid_structure structure;

	/* Parent SRv6 locator */
	struct srv6_locator_chunk *locator;

	/* Backpointer to IS-IS area */
	struct isis_area *area;
};

/* SRv6 Locator */
struct isis_srv6_locator {
	struct isis_srv6_locator *next;

	uint32_t metric;

	uint8_t flags;
#define ISIS_SRV6_LOCATOR_FLAG_D 1 << 7

	uint8_t algorithm;
	struct prefix_ipv6 prefix;

	struct list *srv6_sid;
};

/* Per-area IS-IS SRv6 Data Base (SRv6 DB) */
struct isis_srv6_db {

	/* List of SRv6 Locator chunks */
	struct list *srv6_locator_chunks;

	/* List of SRv6 SIDs allocated by the IS-IS instance */
	struct list *srv6_sids;

	/* Area SRv6 configuration. */
	struct {
		/* Administrative status of SRv6 */
		bool enabled;

		/* Name of the SRv6 Locator */
		char srv6_locator_name[SRV6_LOCNAME_SIZE];

		/* Maximum Segments Left Depth supported by the router */
		uint8_t max_seg_left_msd;

		/* Maximum Maximum End Pop Depth supported by the router */
		uint8_t max_end_pop_msd;

		/* Maximum H.Encaps supported by the router */
		uint8_t max_h_encaps_msd;

		/* Maximum End D MSD supported by the router */
		uint8_t max_end_d_msd;
	} config;
};

bool isis_srv6_locator_unset(struct isis_area *area);

struct isis_srv6_sid *
isis_srv6_sid_alloc(struct isis_area *area, struct srv6_locator_chunk *chunk,
		    enum srv6_endpoint_behavior_codepoint behavior,
		    int sid_func);
extern void isis_srv6_sid_free(struct isis_srv6_sid *sid);

extern void isis_srv6_area_init(struct isis_area *area);
extern void isis_srv6_area_term(struct isis_area *area);

void isis_srv6_init(void);
void isis_srv6_term(void);

#endif /* _FRR_ISIS_SRV6_H */
