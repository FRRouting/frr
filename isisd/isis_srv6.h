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
#include "isisd/isis_tlvs.h"

#define ISIS_DEFAULT_SRV6_MAX_SEG_LEFT_MSD        3
#define ISIS_DEFAULT_SRV6_MAX_END_POP_MSD         3
#define ISIS_DEFAULT_SRV6_MAX_H_ENCAPS_MSD        2
#define ISIS_DEFAULT_SRV6_MAX_END_D_MSD           5
#define ISIS_DEFAULT_SRV6_IFNAME                 "sr0"

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

/* SRv6 Adjacency-SID type */
enum srv6_adj_type {
	ISIS_SRV6_ADJ_NORMAL = 0,
	ISIS_SRV6_LAN_BACKUP,
};

/* SRv6 Adjacency. */
struct srv6_adjacency {
	/* Adjacency type */
	enum srv6_adj_type type;

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

	/* Adjacency-SID nexthop information */
	struct in6_addr nexthop;

	/* End.X SID TI-LFA backup nexthops */
	struct list *backup_nexthops;

	/* SRv6 (LAN) End.X SID Sub-TLV */
	union {
		struct isis_srv6_endx_sid_subtlv *endx_sid;
		struct isis_srv6_lan_endx_sid_subtlv *lendx_sid;
	} u;

	/* Back pointer to IS-IS adjacency. */
	struct isis_adjacency *adj;
};

/* Per-area IS-IS SRv6 Data Base (SRv6 DB) */
struct isis_srv6_db {

	/* List of SRv6 Locator chunks */
	struct list *srv6_locator_chunks;

	/* List of SRv6 SIDs allocated by the IS-IS instance */
	struct list *srv6_sids;

	/* List of SRv6 End.X SIDs allocated by the IS-IS instance */
	struct list *srv6_endx_sids;

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

		/* Interface used for installing SRv6 SIDs into the data plane */
		char srv6_ifname[IF_NAMESIZE];
	} config;
};

bool isis_srv6_locator_unset(struct isis_area *area);

void isis_srv6_interface_set(struct isis_area *area, const char *ifname);

struct isis_srv6_sid *
isis_srv6_sid_alloc(struct isis_area *area, struct srv6_locator_chunk *chunk,
		    enum srv6_endpoint_behavior_codepoint behavior,
		    int sid_func);
extern void isis_srv6_sid_free(struct isis_srv6_sid *sid);

extern void isis_srv6_area_init(struct isis_area *area);
extern void isis_srv6_area_term(struct isis_area *area);

void isis_srv6_init(void);
void isis_srv6_term(void);

void isis_srv6_sid_structure2subsubtlv(
	const struct isis_srv6_sid *sid,
	struct isis_srv6_sid_structure_subsubtlv *structure_subsubtlv);
void isis_srv6_end_sid2subtlv(const struct isis_srv6_sid *sid,
			      struct isis_srv6_end_sid_subtlv *sid_subtlv);
void isis_srv6_locator2tlv(const struct isis_srv6_locator *loc,
			   struct isis_srv6_locator_tlv *loc_tlv);

void srv6_endx_sid_add_single(struct isis_adjacency *adj, bool backup,
			      struct list *nexthops);
void srv6_endx_sid_add(struct isis_adjacency *adj);
void srv6_endx_sid_del(struct srv6_adjacency *sra);
struct srv6_adjacency *isis_srv6_endx_sid_find(struct isis_adjacency *adj,
					       enum srv6_adj_type type);
void isis_area_delete_backup_srv6_endx_sids(struct isis_area *area, int level);

int isis_srv6_ifp_up_notify(struct interface *ifp);

#endif /* _FRR_ISIS_SRV6_H */
