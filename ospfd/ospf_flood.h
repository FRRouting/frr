// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Flooding -- RFC2328 Section 13.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_FLOOD_H
#define _ZEBRA_OSPF_FLOOD_H

#include "typesafe.h"

/*
 * OSPF Temporal LSA List
 */
PREDECL_DLIST(ospf_lsa_list);

struct ospf_lsa_list_entry {
	/* Linkage for LSA List */
	struct ospf_lsa_list_item list_linkage;

	union {
		/*
		 * Time associated with the list entry. For example, for a
		 * neigbhor link retransmission list, this is the
		 * retransmission time.
		 */
		struct timeval list_entry_timeval;

		/*
		 * Destanation address specific to the LSA list. For example,
		 * the distination for an associated direct LS acknowledgment.
		 */
		struct in_addr list_entry_dst_addr;
	} u;

	struct ospf_lsa *lsa;
};
#define list_entry_time u.list_entry_timeval
#define list_entry_dst	u.list_entry_dst_addr

DECLARE_DLIST(ospf_lsa_list, struct ospf_lsa_list_entry, list_linkage);

extern int ospf_flood(struct ospf *, struct ospf_neighbor *, struct ospf_lsa *,
		      struct ospf_lsa *);
extern int ospf_flood_through(struct ospf *, struct ospf_neighbor *,
			      struct ospf_lsa *);
extern int ospf_flood_through_area(struct ospf_area *, struct ospf_neighbor *,
				   struct ospf_lsa *);
extern int ospf_flood_through_as(struct ospf *, struct ospf_neighbor *,
				 struct ospf_lsa *);
extern int ospf_flood_through_interface(struct ospf_interface *oi,
					struct ospf_neighbor *inbr,
					struct ospf_lsa *lsa);

extern unsigned long ospf_ls_request_count(struct ospf_neighbor *);
extern int ospf_ls_request_isempty(struct ospf_neighbor *);
extern struct ospf_lsa *ospf_ls_request_new(struct lsa_header *);
extern void ospf_ls_request_free(struct ospf_lsa *);
extern void ospf_ls_request_add(struct ospf_neighbor *, struct ospf_lsa *);
extern void ospf_ls_request_delete(struct ospf_neighbor *, struct ospf_lsa *);
extern void ospf_ls_request_delete_all(struct ospf_neighbor *);
extern struct ospf_lsa *ospf_ls_request_lookup(struct ospf_neighbor *,
					       struct ospf_lsa *);

extern unsigned long ospf_ls_retransmit_count(struct ospf_neighbor *);
extern unsigned long ospf_ls_retransmit_count_self(struct ospf_neighbor *, int);
extern int ospf_ls_retransmit_isempty(struct ospf_neighbor *);
extern void ospf_ls_retransmit_add(struct ospf_neighbor *, struct ospf_lsa *);
extern void ospf_ls_retransmit_delete(struct ospf_neighbor *,
				      struct ospf_lsa *);
extern void ospf_ls_retransmit_clear(struct ospf_neighbor *);
extern void ospf_ls_retransmit_set_timer(struct ospf_neighbor *nbr);

extern struct ospf_lsa *ospf_ls_retransmit_lookup(struct ospf_neighbor *,
						  struct ospf_lsa *);
extern void ospf_ls_retransmit_delete_nbr_area(struct ospf_area *,
					       struct ospf_lsa *);
extern void ospf_ls_retransmit_delete_nbr_as(struct ospf *, struct ospf_lsa *);
extern void ospf_ls_retransmit_add_nbr_all(struct ospf_interface *,
					   struct ospf_lsa *);

extern void ospf_flood_lsa_area(struct ospf_lsa *, struct ospf_area *);
extern void ospf_flood_lsa_as(struct ospf_lsa *);
extern void ospf_lsa_flush_area(struct ospf_lsa *, struct ospf_area *);
extern void ospf_lsa_flush_as(struct ospf *, struct ospf_lsa *);
extern void ospf_lsa_flush(struct ospf *, struct ospf_lsa *);
extern struct external_info *ospf_external_info_check(struct ospf *,
						      struct ospf_lsa *);

extern void ospf_lsdb_init(struct ospf_lsdb *);
extern void ospf_area_update_fr_state(struct ospf_area *area);
extern void ospf_refresh_dna_type5_and_type7_lsas(struct ospf *ospf);

#endif /* _ZEBRA_OSPF_FLOOD_H */
