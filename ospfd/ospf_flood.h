// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Flooding -- RFC2328 Section 13.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_FLOOD_H
#define _ZEBRA_OSPF_FLOOD_H

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
