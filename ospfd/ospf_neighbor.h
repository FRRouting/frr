// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Neighbor functions.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_NEIGHBOR_H
#define _ZEBRA_OSPF_NEIGHBOR_H

#include <ospfd/ospf_gr.h>
#include <ospfd/ospf_packet.h>
#include <ospfd/ospf_flood.h>

/* Neighbor Data Structure */
struct ospf_neighbor {
	/* This neighbor's parent ospf interface. */
	struct ospf_interface *oi;

	/* OSPF neighbor Information */
	uint8_t state;      /* NSM status. */
	uint8_t dd_flags;   /* DD bit flags. */
	uint32_t dd_seqnum; /* DD Sequence Number. */

	/* Neighbor Information from Hello. */
	struct prefix address; /* Neighbor Interface Address. */

	struct in_addr src;       /* Src address. */
	struct in_addr router_id; /* Router ID. */
	uint8_t options;	  /* Options. */
	int priority;		  /* Router Priority. */
	struct in_addr d_router;  /* Designated Router. */
	struct in_addr bd_router; /* Backup Designated Router. */

	/* Last sent Database Description packet. */
	struct ospf_packet *last_send;
	/* Timestemp when last Database Description packet was sent */
	struct timeval last_send_ts;

	/* Last received Databse Description packet. */
	struct {
		uint8_t options;
		uint8_t flags;
		uint32_t dd_seqnum;
	} last_recv;

	/* LSA data. */
	struct ospf_lsdb ls_rxmt;
	struct ospf_lsa_list_head ls_rxmt_list;
	struct ospf_lsdb db_sum;
	struct ospf_lsdb ls_req;
	struct ospf_lsa *ls_req_last;

	uint32_t crypt_seqnum; /* Cryptographic Sequence Number. */

	/* Timer values. */
	uint32_t v_inactivity;
	uint32_t v_db_desc;
	uint32_t v_ls_req;
	uint32_t v_ls_rxmt;

	/* Threads. */
	struct event *t_inactivity;
	struct event *t_db_desc;
	struct event *t_ls_req;
	struct event *t_ls_rxmt;
	struct event *t_hello_reply;

	/* NBMA configured neighbour */
	struct ospf_nbr_nbma *nbr_nbma;

	/* Statistics */
	struct timeval ts_last_progress; /* last advance of NSM            */
	struct timeval ts_last_regress;  /* last regressive NSM change     */
	const char *last_regress_str;    /* Event which last regressed NSM */
	uint32_t state_change;		 /* NSM state change counter       */
	uint32_t ls_rxmt_lsa;		 /* Number of LSAs retransmited.   */

	/* BFD information */
	struct bfd_session_params *bfd_session;

	/* ospf graceful restart HELPER info */
	struct ospf_helper_info gr_helper_info;
};

/* Macros. */
#define NBR_IS_DR(n)	IPV4_ADDR_SAME (&n->address.u.prefix4, &n->d_router)
#define NBR_IS_BDR(n)   IPV4_ADDR_SAME (&n->address.u.prefix4, &n->bd_router)

/* Prototypes. */
extern struct ospf_neighbor *ospf_nbr_new(struct ospf_interface *);
extern void ospf_nbr_free(struct ospf_neighbor *);
extern void ospf_nbr_delete(struct ospf_neighbor *);
extern int ospf_nbr_bidirectional(struct in_addr *, struct in_addr *, int);
extern void ospf_nbr_self_reset(struct ospf_interface *, struct in_addr);
extern void ospf_nbr_add_self(struct ospf_interface *, struct in_addr);
extern int ospf_nbr_count(struct ospf_interface *, int);
extern int ospf_nbr_count_opaque_capable(struct ospf_interface *);
extern struct ospf_neighbor *ospf_nbr_get(struct ospf_interface *,
					  struct ospf_header *, struct ip *,
					  struct prefix *);
extern struct ospf_neighbor *ospf_nbr_lookup(struct ospf_interface *,
					     struct ip *, struct ospf_header *);
extern struct ospf_neighbor *ospf_nbr_lookup_by_addr(struct route_table *,
						     struct in_addr *);
extern struct ospf_neighbor *ospf_nbr_lookup_by_routerid(struct route_table *,
							 struct in_addr *);
extern void ospf_renegotiate_optional_capabilities(struct ospf *top);
#endif /* _ZEBRA_OSPF_NEIGHBOR_H */
