/*
 * OSPF Link State Advertisement
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_OSPF_LSA_H
#define _ZEBRA_OSPF_LSA_H

#include "stream.h"

/* OSPF LSA Range definition. */
#define OSPF_MIN_LSA		1  /* begin range here */
#define OSPF_MAX_LSA           12

/* OSPF LSA Type definition. */
#define OSPF_UNKNOWN_LSA	      0
#define OSPF_ROUTER_LSA               1
#define OSPF_NETWORK_LSA              2
#define OSPF_SUMMARY_LSA              3
#define OSPF_ASBR_SUMMARY_LSA         4
#define OSPF_AS_EXTERNAL_LSA          5
#define OSPF_GROUP_MEMBER_LSA	      6  /* Not supported. */
#define OSPF_AS_NSSA_LSA	              7
#define OSPF_EXTERNAL_ATTRIBUTES_LSA  8  /* Not supported. */
#define OSPF_OPAQUE_LINK_LSA	      9
#define OSPF_OPAQUE_AREA_LSA	     10
#define OSPF_OPAQUE_AS_LSA	     11

#define OSPF_LSA_HEADER_SIZE	     20U
#define OSPF_ROUTER_LSA_LINK_SIZE    12U
#define OSPF_ROUTER_LSA_TOS_SIZE      4U
#define OSPF_MAX_LSA_SIZE	   1500U

/* AS-external-LSA refresh method. */
#define LSA_REFRESH_IF_CHANGED	0
#define LSA_REFRESH_FORCE	1

/* OSPF LSA header. */
struct lsa_header {
	uint16_t ls_age;
	uint8_t options;
	uint8_t type;
	struct in_addr id;
	struct in_addr adv_router;
	uint32_t ls_seqnum;
	uint16_t checksum;
	uint16_t length;
};

/* OSPF LSA. */
struct ospf_lsa {
	/* LSA origination flag. */
	uint8_t flags;
#define OSPF_LSA_SELF		  0x01
#define OSPF_LSA_SELF_CHECKED	  0x02
#define OSPF_LSA_RECEIVED	  0x04
#define OSPF_LSA_APPROVED	  0x08
#define OSPF_LSA_DISCARD	  0x10
#define OSPF_LSA_LOCAL_XLT	  0x20
#define OSPF_LSA_PREMATURE_AGE	  0x40
#define OSPF_LSA_IN_MAXAGE	  0x80

	/* LSA data. */
	struct lsa_header *data;

	/* Received time stamp. */
	struct timeval tv_recv;

	/* Last time it was originated */
	struct timeval tv_orig;

	/* All of reference count, also lock to remove. */
	int lock;

	/* Flags for the SPF calculation. */
	int stat;
#define LSA_SPF_NOT_EXPLORED -1
#define LSA_SPF_IN_SPFTREE -2
	/* If stat >= 0, stat is LSA position in candidates heap. */

	/* References to this LSA in neighbor retransmission lists*/
	int retransmit_counter;

	/* Area the LSA belongs to, may be NULL if AS-external-LSA. */
	struct ospf_area *area;

	/* Parent LSDB. */
	struct ospf_lsdb *lsdb;

	/* Related Route. */
	void *route;

	/* Refreshement List or Queue */
	int refresh_list;

	/* For Type-9 Opaque-LSAs */
	struct ospf_interface *oi;

	/* VRF Id */
	vrf_id_t vrf_id;
};

/* OSPF LSA Link Type. */
#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_VIRTUALLINK      4

/* OSPF Router LSA Flag. */
#define ROUTER_LSA_BORDER	       0x01 /* The router is an ABR */
#define ROUTER_LSA_EXTERNAL	       0x02 /* The router is an ASBR */
#define ROUTER_LSA_VIRTUAL	       0x04 /* The router has a VL in this area */
#define ROUTER_LSA_NT		       0x10 /* The routers always translates Type-7 */
#define ROUTER_LSA_SHORTCUT	       0x20 /* Shortcut-ABR specific flag */

#define IS_ROUTER_LSA_VIRTUAL(x)       ((x)->flags & ROUTER_LSA_VIRTUAL)
#define IS_ROUTER_LSA_EXTERNAL(x)      ((x)->flags & ROUTER_LSA_EXTERNAL)
#define IS_ROUTER_LSA_BORDER(x)	       ((x)->flags & ROUTER_LSA_BORDER)
#define IS_ROUTER_LSA_SHORTCUT(x)      ((x)->flags & ROUTER_LSA_SHORTCUT)
#define IS_ROUTER_LSA_NT(x)            ((x)->flags & ROUTER_LSA_NT)

/* OSPF Router-LSA Link information. */
struct router_lsa_link {
	struct in_addr link_id;
	struct in_addr link_data;
	struct {
		uint8_t type;
		uint8_t tos_count;
		uint16_t metric;
	} m[1];
};

/* OSPF Router-LSAs structure. */
#define OSPF_ROUTER_LSA_MIN_SIZE                   4U /* w/0 link descriptors */
/* There is an edge case, when number of links in a Router-LSA may be 0 without
   breaking the specification. A router, which has no other links to backbone
   area besides one virtual link, will not put any VL descriptor blocks into
   the Router-LSA generated for area 0 until a full adjacency over the VL is
   reached (RFC2328 12.4.1.3). In this case the Router-LSA initially received
   by the other end of the VL will have 0 link descriptor blocks, but soon will
   be replaced with the next revision having 1 descriptor block. */
struct router_lsa {
	struct lsa_header header;
	uint8_t flags;
	uint8_t zero;
	uint16_t links;
	struct {
		struct in_addr link_id;
		struct in_addr link_data;
		uint8_t type;
		uint8_t tos;
		uint16_t metric;
	} link[1];
};

/* OSPF Network-LSAs structure. */
#define OSPF_NETWORK_LSA_MIN_SIZE                  8U /* w/1 router-ID */
struct network_lsa {
	struct lsa_header header;
	struct in_addr mask;
	struct in_addr routers[1];
};

/* OSPF Summary-LSAs structure. */
#define OSPF_SUMMARY_LSA_MIN_SIZE                  8U /* w/1 TOS metric block */
struct summary_lsa {
	struct lsa_header header;
	struct in_addr mask;
	uint8_t tos;
	uint8_t metric[3];
};

/* OSPF AS-external-LSAs structure. */
#define OSPF_AS_EXTERNAL_LSA_MIN_SIZE             16U /* w/1 TOS forwarding block */
struct as_external_lsa {
	struct lsa_header header;
	struct in_addr mask;
	struct {
		uint8_t tos;
		uint8_t metric[3];
		struct in_addr fwd_addr;
		uint32_t route_tag;
	} e[1];
};

#include "ospfd/ospf_opaque.h"

/* Macros. */
#define GET_METRIC(x) get_metric(x)
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)

#define GET_AGE(x)     (ntohs ((x)->data->ls_age) + time (NULL) - (x)->tv_recv)
#define LS_AGE(x) (OSPF_LSA_MAXAGE < get_age(x) ? OSPF_LSA_MAXAGE : get_age(x))
#define IS_LSA_SELF(L)          (CHECK_FLAG ((L)->flags, OSPF_LSA_SELF))
#define IS_LSA_MAXAGE(L)        (LS_AGE ((L)) == OSPF_LSA_MAXAGE)

#define OSPF_LSA_UPDATE_DELAY		2

#define OSPF_LSA_UPDATE_TIMER_ON(T, F)                                         \
	if (!(T))                                                              \
	(T) = thread_add_timer(master, (F), 0, 2)

/* Prototypes. */
/* XXX: Eek, time functions, similar are in lib/thread.c */
extern struct timeval int2tv(int);
extern struct timeval msec2tv(int);

extern int get_age(struct ospf_lsa *);
extern uint16_t ospf_lsa_checksum(struct lsa_header *);
extern int ospf_lsa_checksum_valid(struct lsa_header *);
extern int ospf_lsa_refresh_delay(struct ospf_lsa *);

extern const char *dump_lsa_key(struct ospf_lsa *);
extern uint32_t lsa_seqnum_increment(struct ospf_lsa *);
extern void lsa_header_set(struct stream *, uint8_t, uint8_t, struct in_addr,
			   struct in_addr);
extern struct ospf_neighbor *ospf_nbr_lookup_ptop(struct ospf_interface *);
extern int ospf_check_nbr_status(struct ospf *);

/* Prototype for LSA primitive. */
extern struct ospf_lsa *ospf_lsa_new(void);
extern struct ospf_lsa *ospf_lsa_dup(struct ospf_lsa *);
extern void ospf_lsa_free(struct ospf_lsa *);
extern struct ospf_lsa *ospf_lsa_lock(struct ospf_lsa *);
extern void ospf_lsa_unlock(struct ospf_lsa **);
extern void ospf_lsa_discard(struct ospf_lsa *);
extern int ospf_lsa_flush_schedule(struct ospf *, struct ospf_lsa *);
extern struct lsa_header *ospf_lsa_data_new(size_t);
extern struct lsa_header *ospf_lsa_data_dup(struct lsa_header *);
extern void ospf_lsa_data_free(struct lsa_header *);

/* Prototype for various LSAs */
extern int ospf_router_lsa_update(struct ospf *);
extern int ospf_router_lsa_update_area(struct ospf_area *);

extern void ospf_network_lsa_update(struct ospf_interface *);

extern struct ospf_lsa *
ospf_summary_lsa_originate(struct prefix_ipv4 *, uint32_t, struct ospf_area *);
extern struct ospf_lsa *ospf_summary_asbr_lsa_originate(struct prefix_ipv4 *,
							uint32_t,
							struct ospf_area *);

extern struct ospf_lsa *ospf_lsa_install(struct ospf *, struct ospf_interface *,
					 struct ospf_lsa *);

extern void ospf_nssa_lsa_flush(struct ospf *ospf, struct prefix_ipv4 *p);
extern void ospf_external_lsa_flush(struct ospf *, uint8_t,
				    struct prefix_ipv4 *,
				    ifindex_t /* , struct in_addr nexthop */);

extern struct in_addr ospf_get_ip_from_ifp(struct ospf_interface *);

extern struct ospf_lsa *ospf_external_lsa_originate(struct ospf *,
						    struct external_info *);
extern int ospf_external_lsa_originate_timer(struct thread *);
extern int ospf_default_originate_timer(struct thread *);
extern struct ospf_lsa *ospf_lsa_lookup(struct ospf *ospf, struct ospf_area *,
					uint32_t, struct in_addr,
					struct in_addr);
extern struct ospf_lsa *ospf_lsa_lookup_by_id(struct ospf_area *, uint32_t,
					      struct in_addr);
extern struct ospf_lsa *ospf_lsa_lookup_by_header(struct ospf_area *,
						  struct lsa_header *);
extern int ospf_lsa_more_recent(struct ospf_lsa *, struct ospf_lsa *);
extern int ospf_lsa_different(struct ospf_lsa *, struct ospf_lsa *);
extern void ospf_flush_self_originated_lsas_now(struct ospf *);

extern int ospf_lsa_is_self_originated(struct ospf *, struct ospf_lsa *);

extern struct ospf_lsa *ospf_lsa_lookup_by_prefix(struct ospf_lsdb *, uint8_t,
						  struct prefix_ipv4 *,
						  struct in_addr);

extern void ospf_lsa_maxage(struct ospf *, struct ospf_lsa *);
extern uint32_t get_metric(uint8_t *);

extern int ospf_lsa_maxage_walker(struct thread *);
extern struct ospf_lsa *ospf_lsa_refresh(struct ospf *, struct ospf_lsa *);

extern void ospf_external_lsa_refresh_default(struct ospf *);

extern void ospf_external_lsa_refresh_type(struct ospf *, uint8_t,
					   unsigned short, int);
extern struct ospf_lsa *ospf_external_lsa_refresh(struct ospf *,
						  struct ospf_lsa *,
						  struct external_info *, int);
extern struct in_addr ospf_lsa_unique_id(struct ospf *, struct ospf_lsdb *,
					 uint8_t, struct prefix_ipv4 *);
extern void ospf_schedule_lsa_flood_area(struct ospf_area *, struct ospf_lsa *);
extern void ospf_schedule_lsa_flush_area(struct ospf_area *, struct ospf_lsa *);

extern void ospf_refresher_register_lsa(struct ospf *, struct ospf_lsa *);
extern void ospf_refresher_unregister_lsa(struct ospf *, struct ospf_lsa *);
extern int ospf_lsa_refresh_walker(struct thread *);

extern void ospf_lsa_maxage_delete(struct ospf *, struct ospf_lsa *);

extern void ospf_discard_from_db(struct ospf *, struct ospf_lsdb *,
				 struct ospf_lsa *);
extern int is_prefix_default(struct prefix_ipv4 *);

extern int metric_type(struct ospf *, uint8_t, unsigned short);
extern int metric_value(struct ospf *, uint8_t, unsigned short);

extern struct in_addr ospf_get_nssa_ip(struct ospf_area *);
extern int ospf_translated_nssa_compare(struct ospf_lsa *, struct ospf_lsa *);
extern struct ospf_lsa *ospf_translated_nssa_refresh(struct ospf *,
						     struct ospf_lsa *,
						     struct ospf_lsa *);
extern struct ospf_lsa *ospf_translated_nssa_originate(struct ospf *,
						       struct ospf_lsa *);

#endif /* _ZEBRA_OSPF_LSA_H */
