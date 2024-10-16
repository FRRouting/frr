// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Link State Advertisement
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_LSA_H
#define _ZEBRA_OSPF_LSA_H

#include "stream.h"

/* OSPF LSA Default metric values */
#define DEFAULT_DEFAULT_METRIC 20
#define DEFAULT_DEFAULT_ORIGINATE_METRIC 10
#define DEFAULT_DEFAULT_ALWAYS_METRIC 1
#define DEFAULT_METRIC_TYPE EXTERNAL_METRIC_TYPE_2

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
#define DO_NOT_AGE 0x8000
	uint8_t options;
	uint8_t type;
	struct in_addr id;
	struct in_addr adv_router;
	uint32_t ls_seqnum;
	uint16_t checksum;
	uint16_t length;
};

struct vertex;

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

	/* LSA data. and size */
	struct lsa_header *data;
	size_t size;

	/* Received time stamp. */
	struct timeval tv_recv;

	/* Last time it was originated */
	struct timeval tv_orig;

	/* All of reference count, also lock to remove. */
	int lock;

	/* Flags for the SPF calculation. */
	struct vertex *stat;

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

	/*For topo chg detection in HELPER role*/
	bool to_be_acknowledged;

	/* send maxage with no data */
	bool opaque_zero_len_delete;
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
	struct router_link {
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
	struct as_route {
		uint8_t tos;
		uint8_t metric[3];
		struct in_addr fwd_addr;
		uint32_t route_tag;
	} e[1];
};

enum lsid_status { LSID_AVAILABLE = 0, LSID_CHANGE, LSID_NOT_AVAILABLE };

#include "ospfd/ospf_opaque.h"

/* Macros. */
#define GET_METRIC(x) get_metric(x)
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)

#define GET_AGE(x)     (ntohs ((x)->data->ls_age) + time (NULL) - (x)->tv_recv)
#define LS_AGE(x) (OSPF_LSA_MAXAGE < get_age(x) ? OSPF_LSA_MAXAGE : get_age(x))
#define IS_LSA_SELF(L)          (CHECK_FLAG ((L)->flags, OSPF_LSA_SELF))
#define IS_LSA_MAXAGE(L)        (LS_AGE ((L)) == OSPF_LSA_MAXAGE)
#define IS_LSA_MAX_SEQ(L)                                                      \
	((L)->data->ls_seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER))

#define OSPF_LSA_UPDATE_DELAY		2

#define CHECK_LSA_TYPE_1_TO_5_OR_7(type)                                       \
	((type == OSPF_ROUTER_LSA) || (type == OSPF_NETWORK_LSA)               \
	 || (type == OSPF_SUMMARY_LSA) || (type == OSPF_ASBR_SUMMARY_LSA)      \
	 || (type == OSPF_AS_EXTERNAL_LSA) || (type == OSPF_AS_NSSA_LSA))

#define OSPF_FR_CONFIG(o, a)                                                   \
	(o->fr_configured || ((a != NULL) ? a->fr_info.configured : 0))

/* Prototypes. */
/* XXX: Eek, time functions, similar are in lib/thread.c */
extern struct timeval int2tv(int);

extern struct timeval msec2tv(int a);
extern int tv2msec(struct timeval tv);

extern int get_age(struct ospf_lsa *lsa);
extern uint16_t ospf_lsa_checksum(struct lsa_header *lsah);
extern int ospf_lsa_checksum_valid(struct lsa_header *lsah);
extern int ospf_lsa_refresh_delay(struct ospf *ospf, struct ospf_lsa *lsa);

extern const char *dump_lsa_key(struct ospf_lsa *lsa);
extern uint32_t lsa_seqnum_increment(struct ospf_lsa *lsa);
extern void lsa_header_set(struct stream *s, uint8_t options, uint8_t type, struct in_addr id,
			   struct in_addr router_id);
extern struct ospf_neighbor *ospf_nbr_lookup_ptop(struct ospf_interface *oi);
extern int ospf_check_nbr_status(struct ospf *ospf);

/* Prototype for LSA primitive. */
extern struct ospf_lsa *ospf_lsa_new(void);
extern struct ospf_lsa *ospf_lsa_new_and_data(size_t size);
extern struct ospf_lsa *ospf_lsa_dup(struct ospf_lsa *lsa);
extern void ospf_lsa_free(struct ospf_lsa *lsa);
extern struct ospf_lsa *ospf_lsa_lock(struct ospf_lsa *lsa);
extern void ospf_lsa_unlock(struct ospf_lsa **lsa);
extern void ospf_lsa_discard(struct ospf_lsa *lsa);
extern int ospf_lsa_flush_schedule(struct ospf *ospf, struct ospf_lsa *lsa);
extern struct lsa_header *ospf_lsa_data_new(size_t size);
extern struct lsa_header *ospf_lsa_data_dup(struct lsa_header *lsah);
extern void ospf_lsa_data_free(struct lsa_header *lsah);

/* Prototype for various LSAs */
extern void ospf_router_lsa_body_set(struct stream **s, struct ospf_area *area);
extern uint8_t router_lsa_flags(struct ospf_area *area);
extern int ospf_router_lsa_update(struct ospf *ospf);
extern int ospf_router_lsa_update_area(struct ospf_area *area);

extern void ospf_network_lsa_update(struct ospf_interface *oi);

extern struct ospf_lsa *ospf_summary_lsa_originate(struct prefix_ipv4 *p, uint32_t metric,
						   struct ospf_area *area);
extern struct ospf_lsa *ospf_summary_asbr_lsa_originate(struct prefix_ipv4 *p, uint32_t metric,
							struct ospf_area *area);

extern struct ospf_lsa *ospf_lsa_install(struct ospf *ospf, struct ospf_interface *oi,
					 struct ospf_lsa *lsa);

extern void ospf_nssa_lsa_flush(struct ospf *ospf, struct prefix_ipv4 *p);
extern void ospf_external_lsa_flush(struct ospf *ospf, uint8_t type, struct prefix_ipv4 *p,
				    ifindex_t /* , struct in_addr nexthop */);

extern struct in_addr ospf_get_ip_from_ifp(struct ospf_interface *oi);

extern struct ospf_lsa *ospf_external_lsa_originate(struct ospf *ospf, struct external_info *ei);
extern struct ospf_lsa *ospf_nssa_lsa_originate(struct ospf_area *area,
						struct external_info *ei);
extern struct ospf_lsa *ospf_nssa_lsa_refresh(struct ospf_area *area,
					      struct ospf_lsa *lsa,
					      struct external_info *ei);
extern void ospf_external_lsa_rid_change(struct ospf *ospf);
extern struct ospf_lsa *ospf_lsa_lookup(struct ospf *ospf, struct ospf_area *area, uint32_t type,
					struct in_addr id, struct in_addr adv_router);
extern struct ospf_lsa *ospf_lsa_lookup_by_id(struct ospf_area *area, uint32_t type,
					      struct in_addr id);
extern struct ospf_lsa *ospf_lsa_lookup_by_header(struct ospf_area *area, struct lsa_header *lsah);
extern int ospf_lsa_more_recent(struct ospf_lsa *l1, struct ospf_lsa *l2);
extern int ospf_lsa_different(struct ospf_lsa *l1, struct ospf_lsa *l2, bool ignore_rcvd_flag);
extern void ospf_flush_self_originated_lsas_now(struct ospf *ospf);

extern int ospf_lsa_is_self_originated(struct ospf *ospf, struct ospf_lsa *lsa);

extern struct ospf_lsa *ospf_lsa_lookup_by_prefix(struct ospf_lsdb *lsdb, uint8_t type,
						  struct prefix_ipv4 *p, struct in_addr router_id);

extern void ospf_lsa_maxage(struct ospf *ospf, struct ospf_lsa *lsa);
extern uint32_t get_metric(uint8_t *metric);

extern void ospf_lsa_maxage_walker(struct event *event);
extern struct ospf_lsa *ospf_lsa_refresh(struct ospf *ospf, struct ospf_lsa *lsa);

extern void ospf_external_lsa_refresh_default(struct ospf *ospf);

extern void ospf_external_lsa_refresh_type(struct ospf *ospf, uint8_t type, uint8_t instance,
					   int force);
extern struct ospf_lsa *ospf_external_lsa_refresh(struct ospf *ospf, struct ospf_lsa *lsa,
						  struct external_info *ei, int force, bool aggr);
extern enum lsid_status ospf_lsa_unique_id(struct ospf *ospf,
					   struct ospf_lsdb *lsdb,
					   uint8_t type, struct prefix_ipv4 *p,
					   struct in_addr *addr);
extern void ospf_schedule_lsa_flood_area(struct ospf_area *area, struct ospf_lsa *lsa);
extern void ospf_schedule_lsa_flush_area(struct ospf_area *area, struct ospf_lsa *lsa);

extern void ospf_refresher_register_lsa(struct ospf *ospf, struct ospf_lsa *lsa);
extern void ospf_refresher_unregister_lsa(struct ospf *ospf, struct ospf_lsa *lsa);
extern void ospf_lsa_refresh_walker(struct event *event);

extern void ospf_lsa_maxage_delete(struct ospf *ospf, struct ospf_lsa *lsa);

extern void ospf_discard_from_db(struct ospf *ospf, struct ospf_lsdb *lsdb, struct ospf_lsa *lsa);

extern int metric_type(struct ospf *ospf, uint8_t src, unsigned short instance);
extern int metric_value(struct ospf *ospf, uint8_t src, unsigned short instance);

extern char link_info_set(struct stream **s, struct in_addr id,
			  struct in_addr data, uint8_t type, uint8_t tos,
			  uint16_t cost);

extern struct in_addr ospf_get_nssa_ip(struct ospf_area *area);
extern struct ospf_lsa *ospf_translated_nssa_refresh(struct ospf *ospf,
						     struct ospf_lsa *type7,
						     struct ospf_lsa *type5);
extern struct ospf_lsa *ospf_translated_nssa_originate(struct ospf *ospf,
						       struct ospf_lsa *type7,
						       struct ospf_lsa *type5);
extern void ospf_check_and_gen_init_seq_lsa(struct ospf_interface *oi,
					    struct ospf_lsa *lsa);
extern void ospf_flush_lsa_from_area(struct ospf *ospf, struct in_addr area_id,
				     int type);
extern void ospf_maxage_lsa_remover(struct event *event);
extern bool ospf_check_dna_lsa(const struct ospf_lsa *lsa);
extern void ospf_refresh_area_self_lsas(struct ospf_area *area);

/** @brief Check if the LSA is an indication LSA.
 *  @param lsa pointer.
 *  @return true or false based on lsa info.
 */
static inline bool ospf_check_indication_lsa(struct ospf_lsa *lsa)
{
	struct summary_lsa *sl = NULL;

	if (lsa->data->type == OSPF_ASBR_SUMMARY_LSA) {
		sl = (struct summary_lsa *)lsa->data;
		if ((GET_METRIC(sl->metric) == OSPF_LS_INFINITY) &&
		    !CHECK_FLAG(lsa->data->options, OSPF_OPTION_DC))
			return true;
	}

	return false;
}
#endif /* _ZEBRA_OSPF_LSA_H */
