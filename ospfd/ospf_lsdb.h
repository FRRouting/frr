// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF LSDB support.
 * Copyright (C) 1999, 2000 Alex Zinin, Kunihiro Ishiguro, Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_LSDB_H
#define _ZEBRA_OSPF_LSDB_H

#include "prefix.h"
#include "table.h"

/* OSPF LSDB structure. */
struct ospf_lsdb {
	struct {
		unsigned long count;
		unsigned long count_self;
		unsigned int checksum;
		struct route_table *db;
	} type[OSPF_MAX_LSA];
	unsigned long total;
#define MONITOR_LSDB_CHANGE 1 /* XXX */
#ifdef MONITOR_LSDB_CHANGE
	/* Hooks for callback functions to catch every add/del event. */
	int (*new_lsa_hook)(struct ospf_lsa *);
	int (*del_lsa_hook)(struct ospf_lsa *);
#endif /* MONITOR_LSDB_CHANGE */
};

/* Macros. */
#define LSDB_LOOP(T, N, L)                                                     \
	if ((T) != NULL)                                                       \
		for ((N) = route_top((T)); ((N)); ((N)) = route_next((N)))     \
			if (((L) = (N)->info))

#define ROUTER_LSDB(A)       ((A)->lsdb->type[OSPF_ROUTER_LSA].db)
#define NETWORK_LSDB(A)	     ((A)->lsdb->type[OSPF_NETWORK_LSA].db)
#define SUMMARY_LSDB(A)      ((A)->lsdb->type[OSPF_SUMMARY_LSA].db)
#define ASBR_SUMMARY_LSDB(A) ((A)->lsdb->type[OSPF_ASBR_SUMMARY_LSA].db)
#define EXTERNAL_LSDB(O)     ((O)->lsdb->type[OSPF_AS_EXTERNAL_LSA].db)
#define NSSA_LSDB(A)         ((A)->lsdb->type[OSPF_AS_NSSA_LSA].db)
#define OPAQUE_LINK_LSDB(A)  ((A)->lsdb->type[OSPF_OPAQUE_LINK_LSA].db)
#define OPAQUE_AREA_LSDB(A)  ((A)->lsdb->type[OSPF_OPAQUE_AREA_LSA].db)
#define OPAQUE_AS_LSDB(O)    ((O)->lsdb->type[OSPF_OPAQUE_AS_LSA].db)

#define AREA_LSDB(A,T)       ((A)->lsdb->type[(T)].db)
#define AS_LSDB(O,T)         ((O)->lsdb->type[(T)].db)

/*
 * Alternate route node structure for LSDB nodes linked to
 * list elements.
 */
struct ospf_lsdb_linked_node {
	/*
	 * Caution these must be the very first fields
	 */
	ROUTE_NODE_FIELDS

	/*
	 * List entry on an LSA list, e.g., a neighbor
	 * retransmission list.
	 */
	struct ospf_lsa_list_entry *lsa_list_entry;
};

/* OSPF LSDB related functions. */
extern struct ospf_lsdb *ospf_lsdb_new(void);
extern void ospf_lsdb_init(struct ospf_lsdb *);
extern void ospf_lsdb_linked_init(struct ospf_lsdb *lsdb);
extern struct ospf_lsdb_linked_node *
ospf_lsdb_linked_lookup(struct ospf_lsdb *lsdb, struct ospf_lsa *lsa);
extern void ospf_lsdb_free(struct ospf_lsdb *);
extern void ospf_lsdb_cleanup(struct ospf_lsdb *);
extern void ls_prefix_set(struct prefix_ls *lp, struct ospf_lsa *lsa);
extern void ospf_lsdb_add(struct ospf_lsdb *, struct ospf_lsa *);
extern void ospf_lsdb_delete(struct ospf_lsdb *, struct ospf_lsa *);
extern void ospf_lsdb_delete_all(struct ospf_lsdb *);
extern struct ospf_lsa *ospf_lsdb_lookup(struct ospf_lsdb *, struct ospf_lsa *);
extern struct ospf_lsa *ospf_lsdb_lookup_by_id(struct ospf_lsdb *, uint8_t,
					       struct in_addr, struct in_addr);
extern struct ospf_lsa *ospf_lsdb_lookup_by_id_next(struct ospf_lsdb *, uint8_t,
						    struct in_addr,
						    struct in_addr, int);
extern unsigned long ospf_lsdb_count_all(struct ospf_lsdb *);
extern unsigned long ospf_lsdb_count(struct ospf_lsdb *, int);
extern unsigned long ospf_lsdb_count_self(struct ospf_lsdb *, int);
extern unsigned int ospf_lsdb_checksum(struct ospf_lsdb *, int);
extern unsigned long ospf_lsdb_isempty(struct ospf_lsdb *);

#endif /* _ZEBRA_OSPF_LSDB_H */
