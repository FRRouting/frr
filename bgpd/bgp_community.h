/* Community attribute related functions.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_COMMUNITY_H
#define _QUAGGA_BGP_COMMUNITY_H

#include "lib/json.h"
#include "bgpd/bgp_route.h"

/* Communities attribute.  */
struct community {
	/* Reference count of communities value.  */
	unsigned long refcnt;

	/* Communities value size.  */
	int size;

	/* Communities value.  */
	uint32_t *val;

	/* Communities as a json object */
	json_object *json;

	/* String of community attribute.  This sring is used by vty output
	   and expanded community-list for regular expression match.  */
	char *str;
};

/* Well-known communities value.  */
#define COMMUNITY_INTERNET                      0x0
#define COMMUNITY_GSHUT                         0xFFFF0000
#define COMMUNITY_ACCEPT_OWN                    0xFFFF0001
#define COMMUNITY_ROUTE_FILTER_TRANSLATED_v4    0xFFFF0002
#define COMMUNITY_ROUTE_FILTER_v4               0xFFFF0003
#define COMMUNITY_ROUTE_FILTER_TRANSLATED_v6    0xFFFF0004
#define COMMUNITY_ROUTE_FILTER_v6               0xFFFF0005
#define COMMUNITY_LLGR_STALE                    0xFFFF0006
#define COMMUNITY_NO_LLGR                       0xFFFF0007
#define COMMUNITY_ACCEPT_OWN_NEXTHOP            0xFFFF0008
#define COMMUNITY_BLACKHOLE                     0xFFFF029A
#define COMMUNITY_NO_EXPORT                     0xFFFFFF01
#define COMMUNITY_NO_ADVERTISE                  0xFFFFFF02
#define COMMUNITY_NO_EXPORT_SUBCONFED           0xFFFFFF03
#define COMMUNITY_LOCAL_AS                      0xFFFFFF03
#define COMMUNITY_NO_PEER                       0xFFFFFF04

/* Macros of community attribute.  */
#define com_length(X)    ((X)->size * 4)
#define com_lastval(X)   ((X)->val + (X)->size - 1)
#define com_nthval(X,n)  ((X)->val + (n))

/* Prototypes of communities attribute functions.  */
extern void community_init(void);
extern void community_finish(void);
extern void community_free(struct community **comm);
extern struct community *community_uniq_sort(struct community *);
extern struct community *community_parse(uint32_t *, unsigned short);
extern struct community *community_intern(struct community *);
extern void community_unintern(struct community **);
extern char *community_str(struct community *, bool make_json);
extern unsigned int community_hash_make(const struct community *);
extern struct community *community_str2com(const char *);
extern int community_match(const struct community *, const struct community *);
extern bool community_cmp(const struct community *c1,
			  const struct community *c2);
extern struct community *community_merge(struct community *,
					 struct community *);
extern struct community *community_delete(struct community *,
					  struct community *);
extern struct community *community_dup(struct community *);
extern int community_include(struct community *, uint32_t);
extern void community_del_val(struct community *, uint32_t *);
extern unsigned long community_count(void);
extern struct hash *community_hash(void);
extern uint32_t community_val_get(struct community *com, int i);
extern void bgp_compute_aggregate_community(struct bgp_aggregate *aggregate,
					    struct community *community);

extern void bgp_compute_aggregate_community_val(
					       struct bgp_aggregate *aggregate);
extern void bgp_compute_aggregate_community_hash(
						struct bgp_aggregate *aggregate,
						struct community *community);
extern void bgp_remove_community_from_aggregate(struct bgp_aggregate *aggregate,
						struct community *community);
extern void bgp_remove_comm_from_aggregate_hash(struct bgp_aggregate *aggregate,
						struct community *community);
extern void bgp_aggr_community_remove(void *arg);

#endif /* _QUAGGA_BGP_COMMUNITY_H */
