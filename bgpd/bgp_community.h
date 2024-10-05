// SPDX-License-Identifier: GPL-2.0-or-later
/* Community attribute related functions.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_COMMUNITY_H
#define _QUAGGA_BGP_COMMUNITY_H

#include "lib/json.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"

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

#define COMMUNITY_SIZE 4

/* Macros of community attribute.  */
#define com_length(X)    ((X)->size * COMMUNITY_SIZE)
#define com_lastval(X)   ((X)->val + (X)->size - 1)
#define com_nthval(X,n)  ((X)->val + (n))

/* Prototypes of communities attribute functions.  */
extern void community_init(void);
extern void community_finish(void);
extern void community_free(struct community **comm);
extern struct community *community_uniq_sort(struct community *com);
extern struct community *community_parse(uint32_t *pnt, unsigned short length);
extern struct community *community_intern(struct community *com);
extern void community_unintern(struct community **com);
extern char *community_str(struct community *com, bool make_json,
			   bool translate_alias);
extern unsigned int community_hash_make(const struct community *com);
extern struct community *community_str2com(const char *str);
extern bool community_match(const struct community *com1,
			    const struct community *com2);
extern bool community_cmp(const struct community *c1,
			  const struct community *c2);
extern struct community *community_merge(struct community *com1,
					 struct community *com2);
extern struct community *community_delete(struct community *com1,
					  struct community *com2);
extern struct community *community_dup(struct community *com);
extern bool community_include(struct community *com, uint32_t val);
extern void community_add_val(struct community *com, uint32_t val);
extern void community_del_val(struct community *com, uint32_t *val);
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

/* This implies that when propagating routes into a VRF, the ACCEPT_OWN
 * community SHOULD NOT be propagated.
 */
static inline void community_strip_accept_own(struct attr *attr)
{
	struct community *old_com = bgp_attr_get_community(attr);
	struct community *new_com = NULL;
	uint32_t val = COMMUNITY_ACCEPT_OWN;

	if (old_com && community_include(old_com, val)) {
		new_com = community_dup(old_com);
		val = htonl(val);
		community_del_val(new_com, &val);

		if (!old_com->refcnt)
			community_free(&old_com);

		if (!new_com->size) {
			community_free(&new_com);
			bgp_attr_set_community(attr, NULL);
		} else {
			bgp_attr_set_community(attr, new_com);
		}
	}
}

#endif /* _QUAGGA_BGP_COMMUNITY_H */
