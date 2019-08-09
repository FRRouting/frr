/* BGP Large Communities Attribute.
 *
 * Copyright (C) 2016 Keyur Patel <keyur@arrcus.com>
 *
 * This file is part of FreeRangeRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_LCOMMUNITY_H
#define _QUAGGA_BGP_LCOMMUNITY_H

#include "lib/json.h"
#include "bgpd/bgp_route.h"

/* Large Communities value is twelve octets long.  */
#define LCOMMUNITY_SIZE                        12

/* Large Communities attribute.  */
struct lcommunity {
	/* Reference counter.  */
	unsigned long refcnt;

	/* Size of Extended Communities attribute.  */
	int size;

	/* Large Communities value.  */
	uint8_t *val;

	/* Large Communities as a json object */
	json_object *json;

	/* Human readable format string.  */
	char *str;
};

/* Large community value is 12 octets.  */
struct lcommunity_val {
	char val[LCOMMUNITY_SIZE];
};

#define lcom_length(X)    ((X)->size * LCOMMUNITY_SIZE)

extern void lcommunity_init(void);
extern void lcommunity_finish(void);
extern void lcommunity_free(struct lcommunity **);
extern struct lcommunity *lcommunity_parse(uint8_t *, unsigned short);
extern struct lcommunity *lcommunity_dup(struct lcommunity *);
extern struct lcommunity *lcommunity_merge(struct lcommunity *,
					   struct lcommunity *);
extern struct lcommunity *lcommunity_uniq_sort(struct lcommunity *);
extern struct lcommunity *lcommunity_intern(struct lcommunity *);
extern bool lcommunity_cmp(const void *arg1, const void *arg2);
extern void lcommunity_unintern(struct lcommunity **);
extern unsigned int lcommunity_hash_make(const void *);
extern struct hash *lcommunity_hash(void);
extern struct lcommunity *lcommunity_str2com(const char *);
extern int lcommunity_match(const struct lcommunity *,
			    const struct lcommunity *);
extern char *lcommunity_str(struct lcommunity *, bool make_json);
extern int lcommunity_include(struct lcommunity *lcom, uint8_t *ptr);
extern void lcommunity_del_val(struct lcommunity *lcom, uint8_t *ptr);

extern void bgp_compute_aggregate_lcommunity(
					struct bgp_aggregate *aggregate,
					struct lcommunity *lcommunity);

extern void bgp_compute_aggregate_lcommunity_hash(
					struct bgp_aggregate *aggregate,
					struct lcommunity *lcommunity);
extern void bgp_compute_aggregate_lcommunity_val(
					struct bgp_aggregate *aggregate);

extern void bgp_remove_lcommunity_from_aggregate(
					struct bgp_aggregate *aggregate,
					struct lcommunity *lcommunity);
extern void bgp_remove_lcomm_from_aggregate_hash(
					struct bgp_aggregate *aggregate,
					struct lcommunity *lcommunity);
extern void bgp_aggr_lcommunity_remove(void *arg);

#endif /* _QUAGGA_BGP_LCOMMUNITY_H */
