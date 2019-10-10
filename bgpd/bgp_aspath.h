/* AS path related definitions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_ASPATH_H
#define _QUAGGA_BGP_ASPATH_H

#include "lib/json.h"
#include "bgpd/bgp_route.h"

/* AS path segment type.  */
#define AS_SET                       1
#define AS_SEQUENCE                  2
#define AS_CONFED_SEQUENCE           3
#define AS_CONFED_SET                4

/* Private AS range defined in RFC2270.  */
#define BGP_PRIVATE_AS_MIN       64512U
#define BGP_PRIVATE_AS_MAX       65535U

/* Private 4 byte AS range defined in RFC6996.  */
#define BGP_PRIVATE_AS4_MIN     4200000000U
#define BGP_PRIVATE_AS4_MAX     4294967294U

/* we leave BGP_AS_MAX as the 16bit AS MAX number.  */
#define BGP_AS_MAX		     65535U
#define BGP_AS4_MAX		4294967295U
/* Transition 16Bit AS as defined by IANA */
#define BGP_AS_TRANS		 23456U

#define BGP_AS_IS_PRIVATE(ASN)                                                 \
	(((ASN) >= BGP_PRIVATE_AS_MIN && (ASN) <= BGP_PRIVATE_AS_MAX)          \
	 || ((ASN) >= BGP_PRIVATE_AS4_MIN && (ASN) <= BGP_PRIVATE_AS4_MAX))

/* AS_PATH segment data in abstracted form, no limit is placed on length */
struct assegment {
	struct assegment *next;
	as_t *as;
	unsigned short length;
	uint8_t type;
};

/* AS path may be include some AsSegments.  */
struct aspath {
	/* Reference count to this aspath.  */
	unsigned long refcnt;

	/* segment data */
	struct assegment *segments;

	/* AS path as a json object */
	json_object *json;

	/* String expression of AS path.  This string is used by vty output
	   and AS path regular expression match.  */
	char *str;
	unsigned short str_len;
};

#define ASPATH_STR_DEFAULT_LEN 32

/* Prototypes. */
extern void aspath_init(void);
extern void aspath_finish(void);
extern struct aspath *aspath_parse(struct stream *, size_t, int);
extern struct aspath *aspath_dup(struct aspath *);
extern struct aspath *aspath_aggregate(struct aspath *, struct aspath *);
extern struct aspath *aspath_prepend(struct aspath *, struct aspath *);
extern struct aspath *aspath_filter_exclude(struct aspath *, struct aspath *);
extern struct aspath *aspath_add_seq_n(struct aspath *, as_t, unsigned);
extern struct aspath *aspath_add_seq(struct aspath *, as_t);
extern struct aspath *aspath_add_confed_seq(struct aspath *, as_t);
extern bool aspath_cmp(const void *as1, const void *as2);
extern int aspath_cmp_left(const struct aspath *, const struct aspath *);
extern bool aspath_cmp_left_confed(const struct aspath *as1,
				   const struct aspath *as2xs);
extern struct aspath *aspath_delete_confed_seq(struct aspath *);
extern struct aspath *aspath_empty(void);
extern struct aspath *aspath_empty_get(void);
extern struct aspath *aspath_str2aspath(const char *);
extern void aspath_str_update(struct aspath *as, bool make_json);
extern void aspath_free(struct aspath *);
extern struct aspath *aspath_intern(struct aspath *);
extern void aspath_unintern(struct aspath **);
extern const char *aspath_print(struct aspath *);
extern void aspath_print_vty(struct vty *, const char *, struct aspath *,
			     const char *);
extern void aspath_print_all_vty(struct vty *);
extern unsigned int aspath_key_make(const void *);
extern unsigned int aspath_get_first_as(struct aspath *);
extern unsigned int aspath_get_last_as(struct aspath *);
extern int aspath_loop_check(struct aspath *, as_t);
extern int aspath_private_as_check(struct aspath *);
extern int aspath_single_asn_check(struct aspath *, as_t asn);
extern struct aspath *aspath_replace_specific_asn(struct aspath *aspath,
						  as_t target_asn,
						  as_t our_asn);
extern struct aspath *aspath_replace_private_asns(struct aspath *aspath,
						  as_t asn, as_t peer_asn);
extern struct aspath *aspath_remove_private_asns(struct aspath *aspath,
						 as_t peer_asn);
extern int aspath_firstas_check(struct aspath *, as_t);
extern int aspath_confed_check(struct aspath *);
extern int aspath_left_confed_check(struct aspath *);
extern unsigned long aspath_count(void);
extern unsigned int aspath_count_hops(const struct aspath *);
extern unsigned int aspath_count_confeds(struct aspath *);
extern unsigned int aspath_size(struct aspath *);
extern as_t aspath_highest(struct aspath *);
extern as_t aspath_leftmost(struct aspath *);
extern size_t aspath_put(struct stream *, struct aspath *, int);

extern struct aspath *aspath_reconcile_as4(struct aspath *, struct aspath *);
extern unsigned int aspath_has_as4(struct aspath *);

/* For SNMP BGP4PATHATTRASPATHSEGMENT, might be useful for debug */
extern uint8_t *aspath_snmp_pathseg(struct aspath *, size_t *);

extern void bgp_compute_aggregate_aspath(struct bgp_aggregate *aggregate,
					 struct aspath *aspath);
extern void bgp_remove_aspath_from_aggregate(struct bgp_aggregate *aggregate,
					     struct aspath *aspath);
extern void bgp_aggr_aspath_remove(void *arg);

#endif /* _QUAGGA_BGP_ASPATH_H */
