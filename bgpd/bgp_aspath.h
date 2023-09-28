// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path related definitions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_ASPATH_H
#define _QUAGGA_BGP_ASPATH_H

#include "lib/json.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_filter.h"

/* AS path segment type.  */
#define AS_SET                       1
#define AS_SEQUENCE                  2
#define AS_CONFED_SEQUENCE           3
#define AS_CONFED_SET                4

/* Private AS range defined in RFC2270.  */
#define BGP_PRIVATE_AS_MIN       64512U
#define BGP_PRIVATE_AS_MAX UINT16_MAX

/* Private 4 byte AS range defined in RFC6996.  */
#define BGP_PRIVATE_AS4_MIN     4200000000U
#define BGP_PRIVATE_AS4_MAX     4294967294U

/* we leave BGP_AS_MAX as the 16bit AS MAX number.  */
#define BGP_AS_ZERO		          0
#define BGP_AS_MAX UINT16_MAX
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

	/* AS notation used by string expression of AS path */
	enum asnotation_mode asnotation;
};

#define ASPATH_STR_DEFAULT_LEN 32

/* Prototypes. */
extern void aspath_init(void);
extern void aspath_finish(void);
extern struct aspath *aspath_parse(struct stream *s, size_t length,
				   int use32bit,
				   enum asnotation_mode asnotation);

extern struct aspath *aspath_dup(struct aspath *aspath);
extern struct aspath *aspath_aggregate(struct aspath *as1, struct aspath *as2);
extern struct aspath *aspath_prepend(struct aspath *as1, struct aspath *as2);
extern struct aspath *aspath_filter_exclude(struct aspath *source,
					    struct aspath *exclude_list);
extern struct aspath *aspath_filter_exclude_all(struct aspath *source);
extern struct aspath *aspath_filter_exclude_acl(struct aspath *source,
						struct as_list *acl_list);
extern struct aspath *aspath_add_seq_n(struct aspath *aspath, as_t asno,
				       unsigned num);
extern struct aspath *aspath_add_seq(struct aspath *aspath, as_t asno);
extern struct aspath *aspath_add_confed_seq(struct aspath *aspath, as_t asno);
extern bool aspath_cmp(const void *as1, const void *as2);
extern bool aspath_cmp_left(const struct aspath *aspath1,
			    const struct aspath *aspath2);
extern bool aspath_cmp_left_confed(const struct aspath *as1,
				   const struct aspath *as2);
extern struct aspath *aspath_delete_confed_seq(struct aspath *aspath);
extern struct aspath *aspath_empty(enum asnotation_mode asnotation);
extern struct aspath *aspath_empty_get(void);
extern struct aspath *aspath_str2aspath(const char *str,
					enum asnotation_mode asnotation);
extern void aspath_str_update(struct aspath *as, bool make_json);
extern void aspath_free(struct aspath *aspath);
extern struct aspath *aspath_intern(struct aspath *aspath);
extern void aspath_unintern(struct aspath **aspath);
extern const char *aspath_print(struct aspath *aspath);
extern void aspath_print_vty(struct vty *vty, struct aspath *aspath);
extern void aspath_print_all_vty(struct vty *vty);
extern unsigned int aspath_key_make(const void *p);
extern unsigned int aspath_get_first_as(struct aspath *aspath);
extern unsigned int aspath_get_last_as(struct aspath *aspath);
extern int aspath_loop_check(struct aspath *aspath, as_t asno);
extern int aspath_loop_check_confed(struct aspath *aspath, as_t asno);
extern bool aspath_private_as_check(struct aspath *aspath);
extern struct aspath *aspath_replace_regex_asn(struct aspath *aspath,
					       struct as_list *acl_list,
					       as_t our_asn);
extern struct aspath *aspath_replace_specific_asn(struct aspath *aspath,
						  as_t target_asn,
						  as_t our_asn);
extern struct aspath *aspath_replace_all_asn(struct aspath *aspath,
					     as_t our_asn);
extern struct aspath *aspath_replace_private_asns(struct aspath *aspath,
						  as_t asn, as_t peer_asn);
extern struct aspath *aspath_remove_private_asns(struct aspath *aspath,
						 as_t peer_asn);
extern bool aspath_firstas_check(struct aspath *aspath, as_t asno);
extern bool aspath_confed_check(struct aspath *aspath);
extern bool aspath_left_confed_check(struct aspath *aspath);
extern unsigned long aspath_count(void);
extern unsigned int aspath_count_hops(const struct aspath *aspath);
extern bool aspath_check_as_sets(struct aspath *aspath);
extern bool aspath_check_as_zero(struct aspath *aspath);
extern unsigned int aspath_count_confeds(struct aspath *aspath);
extern unsigned int aspath_size(struct aspath *aspath);
extern as_t aspath_highest(struct aspath *aspath);
extern as_t aspath_leftmost(struct aspath *aspath);
extern size_t aspath_put(struct stream *s, struct aspath *aspath, int use32bit);

extern struct aspath *aspath_reconcile_as4(struct aspath *aspath,
					   struct aspath *as4path);
extern bool aspath_has_as4(struct aspath *aspath);

/* For SNMP BGP4PATHATTRASPATHSEGMENT, might be useful for debug */
extern uint8_t *aspath_snmp_pathseg(struct aspath *aspath, size_t *varlen);

extern void bgp_compute_aggregate_aspath(struct bgp_aggregate *aggregate,
					 struct aspath *aspath);

extern void bgp_compute_aggregate_aspath_hash(struct bgp_aggregate *aggregate,
					      struct aspath *aspath);
extern void bgp_compute_aggregate_aspath_val(struct bgp_aggregate *aggregate);
extern void bgp_remove_aspath_from_aggregate(struct bgp_aggregate *aggregate,
					     struct aspath *aspath);
extern void bgp_remove_aspath_from_aggregate_hash(
						struct bgp_aggregate *aggregate,
						struct aspath *aspath);

extern void bgp_aggr_aspath_remove(void *arg);

#endif /* _QUAGGA_BGP_ASPATH_H */
