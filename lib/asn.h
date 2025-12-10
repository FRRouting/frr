// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AS number structure
 * Copyright 2022 6WIND
 */

#ifndef _FRR_ASN_H
#define _FRR_ASN_H

#include "zebra.h"
#include "command_match.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASN_STRING_MAX_SIZE	12

enum asnotation_mode {
	ASNOTATION_PLAIN = 0,
	ASNOTATION_DOT,
	ASNOTATION_DOTPLUS,
	ASNOTATION_UNDEFINED,
};

typedef uint32_t as_t;

extern bool asn_str2asn(const char *asstring, as_t *asn);
extern const char *asn_asn2asplain(as_t asn);
extern const char *asn_str2asn_parse(const char *asstring, as_t *asn,
				     bool *found_ptr);
extern enum match_type asn_str2asn_match(const char *str);
extern bool asn_str2asn_notation(const char *asstring, as_t *asn,
				 enum asnotation_mode *asnotation);
extern const char *asn_mode2str(enum asnotation_mode asnotation);

struct json_object;
void asn_asn2json_array(struct json_object *jseg_list, as_t asn,
			enum asnotation_mode asnotation);
void asn_asn2json(struct json_object *jseg_list, const char *attr, as_t asn,
		  enum asnotation_mode asnotation);
extern char *asn_asn2string(const as_t *as, char *buf, size_t len,
			    enum asnotation_mode asnotation);
/* display AS in appropriate format */
#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pASP"  (as_t *)
#pragma FRR printfrr_ext "%pASD"  (as_t *)
#pragma FRR printfrr_ext "%pASE"  (as_t *)
#endif

#define ASN_FORMAT(mode)  \
	((mode == ASNOTATION_DOT) ? "%pASD" :	    \
	 ((mode == ASNOTATION_DOTPLUS) ? "%pASE" :	\
	  "%pASP"))
#define ASN_FORMAT_SPACE(mode)                                                 \
	((mode == ASNOTATION_DOT)                                              \
		 ? "%11pASD"                                                   \
		 : ((mode == ASNOTATION_DOTPLUS) ? "%11pASE" : "%11pASP"))

/* for test */
extern void asn_relax_as_zero(bool relax);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ASN_H */
