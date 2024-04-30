// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Flowspec header for utilities
 * Copyright (C) 2018 6WIND
 */

#ifndef _FRR_BGP_FLOWSPEC_UTIL_H
#define _FRR_BGP_FLOWSPEC_UTIL_H

#include "zclient.h"

#define BGP_FLOWSPEC_STRING_DISPLAY_MAX 512

enum bgp_flowspec_util_nlri_t {
	BGP_FLOWSPEC_VALIDATE_ONLY = 0,
	BGP_FLOWSPEC_RETURN_STRING = 1,
	BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE = 2,
	BGP_FLOWSPEC_RETURN_JSON = 3,
};


extern int bgp_flowspec_op_decode(enum bgp_flowspec_util_nlri_t type,
				  uint8_t *nlri_ptr,
				  uint32_t max_len,
				  void *result, int *error);

extern int bgp_flowspec_ip_address(enum bgp_flowspec_util_nlri_t type,
				   uint8_t *nlri_ptr,
				   uint32_t max_len,
				   void *result, int *error,
				   afi_t afi, uint8_t *ipv6_offset);

extern int bgp_flowspec_bitmask_decode(enum bgp_flowspec_util_nlri_t type,
					uint8_t *nlri_ptr,
					uint32_t max_len,
					void *result, int *error);

struct bgp_pbr_entry_main;
extern int bgp_flowspec_match_rules_fill(uint8_t *nlri_content, int len,
					 struct bgp_pbr_entry_main *bpem,
					 afi_t afi);

extern bool bgp_flowspec_contains_prefix(const struct prefix *pfs,
					 struct prefix *input,
					 int prefix_check);

extern bool bgp_flowspec_get_first_nh(struct bgp *bgp, struct bgp_path_info *pi,
				      struct prefix *nh, afi_t afi);

#endif /* _FRR_BGP_FLOWSPEC_UTIL_H */
