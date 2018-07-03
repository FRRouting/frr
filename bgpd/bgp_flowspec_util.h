/* BGP Flowspec header for utilities
 * Copyright (C) 2018 6WIND
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
				   void *result, int *error);

extern int bgp_flowspec_bitmask_decode(enum bgp_flowspec_util_nlri_t type,
					uint8_t *nlri_ptr,
					uint32_t max_len,
					void *result, int *error);

struct bgp_pbr_entry_main;
extern int bgp_flowspec_match_rules_fill(uint8_t *nlri_content, int len,
					 struct bgp_pbr_entry_main *bpem);

extern struct bgp_node *bgp_flowspec_get_match_per_ip(afi_t afi,
						      struct bgp_table *rib,
						      struct prefix *match,
						      int prefix_check);
#endif /* _FRR_BGP_FLOWSPEC_UTIL_H */
