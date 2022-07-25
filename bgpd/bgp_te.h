/* BGP Endpoint End Point Tracking Database
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
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

#ifndef __BGP_TE_H
#define __BGP_TE_H

#include "lib/zapi_client.h"
#include "lib/mpls.h"
#include "lib/ipaddr.h"

struct bgp_te_entry {
	/* RB-tree entry. */
	RB_ENTRY(bgp_te_entry) entry;

	/* Color */
	uint32_t color;
	/* Endpoint */
	struct ipaddr endpoint;

	/* callback pointer */
	struct bgp_nexthop_cache *bnc;

	/* response */
	/* Name */
	char name[SRTE_POLICY_NAME_MAX_LENGTH];
	/* Binding SID */
	mpls_label_t binding_sid;
	/* segment list name */
	char segmentlistname[SRTE_SEGMENT_LIST_NAME_MAX_LENGTH];
};

extern int bgp_te_entry_compare(const struct bgp_te_entry *a,
				const struct bgp_te_entry *b);
RB_HEAD(bgp_te_entry_head, bgp_te_entry);
RB_PROTOTYPE(bgp_te_entry_head, bgp_te_entry, entry, bgp_te_entry_compare)

int bgp_te_process_tsrte_client_ready(struct stream *s);
int bgp_te_process_tsrte_bgp_update(struct stream *s);

struct bgp_te_entry *bgp_te_entry_find(uint32_t color, struct ipaddr *ipaddr);

void bgp_te_show_nexthops_detail(struct vty *vty, struct bgp *bgp,
				 struct bgp_nexthop_cache *bnc);

void bgp_te_init(void);

#endif
