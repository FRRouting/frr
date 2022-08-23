/*
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_PATH_TRIGGERED_H_
#define _FRR_PATH_TRIGGERED_H_

#include "lib/ipaddr.h"
#include "lib/srte.h"

void srte_triggered_update(void);
enum srte_protocol_origin srte_triggered_get_protocol_origin(void);

void srte_triggered_add(uint32_t color, struct ipaddr *endpoint);
void srte_triggered_del(uint32_t color, struct ipaddr *endpoint);

struct srte_triggered_policy {
	RB_ENTRY(srte_triggered_policy) entry;

	/* Color */
	uint32_t color;

	/* Endpoint */
	struct ipaddr endpoint;
};

RB_HEAD(srte_triggered_policy_head, srte_triggered_policy);
RB_PROTOTYPE(srte_triggered_policy_head, srte_triggered_policy, entry,
	     srte_triggered_policy_compare)

void srte_triggered_clean_zebra(void);
void srte_triggered_removing(struct srte_triggered_policy *bgp_policy);
void srte_bgp_policy_candidate_removing(
	struct srte_triggered_policy *bgp_policy, uint32_t preference);
void srte_triggered_update_candidate_removing(uint32_t color,
					      uint32_t preference);
void srte_triggered_update_candidate_changed(uint32_t color);
void srte_triggered_del(uint32_t color, struct ipaddr *endpoint);
void srte_triggered_add(uint32_t color, struct ipaddr *endpoint);
void srte_triggered_init(void);

#endif
