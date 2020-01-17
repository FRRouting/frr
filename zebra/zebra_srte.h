/* Zebra's client header.
 * Copyright (C) 2020 Netdef, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#include "lib/zclient.h"

enum zebra_sr_policy_update_label_mode {
	ZEBRA_SR_POLICY_LABEL_CREATED = 1,
	ZEBRA_SR_POLICY_LABEL_REMOVED = 2,
};

enum zebra_sr_policy_status {
	ZEBRA_SR_POLICY_UP = 1,
	ZEBRA_SR_POLICY_DOWN = 2,
};

struct zebra_sr_policy {
	RB_ENTRY(zebra_sr_policy) entry;
	uint32_t color;
	struct in_addr endpoint;
	char name[ZEBRA_SR_POLICY_NAME_MAX_LENGTH];
	enum zebra_sr_policy_status status;
	struct zapi_srte_tunnel active_segment_list;
	struct zebra_vrf *zvrf;
};
RB_HEAD(zebra_sr_policy_instance_head, zebra_sr_policy);
RB_PROTOTYPE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	     zebra_sr_policy_instance_compare)

extern struct zebra_sr_policy_instance_head zebra_sr_policy_instances;

void zebra_sr_policy_set(struct zapi_sr_policy *zapi_sr_policy,
			 struct zebra_vrf *zvrf,
			 enum zebra_sr_policy_status status);

void zebra_sr_policy_delete(struct zapi_sr_policy *zapi_sr_policy);

void zebra_srte_init(void);
