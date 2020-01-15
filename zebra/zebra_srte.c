/* Zebra SR-TE code
 * Copyright (C) 2020  NetDEF, Inc.
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

#include "zebra/zebra_srte.h"
#include "lib/zclient.h"
#include "zebra/zebra_memory.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR_POLICY, "SR Policy")

/* Generate rb-tree of SR Policy instances. */
static inline int
zebra_sr_policy_instance_compare(const struct zebra_sr_policy *a,
				 const struct zebra_sr_policy *b)
{
	bool color_is_equal = !(a->color - b->color);
	bool endpoint_is_equal = (a->endpoint.s_addr == b->endpoint.s_addr);

	if (color_is_equal && endpoint_is_equal)
		return 0;

	if (a->active_segment_list.local_label
	    && b->active_segment_list.local_label)
		return (a->active_segment_list.local_label
			- b->active_segment_list.local_label);

	return -1;
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

void zebra_sr_policy_set(struct zapi_sr_policy *zapi_sr_policy,
			 enum zebra_sr_policy_status status)
{
	struct zebra_sr_policy *zebra_sr_policy;
	struct zebra_sr_policy *removed_zebra_sr_policy;

	zebra_sr_policy =
		XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(struct zebra_sr_policy));
	zebra_sr_policy->color = zapi_sr_policy->color;
	memcpy(&zebra_sr_policy->endpoint, &zapi_sr_policy->endpoint,
	       sizeof(struct in_addr));
	strncpy((char *)&zebra_sr_policy->name, (char *)&zapi_sr_policy->name,
		ZEBRA_SR_POLICY_NAME_MAX_LENGTH);
	zebra_sr_policy->status = status;
	zebra_sr_policy->active_segment_list =
		zapi_sr_policy->active_segment_list;

	removed_zebra_sr_policy =
		RB_REMOVE(zebra_sr_policy_instance_head,
			  &zebra_sr_policy_instances, zebra_sr_policy);
	if (removed_zebra_sr_policy)
		XFREE(MTYPE_ZEBRA_SR_POLICY, removed_zebra_sr_policy);

	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  zebra_sr_policy);
}
