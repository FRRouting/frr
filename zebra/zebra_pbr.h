/*
 * Zebra Policy Based Routing (PBR) Data structures and definitions
 * These are public definitions referenced by multiple files.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_PBR_H
#define _ZEBRA_PBR_H

#include <zebra.h>

#include "prefix.h"
#include "if.h"
#include "rt.h"

/*
 * A PBR filter
 *
 * The filter or match criteria in a PBR rule.
 * For simplicity, all supported filters are grouped into a structure rather
 * than delineating further. A bitmask denotes which filters are actually
 * specified.
 */
struct zebra_pbr_filter {
	uint32_t filter_bm;
#define PBR_FILTER_SRC_IP     (1 << 0)
#define PBR_FILTER_DST_IP     (1 << 1)
#define PBR_FILTER_SRC_PORT   (1 << 2)
#define PBR_FILTER_DST_PORT   (1 << 3)

	/* Source and Destination IP address with masks. */
	struct prefix src_ip;
	struct prefix dst_ip;

	/* Source and Destination higher-layer (TCP/UDP) port numbers. */
	uint16_t src_port;
	uint16_t dst_port;
};

#define IS_RULE_FILTERING_ON_SRC_IP(r) \
	(r->filter.filter_bm & PBR_FILTER_SRC_IP)
#define IS_RULE_FILTERING_ON_DST_IP(r) \
	(r->filter.filter_bm & PBR_FILTER_DST_IP)
#define IS_RULE_FILTERING_ON_SRC_PORT(r) \
	(r->filter.filter_bm & PBR_FILTER_SRC_PORT)
#define IS_RULE_FILTERING_ON_DST_PORT(r) \
	(r->filter.filter_bm & PBR_FILTER_DST_PORT)

/*
 * A PBR action
 *
 * The action corresponding to a PBR rule.
 * While the user specifies the action in a particular way, the forwarding
 * plane implementation (Linux only) requires that to be encoded into a
 * route table and the rule then point to that route table; in some cases,
 * the user criteria may directly point to a table too.
 */
struct zebra_pbr_action {
	uint32_t table;
};

/*
 * A PBR rule
 *
 * This is a combination of the filter criteria and corresponding action.
 * Rules also have a user-defined sequence number which defines the relative
 * order amongst rules.
 */
struct zebra_pbr_rule {
	uint32_t seq;
	uint32_t priority;
	struct zebra_pbr_filter filter;
	struct zebra_pbr_action action;
};

void zebra_pbr_add_rule(struct zebra_pbr_rule *rule, struct interface *ifp);
void zebra_pbr_del_rule(struct zebra_pbr_rule *rule, struct interface *ifp);

/*
 * Install specified rule for a specific interface.
 * It is possible that the user-defined sequence number and the one in the
 * forwarding plane may not coincide, hence the API requires a separate
 * rule priority - maps to preference/FRA_PRIORITY on Linux.
 */
extern void kernel_add_pbr_rule(struct zebra_pbr_rule *rule,
				struct interface *ifp);

/*
 * Uninstall specified rule for a specific interface.
 */
extern void kernel_del_pbr_rule(struct zebra_pbr_rule *rule,
				struct interface *ifp);

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
extern void kernel_read_pbr_rules(struct zebra_ns *zns);

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
extern void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
					   struct interface *ifp,
					   enum southbound_results res);

/*
 * Handle rule delete notification from kernel.
 */
extern int kernel_pbr_rule_del(struct zebra_pbr_rule *rule,
			       struct interface *ifp);

#endif /* _ZEBRA_PBR_H */
