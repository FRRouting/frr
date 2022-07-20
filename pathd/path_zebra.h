/*
 * Copyright (C) 2020  NetDEF, Inc.
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

#ifndef _FRR_PATH_MPLS_H_
#define _FRR_PATH_MPLS_H_

#include <zebra.h>
#include "pathd/pathd.h"

bool get_ipv4_router_id(struct in_addr *router_id);
bool get_ipv6_router_id(struct in6_addr *router_id);
void path_zebra_add_sr_policy(struct srte_policy *policy,
			      struct srte_segment_list *segment_list);
void path_zebra_delete_sr_policy(struct srte_policy *policy);
int path_zebra_request_label(mpls_label_t label);
void path_zebra_release_label(mpls_label_t label);
void path_zebra_init(struct thread_master *master);
void path_zebra_stop(void);

#endif /* _FRR_PATH_MPLS_H_ */
