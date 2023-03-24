// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
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
void path_zebra_init(struct event_loop *master);
void path_zebra_stop(void);

#endif /* _FRR_PATH_MPLS_H_ */
