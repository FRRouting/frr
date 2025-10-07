// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Sanitizer related code
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#include "sanitizer.h"


/* Suppress known FRRouting memory leaks in leak sanitizer output */
#if defined(FRR_HAVE_LEAK_SANITIZER) && !defined(FRR_NO_KNOWN_MEMLEAK)
const char *__lsan_default_suppressions(void)
{
	/* clang-format off */

	/*
	 * List of known memory leaks to suppress. Please keep in alphabetical
	 * order.
	 */
	return
		"leak:list_new\n"
		"leak:listnode_new\n"
		"leak:ospf_path_new\n"
		"leak:ospf_route_new\n"
		"leak:ospf_spf_vertex_copy\n"
		"leak:ospf_spf_vertex_parent_copy\n"
		"leak:prefix_copy\n"
		"leak:route_node_create\n"
		"leak:route_table_init_with_delegate\n"
		"leak:vertex_nexthop_new\n"
		"leak:vertex_parent_new\n"
		"";

	/* clang-format on */
}
#endif


/* EOF */
