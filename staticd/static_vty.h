// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vty header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_VTY_H__
#define __STATIC_VTY_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INCLUDE_MGMTD_CMDDEFS_ONLY
void static_mgmt_init(struct thread_master *master);
void static_mgmt_destroy(void);
#endif /* ifndef INCLUDE_MGMTD_CMDDEFS_ONLY */

void static_cli_show(struct vty *vty, const struct lyd_node *dnode,
		     bool show_defaults);
void static_cli_show_end(struct vty *vty, const struct lyd_node *dnode);
void static_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
void static_src_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
int static_nexthop_cli_cmp(const struct lyd_node *dnode1,
			   const struct lyd_node *dnode2);
int static_route_list_cli_cmp(const struct lyd_node *dnode1,
			      const struct lyd_node *dnode2);
int static_src_list_cli_cmp(const struct lyd_node *dnode1,
			    const struct lyd_node *dnode2);
int static_path_list_cli_cmp(const struct lyd_node *dnode1,
			     const struct lyd_node *dnode2);

void static_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
