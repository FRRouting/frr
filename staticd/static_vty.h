/*
 * STATICd - vty header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#ifndef __STATIC_VTY_H__
#define __STATIC_VTY_H__

#ifdef __cplusplus
extern "C" {
#endif

void static_cli_show(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults);
void static_cli_show_end(struct vty *vty, struct lyd_node *dnode);
void static_nexthop_cli_show(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults);
void static_src_nexthop_cli_show(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);
int static_nexthop_cli_cmp(struct lyd_node *dnode1, struct lyd_node *dnode2);
int static_route_list_cli_cmp(struct lyd_node *dnode1, struct lyd_node *dnode2);
int static_src_list_cli_cmp(struct lyd_node *dnode1, struct lyd_node *dnode2);
int static_path_list_cli_cmp(struct lyd_node *dnode1, struct lyd_node *dnode2);

void static_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
