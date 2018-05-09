/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#ifndef _FRR_RIP_CLI_H_
#define _FRR_RIP_CLI_H_

extern void cli_show_router_rip(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
extern void cli_show_rip_allow_ecmp(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
extern void cli_show_rip_default_information_originate(struct vty *vty,
						       struct lyd_node *dnode,
						       bool show_defaults);
extern void cli_show_rip_default_metric(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
extern void cli_show_rip_distance(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
extern void cli_show_rip_distance_source(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
extern void cli_show_rip_neighbor(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
extern void cli_show_rip_network_prefix(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
extern void cli_show_rip_network_interface(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults);
extern void cli_show_rip_offset_list(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
extern void cli_show_rip_passive_default(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
extern void cli_show_rip_passive_interface(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults);
extern void cli_show_rip_non_passive_interface(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults);

#endif /* _FRR_RIP_CLI_H_ */
