/*
 * EIGRP CLI Functions.
 * Copyright (C) 2019
 * Authors:
 *   Donnie Savage
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _EIGRP_CLI_H_
#define _EIGRP_CLI_H_

/*Prototypes*/
extern void eigrp_cli_show_header(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
extern void eigrp_cli_show_end_header(struct vty *vty,
				      const struct lyd_node *dnode);
extern void eigrp_cli_show_router_id(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_passive_interface(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults);
extern void eigrp_cli_show_active_time(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
extern void eigrp_cli_show_variance(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_show_maximum_paths(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults);
extern void eigrp_cli_show_metrics(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
extern void eigrp_cli_show_network(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
extern void eigrp_cli_show_neighbor(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_show_redistribute(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
extern void eigrp_cli_show_delay(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
extern void eigrp_cli_show_bandwidth(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_hello_interval(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
extern void eigrp_cli_show_hold_time(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_summarize_address(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults);
extern void eigrp_cli_show_authentication(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
extern void eigrp_cli_show_keychain(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_init(void);

#endif /*EIGRP_CLI_H_ */
