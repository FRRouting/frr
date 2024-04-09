// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP CLI Functions.
 * Copyright (C) 2019
 * Authors:
 *   Donnie Savage
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
