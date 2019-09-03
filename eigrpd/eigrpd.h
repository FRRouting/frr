/*
 * EIGRP main header.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#ifndef _ZEBRA_EIGRPD_H
#define _ZEBRA_EIGRPD_H

#include <zebra.h>

#include "filter.h"
#include "log.h"

/* Set EIGRP version is "classic" - wide metrics comes next */
#define EIGRP_MAJOR_VERSION     1
#define EIGRP_MINOR_VERSION	2

/* Extern variables. */
extern struct zclient *zclient;
extern struct thread_master *master;
extern struct eigrp_master *eigrp_om;
extern struct zebra_privs_t eigrpd_privs;

/* Prototypes */
extern void eigrp_master_init(void);
extern void eigrp_terminate(void);
extern void eigrp_finish_final(struct eigrp *);
extern void eigrp_finish(struct eigrp *);
extern struct eigrp *eigrp_get(uint16_t as, vrf_id_t vrf_id);
extern struct eigrp *eigrp_lookup(vrf_id_t vrf_id);
extern void eigrp_router_id_update(struct eigrp *);

/* eigrp_cli.c */
extern void eigrp_cli_show_header(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
extern void eigrp_cli_show_end_header(struct vty *vty, struct lyd_node *dnode);
extern void eigrp_cli_show_router_id(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_passive_interface(struct vty *vty,
					     struct lyd_node *dnode,
					     bool show_defaults);
extern void eigrp_cli_show_active_time(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults);
extern void eigrp_cli_show_variance(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_show_maximum_paths(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
extern void eigrp_cli_show_metrics(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
extern void eigrp_cli_show_network(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
extern void eigrp_cli_show_neighbor(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_show_redistribute(struct vty *vty,
					struct lyd_node *dnode,
					bool show_defaults);
extern void eigrp_cli_show_delay(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);
extern void eigrp_cli_show_bandwidth(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_hello_interval(struct vty *vty,
					  struct lyd_node *dnode,
					  bool show_defaults);
extern void eigrp_cli_show_hold_time(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
extern void eigrp_cli_show_summarize_address(struct vty *vty,
					     struct lyd_node *dnode,
					     bool show_defaults);
extern void eigrp_cli_show_authentication(struct vty *vty,
					  struct lyd_node *dnode,
					  bool show_defaults);
extern void eigrp_cli_show_keychain(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
extern void eigrp_cli_init(void);

/* eigrp_northbound.c */
extern const struct frr_yang_module_info frr_eigrpd_info;

#endif /* _ZEBRA_EIGRPD_H */
