/*
 * VRRP CLI commands.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
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
#ifndef __VRRP_VTY_H__
#define __VRRP_VTY_H__

#include "lib/northbound.h"

void vrrp_vty_init(void);

/* Northbound callbacks */
void cli_show_vrrp(struct vty *vty, const struct lyd_node *dnode,
		   bool show_defaults);
void cli_show_shutdown(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults);
void cli_show_priority(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults);
void cli_show_advertisement_interval(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip(struct vty *vty, const struct lyd_node *dnode,
		 bool show_defaults);
void cli_show_ipv6(struct vty *vty, const struct lyd_node *dnode,
		   bool show_defaults);
void cli_show_preempt(struct vty *vty, const struct lyd_node *dnode,
		      bool show_defaults);
void cli_show_checksum_with_ipv4_pseudoheader(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults);

#endif /* __VRRP_VTY_H__ */
