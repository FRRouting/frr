/*
 * Copyright (C) 2018       Volta Networks
 *                          Emanuele Di Pascale
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

#ifndef ISISD_ISIS_CLI_H_
#define ISISD_ISIS_CLI_H_

/* add cli_show declarations here as externs */
void cli_show_router_isis(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_ip_isis_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_isis_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_area_address(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_is_type(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_dynamic_hostname(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_attached(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_overload(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_metric_style(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_area_pwd(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_domain_pwd(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_lsp_gen_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_ref_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_max_lifetime(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_mtu(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);

#endif /* ISISD_ISIS_CLI_H_ */
