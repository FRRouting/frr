// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP CLI commands.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
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
