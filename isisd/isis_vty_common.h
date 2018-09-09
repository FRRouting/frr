/*
 * IS-IS Rout(e)ing protocol - isis_vty_common.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2016        David Lamparter, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef ISIS_VTY_COMMON_H
#define ISIS_VTY_COMMON_H

struct isis_circuit *isis_circuit_lookup(struct vty *vty);

int isis_vty_max_lsp_lifetime_set(struct vty *vty, int level, uint16_t interval);
int isis_vty_lsp_refresh_set(struct vty *vty, int level, uint16_t interval);
int isis_vty_lsp_gen_interval_set(struct vty *vty, int level, uint16_t interval);
int isis_vty_password_set(struct vty *vty, int argc,
			  struct cmd_token *argv[], int level);

void isis_vty_daemon_init(void);
void isis_vty_init(void);

#endif
