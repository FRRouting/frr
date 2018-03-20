/*
 * Common definitions for watchfrr API socket.
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef FRR_WATCHFRR_H
#define FRR_WATCHFRR_H

extern void watchfrr_vty_init(void);

extern pid_t integrated_write_pid;
extern void integrated_write_sigchld(int status);
/*
 * Check if all daemons we are monitoring are in the DAEMON_UP state.
 *
 * Returns:
 *    True if they are all DAEMON_UP, false otherwise.
 */
extern bool check_all_up(void);

#endif /* FRR_WATCHFRR_H */
