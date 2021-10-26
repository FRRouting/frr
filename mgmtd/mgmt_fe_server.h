/*
 * MGMTD Frontend Server
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

#ifndef _FRR_MGMTD_FE_SERVER_H_
#define _FRR_MGMTD_FE_SERVER_H_

#define MGMTD_FE_MAX_CONN 32

/* Initialise frontend server */
extern int mgmt_fe_server_init(struct thread_master *master);

/* Destroy frontend server */
extern void mgmt_fe_server_destroy(void);

#endif /* _FRR_MGMTD_FE_SERVER_H_ */
