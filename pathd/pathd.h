/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#ifndef _FRR_PATHD_H_
#define _FRR_PATHD_H_

#include "lib/mpls.h"
#include "lib/ipaddr.h"

extern struct zebra_privs_t pathd_privs;

/* Prototypes. */
void path_zebra_init(struct thread_master *master);
void path_cli_init(void);

#endif /* _FRR_PATHD_H_ */
