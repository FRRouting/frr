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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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

/* Prototypes */
 extern void eigrp_master_init (void);
 extern void eigrp_terminate (void);
 extern void eigrp_finish (struct eigrp *);
 extern struct eigrp *eigrp_get (const char *);
 extern struct eigrp *eigrp_lookup (void);
 extern void eigrp_router_id_update (struct eigrp *);

#endif /* _ZEBRA_EIGRPD_H */
