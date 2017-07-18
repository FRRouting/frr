/*
 * FRR switchable defaults.
 * Copyright (C) 2017  David Lamparter for NetDEF, Inc.
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_DEFAULTS_H
#define _FRR_DEFAULTS_H

#include "config.h"

#ifdef HAVE_DATACENTER

#define DFLT_BGP_IMPORT_CHECK			1
#define DFLT_BGP_TIMERS_CONNECT			10
#define DFLT_BGP_HOLDTIME			9
#define DFLT_BGP_KEEPALIVE			3
#define DFLT_BGP_LOG_NEIGHBOR_CHANGES		1
#define DFLT_BGP_SHOW_HOSTNAME			1
#define DFLT_BGP_DETERMINISTIC_MED		1

#define DFLT_OSPF_LOG_ADJACENCY_CHANGES		1
#define DFLT_OSPF6_LOG_ADJACENCY_CHANGES	1

#else  /* !HAVE_DATACENTER */

#define DFLT_BGP_IMPORT_CHECK			0
#define DFLT_BGP_TIMERS_CONNECT			120
#define DFLT_BGP_HOLDTIME			180
#define DFLT_BGP_KEEPALIVE			60
#define DFLT_BGP_LOG_NEIGHBOR_CHANGES		0
#define DFLT_BGP_SHOW_HOSTNAME			0
#define DFLT_BGP_DETERMINISTIC_MED		0

#define DFLT_OSPF_LOG_ADJACENCY_CHANGES		0
#define DFLT_OSPF6_LOG_ADJACENCY_CHANGES	0

#endif /* !HAVE_DATACENTER */

#endif /* _FRR_DEFAULTS_H */
