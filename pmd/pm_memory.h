/*
 * header for path monitoring daemon memory
 * Copyright 2019 6WIND S.A.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __PM_MEMORY_H__
#define __PM_MEMORY_H__

#include "memory.h"

DECLARE_MGROUP(PMD);
DECLARE_MTYPE(PM_SESSION);
DECLARE_MTYPE(PM_ECHO);
DECLARE_MTYPE(PM_PACKET);
DECLARE_MTYPE(PM_RTT_STATS);
DECLARE_MTYPE(PM_CONTROL);
DECLARE_MTYPE(PM_NOTIFICATION);

#endif /* _PM_MEMORY_H */
