/*
 * header for path monitoring general services
 * Copyright (C) 6WIND 2019
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
#ifndef __LIB_PM_H__
#define __LIB_PM_H__

#include "lib/json.h"
#include "lib/zclient.h"

#define PM_DEF_INTERVAL 5000
#define PM_DEF_PACKET_SIZE 100
#define PM_DEF_IPV6_PACKET_SIZE 100
#define PM_DEF_TOS_VAL 0xc0  /* Inter Network Control */
#define PM_DEF_TIMEOUT 5000


#endif /* __LIB_PM_H__ */
