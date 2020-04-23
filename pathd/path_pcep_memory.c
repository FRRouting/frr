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

#include <zebra.h>

#include <memory.h>

#include "pathd/path_pcep_memory.h"

DEFINE_MTYPE(PATHD, PCEP, "PCEP module")
DEFINE_MTYPE(PATHD, PCEPLIB_INFRA, "PCEPlib Infrastructure")
DEFINE_MTYPE(PATHD, PCEPLIB_MESSAGES, "PCEPlib PCEP Messages")
