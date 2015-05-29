/* ripd memory type definitions
 *
 * Copyright (C) 2015  David Lamparter
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rip_memory.h"

DEFINE_MGROUP(RIPD, "ripd")
DEFINE_MTYPE(RIPD, RIP,             "RIP structure")
DEFINE_MTYPE(RIPD, RIP_INFO,        "RIP route info")
DEFINE_MTYPE(RIPD, RIP_INTERFACE,   "RIP interface")
DEFINE_MTYPE(RIPD, RIP_PEER,        "RIP peer")
DEFINE_MTYPE(RIPD, RIP_OFFSET_LIST, "RIP offset list")
DEFINE_MTYPE(RIPD, RIP_DISTANCE,    "RIP distance")
