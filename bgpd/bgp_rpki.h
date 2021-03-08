/*
 * bgp_rpki code
 * Copyright (C) 2021 NVIDIA Corporation and Mellanox Technologies, LTD
 *                    All Rights Reserved
 *               Donald Sharp
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
#ifndef __BGP_RPKI_H__
#define __BGP_RPKI_H__

enum rpki_states {
	RPKI_NOT_BEING_USED,
	RPKI_VALID,
	RPKI_NOTFOUND,
	RPKI_INVALID
};

#endif
