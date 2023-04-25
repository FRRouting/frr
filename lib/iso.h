/*
 * ISO Network definition - iso_net.h
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2023 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
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

#ifndef LIB_ISO_H_
#define LIB_ISO_H_

#include "compiler.h"

/* len of "xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xx" + '\0' */
#define ISO_ADDR_STRLEN	51
#define ISO_ADDR_MIN	8
#define ISO_ADDR_SIZE	20
struct iso_address {
	uint8_t addr_len;
	uint8_t area_addr[ISO_ADDR_SIZE];
};

/* len of "xxxx.xxxx.xxxx.xx-xx" + '\0' */
#define ISO_SYSID_STRLEN 21

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pSY" (uint8_t *)
#pragma FRR printfrr_ext "%pPN" (uint8_t *)
#pragma FRR printfrr_ext "%pLS" (uint8_t *)
#pragma FRR printfrr_ext "%pIS" (struct iso_address *)
#endif

#endif /* LIB_ISO_H_ */
