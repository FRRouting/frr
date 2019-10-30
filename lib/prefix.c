/*
 * Prefix related functions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"
#include "jhash.h"
#include "lib_errors.h"
#include "printfrr.h"

DEFINE_MTYPE_STATIC(LIB, PREFIX, "Prefix")
DEFINE_MTYPE_STATIC(LIB, PREFIX_FLOWSPEC, "Prefix Flowspec")

/* Maskbit. */
static const uint8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
				  0xf8, 0xfc, 0xfe, 0xff};

static const struct in6_addr maskbytes6[] = {
	/* /0   */ {{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /1   */
	{{{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /2   */
	{{{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /3   */
	{{{0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /4   */
	{{{0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /5   */
	{{{0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /6   */
	{{{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /7   */
	{{{0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /8   */
	{{{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /9   */
	{{{0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /10  */
	{{{0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /11  */
	{{{0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /12  */
	{{{0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /13  */
	{{{0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /14  */
	{{{0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /15  */
	{{{0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /16  */
	{{{0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /17  */
	{{{0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /18  */
	{{{0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /19  */
	{{{0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /20  */
	{{{0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /21  */
	{{{0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /22  */
	{{{0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /23  */
	{{{0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /24  */
	{{{0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /25  */
	{{{0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /26  */
	{{{0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /27  */
	{{{0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /28  */
	{{{0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /29  */
	{{{0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /30  */
	{{{0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /31  */
	{{{0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /32  */
	{{{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /33  */
	{{{0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /34  */
	{{{0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /35  */
	{{{0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /36  */
	{{{0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /37  */
	{{{0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /38  */
	{{{0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /39  */
	{{{0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /40  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /41  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /42  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /43  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /44  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /45  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /46  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /47  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /48  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /49  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /50  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /51  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /52  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /53  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /54  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /55  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /56  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /57  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /58  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /59  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /60  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /61  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /62  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /63  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /64  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /65  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /66  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /67  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /68  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /69  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /70  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /71  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /72  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /73  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /74  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /75  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /76  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /77  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /78  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /79  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /80  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /81  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /82  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /83  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /84  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /85  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /86  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /87  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /88  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0x00, 0x00, 0x00, 0x00, 0x00}}},
	/* /89  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0x80, 0x00, 0x00, 0x00, 0x00}}},
	/* /90  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xc0, 0x00, 0x00, 0x00, 0x00}}},
	/* /91  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xe0, 0x00, 0x00, 0x00, 0x00}}},
	/* /92  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xf0, 0x00, 0x00, 0x00, 0x00}}},
	/* /93  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xf8, 0x00, 0x00, 0x00, 0x00}}},
	/* /94  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xfc, 0x00, 0x00, 0x00, 0x00}}},
	/* /95  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xfe, 0x00, 0x00, 0x00, 0x00}}},
	/* /96  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0x00, 0x00, 0x00, 0x00}}},
	/* /97  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0x80, 0x00, 0x00, 0x00}}},
	/* /98  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xc0, 0x00, 0x00, 0x00}}},
	/* /99  */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xe0, 0x00, 0x00, 0x00}}},
	/* /100 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xf0, 0x00, 0x00, 0x00}}},
	/* /101 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xf8, 0x00, 0x00, 0x00}}},
	/* /102 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xfc, 0x00, 0x00, 0x00}}},
	/* /103 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xfe, 0x00, 0x00, 0x00}}},
	/* /104 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0x00, 0x00, 0x00}}},
	/* /105 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0x80, 0x00, 0x00}}},
	/* /106 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xc0, 0x00, 0x00}}},
	/* /107 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xe0, 0x00, 0x00}}},
	/* /108 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xf0, 0x00, 0x00}}},
	/* /109 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xf8, 0x00, 0x00}}},
	/* /110 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xfc, 0x00, 0x00}}},
	/* /111 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xfe, 0x00, 0x00}}},
	/* /112 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0x00, 0x00}}},
	/* /113 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0x80, 0x00}}},
	/* /114 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xc0, 0x00}}},
	/* /115 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xe0, 0x00}}},
	/* /116 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xf0, 0x00}}},
	/* /117 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xf8, 0x00}}},
	/* /118 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xfc, 0x00}}},
	/* /119 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xfe, 0x00}}},
	/* /120 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0x00}}},
	/* /121 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0x80}}},
	/* /122 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xc0}}},
	/* /123 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xe0}}},
	/* /124 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xf0}}},
	/* /125 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xf8}}},
	/* /126 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xfc}}},
	/* /127 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xfe}}},
	/* /128 */
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xff}}}};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)

void prefix_hexdump(const struct prefix *p)
{
	char buf[PREFIX_STRLEN];

	zlog_debug("prefix: %s",
		   prefix2str(p, buf, sizeof(buf)));
	zlog_hexdump(p, sizeof(struct prefix));
}

int is_zero_mac(const struct ethaddr *mac)
{
	int i = 0;

	for (i = 0; i < ETH_ALEN; i++) {
		if (mac->octet[i])
			return 0;
	}

	return 1;
}

unsigned int prefix_bit(const uint8_t *prefix, const uint16_t prefixlen)
{
	unsigned int offset = prefixlen / 8;
	unsigned int shift = 7 - (prefixlen % 8);

	return (prefix[offset] >> shift) & 1;
}

unsigned int prefix6_bit(const struct in6_addr *prefix, const uint16_t prefixlen)
{
	return prefix_bit((const uint8_t *)&prefix->s6_addr, prefixlen);
}

int str2family(const char *string)
{
	if (!strcmp("ipv4", string))
		return AF_INET;
	else if (!strcmp("ipv6", string))
		return AF_INET6;
	else if (!strcmp("ethernet", string))
		return AF_ETHERNET;
	else if (!strcmp("evpn", string))
		return AF_EVPN;
	return -1;
}

const char *family2str(int family)
{
	switch (family) {
	case AF_INET:
		return "IPv4";
	case AF_INET6:
		return "IPv6";
	case AF_ETHERNET:
		return "Ethernet";
	case AF_EVPN:
		return "Evpn";
	}
	return "?";
}

/* Address Famiy Identifier to Address Family converter. */
int afi2family(afi_t afi)
{
	if (afi == AFI_IP)
		return AF_INET;
	else if (afi == AFI_IP6)
		return AF_INET6;
	else if (afi == AFI_L2VPN)
		return AF_ETHERNET;
	/* NOTE: EVPN code should NOT use this interface. */
	return 0;
}

afi_t family2afi(int family)
{
	if (family == AF_INET)
		return AFI_IP;
	else if (family == AF_INET6)
		return AFI_IP6;
	else if (family == AF_ETHERNET || family == AF_EVPN)
		return AFI_L2VPN;
	return 0;
}

const char *afi2str(afi_t afi)
{
	switch (afi) {
	case AFI_IP:
		return "IPv4";
	case AFI_IP6:
		return "IPv6";
	case AFI_L2VPN:
		return "l2vpn";
	case AFI_MAX:
		return "bad-value";
	default:
		break;
	}
	return NULL;
}

const char *safi2str(safi_t safi)
{
	switch (safi) {
	case SAFI_UNICAST:
		return "unicast";
	case SAFI_MULTICAST:
		return "multicast";
	case SAFI_MPLS_VPN:
		return "vpn";
	case SAFI_ENCAP:
		return "encap";
	case SAFI_EVPN:
		return "evpn";
	case SAFI_LABELED_UNICAST:
		return "labeled-unicast";
	case SAFI_FLOWSPEC:
		return "flowspec";
	default:
		return "unknown";
	}
}

/* If n includes p prefix then return 1 else return 0. */
int prefix_match(const struct prefix *n, const struct prefix *p)
{
	int offset;
	int shift;
	const uint8_t *np, *pp;

	/* If n's prefix is longer than p's one return 0. */
	if (n->prefixlen > p->prefixlen)
		return 0;

	if (n->family == AF_FLOWSPEC) {
		/* prefixlen is unused. look at fs prefix len */
		if (n->u.prefix_flowspec.prefixlen >
		    p->u.prefix_flowspec.prefixlen)
			return 0;

		/* Set both prefix's head pointer. */
		np = (const uint8_t *)&n->u.prefix_flowspec.ptr;
		pp = (const uint8_t *)&p->u.prefix_flowspec.ptr;

		offset = n->u.prefix_flowspec.prefixlen;

		while (offset--)
			if (np[offset] != pp[offset])
				return 0;
		return 1;
	}

	/* Set both prefix's head pointer. */
	np = n->u.val;
	pp = p->u.val;

	offset = n->prefixlen / PNBBY;
	shift = n->prefixlen % PNBBY;

	if (shift)
		if (maskbit[shift] & (np[offset] ^ pp[offset]))
			return 0;

	while (offset--)
		if (np[offset] != pp[offset])
			return 0;
	return 1;

}

/*
 * n is a type5 evpn prefix. This function tries to see if there is an
 * ip-prefix within n which matches prefix p
 * If n includes p prefix then return 1 else return 0.
 */
int evpn_type5_prefix_match(const struct prefix *n, const struct prefix *p)
{
	int offset;
	int shift;
	int prefixlen;
	const uint8_t *np, *pp;
	struct prefix_evpn *evp;

	if (n->family != AF_EVPN)
		return 0;

	evp = (struct prefix_evpn *)n;
	pp = p->u.val;

	if ((evp->prefix.route_type != 5) ||
	    (p->family == AF_INET6 && !is_evpn_prefix_ipaddr_v6(evp)) ||
	    (p->family == AF_INET && !is_evpn_prefix_ipaddr_v4(evp)) ||
	    (is_evpn_prefix_ipaddr_none(evp)))
		return 0;

	prefixlen = evp->prefix.prefix_addr.ip_prefix_length;
	np = &evp->prefix.prefix_addr.ip.ip.addr;

	/* If n's prefix is longer than p's one return 0. */
	if (prefixlen > p->prefixlen)
		return 0;

	offset = prefixlen / PNBBY;
	shift = prefixlen % PNBBY;

	if (shift)
		if (maskbit[shift] & (np[offset] ^ pp[offset]))
			return 0;

	while (offset--)
		if (np[offset] != pp[offset])
			return 0;
	return 1;

}

/* If n includes p then return 1 else return 0. Prefix mask is not considered */
int prefix_match_network_statement(const struct prefix *n,
				   const struct prefix *p)
{
	int offset;
	int shift;
	const uint8_t *np, *pp;

	/* Set both prefix's head pointer. */
	np = n->u.val;
	pp = p->u.val;

	offset = n->prefixlen / PNBBY;
	shift = n->prefixlen % PNBBY;

	if (shift)
		if (maskbit[shift] & (np[offset] ^ pp[offset]))
			return 0;

	while (offset--)
		if (np[offset] != pp[offset])
			return 0;
	return 1;
}

#ifdef __clang_analyzer__
#undef prefix_copy	/* cf. prefix.h */
#endif

void prefix_copy(union prefixptr udest, union prefixconstptr usrc)
{
	struct prefix *dest = udest.p;
	const struct prefix *src = usrc.p;

	dest->family = src->family;
	dest->prefixlen = src->prefixlen;

	if (src->family == AF_INET)
		dest->u.prefix4 = src->u.prefix4;
	else if (src->family == AF_INET6)
		dest->u.prefix6 = src->u.prefix6;
	else if (src->family == AF_ETHERNET) {
		memcpy(&dest->u.prefix_eth, &src->u.prefix_eth,
		       sizeof(struct ethaddr));
	} else if (src->family == AF_EVPN) {
		memcpy(&dest->u.prefix_evpn, &src->u.prefix_evpn,
		       sizeof(struct evpn_addr));
	} else if (src->family == AF_UNSPEC) {
		dest->u.lp.id = src->u.lp.id;
		dest->u.lp.adv_router = src->u.lp.adv_router;
	} else if (src->family == AF_FLOWSPEC) {
		void *temp;
		int len;

		len = src->u.prefix_flowspec.prefixlen;
		dest->u.prefix_flowspec.prefixlen =
			src->u.prefix_flowspec.prefixlen;
		dest->family = src->family;
		temp = XCALLOC(MTYPE_PREFIX_FLOWSPEC, len);
		dest->u.prefix_flowspec.ptr = (uintptr_t)temp;
		memcpy((void *)dest->u.prefix_flowspec.ptr,
		       (void *)src->u.prefix_flowspec.ptr, len);
	} else {
		flog_err(EC_LIB_DEVELOPMENT,
			 "prefix_copy(): Unknown address family %d",
			 src->family);
		assert(0);
	}
}

/*
 * Return 1 if the address/netmask contained in the prefix structure
 * is the same, and else return 0.  For this routine, 'same' requires
 * that not only the prefix length and the network part be the same,
 * but also the host part.  Thus, 10.0.0.1/8 and 10.0.0.2/8 are not
 * the same.  Note that this routine has the same return value sense
 * as '==' (which is different from prefix_cmp).
 */
int prefix_same(union prefixconstptr up1, union prefixconstptr up2)
{
	const struct prefix *p1 = up1.p;
	const struct prefix *p2 = up2.p;

	if ((p1 && !p2) || (!p1 && p2))
		return 0;

	if (!p1 && !p2)
		return 1;

	if (p1->family == p2->family && p1->prefixlen == p2->prefixlen) {
		if (p1->family == AF_INET)
			if (IPV4_ADDR_SAME(&p1->u.prefix4, &p2->u.prefix4))
				return 1;
		if (p1->family == AF_INET6)
			if (IPV6_ADDR_SAME(&p1->u.prefix6.s6_addr,
					   &p2->u.prefix6.s6_addr))
				return 1;
		if (p1->family == AF_ETHERNET)
			if (!memcmp(&p1->u.prefix_eth, &p2->u.prefix_eth,
				    sizeof(struct ethaddr)))
				return 1;
		if (p1->family == AF_EVPN)
			if (!memcmp(&p1->u.prefix_evpn, &p2->u.prefix_evpn,
				    sizeof(struct evpn_addr)))
				return 1;
		if (p1->family == AF_FLOWSPEC) {
			if (p1->u.prefix_flowspec.prefixlen !=
			    p2->u.prefix_flowspec.prefixlen)
				return 0;
			if (!memcmp(&p1->u.prefix_flowspec.ptr,
				    &p2->u.prefix_flowspec.ptr,
				    p2->u.prefix_flowspec.prefixlen))
				return 1;
		}
	}
	return 0;
}

/*
 * Return -1/0/1 comparing the prefixes in a way that gives a full/linear
 * order.
 *
 * Network prefixes are considered the same if the prefix lengths are equal
 * and the network parts are the same.  Host bits (which are considered masked
 * by the prefix length) are not significant.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are considered equivalent by this routine.  Note that
 * this routine has the same return sense as strcmp (which is different
 * from prefix_same).
 */
int prefix_cmp(union prefixconstptr up1, union prefixconstptr up2)
{
	const struct prefix *p1 = up1.p;
	const struct prefix *p2 = up2.p;
	int offset;
	int shift;
	int i;

	/* Set both prefix's head pointer. */
	const uint8_t *pp1;
	const uint8_t *pp2;

	if (p1->family != p2->family)
		return numcmp(p1->family, p2->family);
	if (p1->family == AF_FLOWSPEC) {
		pp1 = (const uint8_t *)p1->u.prefix_flowspec.ptr;
		pp2 = (const uint8_t *)p2->u.prefix_flowspec.ptr;

		if (p1->u.prefix_flowspec.prefixlen !=
		    p2->u.prefix_flowspec.prefixlen)
			return numcmp(p1->u.prefix_flowspec.prefixlen,
				      p2->u.prefix_flowspec.prefixlen);

		offset = p1->u.prefix_flowspec.prefixlen;
		while (offset--)
			if (pp1[offset] != pp2[offset])
				return numcmp(pp1[offset], pp2[offset]);
		return 0;
	}
	pp1 = p1->u.val;
	pp2 = p2->u.val;

	if (p1->prefixlen != p2->prefixlen)
		return numcmp(p1->prefixlen, p2->prefixlen);
	offset = p1->prefixlen / PNBBY;
	shift = p1->prefixlen % PNBBY;

	i = memcmp(pp1, pp2, offset);
	if (i)
		return i;

	/*
	 * At this point offset was the same, if we have shift
	 * that means we still have data to compare, if shift is
	 * 0 then we are at the end of the data structure
	 * and should just return, as that we will be accessing
	 * memory beyond the end of the party zone
	 */
	if (shift)
		return numcmp(pp1[offset] & maskbit[shift],
			      pp2[offset] & maskbit[shift]);

	return 0;
}

/*
 * Count the number of common bits in 2 prefixes. The prefix length is
 * ignored for this function; the whole prefix is compared. If the prefix
 * address families don't match, return -1; otherwise the return value is
 * in range 0 ... maximum prefix length for the address family.
 */
int prefix_common_bits(const struct prefix *p1, const struct prefix *p2)
{
	int pos, bit;
	int length = 0;
	uint8_t xor ;

	/* Set both prefix's head pointer. */
	const uint8_t *pp1 = p1->u.val;
	const uint8_t *pp2 = p2->u.val;

	if (p1->family == AF_INET)
		length = IPV4_MAX_BYTELEN;
	if (p1->family == AF_INET6)
		length = IPV6_MAX_BYTELEN;
	if (p1->family == AF_ETHERNET)
		length = ETH_ALEN;
	if (p1->family == AF_EVPN)
		length = 8 * sizeof(struct evpn_addr);

	if (p1->family != p2->family || !length)
		return -1;

	for (pos = 0; pos < length; pos++)
		if (pp1[pos] != pp2[pos])
			break;
	if (pos == length)
		return pos * 8;

	xor = pp1[pos] ^ pp2[pos];
	for (bit = 0; bit < 8; bit++)
		if (xor&(1 << (7 - bit)))
			break;

	return pos * 8 + bit;
}

/* Return prefix family type string. */
const char *prefix_family_str(const struct prefix *p)
{
	if (p->family == AF_INET)
		return "inet";
	if (p->family == AF_INET6)
		return "inet6";
	if (p->family == AF_ETHERNET)
		return "ether";
	if (p->family == AF_EVPN)
		return "evpn";
	return "unspec";
}

/* Allocate new prefix_ipv4 structure. */
struct prefix_ipv4 *prefix_ipv4_new(void)
{
	struct prefix_ipv4 *p;

	/* Call prefix_new to allocate a full-size struct prefix to avoid
	   problems
	   where the struct prefix_ipv4 is cast to struct prefix and unallocated
	   bytes were being referenced (e.g. in structure assignments). */
	p = (struct prefix_ipv4 *)prefix_new();
	p->family = AF_INET;
	return p;
}

/* Free prefix_ipv4 structure. */
void prefix_ipv4_free(struct prefix_ipv4 **p)
{
	prefix_free((struct prefix **)p);
}

/* If given string is valid return 1 else return 0 */
int str2prefix_ipv4(const char *str, struct prefix_ipv4 *p)
{
	int ret;
	int plen;
	char *pnt;
	char *cp;

	/* Find slash inside string. */
	pnt = strchr(str, '/');

	/* String doesn't contail slash. */
	if (pnt == NULL) {
		/* Convert string to prefix. */
		ret = inet_pton(AF_INET, str, &p->prefix);
		if (ret == 0)
			return 0;

		/* If address doesn't contain slash we assume it host address.
		 */
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;

		return ret;
	} else {
		cp = XMALLOC(MTYPE_TMP, (pnt - str) + 1);
		memcpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_pton(AF_INET, cp, &p->prefix);
		XFREE(MTYPE_TMP, cp);
		if (ret == 0)
			return 0;

		/* Get prefix length. */
		plen = (uint8_t)atoi(++pnt);
		if (plen > IPV4_MAX_PREFIXLEN)
			return 0;

		p->family = AF_INET;
		p->prefixlen = plen;
	}

	return ret;
}

/* When string format is invalid return 0. */
int str2prefix_eth(const char *str, struct prefix_eth *p)
{
	int ret = 0;
	int plen = 48;
	char *pnt;
	char *cp = NULL;
	const char *str_addr = str;
	unsigned int a[6];
	int i;
	bool slash = false;

	if (!strcmp(str, "any")) {
		memset(p, 0, sizeof(*p));
		p->family = AF_ETHERNET;
		return 1;
	}

	/* Find slash inside string. */
	pnt = strchr(str, '/');

	if (pnt) {
		/* Get prefix length. */
		plen = (uint8_t)atoi(++pnt);
		if (plen > 48) {
			ret = 0;
			goto done;
		}

		cp = XMALLOC(MTYPE_TMP, (pnt - str) + 1);
		memcpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';

		str_addr = cp;
		slash = true;
	}

	/* Convert string to prefix. */
	if (sscanf(str_addr, "%2x:%2x:%2x:%2x:%2x:%2x", a + 0, a + 1, a + 2,
		   a + 3, a + 4, a + 5)
	    != 6) {
		ret = 0;
		goto done;
	}
	for (i = 0; i < 6; ++i) {
		p->eth_addr.octet[i] = a[i] & 0xff;
	}
	p->prefixlen = plen;
	p->family = AF_ETHERNET;

	/*
	 * special case to allow old configurations to work
	 * Since all zero's is implicitly meant to allow
	 * a comparison to zero, let's assume
	 */
	if (!slash && is_zero_mac(&(p->eth_addr)))
		p->prefixlen = 0;

	ret = 1;

done:
	XFREE(MTYPE_TMP, cp);

	return ret;
}

/* Convert masklen into IP address's netmask (network byte order). */
void masklen2ip(const int masklen, struct in_addr *netmask)
{
	assert(masklen >= 0 && masklen <= IPV4_MAX_BITLEN);

	/* left shift is only defined for less than the size of the type.
	 * we unconditionally use long long in case the target platform
	 * has defined behaviour for << 32 (or has a 64-bit left shift) */

	if (sizeof(unsigned long long) > 4)
		netmask->s_addr = htonl(0xffffffffULL << (32 - masklen));
	else
		netmask->s_addr =
			htonl(masklen ? 0xffffffffU << (32 - masklen) : 0);
}

/* Convert IP address's netmask into integer. We assume netmask is
 * sequential one. Argument netmask should be network byte order. */
uint8_t ip_masklen(struct in_addr netmask)
{
	uint32_t tmp = ~ntohl(netmask.s_addr);

	/*
	 * clz: count leading zeroes. sadly, the behaviour of this builtin is
	 * undefined for a 0 argument, even though most CPUs give 32
	 */
	return tmp ? __builtin_clz(tmp) : 32;
}

/* Apply mask to IPv4 prefix (network byte order). */
void apply_mask_ipv4(struct prefix_ipv4 *p)
{
	struct in_addr mask;
	masklen2ip(p->prefixlen, &mask);
	p->prefix.s_addr &= mask.s_addr;
}

/* If prefix is 0.0.0.0/0 then return 1 else return 0. */
int prefix_ipv4_any(const struct prefix_ipv4 *p)
{
	return (p->prefix.s_addr == 0 && p->prefixlen == 0);
}

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *prefix_ipv6_new(void)
{
	struct prefix_ipv6 *p;

	/* Allocate a full-size struct prefix to avoid problems with structure
	   size mismatches. */
	p = (struct prefix_ipv6 *)prefix_new();
	p->family = AF_INET6;
	return p;
}

/* Free prefix for IPv6. */
void prefix_ipv6_free(struct prefix_ipv6 **p)
{
	prefix_free((struct prefix **)p);
}

/* If given string is valid return 1 else return 0 */
int str2prefix_ipv6(const char *str, struct prefix_ipv6 *p)
{
	char *pnt;
	char *cp;
	int ret;

	pnt = strchr(str, '/');

	/* If string doesn't contain `/' treat it as host route. */
	if (pnt == NULL) {
		ret = inet_pton(AF_INET6, str, &p->prefix);
		if (ret == 0)
			return 0;
		p->prefixlen = IPV6_MAX_BITLEN;
	} else {
		int plen;

		cp = XMALLOC(MTYPE_TMP, (pnt - str) + 1);
		memcpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_pton(AF_INET6, cp, &p->prefix);
		XFREE(MTYPE_TMP, cp);
		if (ret == 0)
			return 0;
		plen = (uint8_t)atoi(++pnt);
		if (plen > IPV6_MAX_BITLEN)
			return 0;
		p->prefixlen = plen;
	}
	p->family = AF_INET6;

	return ret;
}

/* Convert struct in6_addr netmask into integer.
 * FIXME return uint8_t as ip_maskleni() does. */
int ip6_masklen(struct in6_addr netmask)
{
	int len = 0;
	unsigned char val;
	unsigned char *pnt;

	pnt = (unsigned char *)&netmask;

	while ((*pnt == 0xff) && len < IPV6_MAX_BITLEN) {
		len += 8;
		pnt++;
	}

	if (len < IPV6_MAX_BITLEN) {
		val = *pnt;
		while (val) {
			len++;
			val <<= 1;
		}
	}
	return len;
}

void masklen2ip6(const int masklen, struct in6_addr *netmask)
{
	assert(masklen >= 0 && masklen <= IPV6_MAX_BITLEN);
	memcpy(netmask, maskbytes6 + masklen, sizeof(struct in6_addr));
}

void apply_mask_ipv6(struct prefix_ipv6 *p)
{
	uint8_t *pnt;
	int index;
	int offset;

	index = p->prefixlen / 8;

	if (index < 16) {
		pnt = (uint8_t *)&p->prefix;
		offset = p->prefixlen % 8;

		pnt[index] &= maskbit[offset];
		index++;

		while (index < 16)
			pnt[index++] = 0;
	}
}

void apply_mask(struct prefix *p)
{
	switch (p->family) {
	case AF_INET:
		apply_mask_ipv4((struct prefix_ipv4 *)p);
		break;
	case AF_INET6:
		apply_mask_ipv6((struct prefix_ipv6 *)p);
		break;
	default:
		break;
	}
	return;
}

/* Utility function of convert between struct prefix <=> union sockunion.
 * FIXME This function isn't used anywhere. */
struct prefix *sockunion2prefix(const union sockunion *dest,
				const union sockunion *mask)
{
	if (dest->sa.sa_family == AF_INET) {
		struct prefix_ipv4 *p;

		p = prefix_ipv4_new();
		p->family = AF_INET;
		p->prefix = dest->sin.sin_addr;
		p->prefixlen = ip_masklen(mask->sin.sin_addr);
		return (struct prefix *)p;
	}
	if (dest->sa.sa_family == AF_INET6) {
		struct prefix_ipv6 *p;

		p = prefix_ipv6_new();
		p->family = AF_INET6;
		p->prefixlen = ip6_masklen(mask->sin6.sin6_addr);
		memcpy(&p->prefix, &dest->sin6.sin6_addr,
		       sizeof(struct in6_addr));
		return (struct prefix *)p;
	}
	return NULL;
}

/* Utility function of convert between struct prefix <=> union sockunion. */
struct prefix *sockunion2hostprefix(const union sockunion *su,
				    struct prefix *prefix)
{
	if (su->sa.sa_family == AF_INET) {
		struct prefix_ipv4 *p;

		p = prefix ? (struct prefix_ipv4 *)prefix : prefix_ipv4_new();
		p->family = AF_INET;
		p->prefix = su->sin.sin_addr;
		p->prefixlen = IPV4_MAX_BITLEN;
		return (struct prefix *)p;
	}
	if (su->sa.sa_family == AF_INET6) {
		struct prefix_ipv6 *p;

		p = prefix ? (struct prefix_ipv6 *)prefix : prefix_ipv6_new();
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		memcpy(&p->prefix, &su->sin6.sin6_addr,
		       sizeof(struct in6_addr));
		return (struct prefix *)p;
	}
	return NULL;
}

void prefix2sockunion(const struct prefix *p, union sockunion *su)
{
	memset(su, 0, sizeof(*su));

	su->sa.sa_family = p->family;
	if (p->family == AF_INET)
		su->sin.sin_addr = p->u.prefix4;
	if (p->family == AF_INET6)
		memcpy(&su->sin6.sin6_addr, &p->u.prefix6,
		       sizeof(struct in6_addr));
}

int prefix_blen(const struct prefix *p)
{
	switch (p->family) {
	case AF_INET:
		return IPV4_MAX_BYTELEN;
		break;
	case AF_INET6:
		return IPV6_MAX_BYTELEN;
		break;
	case AF_ETHERNET:
		return ETH_ALEN;
		break;
	}
	return 0;
}

/* Generic function for conversion string to struct prefix. */
int str2prefix(const char *str, struct prefix *p)
{
	int ret;

	if (!str || !p)
		return 0;

	/* First we try to convert string to struct prefix_ipv4. */
	ret = str2prefix_ipv4(str, (struct prefix_ipv4 *)p);
	if (ret)
		return ret;

	/* Next we try to convert string to struct prefix_ipv6. */
	ret = str2prefix_ipv6(str, (struct prefix_ipv6 *)p);
	if (ret)
		return ret;

	/* Next we try to convert string to struct prefix_eth. */
	ret = str2prefix_eth(str, (struct prefix_eth *)p);
	if (ret)
		return ret;

	return 0;
}

static const char *prefixevpn_ead2str(const struct prefix_evpn *p, char *str,
				      int size)
{
	snprintf(str, size, "Unsupported EVPN prefix");
	return str;
}

static const char *prefixevpn_macip2str(const struct prefix_evpn *p, char *str,
					int size)
{
	uint8_t family;
	char buf[PREFIX2STR_BUFFER];
	char buf2[ETHER_ADDR_STRLEN];

	if (is_evpn_prefix_ipaddr_none(p))
		snprintf(str, size, "[%d]:[%s]/%d",
			 p->prefix.route_type,
			 prefix_mac2str(&p->prefix.macip_addr.mac,
					buf2, sizeof(buf2)),
			 p->prefixlen);
	else {
		family = is_evpn_prefix_ipaddr_v4(p)
				 ? AF_INET
				 : AF_INET6;
		snprintf(str, size, "[%d]:[%s]:[%s]/%d",
			 p->prefix.route_type,
			 prefix_mac2str(&p->prefix.macip_addr.mac,
					buf2, sizeof(buf2)),
			 inet_ntop(family,
				   &p->prefix.macip_addr.ip.ip.addr,
				   buf, PREFIX2STR_BUFFER),
			 p->prefixlen);
	}
	return str;
}

static const char *prefixevpn_imet2str(const struct prefix_evpn *p, char *str,
				       int size)
{
	uint8_t family;
	char buf[PREFIX2STR_BUFFER];

	family = is_evpn_prefix_ipaddr_v4(p)
			 ? AF_INET
			 : AF_INET6;
	snprintf(str, size, "[%d]:[%s]/%d", p->prefix.route_type,
		 inet_ntop(family,
			   &p->prefix.imet_addr.ip.ip.addr, buf,
			   PREFIX2STR_BUFFER),
		 p->prefixlen);
	return str;
}

static const char *prefixevpn_es2str(const struct prefix_evpn *p, char *str,
				     int size)
{
	char buf[ESI_STR_LEN];

	snprintf(str, size, "[%d]:[%s]:[%s]/%d", p->prefix.route_type,
		 esi_to_str(&p->prefix.es_addr.esi, buf, sizeof(buf)),
		 inet_ntoa(p->prefix.es_addr.ip.ipaddr_v4),
		 p->prefixlen);
	return str;
}

static const char *prefixevpn_prefix2str(const struct prefix_evpn *p, char *str,
					 int size)
{
	uint8_t family;
	char buf[PREFIX2STR_BUFFER];

	family = is_evpn_prefix_ipaddr_v4(p)
			 ? AF_INET
			 : AF_INET6;
	snprintf(str, size, "[%d]:[%u][%s/%d]/%d",
		 p->prefix.route_type,
		 p->prefix.prefix_addr.eth_tag,
		 inet_ntop(family,
			   &p->prefix.prefix_addr.ip.ip.addr, buf,
			   PREFIX2STR_BUFFER),
		 p->prefix.prefix_addr.ip_prefix_length,
		 p->prefixlen);
	return str;
}

static const char *prefixevpn2str(const struct prefix_evpn *p, char *str,
				  int size)
{
	switch (p->prefix.route_type) {
	case 1:
		return prefixevpn_ead2str(p, str, size);
	case 2:
		return prefixevpn_macip2str(p, str, size);
	case 3:
		return prefixevpn_imet2str(p, str, size);
	case 4:
		return prefixevpn_es2str(p, str, size);
	case 5:
		return prefixevpn_prefix2str(p, str, size);
	default:
		snprintf(str, size, "Unsupported EVPN prefix");
		break;
	}
	return str;
}

const char *prefix2str(union prefixconstptr pu, char *str, int size)
{
	const struct prefix *p = pu.p;
	char buf[PREFIX2STR_BUFFER];
	int byte, tmp, a, b;
	bool z = false;
	size_t l;

	switch (p->family) {
	case AF_INET:
	case AF_INET6:
		inet_ntop(p->family, &p->u.prefix, buf, sizeof(buf));
		l = strlen(buf);
		buf[l++] = '/';
		byte = p->prefixlen;
		if ((tmp = p->prefixlen - 100) >= 0) {
			buf[l++] = '1';
			z = true;
			byte = tmp;
		}
		b = byte % 10;
		a = byte / 10;
		if (a || z)
			buf[l++] = '0' + a;
		buf[l++] = '0' + b;
		buf[l] = '\0';
		strlcpy(str, buf, size);
		break;

	case AF_ETHERNET:
		snprintf(str, size, "%s/%d",
			 prefix_mac2str(&p->u.prefix_eth, buf, sizeof(buf)),
			 p->prefixlen);
		break;

	case AF_EVPN:
		prefixevpn2str((const struct prefix_evpn *)p, str, size);
		break;

	case AF_FLOWSPEC:
		strlcpy(str, "FS prefix", size);
		break;

	default:
		strlcpy(str, "UNK prefix", size);
		break;
	}

	return str;
}

void prefix_mcast_inet4_dump(const char *onfail, struct in_addr addr,
		char *buf, int buf_size)
{
	int save_errno = errno;

	if (addr.s_addr == INADDR_ANY)
		strlcpy(buf, "*", buf_size);
	else {
		if (!inet_ntop(AF_INET, &addr, buf, buf_size)) {
			if (onfail)
				snprintf(buf, buf_size, "%s", onfail);
		}
	}

	errno = save_errno;
}

const char *prefix_sg2str(const struct prefix_sg *sg, char *sg_str)
{
	char src_str[INET_ADDRSTRLEN];
	char grp_str[INET_ADDRSTRLEN];

	prefix_mcast_inet4_dump("<src?>", sg->src, src_str, sizeof(src_str));
	prefix_mcast_inet4_dump("<grp?>", sg->grp, grp_str, sizeof(grp_str));
	snprintf(sg_str, PREFIX_SG_STR_LEN, "(%s,%s)", src_str, grp_str);

	return sg_str;
}

struct prefix *prefix_new(void)
{
	struct prefix *p;

	p = XCALLOC(MTYPE_PREFIX, sizeof *p);
	return p;
}

void prefix_free_lists(void *arg)
{
	struct prefix *p = arg;

	prefix_free(&p);
}

/* Free prefix structure. */
void prefix_free(struct prefix **p)
{
	XFREE(MTYPE_PREFIX, *p);
	*p = NULL;
}

/* Utility function to convert ipv4 prefixes to Classful prefixes */
void apply_classful_mask_ipv4(struct prefix_ipv4 *p)
{

	uint32_t destination;

	destination = ntohl(p->prefix.s_addr);

	if (p->prefixlen == IPV4_MAX_PREFIXLEN)
		;
	/* do nothing for host routes */
	else if (IN_CLASSC(destination)) {
		p->prefixlen = 24;
		apply_mask_ipv4(p);
	} else if (IN_CLASSB(destination)) {
		p->prefixlen = 16;
		apply_mask_ipv4(p);
	} else {
		p->prefixlen = 8;
		apply_mask_ipv4(p);
	}
}

in_addr_t ipv4_network_addr(in_addr_t hostaddr, int masklen)
{
	struct in_addr mask;

	masklen2ip(masklen, &mask);
	return hostaddr & mask.s_addr;
}

in_addr_t ipv4_broadcast_addr(in_addr_t hostaddr, int masklen)
{
	struct in_addr mask;

	masklen2ip(masklen, &mask);
	return (masklen != IPV4_MAX_PREFIXLEN - 1) ?
						   /* normal case */
		       (hostaddr | ~mask.s_addr)
						   :
						   /* special case for /31 */
		       (hostaddr ^ ~mask.s_addr);
}

/* Utility function to convert ipv4 netmask to prefixes
   ex.) "1.1.0.0" "255.255.0.0" => "1.1.0.0/16"
   ex.) "1.0.0.0" NULL => "1.0.0.0/8"                   */
int netmask_str2prefix_str(const char *net_str, const char *mask_str,
			   char *prefix_str)
{
	struct in_addr network;
	struct in_addr mask;
	uint8_t prefixlen;
	uint32_t destination;
	int ret;

	ret = inet_aton(net_str, &network);
	if (!ret)
		return 0;

	if (mask_str) {
		ret = inet_aton(mask_str, &mask);
		if (!ret)
			return 0;

		prefixlen = ip_masklen(mask);
	} else {
		destination = ntohl(network.s_addr);

		if (network.s_addr == 0)
			prefixlen = 0;
		else if (IN_CLASSC(destination))
			prefixlen = 24;
		else if (IN_CLASSB(destination))
			prefixlen = 16;
		else if (IN_CLASSA(destination))
			prefixlen = 8;
		else
			return 0;
	}

	sprintf(prefix_str, "%s/%d", net_str, prefixlen);

	return 1;
}

/* Utility function for making IPv6 address string. */
const char *inet6_ntoa(struct in6_addr addr)
{
	static char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
	return buf;
}

/* converts to internal representation of mac address
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF
 * if mac parameter is null, then check only
 */
int prefix_str2mac(const char *str, struct ethaddr *mac)
{
	unsigned int a[6];
	int i;

	if (!str)
		return 0;

	if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", a + 0, a + 1, a + 2, a + 3,
		   a + 4, a + 5)
	    != 6) {
		/* error in incoming str length */
		return 0;
	}
	/* valid mac address */
	if (!mac)
		return 1;
	for (i = 0; i < 6; ++i)
		mac->octet[i] = a[i] & 0xff;
	return 1;
}

char *prefix_mac2str(const struct ethaddr *mac, char *buf, int size)
{
	char *ptr;

	if (!mac)
		return NULL;
	if (!buf)
		ptr = XMALLOC(MTYPE_TMP, ETHER_ADDR_STRLEN * sizeof(char));
	else {
		assert(size >= ETHER_ADDR_STRLEN);
		ptr = buf;
	}
	snprintf(ptr, (ETHER_ADDR_STRLEN), "%02x:%02x:%02x:%02x:%02x:%02x",
		 (uint8_t)mac->octet[0], (uint8_t)mac->octet[1],
		 (uint8_t)mac->octet[2], (uint8_t)mac->octet[3],
		 (uint8_t)mac->octet[4], (uint8_t)mac->octet[5]);
	return ptr;
}

unsigned prefix_hash_key(const void *pp)
{
	struct prefix copy;

	if (((struct prefix *)pp)->family == AF_FLOWSPEC) {
		uint32_t len;
		void *temp;

		/* make sure *all* unused bits are zero,
		 * particularly including alignment /
		 * padding and unused prefix bytes.
		 */
		memset(&copy, 0, sizeof(copy));
		prefix_copy(&copy, (struct prefix *)pp);
		len = jhash((void *)copy.u.prefix_flowspec.ptr,
			    copy.u.prefix_flowspec.prefixlen,
			    0x55aa5a5a);
		temp = (void *)copy.u.prefix_flowspec.ptr;
		XFREE(MTYPE_PREFIX_FLOWSPEC, temp);
		copy.u.prefix_flowspec.ptr = (uintptr_t)NULL;
		return len;
	}
	/* make sure *all* unused bits are zero, particularly including
	 * alignment /
	 * padding and unused prefix bytes. */
	memset(&copy, 0, sizeof(copy));
	prefix_copy(&copy, (struct prefix *)pp);
	return jhash(&copy,
		     offsetof(struct prefix, u.prefix) + PSIZE(copy.prefixlen),
		     0x55aa5a5a);
}

/* converts to internal representation of esi
 * returns 1 on success, 0 otherwise
 * format accepted: aa:aa:aa:aa:aa:aa:aa:aa:aa:aa
 * if esi parameter is null, then check only
 */
int str_to_esi(const char *str, esi_t *esi)
{
	int i;
	unsigned int a[ESI_BYTES];

	if (!str)
		return 0;

	if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x",
		   a + 0, a + 1, a + 2, a + 3,
		   a + 4, a + 5, a + 6, a + 7,
		   a + 8, a + 9)
	    != ESI_BYTES) {
		/* error in incoming str length */
		return 0;
	}

	/* valid ESI */
	if (!esi)
		return 1;
	for (i = 0; i < ESI_BYTES; ++i)
		esi->val[i] = a[i] & 0xff;
	return 1;
}

char *esi_to_str(const esi_t *esi, char *buf, int size)
{
	char *ptr;

	if (!esi)
		return NULL;
	if (!buf)
		ptr = XMALLOC(MTYPE_TMP, ESI_STR_LEN * sizeof(char));
	else {
		assert(size >= ESI_STR_LEN);
		ptr = buf;
	}

	snprintf(ptr, ESI_STR_LEN,
		 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		 esi->val[0], esi->val[1], esi->val[2],
		 esi->val[3], esi->val[4], esi->val[5],
		 esi->val[6], esi->val[7], esi->val[8],
		 esi->val[9]);
	return ptr;
}

printfrr_ext_autoreg_p("I4", printfrr_i4)
static ssize_t printfrr_i4(char *buf, size_t bsz, const char *fmt,
			   int prec, const void *ptr)
{
	inet_ntop(AF_INET, ptr, buf, bsz);
	return 2;
}

printfrr_ext_autoreg_p("I6", printfrr_i6)
static ssize_t printfrr_i6(char *buf, size_t bsz, const char *fmt,
			   int prec, const void *ptr)
{
	inet_ntop(AF_INET6, ptr, buf, bsz);
	return 2;
}

printfrr_ext_autoreg_p("FX", printfrr_pfx)
static ssize_t printfrr_pfx(char *buf, size_t bsz, const char *fmt,
			    int prec, const void *ptr)
{
	prefix2str(ptr, buf, bsz);
	return 2;
}

printfrr_ext_autoreg_p("SG4", printfrr_psg)
static ssize_t printfrr_psg(char *buf, size_t bsz, const char *fmt,
			    int prec, const void *ptr)
{
	const struct prefix_sg *sg = ptr;
	struct fbuf fb = { .buf = buf, .pos = buf, .len = bsz - 1 };

	if (sg->src.s_addr == INADDR_ANY)
		bprintfrr(&fb, "(*,");
	else
		bprintfrr(&fb, "(%pI4,", &sg->src);

	if (sg->grp.s_addr == INADDR_ANY)
		bprintfrr(&fb, "*)");
	else
		bprintfrr(&fb, "%pI4)", &sg->grp);

	fb.pos[0] = '\0';
	return 3;
}
