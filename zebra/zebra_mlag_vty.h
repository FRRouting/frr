/* Zebra Mlag vty Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __ZEBRA_MLAG_VTY_CODE__
#define __ZEBRA_MLAG_VTY_CODE__

#ifdef __cplusplus
extern "C" {
#endif

extern int32_t zebra_mlag_test_mlag_internal(const char *none,
					     const char *primary,
					     const char *secondary);

extern void zebra_mlag_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
