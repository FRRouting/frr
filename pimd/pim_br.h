/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef PIM_BR_H
#define PIM_BR_H

struct in_addr pim_br_get_pmbr(struct prefix_sg *sg);

void pim_br_set_pmbr(struct prefix_sg *sg, struct in_addr value);
void pim_br_clear_pmbr(struct prefix_sg *sg);

void pim_br_init(void);

extern struct in_addr pim_br_unknown;

#endif
