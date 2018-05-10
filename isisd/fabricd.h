/*
 * IS-IS Rout(e)ing protocol - OpenFabric extensions
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
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
#ifndef FABRICD_H
#define FABRICD_H

struct fabricd;

struct isis_circuit;
struct isis_area;
struct isis_spftree;
struct vty;

struct fabricd *fabricd_new(struct isis_area *area);
void fabricd_finish(struct fabricd *f);
void fabricd_initial_sync_hello(struct isis_circuit *circuit);
bool fabricd_initial_sync_is_in_progress(struct isis_area *area);
struct isis_circuit *fabricd_initial_sync_circuit(struct isis_area *area);
void fabricd_initial_sync_finish(struct isis_area *area);
void fabricd_run_spf(struct isis_area *area);
struct isis_spftree *fabricd_spftree(struct isis_area *area);
void fabricd_configure_tier(struct isis_area *area, uint8_t tier);
uint8_t fabricd_tier(struct isis_area *area);
int fabricd_write_settings(struct isis_area *area, struct vty *vty);

#endif
