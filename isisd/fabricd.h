/*
 * IS-IS Rout(e)ing protocol - OpenFabric extensions
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FRRouting (FRR)
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

#define FABRICD_DEFAULT_CSNP_DELAY 500

struct fabricd;

struct isis_circuit;
struct isis_area;
struct isis_spftree;
struct isis_lsp;
struct vty;

struct fabricd *fabricd_new(struct isis_area *area);
void fabricd_finish(struct fabricd *f);
void fabricd_initial_sync_hello(struct isis_circuit *circuit);
bool fabricd_initial_sync_is_complete(struct isis_area *area);
bool fabricd_initial_sync_is_in_progress(struct isis_area *area);
struct isis_circuit *fabricd_initial_sync_circuit(struct isis_area *area);
void fabricd_initial_sync_finish(struct isis_area *area);
void fabricd_run_spf(struct isis_area *area);
struct isis_spftree *fabricd_spftree(struct isis_area *area);
void fabricd_configure_tier(struct isis_area *area, uint8_t tier);
uint8_t fabricd_tier(struct isis_area *area);
int fabricd_write_settings(struct isis_area *area, struct vty *vty);
void fabricd_lsp_flood(struct isis_lsp *lsp, struct isis_circuit *circuit);
void fabricd_trigger_csnp(struct isis_area *area, bool circuit_scoped);
struct list *fabricd_ip_addrs(struct isis_circuit *circuit);
void fabricd_lsp_free(struct isis_lsp *lsp);
void fabricd_update_lsp_no_flood(struct isis_lsp *lsp,
				 struct isis_circuit *circuit);
void fabricd_configure_triggered_csnp(struct isis_area *area, int delay,
				      bool always_send_csnp);
void fabricd_init(void);
void isis_vty_daemon_init(void);

#endif
