/*
 * IS-IS Rout(e)ing protocol - LSP Hash
 *
 * Copyright (C) 2017 Christian Franke
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
#ifndef ISIS_LSP_HASH_H
#define ISIS_LSP_HASH_H

struct isis_lsp_hash;

struct isis_lsp_hash *isis_lsp_hash_new(void);
void isis_lsp_hash_clean(struct isis_lsp_hash *ih);
void isis_lsp_hash_free(struct isis_lsp_hash *ih);
struct isis_lsp *isis_lsp_hash_lookup(struct isis_lsp_hash *ih,
				      struct isis_lsp *lsp);
void isis_lsp_hash_add(struct isis_lsp_hash *ih, struct isis_lsp *lsp);
void isis_lsp_hash_release(struct isis_lsp_hash *ih, struct isis_lsp *lsp);
#endif
