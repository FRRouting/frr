/*
 * IS-IS Rout(e)ing protocol - LSP TX Queuing logic
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
#ifndef ISIS_TX_QUEUE_H
#define ISIS_TX_QUEUE_H

enum isis_tx_type {
	TX_LSP_NORMAL = 0,
	TX_LSP_CIRCUIT_SCOPED
};

struct isis_tx_queue;

struct isis_tx_queue *isis_tx_queue_new(void *arg,
					void(*send_event)(void *arg,
							  struct isis_lsp *,
							  enum isis_tx_type));

void isis_tx_queue_free(struct isis_tx_queue *queue);

void isis_tx_queue_add(struct isis_tx_queue *queue,
		       struct isis_lsp *lsp,
		       enum isis_tx_type type);

void isis_tx_queue_del(struct isis_tx_queue *queue, struct isis_lsp *lsp);

unsigned long isis_tx_queue_len(struct isis_tx_queue *queue);

void isis_tx_queue_clean(struct isis_tx_queue *queue);

#endif
