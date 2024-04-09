// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - LSP TX Queuing logic
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FRRouting (FRR)
 */
#include <zebra.h>

#include "hash.h"
#include "jhash.h"

#include "isisd/isisd.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_tx_queue.h"

DEFINE_MTYPE_STATIC(ISISD, TX_QUEUE, "ISIS TX Queue");
DEFINE_MTYPE_STATIC(ISISD, TX_QUEUE_ENTRY, "ISIS TX Queue Entry");

struct isis_tx_queue {
	struct isis_circuit *circuit;
	void (*send_event)(struct isis_circuit *circuit,
			   struct isis_lsp *, enum isis_tx_type);
	struct hash *hash;
};

struct isis_tx_queue_entry {
	struct isis_lsp *lsp;
	enum isis_tx_type type;
	bool is_retry;
	struct event *retry;
	struct isis_tx_queue *queue;
};

static unsigned tx_queue_hash_key(const void *p)
{
	const struct isis_tx_queue_entry *e = p;

	uint32_t id_key = jhash(e->lsp->hdr.lsp_id,
				ISIS_SYS_ID_LEN + 2, 0x55aa5a5a);

	return jhash_1word(e->lsp->level, id_key);
}

static bool tx_queue_hash_cmp(const void *a, const void *b)
{
	const struct isis_tx_queue_entry *ea = a, *eb = b;

	if (ea->lsp->level != eb->lsp->level)
		return false;

	if (memcmp(ea->lsp->hdr.lsp_id, eb->lsp->hdr.lsp_id,
		   ISIS_SYS_ID_LEN + 2))
		return false;

	return true;
}

struct isis_tx_queue *isis_tx_queue_new(
		struct isis_circuit *circuit,
		void(*send_event)(struct isis_circuit *circuit,
				  struct isis_lsp *,
				  enum isis_tx_type))
{
	struct isis_tx_queue *rv = XCALLOC(MTYPE_TX_QUEUE, sizeof(*rv));

	rv->circuit = circuit;
	rv->send_event = send_event;

	rv->hash = hash_create(tx_queue_hash_key, tx_queue_hash_cmp, NULL);
	return rv;
}

static void tx_queue_element_free(void *element)
{
	struct isis_tx_queue_entry *e = element;

	EVENT_OFF(e->retry);

	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

void isis_tx_queue_free(struct isis_tx_queue *queue)
{
	hash_clean_and_free(&queue->hash, tx_queue_element_free);
	XFREE(MTYPE_TX_QUEUE, queue);
}

static struct isis_tx_queue_entry *tx_queue_find(struct isis_tx_queue *queue,
						 struct isis_lsp *lsp)
{
	struct isis_tx_queue_entry e = {
		.lsp = lsp
	};

	return hash_lookup(queue->hash, &e);
}

static void tx_queue_send_event(struct event *thread)
{
	struct isis_tx_queue_entry *e = EVENT_ARG(thread);
	struct isis_tx_queue *queue = e->queue;

	event_add_timer(master, tx_queue_send_event, e, 5, &e->retry);

	if (e->is_retry)
		queue->circuit->area->lsp_rxmt_count++;
	else
		e->is_retry = true;

	queue->send_event(queue->circuit, e->lsp, e->type);
	/* Don't access e here anymore, send_event might have destroyed it */
}

void _isis_tx_queue_add(struct isis_tx_queue *queue,
			struct isis_lsp *lsp,
			enum isis_tx_type type,
			const char *func, const char *file,
			int line)
{
	if (!queue)
		return;

	if (IS_DEBUG_TX_QUEUE) {
		zlog_debug(
			"Add LSP %pLS to %s queue as %s LSP. (From %s %s:%d)",
			lsp->hdr.lsp_id, queue->circuit->interface->name,
			(type == TX_LSP_CIRCUIT_SCOPED) ? "circuit scoped"
							: "regular",
			func, file, line);
	}

	struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e) {
		e = XCALLOC(MTYPE_TX_QUEUE_ENTRY, sizeof(*e));
		e->lsp = lsp;
		e->queue = queue;

		struct isis_tx_queue_entry *inserted;
		inserted = hash_get(queue->hash, e, hash_alloc_intern);
		assert(inserted == e);
	}

	e->type = type;

	EVENT_OFF(e->retry);
	event_add_event(master, tx_queue_send_event, e, 0, &e->retry);

	e->is_retry = false;
}

void _isis_tx_queue_del(struct isis_tx_queue *queue, struct isis_lsp *lsp,
			const char *func, const char *file, int line)
{
	if (!queue)
		return;

	struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e)
		return;

	if (IS_DEBUG_TX_QUEUE) {
		zlog_debug("Remove LSP %pLS from %s queue. (From %s %s:%d)",
			   lsp->hdr.lsp_id, queue->circuit->interface->name,
			   func, file, line);
	}

	EVENT_OFF(e->retry);

	hash_release(queue->hash, e);
	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

unsigned long isis_tx_queue_len(struct isis_tx_queue *queue)
{
	if (!queue)
		return 0;

	return hashcount(queue->hash);
}

void isis_tx_queue_clean(struct isis_tx_queue *queue)
{
	hash_clean(queue->hash, tx_queue_element_free);
}
