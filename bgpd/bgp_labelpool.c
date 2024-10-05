// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Label Pool - Manage label chunk allocations from zebra asynchronously
 *
 * Copyright (C) 2018 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "stream.h"
#include "mpls.h"
#include "vty.h"
#include "linklist.h"
#include "skiplist.h"
#include "workqueue.h"
#include "mpls.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_labelpool.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_rd.h"

#define BGP_LABELPOOL_ENABLE_TESTS 0

#include "bgpd/bgp_labelpool_clippy.c"


#if BGP_LABELPOOL_ENABLE_TESTS
static void lptest_init(void);
static void lptest_finish(void);
#endif

static void bgp_sync_label_manager(struct event *e);

/*
 * Remember where pool data are kept
 */
static struct labelpool *lp;

/*
 * Number of labels requested at a time from the zebra label manager.
 * We start small but double the request size each time up to a
 * maximum size.
 *
 * The label space is 20 bits which is shared with other FRR processes
 * on this host, so to avoid greedily requesting a mostly wasted chunk,
 * we limit the chunk size to 1/16 of the label space (that's the -4 bits
 * in the definition below). This limit slightly increases our cost of
 * finding free labels in our allocated chunks.
 */
#define LP_CHUNK_SIZE_MIN 128
#define LP_CHUNK_SIZE_MAX (1 << (20 - 4))

DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CHUNK, "BGP Label Chunk");
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_FIFO, "BGP Label FIFO item");
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CB, "BGP Dynamic Label Assignment");
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CBQ, "BGP Dynamic Label Callback");

struct lp_chunk {
	uint32_t	first;
	uint32_t	last;
	uint32_t nfree;		     /* un-allocated count */
	uint32_t idx_last_allocated; /* start looking here */
	bitfield_t allocated_map;
};

/*
 * label control block
 */
struct lp_lcb {
	mpls_label_t	label;		/* MPLS_LABEL_NONE = not allocated */
	int		type;
	void		*labelid;	/* unique ID */
	/*
	 * callback for label allocation and loss
	 *
	 * allocated: false = lost
	 */
	int		(*cbfunc)(mpls_label_t label, void *lblid, bool alloc);
};

struct lp_fifo {
	struct lp_fifo_item fifo;
	struct lp_lcb	lcb;
};

DECLARE_LIST(lp_fifo, struct lp_fifo, fifo);

struct lp_cbq_item {
	int		(*cbfunc)(mpls_label_t label, void *lblid, bool alloc);
	int		type;
	mpls_label_t	label;
	void		*labelid;
	bool		allocated;	/* false = lost */
};

static wq_item_status lp_cbq_docallback(struct work_queue *wq, void *data)
{
	struct lp_cbq_item *lcbq = data;
	int rc;
	int debug = BGP_DEBUG(labelpool, LABELPOOL);

	if (debug)
		zlog_debug("%s: calling callback with labelid=%p label=%u allocated=%d",
			__func__, lcbq->labelid, lcbq->label, lcbq->allocated);

	if (lcbq->label == MPLS_LABEL_NONE) {
		/* shouldn't happen */
		flog_err(EC_BGP_LABEL, "%s: error: label==MPLS_LABEL_NONE",
			 __func__);
		return WQ_SUCCESS;
	}

	rc = (*(lcbq->cbfunc))(lcbq->label, lcbq->labelid, lcbq->allocated);

	if (lcbq->allocated && rc) {
		/*
		 * Callback rejected allocation. This situation could arise
		 * if there was a label request followed by the requestor
		 * deciding it didn't need the assignment (e.g., config
		 * change) while the reply to the original request (with
		 * label) was in the work queue.
		 */
		if (debug)
			zlog_debug("%s: callback rejected allocation, releasing labelid=%p label=%u",
				__func__, lcbq->labelid, lcbq->label);

		uintptr_t lbl = lcbq->label;
		void *labelid;
		struct lp_lcb *lcb;

		/*
		 * If the rejected label was marked inuse by this labelid,
		 * release the label back to the pool.
		 *
		 * Further, if the rejected label was still assigned to
		 * this labelid in the LCB, delete the LCB.
		 */
		if (!skiplist_search(lp->inuse, (void *)lbl, &labelid)) {
			if (labelid == lcbq->labelid) {
				if (!skiplist_search(lp->ledger, labelid,
					(void **)&lcb)) {
					if (lcbq->label == lcb->label)
						skiplist_delete(lp->ledger,
							labelid, NULL);
				}
				skiplist_delete(lp->inuse, (void *)lbl, NULL);
			}
		}
	}

	return WQ_SUCCESS;
}

static void lp_cbq_item_free(struct work_queue *wq, void *data)
{
	XFREE(MTYPE_BGP_LABEL_CBQ, data);
}

static void lp_lcb_free(void *goner)
{
	XFREE(MTYPE_BGP_LABEL_CB, goner);
}

static void lp_chunk_free(void *goner)
{
	struct lp_chunk *chunk = (struct lp_chunk *)goner;

	bf_free(chunk->allocated_map);
	XFREE(MTYPE_BGP_LABEL_CHUNK, goner);
}

void bgp_lp_init(struct event_loop *master, struct labelpool *pool)
{
	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: entry", __func__);

	lp = pool;	/* Set module pointer to pool data */

	lp->ledger = skiplist_new(0, NULL, lp_lcb_free);
	lp->inuse = skiplist_new(0, NULL, NULL);
	lp->chunks = list_new();
	lp->chunks->del = lp_chunk_free;
	lp_fifo_init(&lp->requests);
	lp->callback_q = work_queue_new(master, "label callbacks");

	lp->callback_q->spec.workfunc = lp_cbq_docallback;
	lp->callback_q->spec.del_item_data = lp_cbq_item_free;
	lp->callback_q->spec.max_retries = 0;

	lp->next_chunksize = LP_CHUNK_SIZE_MIN;

#if BGP_LABELPOOL_ENABLE_TESTS
	lptest_init();
#endif
}

/* check if a label callback was for a BGP LU node, and if so, unlock it */
static void check_bgp_lu_cb_unlock(struct lp_lcb *lcb)
{
	if (lcb->type == LP_TYPE_BGP_LU)
		bgp_dest_unlock_node(lcb->labelid);
}

/* check if a label callback was for a BGP LU node, and if so, lock it */
static void check_bgp_lu_cb_lock(struct lp_lcb *lcb)
{
	if (lcb->type == LP_TYPE_BGP_LU)
		bgp_dest_lock_node(lcb->labelid);
}

void bgp_lp_finish(void)
{
	struct lp_fifo *lf;
	struct work_queue_item *item, *titem;
	struct listnode *node;
	struct lp_chunk *chunk;

#if BGP_LABELPOOL_ENABLE_TESTS
	lptest_finish();
#endif
	if (!lp)
		return;

	skiplist_free(lp->ledger);
	lp->ledger = NULL;

	skiplist_free(lp->inuse);
	lp->inuse = NULL;

	for (ALL_LIST_ELEMENTS_RO(lp->chunks, node, chunk))
		bgp_zebra_release_label_range(chunk->first, chunk->last);

	list_delete(&lp->chunks);

	while ((lf = lp_fifo_pop(&lp->requests))) {
		check_bgp_lu_cb_unlock(&lf->lcb);
		XFREE(MTYPE_BGP_LABEL_FIFO, lf);
	}
	lp_fifo_fini(&lp->requests);

	/* we must unlock path infos for LU callbacks; but we cannot do that
	 * in the deletion callback of the workqueue, as that is also called
	 * to remove an element from the queue after it has been run, resulting
	 * in a double unlock. Hence we need to iterate over our queues and
	 * lists and manually perform the unlocking (ugh)
	 */
	STAILQ_FOREACH_SAFE (item, &lp->callback_q->items, wq, titem)
		check_bgp_lu_cb_unlock(item->data);

	work_queue_free_and_null(&lp->callback_q);

	lp = NULL;
}

static mpls_label_t get_label_from_pool(void *labelid)
{
	struct listnode *node;
	struct lp_chunk *chunk;
	int debug = BGP_DEBUG(labelpool, LABELPOOL);

	/*
	 * Find a free label
	 */
	for (ALL_LIST_ELEMENTS_RO(lp->chunks, node, chunk)) {
		uintptr_t lbl;
		unsigned int index;

		if (debug)
			zlog_debug("%s: chunk first=%u last=%u",
				__func__, chunk->first, chunk->last);

		/*
		 * don't look in chunks with no available labels
		 */
		if (!chunk->nfree)
			continue;

		/*
		 * roll through bitfield starting where we stopped
		 * last time
		 */
		index = bf_find_next_clear_bit_wrap(
			&chunk->allocated_map, chunk->idx_last_allocated + 1,
			0);

		/*
		 * since chunk->nfree is non-zero, we should always get
		 * a valid index
		 */
		assert(index != WORD_MAX);

		lbl = chunk->first + index;
		if (skiplist_insert(lp->inuse, (void *)lbl, labelid)) {
			/* something is very wrong */
			zlog_err("%s: unable to insert inuse label %u (id %p)",
				 __func__, (uint32_t)lbl, labelid);
			return MPLS_LABEL_NONE;
		}

		/*
		 * Success
		 */
		bf_set_bit(chunk->allocated_map, index);
		chunk->idx_last_allocated = index;
		chunk->nfree -= 1;

		return lbl;
	}

	return MPLS_LABEL_NONE;
}

/*
 * Success indicated by value of "label" field in returned LCB
 */
static struct lp_lcb *lcb_alloc(
	int	type,
	void	*labelid,
	int	(*cbfunc)(mpls_label_t label, void *labelid, bool allocated))
{
	/*
	 * Set up label control block
	 */
	struct lp_lcb *new = XCALLOC(MTYPE_BGP_LABEL_CB,
		sizeof(struct lp_lcb));

	new->label = get_label_from_pool(labelid);
	new->type = type;
	new->labelid = labelid;
	new->cbfunc = cbfunc;

	return new;
}

/*
 * Callers who need labels must supply a type, labelid, and callback.
 * The type is a value defined in bgp_labelpool.h (add types as needed).
 * The callback is for asynchronous notification of label allocation.
 * The labelid is passed as an argument to the callback. It should be unique
 * to the requested label instance.
 *
 * If zebra is not connected, callbacks with labels will be delayed
 * until connection is established. If zebra connection is lost after
 * labels have been assigned, existing assignments via this labelpool
 * module will continue until reconnection.
 *
 * When connection to zebra is reestablished, previous label assignments
 * will be invalidated (via callbacks having the "allocated" parameter unset)
 * and new labels will be automatically reassigned by this labelpool module
 * (that is, a requestor does not need to call bgp_lp_get() again if it is
 * notified via callback that its label has been lost: it will eventually
 * get another callback with a new label assignment).
 *
 * The callback function should return 0 to accept the allocation
 * and non-zero to refuse it. The callback function return value is
 * ignored for invalidations (i.e., when the "allocated" parameter is false)
 *
 * Prior requests for a given labelid are detected so that requests and
 * assignments are not duplicated.
 */
void bgp_lp_get(
	int	type,
	void	*labelid,
	int	(*cbfunc)(mpls_label_t label, void *labelid, bool allocated))
{
	struct lp_lcb *lcb;
	int requested = 0;
	int debug = BGP_DEBUG(labelpool, LABELPOOL);

	if (debug)
		zlog_debug("%s: labelid=%p", __func__, labelid);

	/*
	 * Have we seen this request before?
	 */
	if (!skiplist_search(lp->ledger, labelid, (void **)&lcb)) {
		requested = 1;
	} else {
		lcb = lcb_alloc(type, labelid, cbfunc);
		if (debug)
			zlog_debug("%s: inserting lcb=%p label=%u",
				__func__, lcb, lcb->label);
		int rc = skiplist_insert(lp->ledger, labelid, lcb);

		if (rc) {
			/* shouldn't happen */
			flog_err(EC_BGP_LABEL,
				 "%s: can't insert new LCB into ledger list",
				 __func__);
			XFREE(MTYPE_BGP_LABEL_CB, lcb);
			return;
		}
	}

	if (lcb->label != MPLS_LABEL_NONE) {
		/*
		 * Fast path: we filled the request from local pool (or
		 * this is a duplicate request that we filled already).
		 * Enqueue response work item with new label.
		 */
		struct lp_cbq_item *q;

		q = XCALLOC(MTYPE_BGP_LABEL_CBQ, sizeof(struct lp_cbq_item));

		q->cbfunc = lcb->cbfunc;
		q->type = lcb->type;
		q->label = lcb->label;
		q->labelid = lcb->labelid;
		q->allocated = true;

		/* if this is a LU request, lock node before queueing */
		check_bgp_lu_cb_lock(lcb);

		work_queue_add(lp->callback_q, q);

		return;
	}

	if (requested)
		return;

	if (debug)
		zlog_debug("%s: slow path. lcb=%p label=%u",
			__func__, lcb, lcb->label);

	/*
	 * Slow path: we are out of labels in the local pool,
	 * so remember the request and also get another chunk from
	 * the label manager.
	 *
	 * We track number of outstanding label requests: don't
	 * need to get a chunk for each one.
	 */

	struct lp_fifo *lf = XCALLOC(MTYPE_BGP_LABEL_FIFO,
		sizeof(struct lp_fifo));

	lf->lcb = *lcb;
	/* if this is a LU request, lock node before queueing */
	check_bgp_lu_cb_lock(lcb);

	lp_fifo_add_tail(&lp->requests, lf);

	if (lp_fifo_count(&lp->requests) > lp->pending_count) {
		if (!bgp_zebra_request_label_range(MPLS_LABEL_BASE_ANY,
						   lp->next_chunksize, true))
			return;

		lp->pending_count += lp->next_chunksize;
		if ((lp->next_chunksize << 1) <= LP_CHUNK_SIZE_MAX)
			lp->next_chunksize <<= 1;
	}

	event_add_timer(bm->master, bgp_sync_label_manager, NULL, 1,
			&bm->t_bgp_sync_label_manager);
}

void bgp_lp_release(
	int		type,
	void		*labelid,
	mpls_label_t	label)
{
	struct lp_lcb *lcb;

	if (!skiplist_search(lp->ledger, labelid, (void **)&lcb)) {
		if (label == lcb->label && type == lcb->type) {
			struct listnode *node;
			struct lp_chunk *chunk;
			uintptr_t lbl = label;
			bool deallocated = false;

			/* no longer in use */
			skiplist_delete(lp->inuse, (void *)lbl, NULL);

			/* no longer requested */
			skiplist_delete(lp->ledger, labelid, NULL);

			/*
			 * Find the chunk this label belongs to and
			 * deallocate the label
			 */
			for (ALL_LIST_ELEMENTS_RO(lp->chunks, node, chunk)) {
				uint32_t index;

				if ((label < chunk->first) ||
				    (label > chunk->last))
					continue;

				index = label - chunk->first;
				assert(bf_test_index(chunk->allocated_map,
						     index));
				bf_release_index(chunk->allocated_map, index);
				chunk->nfree += 1;
				deallocated = true;
				break;
			}
			assert(deallocated);
			if (deallocated &&
			    chunk->nfree == chunk->last - chunk->first + 1 &&
			    lp_fifo_count(&lp->requests) == 0) {
				bgp_zebra_release_label_range(chunk->first,
							      chunk->last);
				list_delete_node(lp->chunks, node);
				lp_chunk_free(chunk);
				lp->next_chunksize = LP_CHUNK_SIZE_MIN;
			}
		}
	}
}

static void bgp_sync_label_manager(struct event *e)
{
	int debug = BGP_DEBUG(labelpool, LABELPOOL);
	struct lp_fifo *lf;

	while ((lf = lp_fifo_pop(&lp->requests))) {
		struct lp_lcb *lcb;
		void *labelid = lf->lcb.labelid;

		if (skiplist_search(lp->ledger, labelid, (void **)&lcb)) {
			/* request no longer in effect */

			if (debug) {
				zlog_debug("%s: labelid %p: request no longer in effect",
					   __func__, labelid);
			}
			/* if this was a BGP_LU request, unlock node
			 */
			check_bgp_lu_cb_unlock(lcb);
			goto finishedrequest;
		}

		/* have LCB */
		if (lcb->label != MPLS_LABEL_NONE) {
			/* request already has a label */
			if (debug) {
				zlog_debug("%s: labelid %p: request already has a label: %u=0x%x, lcb=%p",
					   __func__, labelid, lcb->label,
					   lcb->label, lcb);
			}
			/* if this was a BGP_LU request, unlock node
			 */
			check_bgp_lu_cb_unlock(lcb);

			goto finishedrequest;
		}

		lcb->label = get_label_from_pool(lcb->labelid);

		if (lcb->label == MPLS_LABEL_NONE) {
			/*
			 * Out of labels in local pool, await next chunk
			 */
			if (debug) {
				zlog_debug("%s: out of labels, await more",
					   __func__);
			}

			lp_fifo_add_tail(&lp->requests, lf);
			event_add_timer(bm->master, bgp_sync_label_manager,
					NULL, 1, &bm->t_bgp_sync_label_manager);
			break;
		}

		/*
		 * we filled the request from local pool.
		 * Enqueue response work item with new label.
		 */
		struct lp_cbq_item *q = XCALLOC(MTYPE_BGP_LABEL_CBQ,
						sizeof(struct lp_cbq_item));

		q->cbfunc = lcb->cbfunc;
		q->type = lcb->type;
		q->label = lcb->label;
		q->labelid = lcb->labelid;
		q->allocated = true;

		if (debug)
			zlog_debug("%s: assigning label %u to labelid %p",
				   __func__, q->label, q->labelid);

		work_queue_add(lp->callback_q, q);

finishedrequest:
		XFREE(MTYPE_BGP_LABEL_FIFO, lf);
	}
}

void bgp_lp_event_chunk(uint32_t first, uint32_t last)
{
	struct lp_chunk *chunk;
	uint32_t labelcount;

	if (last < first) {
		flog_err(EC_BGP_LABEL,
			 "%s: zebra label chunk invalid: first=%u, last=%u",
			 __func__, first, last);
		return;
	}

	chunk = XCALLOC(MTYPE_BGP_LABEL_CHUNK, sizeof(struct lp_chunk));

	labelcount = last - first + 1;

	chunk->first = first;
	chunk->last = last;
	chunk->nfree = labelcount;
	bf_init(chunk->allocated_map, labelcount);

	/*
	 * Optimize for allocation by adding the new (presumably larger)
	 * chunk at the head of the list so it is examined first.
	 */
	listnode_add_head(lp->chunks, chunk);

	lp->pending_count -= labelcount;
}

/*
 * continue using allocated labels until zebra returns
 */
void bgp_lp_event_zebra_down(void)
{
	/* rats. */
}

/*
 * Inform owners of previously-allocated labels that their labels
 * are not valid. Request chunk from zebra large enough to satisfy
 * previously-allocated labels plus any outstanding requests.
 */
void bgp_lp_event_zebra_up(void)
{
	unsigned int labels_needed;
	unsigned int chunks_needed;
	void *labelid;
	struct lp_lcb *lcb;

	lp->reconnect_count++;
	/*
	 * Get label chunk allocation request dispatched to zebra
	 */
	labels_needed = lp_fifo_count(&lp->requests) +
		skiplist_count(lp->inuse);

	if (labels_needed > lp->next_chunksize) {
		while ((lp->next_chunksize < labels_needed) &&
		       (lp->next_chunksize << 1 <= LP_CHUNK_SIZE_MAX))

			lp->next_chunksize <<= 1;
	}

	/* round up */
	chunks_needed = (labels_needed + lp->next_chunksize - 1) / lp->next_chunksize;
	labels_needed = chunks_needed * lp->next_chunksize;

	/*
	 * Invalidate current list of chunks
	 */
	list_delete_all_node(lp->chunks);

	if (labels_needed && !bgp_zebra_request_label_range(MPLS_LABEL_BASE_ANY,
							    labels_needed, true))
		return;
	lp->pending_count += labels_needed;

	/*
	 * Invalidate any existing labels and requeue them as requests
	 */
	while (!skiplist_first(lp->inuse, NULL, &labelid)) {

		/*
		 * Get LCB
		 */
		if (!skiplist_search(lp->ledger, labelid, (void **)&lcb)) {

			if (lcb->label != MPLS_LABEL_NONE) {
				/*
				 * invalidate
				 */
				struct lp_cbq_item *q;

				q = XCALLOC(MTYPE_BGP_LABEL_CBQ,
					sizeof(struct lp_cbq_item));
				q->cbfunc = lcb->cbfunc;
				q->type = lcb->type;
				q->label = lcb->label;
				q->labelid = lcb->labelid;
				q->allocated = false;
				check_bgp_lu_cb_lock(lcb);
				work_queue_add(lp->callback_q, q);

				lcb->label = MPLS_LABEL_NONE;
			}

			/*
			 * request queue
			 */
			struct lp_fifo *lf = XCALLOC(MTYPE_BGP_LABEL_FIFO,
				sizeof(struct lp_fifo));

			lf->lcb = *lcb;
			check_bgp_lu_cb_lock(lcb);
			lp_fifo_add_tail(&lp->requests, lf);
		}

		skiplist_delete_first(lp->inuse);
	}

	event_add_timer(bm->master, bgp_sync_label_manager, NULL, 1,
			&bm->t_bgp_sync_label_manager);
}

DEFUN(show_bgp_labelpool_summary, show_bgp_labelpool_summary_cmd,
      "show bgp labelpool summary [json]",
      SHOW_STR BGP_STR
      "BGP Labelpool information\n"
      "BGP Labelpool summary\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (!lp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}

	if (uj) {
		json = json_object_new_object();
		json_object_int_add(json, "ledger", skiplist_count(lp->ledger));
		json_object_int_add(json, "inUse", skiplist_count(lp->inuse));
		json_object_int_add(json, "requests",
				    lp_fifo_count(&lp->requests));
		json_object_int_add(json, "labelChunks", listcount(lp->chunks));
		json_object_int_add(json, "pending", lp->pending_count);
		json_object_int_add(json, "reconnects", lp->reconnect_count);
		vty_json(vty, json);
	} else {
		vty_out(vty, "Labelpool Summary\n");
		vty_out(vty, "-----------------\n");
		vty_out(vty, "%-13s %d\n",
			"Ledger:", skiplist_count(lp->ledger));
		vty_out(vty, "%-13s %d\n", "InUse:", skiplist_count(lp->inuse));
		vty_out(vty, "%-13s %zu\n",
			"Requests:", lp_fifo_count(&lp->requests));
		vty_out(vty, "%-13s %d\n",
			"LabelChunks:", listcount(lp->chunks));
		vty_out(vty, "%-13s %d\n", "Pending:", lp->pending_count);
		vty_out(vty, "%-13s %d\n", "Reconnects:", lp->reconnect_count);
	}
	return CMD_SUCCESS;
}

DEFUN(show_bgp_labelpool_ledger, show_bgp_labelpool_ledger_cmd,
      "show bgp labelpool ledger [json]",
      SHOW_STR BGP_STR
      "BGP Labelpool information\n"
      "BGP Labelpool ledger\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_elem = NULL;
	struct lp_lcb *lcb = NULL;
	struct bgp_dest *dest;
	void *cursor = NULL;
	const struct prefix *p;
	int rc, count;

	if (!lp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}

	if (uj) {
		count = skiplist_count(lp->ledger);
		if (!count) {
			vty_out(vty, "{}\n");
			return CMD_SUCCESS;
		}
		json = json_object_new_array();
	} else {
		vty_out(vty, "Prefix                Label\n");
		vty_out(vty, "---------------------------\n");
	}

	for (rc = skiplist_next(lp->ledger, (void **)&dest, (void **)&lcb,
				&cursor);
	     !rc; rc = skiplist_next(lp->ledger, (void **)&dest, (void **)&lcb,
				     &cursor)) {
		if (uj) {
			json_elem = json_object_new_object();
			json_object_array_add(json, json_elem);
		}
		switch (lcb->type) {
		case LP_TYPE_BGP_LU:
			if (!CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED))
				if (uj) {
					json_object_string_add(
						json_elem, "prefix", "INVALID");
					json_object_int_add(json_elem, "label",
							    lcb->label);
				} else
					vty_out(vty, "%-18s         %u\n",
						"INVALID", lcb->label);
			else {
				p = bgp_dest_get_prefix(dest);
				if (uj) {
					json_object_string_addf(
						json_elem, "prefix", "%pFX", p);
					json_object_int_add(json_elem, "label",
							    lcb->label);
				} else
					vty_out(vty, "%-18pFX    %u\n", p,
						lcb->label);
			}
			break;
		case LP_TYPE_VRF:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "VRF");
				json_object_int_add(json_elem, "label",
						    lcb->label);
			} else
				vty_out(vty, "%-18s         %u\n", "VRF",
					lcb->label);

			break;
		case LP_TYPE_NEXTHOP:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "nexthop");
				json_object_int_add(json_elem, "label",
						    lcb->label);
			} else
				vty_out(vty, "%-18s         %u\n", "nexthop",
					lcb->label);
			break;
		case LP_TYPE_BGP_L3VPN_BIND:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "l3vpn-bind");
				json_object_int_add(json_elem, "label",
						    lcb->label);
			} else
				vty_out(vty, "%-18s         %u\n", "l3vpn-bind",
					lcb->label);
			break;
		}
	}
	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN(show_bgp_labelpool_inuse, show_bgp_labelpool_inuse_cmd,
      "show bgp labelpool inuse [json]",
      SHOW_STR BGP_STR
      "BGP Labelpool information\n"
      "BGP Labelpool inuse\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_elem = NULL;
	struct bgp_dest *dest;
	mpls_label_t label;
	struct lp_lcb *lcb;
	void *cursor = NULL;
	const struct prefix *p;
	int rc, count;

	if (!lp) {
		vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}
	if (!lp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}

	if (uj) {
		count = skiplist_count(lp->inuse);
		if (!count) {
			vty_out(vty, "{}\n");
			return CMD_SUCCESS;
		}
		json = json_object_new_array();
	} else {
		vty_out(vty, "Prefix                Label\n");
		vty_out(vty, "---------------------------\n");
	}
	for (rc = skiplist_next(lp->inuse, (void **)&label, (void **)&dest,
				&cursor);
	     !rc; rc = skiplist_next(lp->ledger, (void **)&label,
				     (void **)&dest, &cursor)) {
		if (skiplist_search(lp->ledger, dest, (void **)&lcb))
			continue;

		if (uj) {
			json_elem = json_object_new_object();
			json_object_array_add(json, json_elem);
		}

		switch (lcb->type) {
		case LP_TYPE_BGP_LU:
			if (!CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED))
				if (uj) {
					json_object_string_add(
						json_elem, "prefix", "INVALID");
					json_object_int_add(json_elem, "label",
							    label);
				} else
					vty_out(vty, "INVALID         %u\n",
						label);
			else {
				p = bgp_dest_get_prefix(dest);
				if (uj) {
					json_object_string_addf(
						json_elem, "prefix", "%pFX", p);
					json_object_int_add(json_elem, "label",
							    label);
				} else
					vty_out(vty, "%-18pFX    %u\n", p,
						label);
			}
			break;
		case LP_TYPE_VRF:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "VRF");
				json_object_int_add(json_elem, "label", label);
			} else
				vty_out(vty, "%-18s         %u\n", "VRF",
					label);
			break;
		case LP_TYPE_NEXTHOP:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "nexthop");
				json_object_int_add(json_elem, "label", label);
			} else
				vty_out(vty, "%-18s         %u\n", "nexthop",
					label);
			break;
		case LP_TYPE_BGP_L3VPN_BIND:
			if (uj) {
				json_object_string_add(json_elem, "prefix",
						       "l3vpn-bind");
				json_object_int_add(json_elem, "label", label);
			} else
				vty_out(vty, "%-18s         %u\n", "l3vpn-bind",
					label);
			break;
		}
	}
	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN(show_bgp_labelpool_requests, show_bgp_labelpool_requests_cmd,
      "show bgp labelpool requests [json]",
      SHOW_STR BGP_STR
      "BGP Labelpool information\n"
      "BGP Labelpool requests\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_elem = NULL;
	struct bgp_dest *dest;
	const struct prefix *p;
	struct lp_fifo *item, *next;
	int count;

	if (!lp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}

	if (uj) {
		count = lp_fifo_count(&lp->requests);
		if (!count) {
			vty_out(vty, "{}\n");
			return CMD_SUCCESS;
		}
		json = json_object_new_array();
	} else {
		vty_out(vty, "Prefix         \n");
		vty_out(vty, "----------------\n");
	}

	for (item = lp_fifo_first(&lp->requests); item; item = next) {
		next = lp_fifo_next_safe(&lp->requests, item);
		dest = item->lcb.labelid;
		if (uj) {
			json_elem = json_object_new_object();
			json_object_array_add(json, json_elem);
		}
		switch (item->lcb.type) {
		case LP_TYPE_BGP_LU:
			if (!CHECK_FLAG(dest->flags,
					BGP_NODE_LABEL_REQUESTED)) {
				if (uj)
					json_object_string_add(
						json_elem, "prefix", "INVALID");
				else
					vty_out(vty, "INVALID\n");
			} else {
				p = bgp_dest_get_prefix(dest);
				if (uj)
					json_object_string_addf(
						json_elem, "prefix", "%pFX", p);
				else
					vty_out(vty, "%-18pFX\n", p);
			}
			break;
		case LP_TYPE_VRF:
			if (uj)
				json_object_string_add(json_elem, "prefix",
						       "VRF");
			else
				vty_out(vty, "VRF\n");
			break;
		case LP_TYPE_NEXTHOP:
			if (uj)
				json_object_string_add(json_elem, "prefix",
						       "nexthop");
			else
				vty_out(vty, "Nexthop\n");
			break;
		case LP_TYPE_BGP_L3VPN_BIND:
			if (uj)
				json_object_string_add(json_elem, "prefix",
						       "l3vpn-bind");
			else
				vty_out(vty, "L3VPN-BIND\n");
			break;
		}
	}
	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

DEFUN(show_bgp_labelpool_chunks, show_bgp_labelpool_chunks_cmd,
      "show bgp labelpool chunks [json]",
      SHOW_STR BGP_STR
      "BGP Labelpool information\n"
      "BGP Labelpool chunks\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_elem;
	struct listnode *node;
	struct lp_chunk *chunk;
	int count;

	if (!lp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No existing BGP labelpool\n");
		return (CMD_WARNING);
	}

	if (uj) {
		count = listcount(lp->chunks);
		if (!count) {
			vty_out(vty, "{}\n");
			return CMD_SUCCESS;
		}
		json = json_object_new_array();
	} else {
		vty_out(vty, "%10s %10s %10s %10s\n", "First", "Last", "Size",
			"nfree");
		vty_out(vty, "-------------------------------------------\n");
	}

	for (ALL_LIST_ELEMENTS_RO(lp->chunks, node, chunk)) {
		uint32_t size;

		size = chunk->last - chunk->first + 1;

		if (uj) {
			json_elem = json_object_new_object();
			json_object_array_add(json, json_elem);
			json_object_int_add(json_elem, "first", chunk->first);
			json_object_int_add(json_elem, "last", chunk->last);
			json_object_int_add(json_elem, "size", size);
			json_object_int_add(json_elem, "numberFree",
					    chunk->nfree);
		} else
			vty_out(vty, "%10u %10u %10u %10u\n", chunk->first,
				chunk->last, size, chunk->nfree);
	}
	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

static void show_bgp_nexthop_label_afi(struct vty *vty, afi_t afi,
				       struct bgp *bgp, bool detail)
{
	struct bgp_label_per_nexthop_cache_head *tree;
	struct bgp_label_per_nexthop_cache *iter;
	safi_t safi;
	void *src;
	char buf[PREFIX2STR_BUFFER];
	char labelstr[MPLS_LABEL_STRLEN];
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	struct bgp *bgp_path;
	struct bgp_table *table;
	time_t tbuf;

	vty_out(vty, "Current BGP label nexthop cache for %s, VRF %s\n",
		afi2str(afi), bgp->name_pretty);

	tree = &bgp->mpls_labels_per_nexthop[afi];
	frr_each (bgp_label_per_nexthop_cache, tree, iter) {
		if (afi2family(afi) == AF_INET)
			src = (void *)&iter->nexthop.u.prefix4;
		else
			src = (void *)&iter->nexthop.u.prefix6;

		vty_out(vty, " %s, label %s #paths %u\n",
			inet_ntop(afi2family(afi), src, buf, sizeof(buf)),
			mpls_label2str(1, &iter->label, labelstr,
				       sizeof(labelstr), 0, true),
			iter->path_count);
		if (iter->nh)
			vty_out(vty, "  if %s\n",
				ifindex2ifname(iter->nh->ifindex,
					       iter->nh->vrf_id));
		tbuf = time(NULL) - (monotime(NULL) - iter->last_update);
		vty_out(vty, "  Last update: %s", ctime_r(&tbuf, buf));
		if (!detail)
			continue;
		vty_out(vty, "  Paths:\n");
		LIST_FOREACH (path, &(iter->paths),
			      mplsvpn.blnc.label_nh_thread) {
			dest = path->net;
			table = bgp_dest_table(dest);
			assert(dest && table);
			afi = family2afi(bgp_dest_get_prefix(dest)->family);
			safi = table->safi;
			bgp_path = table->bgp;

			if (dest->pdest) {
				vty_out(vty, "    %d/%d %pBD RD ", afi, safi,
					dest);

				vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
					(struct prefix_rd *)bgp_dest_get_prefix(
						dest->pdest));
				vty_out(vty, " %s flags 0x%x\n",
					bgp_path->name_pretty, path->flags);
			} else
				vty_out(vty, "    %d/%d %pBD %s flags 0x%x\n",
					afi, safi, dest, bgp_path->name_pretty,
					path->flags);
		}
	}
}

DEFPY(show_bgp_nexthop_label, show_bgp_nexthop_label_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] label-nexthop [detail]",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "BGP label per-nexthop table\n"
      "Show detailed information\n")
{
	int idx = 0;
	char *vrf = NULL;
	struct bgp *bgp;
	bool detail = false;
	int afi;

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[++idx]->arg;
		bgp = bgp_lookup_by_name(vrf);
	} else
		bgp = bgp_get_default();

	if (!bgp)
		return CMD_SUCCESS;

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		show_bgp_nexthop_label_afi(vty, afi, bgp, detail);
	return CMD_SUCCESS;
}

#if BGP_LABELPOOL_ENABLE_TESTS
/*------------------------------------------------------------------------
 *			Testing code start
 *------------------------------------------------------------------------*/

DEFINE_MTYPE_STATIC(BGPD, LABELPOOL_TEST, "Label pool test");

#define LPT_STAT_INSERT_FAIL 0
#define LPT_STAT_DELETE_FAIL 1
#define LPT_STAT_ALLOCATED 2
#define LPT_STAT_DEALLOCATED 3
#define LPT_STAT_MAX 4

const char *lpt_counter_names[] = {
	"sl insert failures",
	"sl delete failures",
	"labels allocated",
	"labels deallocated",
};

static uint8_t lpt_generation;
static bool lpt_inprogress;
static struct skiplist *lp_tests;
static unsigned int lpt_test_cb_tcb_lookup_fails;
static unsigned int lpt_release_tcb_lookup_fails;
static unsigned int lpt_test_event_tcb_lookup_fails;
static unsigned int lpt_stop_tcb_lookup_fails;

struct lp_test {
	uint8_t generation;
	unsigned int request_maximum;
	unsigned int request_blocksize;
	uintptr_t request_count; /* match type of labelid */
	int label_type;
	struct skiplist *labels;
	struct timeval starttime;
	struct skiplist *timestamps_alloc;
	struct skiplist *timestamps_dealloc;
	struct event *event_thread;
	unsigned int counter[LPT_STAT_MAX];
};

/* test parameters */
#define LPT_MAX_COUNT 500000  /* get this many labels in all */
#define LPT_BLKSIZE 10000     /* this many at a time, then yield */
#define LPT_TS_INTERVAL 10000 /* timestamp every this many labels */


static int test_cb(mpls_label_t label, void *labelid, bool allocated)
{
	uintptr_t generation;
	struct lp_test *tcb;

	generation = ((uintptr_t)labelid >> 24) & 0xff;

	if (skiplist_search(lp_tests, (void *)generation, (void **)&tcb)) {

		/* couldn't find current test in progress */
		++lpt_test_cb_tcb_lookup_fails;
		return -1; /* reject allocation */
	}

	if (allocated) {
		++tcb->counter[LPT_STAT_ALLOCATED];
		if (!(tcb->counter[LPT_STAT_ALLOCATED] % LPT_TS_INTERVAL)) {
			uintptr_t time_ms;

			time_ms = monotime_since(&tcb->starttime, NULL) / 1000;
			skiplist_insert(tcb->timestamps_alloc,
					(void *)(uintptr_t)tcb
						->counter[LPT_STAT_ALLOCATED],
					(void *)time_ms);
		}
		if (skiplist_insert(tcb->labels, labelid,
				    (void *)(uintptr_t)label)) {
			++tcb->counter[LPT_STAT_INSERT_FAIL];
			return -1;
		}
	} else {
		++tcb->counter[LPT_STAT_DEALLOCATED];
		if (!(tcb->counter[LPT_STAT_DEALLOCATED] % LPT_TS_INTERVAL)) {
			uintptr_t time_ms;

			time_ms = monotime_since(&tcb->starttime, NULL) / 1000;
			skiplist_insert(tcb->timestamps_dealloc,
					(void *)(uintptr_t)tcb
						->counter[LPT_STAT_ALLOCATED],
					(void *)time_ms);
		}
		if (skiplist_delete(tcb->labels, labelid, 0)) {
			++tcb->counter[LPT_STAT_DELETE_FAIL];
			return -1;
		}
	}
	return 0;
}

static void labelpool_test_event_handler(struct event *thread)
{
	struct lp_test *tcb;

	if (skiplist_search(lp_tests, (void *)(uintptr_t)(lpt_generation),
			    (void **)&tcb)) {

		/* couldn't find current test in progress */
		++lpt_test_event_tcb_lookup_fails;
		return;
	}

	/*
	 * request a bunch of labels
	 */
	for (unsigned int i = 0; (i < tcb->request_blocksize) &&
				 (tcb->request_count < tcb->request_maximum);
	     ++i) {

		uintptr_t id;

		++tcb->request_count;

		/*
		 * construct 32-bit id from request_count and generation
		 */
		id = ((uintptr_t)tcb->generation << 24) |
		     (tcb->request_count & 0x00ffffff);
		bgp_lp_get(LP_TYPE_VRF, (void *)id, test_cb);
	}

	if (tcb->request_count < tcb->request_maximum)
		thread_add_event(bm->master, labelpool_test_event_handler, NULL,
				 0, &tcb->event_thread);
}

static void lptest_stop(void)
{
	struct lp_test *tcb;

	if (!lpt_inprogress)
		return;

	if (skiplist_search(lp_tests, (void *)(uintptr_t)(lpt_generation),
			    (void **)&tcb)) {

		/* couldn't find current test in progress */
		++lpt_stop_tcb_lookup_fails;
		return;
	}

	if (tcb->event_thread)
		event_cancel(&tcb->event_thread);

	lpt_inprogress = false;
}

static int lptest_start(struct vty *vty)
{
	struct lp_test *tcb;

	if (lpt_inprogress) {
		vty_out(vty, "test already in progress\n");
		return -1;
	}

	if (skiplist_count(lp_tests) >=
	    (1 << (8 * sizeof(lpt_generation))) - 1) {
		/*
		 * Too many test runs
		 */
		vty_out(vty, "too many tests: clear first\n");
		return -1;
	}

	/*
	 * We pack the generation and request number into the labelid;
	 * make sure they fit.
	 */
	unsigned int n1 = LPT_MAX_COUNT;
	unsigned int sh = 0;
	unsigned int label_bits;

	label_bits = 8 * (sizeof(tcb->request_count) - sizeof(lpt_generation));

	/* n1 should be same type as tcb->request_maximum */
	assert(sizeof(n1) == sizeof(tcb->request_maximum));

	while (n1 >>= 1)
		++sh;
	sh += 1; /* number of bits needed to hold LPT_MAX_COUNT */

	if (sh > label_bits) {
		vty_out(vty,
			"Sorry, test iteration count too big on this platform (LPT_MAX_COUNT %u, need %u bits, but label_bits is only %u)\n",
			LPT_MAX_COUNT, sh, label_bits);
		return -1;
	}

	lpt_inprogress = true;
	++lpt_generation;

	tcb = XCALLOC(MTYPE_LABELPOOL_TEST, sizeof(*tcb));

	tcb->generation = lpt_generation;
	tcb->label_type = LP_TYPE_VRF;
	tcb->request_maximum = LPT_MAX_COUNT;
	tcb->request_blocksize = LPT_BLKSIZE;
	tcb->labels = skiplist_new(0, NULL, NULL);
	tcb->timestamps_alloc = skiplist_new(0, NULL, NULL);
	tcb->timestamps_dealloc = skiplist_new(0, NULL, NULL);
	thread_add_event(bm->master, labelpool_test_event_handler, NULL, 0,
			 &tcb->event_thread);
	monotime(&tcb->starttime);

	skiplist_insert(lp_tests, (void *)(uintptr_t)tcb->generation, tcb);
	return 0;
}

DEFPY(start_labelpool_perf_test, start_labelpool_perf_test_cmd,
      "debug bgp lptest start",
      DEBUG_STR BGP_STR
      "label pool test\n"
      "start\n")
{
	lptest_start(vty);
	return CMD_SUCCESS;
}

static void lptest_print_stats(struct vty *vty, struct lp_test *tcb)
{
	unsigned int i;

	vty_out(vty, "Global Lookup Failures in test_cb: %5u\n",
		lpt_test_cb_tcb_lookup_fails);
	vty_out(vty, "Global Lookup Failures in release: %5u\n",
		lpt_release_tcb_lookup_fails);
	vty_out(vty, "Global Lookup Failures in event:   %5u\n",
		lpt_test_event_tcb_lookup_fails);
	vty_out(vty, "Global Lookup Failures in stop:    %5u\n",
		lpt_stop_tcb_lookup_fails);
	vty_out(vty, "\n");

	if (!tcb) {
		if (skiplist_search(lp_tests, (void *)(uintptr_t)lpt_generation,
				    (void **)&tcb)) {
			vty_out(vty, "Error: can't find test %u\n",
				lpt_generation);
			return;
		}
	}

	vty_out(vty, "Test Generation %u:\n", tcb->generation);

	vty_out(vty, "Counter   Value\n");
	for (i = 0; i < LPT_STAT_MAX; ++i) {
		vty_out(vty, "%20s: %10u\n", lpt_counter_names[i],
			tcb->counter[i]);
	}
	vty_out(vty, "\n");

	if (tcb->timestamps_alloc) {
		void *Key;
		void *Value;
		void *cursor;

		float elapsed;

		vty_out(vty, "%10s %10s\n", "Count", "Seconds");

		cursor = NULL;
		while (!skiplist_next(tcb->timestamps_alloc, &Key, &Value,
				      &cursor)) {

			elapsed = ((float)(uintptr_t)Value) / 1000;

			vty_out(vty, "%10llu %10.3f\n",
				(unsigned long long)(uintptr_t)Key, elapsed);
		}
		vty_out(vty, "\n");
	}
}

DEFPY(show_labelpool_perf_test, show_labelpool_perf_test_cmd,
      "debug bgp lptest show",
      DEBUG_STR BGP_STR
      "label pool test\n"
      "show\n")
{

	if (lp_tests) {
		void *Key;
		void *Value;
		void *cursor;

		cursor = NULL;
		while (!skiplist_next(lp_tests, &Key, &Value, &cursor)) {
			lptest_print_stats(vty, (struct lp_test *)Value);
		}
	} else {
		vty_out(vty, "no test results\n");
	}
	return CMD_SUCCESS;
}

DEFPY(stop_labelpool_perf_test, stop_labelpool_perf_test_cmd,
      "debug bgp lptest stop",
      DEBUG_STR BGP_STR
      "label pool test\n"
      "stop\n")
{

	if (lpt_inprogress) {
		lptest_stop();
		lptest_print_stats(vty, NULL);
	} else {
		vty_out(vty, "no test in progress\n");
	}
	return CMD_SUCCESS;
}

DEFPY(clear_labelpool_perf_test, clear_labelpool_perf_test_cmd,
      "debug bgp lptest clear",
      DEBUG_STR BGP_STR
      "label pool test\n"
      "clear\n")
{

	if (lpt_inprogress) {
		lptest_stop();
	}
	if (lp_tests) {
		while (!skiplist_first(lp_tests, NULL, NULL))
			/* del function of skiplist cleans up tcbs */
			skiplist_delete_first(lp_tests);
	}
	return CMD_SUCCESS;
}

/*
 * With the "release" command, we can release labels at intervals through
 * the ID space. Thus we can to exercise the bitfield-wrapping behavior
 * of the allocator in a subsequent test.
 */
/* clang-format off */
DEFPY(release_labelpool_perf_test, release_labelpool_perf_test_cmd,
      "debug bgp lptest release test GENERATION$generation every (1-5)$every_nth",
      DEBUG_STR
      BGP_STR
      "label pool test\n"
      "release labels\n"
      "\"test\"\n"
      "test number\n"
      "\"every\"\n"
      "label fraction denominator\n")
{
	/* clang-format on */

	unsigned long testnum;
	char *end;
	struct lp_test *tcb;

	testnum = strtoul(generation, &end, 0);
	if (*end) {
		vty_out(vty, "Invalid test number: \"%s\"\n", generation);
		return CMD_SUCCESS;
	}
	if (lpt_inprogress && (testnum == lpt_generation)) {
		vty_out(vty,
			"Error: Test %lu is still in progress (stop first)\n",
			testnum);
		return CMD_SUCCESS;
	}

	if (skiplist_search(lp_tests, (void *)(uintptr_t)testnum,
			    (void **)&tcb)) {

		/* couldn't find current test in progress */
		vty_out(vty, "Error: Can't look up test number: \"%lu\"\n",
			testnum);
		++lpt_release_tcb_lookup_fails;
		return CMD_SUCCESS;
	}

	void *Key, *cKey;
	void *Value, *cValue;
	void *cursor;
	unsigned int iteration;
	int rc;

	cursor = NULL;
	iteration = 0;
	rc = skiplist_next(tcb->labels, &Key, &Value, &cursor);

	while (!rc) {
		cKey = Key;
		cValue = Value;

		/* find next item before we delete this one */
		rc = skiplist_next(tcb->labels, &Key, &Value, &cursor);

		if (!(iteration % every_nth)) {
			bgp_lp_release(tcb->label_type, cKey,
				       (mpls_label_t)(uintptr_t)cValue);
			skiplist_delete(tcb->labels, cKey, NULL);
			++tcb->counter[LPT_STAT_DEALLOCATED];
		}
		++iteration;
	}

	return CMD_SUCCESS;
}

static void lptest_delete(void *val)
{
	struct lp_test *tcb = (struct lp_test *)val;
	void *Key;
	void *Value;
	void *cursor;

	if (tcb->labels) {
		cursor = NULL;
		while (!skiplist_next(tcb->labels, &Key, &Value, &cursor))
			bgp_lp_release(tcb->label_type, Key,
				       (mpls_label_t)(uintptr_t)Value);
		skiplist_free(tcb->labels);
		tcb->labels = NULL;
	}
	if (tcb->timestamps_alloc) {
		cursor = NULL;
		skiplist_free(tcb->timestamps_alloc);
		tcb->timestamps_alloc = NULL;
	}

	if (tcb->timestamps_dealloc) {
		cursor = NULL;
		skiplist_free(tcb->timestamps_dealloc);
		tcb->timestamps_dealloc = NULL;
	}

	if (tcb->event_thread)
		event_cancel(&tcb->event_thread);

	memset(tcb, 0, sizeof(*tcb));

	XFREE(MTYPE_LABELPOOL_TEST, tcb);
}

static void lptest_init(void)
{
	lp_tests = skiplist_new(0, NULL, lptest_delete);
}

static void lptest_finish(void)
{
	if (lp_tests) {
		skiplist_free(lp_tests);
		lp_tests = NULL;
	}
}

/*------------------------------------------------------------------------
 *			Testing code end
 *------------------------------------------------------------------------*/
#endif /* BGP_LABELPOOL_ENABLE_TESTS */

void bgp_lp_vty_init(void)
{
	install_element(VIEW_NODE, &show_bgp_labelpool_summary_cmd);
	install_element(VIEW_NODE, &show_bgp_labelpool_ledger_cmd);
	install_element(VIEW_NODE, &show_bgp_labelpool_inuse_cmd);
	install_element(VIEW_NODE, &show_bgp_labelpool_requests_cmd);
	install_element(VIEW_NODE, &show_bgp_labelpool_chunks_cmd);

#if BGP_LABELPOOL_ENABLE_TESTS
	install_element(ENABLE_NODE, &start_labelpool_perf_test_cmd);
	install_element(ENABLE_NODE, &show_labelpool_perf_test_cmd);
	install_element(ENABLE_NODE, &stop_labelpool_perf_test_cmd);
	install_element(ENABLE_NODE, &release_labelpool_perf_test_cmd);
	install_element(ENABLE_NODE, &clear_labelpool_perf_test_cmd);
#endif /* BGP_LABELPOOL_ENABLE_TESTS */
}

DEFINE_MTYPE_STATIC(BGPD, LABEL_PER_NEXTHOP_CACHE,
		    "BGP Label Per Nexthop entry");

/* The nexthops values are compared to
 * find in the tree the appropriate cache entry
 */
int bgp_label_per_nexthop_cache_cmp(const struct bgp_label_per_nexthop_cache *a,
				    const struct bgp_label_per_nexthop_cache *b)
{
	return prefix_cmp(&a->nexthop, &b->nexthop);
}

struct bgp_label_per_nexthop_cache *
bgp_label_per_nexthop_new(struct bgp_label_per_nexthop_cache_head *tree,
			  struct prefix *nexthop)
{
	struct bgp_label_per_nexthop_cache *blnc;

	blnc = XCALLOC(MTYPE_LABEL_PER_NEXTHOP_CACHE,
		       sizeof(struct bgp_label_per_nexthop_cache));
	blnc->tree = tree;
	blnc->label = MPLS_INVALID_LABEL;
	prefix_copy(&blnc->nexthop, nexthop);
	LIST_INIT(&(blnc->paths));
	bgp_label_per_nexthop_cache_add(tree, blnc);

	return blnc;
}

struct bgp_label_per_nexthop_cache *
bgp_label_per_nexthop_find(struct bgp_label_per_nexthop_cache_head *tree,
			   struct prefix *nexthop)
{
	struct bgp_label_per_nexthop_cache blnc = {};

	if (!tree)
		return NULL;

	memcpy(&blnc.nexthop, nexthop, sizeof(struct prefix));
	return bgp_label_per_nexthop_cache_find(tree, &blnc);
}

void bgp_label_per_nexthop_free(struct bgp_label_per_nexthop_cache *blnc)
{
	if (blnc->label != MPLS_INVALID_LABEL) {
		bgp_zebra_send_nexthop_label(ZEBRA_MPLS_LABELS_DELETE,
					     blnc->label, blnc->nh->ifindex,
					     blnc->nh->vrf_id, ZEBRA_LSP_BGP,
					     &blnc->nexthop, 0, NULL);
		bgp_lp_release(LP_TYPE_NEXTHOP, blnc, blnc->label);
	}
	bgp_label_per_nexthop_cache_del(blnc->tree, blnc);
	if (blnc->nh)
		nexthop_free(blnc->nh);
	blnc->nh = NULL;
	XFREE(MTYPE_LABEL_PER_NEXTHOP_CACHE, blnc);
}

void bgp_label_per_nexthop_init(void)
{
	install_element(VIEW_NODE, &show_bgp_nexthop_label_cmd);
}
