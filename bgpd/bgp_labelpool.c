/*
 * BGP Label Pool - Manage label chunk allocations from zebra asynchronously
 *
 * Copyright (C) 2018 LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "zclient.h"
#include "mpls.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_labelpool.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_route.h"

/*
 * Definitions and external declarations.
 */
extern struct zclient *zclient;

/*
 * Remember where pool data are kept
 */
static struct labelpool *lp;

/* request this many labels at a time from zebra */
#define LP_CHUNK_SIZE	50

DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CHUNK, "BGP Label Chunk")
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_FIFO, "BGP Label FIFO item")
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CB, "BGP Dynamic Label Assignment")
DEFINE_MTYPE_STATIC(BGPD, BGP_LABEL_CBQ, "BGP Dynamic Label Callback")

struct lp_chunk {
	uint32_t	first;
	uint32_t	last;
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

DECLARE_LIST(lp_fifo, struct lp_fifo, fifo)

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
	XFREE(MTYPE_BGP_LABEL_CHUNK, goner);
}

void bgp_lp_init(struct thread_master *master, struct labelpool *pool)
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
}

/* check if a label callback was for a BGP LU path, and if so, unlock it */
static void check_bgp_lu_cb_unlock(struct lp_lcb *lcb)
{
	if (lcb->type == LP_TYPE_BGP_LU)
		bgp_path_info_unlock(lcb->labelid);
}

/* check if a label callback was for a BGP LU path, and if so, lock it */
static void check_bgp_lu_cb_lock(struct lp_lcb *lcb)
{
	if (lcb->type == LP_TYPE_BGP_LU)
		bgp_path_info_lock(lcb->labelid);
}

void bgp_lp_finish(void)
{
	struct lp_fifo *lf;
	struct work_queue_item *item, *titem;

	if (!lp)
		return;

	skiplist_free(lp->ledger);
	lp->ledger = NULL;

	skiplist_free(lp->inuse);
	lp->inuse = NULL;

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
	 * Linear search is not efficient but should be executed infrequently.
	 */
	for (ALL_LIST_ELEMENTS_RO(lp->chunks, node, chunk)) {
		uintptr_t lbl;

		if (debug)
			zlog_debug("%s: chunk first=%u last=%u",
				__func__, chunk->first, chunk->last);

		for (lbl = chunk->first; lbl <= chunk->last; ++lbl) {
			/* labelid is key to all-request "ledger" list */
			if (!skiplist_insert(lp->inuse, (void *)lbl, labelid)) {
				/*
				 * Success
				 */
				return lbl;
			}
		}
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
 * (that is, a requestor does not need to call lp_get() again if it is
 * notified via callback that its label has been lost: it will eventually
 * get another callback with a new label assignment).
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

		/* if this is a LU request, lock path info before queueing */
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
	/* if this is a LU request, lock path info before queueing */
	check_bgp_lu_cb_lock(lcb);

	lp_fifo_add_tail(&lp->requests, lf);

	if (lp_fifo_count(&lp->requests) > lp->pending_count) {
		if (!zclient || zclient->sock < 0)
			return;
		if (!zclient_send_get_label_chunk(zclient, 0, LP_CHUNK_SIZE,
						  MPLS_LABEL_BASE_ANY))
			lp->pending_count += LP_CHUNK_SIZE;
	}
}

void bgp_lp_release(
	int		type,
	void		*labelid,
	mpls_label_t	label)
{
	struct lp_lcb *lcb;

	if (!skiplist_search(lp->ledger, labelid, (void **)&lcb)) {
		if (label == lcb->label && type == lcb->type) {
			uintptr_t lbl = label;

			/* no longer in use */
			skiplist_delete(lp->inuse, (void *)lbl, NULL);

			/* no longer requested */
			skiplist_delete(lp->ledger, labelid, NULL);
		}
	}
}

/*
 * zebra response giving us a chunk of labels
 */
void bgp_lp_event_chunk(uint8_t keep, uint32_t first, uint32_t last)
{
	struct lp_chunk *chunk;
	int debug = BGP_DEBUG(labelpool, LABELPOOL);
	struct lp_fifo *lf;

	if (last < first) {
		flog_err(EC_BGP_LABEL,
			 "%s: zebra label chunk invalid: first=%u, last=%u",
			 __func__, first, last);
		return;
	}

	chunk = XCALLOC(MTYPE_BGP_LABEL_CHUNK, sizeof(struct lp_chunk));

	chunk->first = first;
	chunk->last = last;

	listnode_add(lp->chunks, chunk);

	lp->pending_count -= (last - first + 1);

	if (debug) {
		zlog_debug("%s: %zu pending requests", __func__,
			lp_fifo_count(&lp->requests));
	}

	while ((lf = lp_fifo_first(&lp->requests))) {

		struct lp_lcb *lcb;
		void *labelid = lf->lcb.labelid;

		if (skiplist_search(lp->ledger, labelid, (void **)&lcb)) {
			/* request no longer in effect */

			if (debug) {
				zlog_debug("%s: labelid %p: request no longer in effect",
						__func__, labelid);
			}
			goto finishedrequest;
		}

		/* have LCB */
		if (lcb->label != MPLS_LABEL_NONE) {
			/* request already has a label */
			if (debug) {
				zlog_debug("%s: labelid %p: request already has a label: %u=0x%x, lcb=%p",
						__func__, labelid,
						lcb->label, lcb->label, lcb);
			}
			/* if this was a BGP_LU request, unlock path info node
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
		lp_fifo_del(&lp->requests, lf);
		XFREE(MTYPE_BGP_LABEL_FIFO, lf);
	}
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
	int labels_needed;
	int chunks_needed;
	void *labelid;
	struct lp_lcb *lcb;
	int lm_init_ok;

	/*
	 * Get label chunk allocation request dispatched to zebra
	 */
	labels_needed = lp_fifo_count(&lp->requests) +
		skiplist_count(lp->inuse);

	/* round up */
	chunks_needed = (labels_needed / LP_CHUNK_SIZE) + 1;
	labels_needed = chunks_needed * LP_CHUNK_SIZE;

	lm_init_ok = lm_label_manager_connect(zclient, 1) == 0;

	if (!lm_init_ok) {
		zlog_err("%s: label manager connection error", __func__);
		return;
	}

	zclient_send_get_label_chunk(zclient, 0, labels_needed,
				     MPLS_LABEL_BASE_ANY);
	lp->pending_count = labels_needed;

	/*
	 * Invalidate current list of chunks
	 */
	list_delete_all_node(lp->chunks);

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
}
