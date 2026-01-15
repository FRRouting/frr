// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra system manager interface module
 * Copyright (C) 2026 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */

#include <zebra.h>

#include "lib/frr_pthread.h"
#include "log.h"
#include "memory.h"
#include "frrevent.h"

#include "zebra/zebra_sysmgr.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_router.h"

static struct zebra_sysmgr_globals {
	_Atomic uint32_t run;
	struct frr_pthread *pthread;
	struct event_loop *master;
	struct event *t_work;
	struct zebra_sysmgr_ctx_q in_q;
	struct zebra_sysmgr_ctx_q out_q;
	struct event *t_results;
} zsysmgr;

DEFINE_MTYPE_STATIC(ZEBRA, SYSMGR_CTX, "System manager context");

static void zebra_sysmgr_process_from_sysmgr_in_master(struct event *event);

struct zebra_sysmgr_ctx {
	enum sysmgr_op_e op;
	enum zebra_sysmgr_result status;
	uint64_t corr_id;
	union {
		struct {
			uint32_t flags;
		} generic;
		struct {
			enum sysmgr_op_e send_op;
		} test;
	} u;

	struct sysmgr_ctx_list_item entries;
};

DECLARE_DLIST(sysmgr_ctx_list, struct zebra_sysmgr_ctx, entries);

const char *zebra_sysmgr_op2str(enum sysmgr_op_e op)
{
	switch (op) {
	case SM_OP_NONE:
		return "NONE";
	case SM_OP_TEST_SEND:
		return "TEST_SEND";
	}

	return "UNKNOWN";
}

struct zebra_sysmgr_ctx *zebra_sysmgr_ctx_alloc(void)
{
	struct zebra_sysmgr_ctx *ctx;

	ctx = XCALLOC(MTYPE_SYSMGR_CTX, sizeof(*ctx));
	ctx->status = ZEBRA_SYSMGR_STATUS_NONE;

	return ctx;
}

void zebra_sysmgr_ctx_reset(struct zebra_sysmgr_ctx *ctx)
{
	if (!ctx)
		return;

	memset(ctx, 0, sizeof(*ctx));
}

void zebra_sysmgr_ctx_fini(struct zebra_sysmgr_ctx **pctx)
{
	if (!pctx || !*pctx)
		return;

	XFREE(MTYPE_SYSMGR_CTX, *pctx);
	*pctx = NULL;
}

void zebra_sysmgr_ctx_q_init(struct zebra_sysmgr_ctx_q *q)
{
	pthread_mutex_init(&q->mutex, NULL);
	sysmgr_ctx_list_init(&q->list);
}

void zebra_sysmgr_ctx_q_fini(struct zebra_sysmgr_ctx_q *q)
{
	pthread_mutex_destroy(&q->mutex);
}

void zebra_sysmgr_ctx_q_enqueue(struct zebra_sysmgr_ctx_q *q, struct zebra_sysmgr_ctx *ctx)
{
	pthread_mutex_lock(&q->mutex);
	sysmgr_ctx_list_add_tail(&q->list, ctx);
	pthread_mutex_unlock(&q->mutex);
}

struct zebra_sysmgr_ctx *zebra_sysmgr_ctx_q_dequeue(struct zebra_sysmgr_ctx_q *q)
{
	struct zebra_sysmgr_ctx *ctx;

	pthread_mutex_lock(&q->mutex);
	ctx = sysmgr_ctx_list_pop(&q->list);
	pthread_mutex_unlock(&q->mutex);

	return ctx;
}

void zebra_sysmgr_ctx_q_append(struct zebra_sysmgr_ctx_q *to, struct sysmgr_ctx_list_head *from)
{
	pthread_mutex_lock(&to->mutex);
	while (true) {
		struct zebra_sysmgr_ctx *ctx = sysmgr_ctx_list_pop(from);

		if (!ctx)
			break;
		sysmgr_ctx_list_add_tail(&to->list, ctx);
	}
	pthread_mutex_unlock(&to->mutex);
}

uint32_t zebra_sysmgr_ctx_q_count(struct zebra_sysmgr_ctx_q *q)
{
	uint32_t count;

	pthread_mutex_lock(&q->mutex);
	count = sysmgr_ctx_list_count(&q->list);
	pthread_mutex_unlock(&q->mutex);

	return count;
}

static void sysmgr_thread_loop(struct event *event)
{
	struct zebra_sysmgr_ctx *ctx;

	if (!atomic_load_explicit(&zsysmgr.run, memory_order_relaxed))
		return;

	while ((ctx = zebra_sysmgr_ctx_q_dequeue(&zsysmgr.in_q)) != NULL) {
		switch (ctx->op) {
		case SM_OP_TEST_SEND: {
			struct zebra_sysmgr_ctx *reply = zebra_sysmgr_ctx_alloc();

			reply->op = ctx->u.test.send_op;
			reply->status = ZEBRA_SYSMGR_REQUEST_SUCCESS;
			reply->corr_id = ctx->corr_id;
			reply->u = ctx->u;

			zebra_sysmgr_ctx_q_enqueue(&zsysmgr.out_q, reply);
			event_add_event(zrouter.master, zebra_sysmgr_process_from_sysmgr_in_master,
					NULL, 0, &zsysmgr.t_results);
		}
			zlog_debug("sysmgr: received %s (response op %s)",
				   zebra_sysmgr_op2str(ctx->op),
				   zebra_sysmgr_op2str(ctx->u.test.send_op));
			break;
		case SM_OP_NONE:
		default:
			break;
		}

		zebra_sysmgr_ctx_fini(&ctx);
	}
}

void zebra_sysmgr_init(void)
{
	memset(&zsysmgr, 0, sizeof(zsysmgr));
	zebra_sysmgr_ctx_q_init(&zsysmgr.in_q);
	zebra_sysmgr_ctx_q_init(&zsysmgr.out_q);
}

void zebra_sysmgr_start(void)
{
	struct frr_pthread_attr pattr = { .start = frr_pthread_attr_default.start,
					  .stop = frr_pthread_attr_default.stop };

	zsysmgr.pthread = frr_pthread_new(&pattr, "Zebra System Manager thread", "zebra_sysmgr");

	zsysmgr.master = zsysmgr.pthread->master;

	atomic_store_explicit(&zsysmgr.run, 1, memory_order_relaxed);

	event_add_event(zsysmgr.master, sysmgr_thread_loop, NULL, 0, &zsysmgr.t_work);

	frr_pthread_run(zsysmgr.pthread, NULL);
}

void zebra_sysmgr_stop(void)
{
	if (!zsysmgr.pthread)
		return;

	atomic_store_explicit(&zsysmgr.run, 0, memory_order_relaxed);

	frr_pthread_stop(zsysmgr.pthread, NULL);
	frr_pthread_destroy(zsysmgr.pthread);
	zsysmgr.pthread = NULL;
	zsysmgr.master = NULL;
}

void zebra_sysmgr_finish(void)
{
	zebra_sysmgr_ctx_q_fini(&zsysmgr.in_q);
	zebra_sysmgr_ctx_q_fini(&zsysmgr.out_q);
}

static void zebra_sysmgr_process_from_sysmgr_in_master(struct event *event)
{
	struct zebra_sysmgr_ctx *ctx;

	while ((ctx = zebra_sysmgr_ctx_q_dequeue(&zsysmgr.out_q)) != NULL) {
		switch (ctx->op) {
		case SM_OP_TEST_SEND:
			zlog_debug("sysmgr: main received response op %s",
				   zebra_sysmgr_op2str(ctx->op));
			break;
		case SM_OP_NONE:
		default:
			break;
		}

		zebra_sysmgr_ctx_fini(&ctx);
	}
}

void zebra_sysmgr_enqueue_ctx(struct zebra_sysmgr_ctx *ctx)
{
	if (!ctx)
		return;

	zebra_sysmgr_ctx_q_enqueue(&zsysmgr.in_q, ctx);

	if (zsysmgr.master)
		event_add_event(zsysmgr.master, sysmgr_thread_loop, NULL, 0, &zsysmgr.t_work);
}

void zebra_sysmgr_test_send(enum sysmgr_op_e op)
{
	struct zebra_sysmgr_ctx *ctx = zebra_sysmgr_ctx_alloc();

	ctx->op = SM_OP_TEST_SEND;
	ctx->status = ZEBRA_SYSMGR_REQUEST_QUEUED;
	ctx->u.test.send_op = op;

	zebra_sysmgr_enqueue_ctx(ctx);
}
