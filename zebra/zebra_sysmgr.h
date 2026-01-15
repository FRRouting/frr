// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra system manager interface module
 * Copyright (C) 2026 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */

#include <zebra.h>
#include "lib/typesafe.h"

#ifndef _ZEBRA_SYSMGR_H
#define _ZEBRA_SYSMGR_H 1

/*
 * Initialize the module at startup
 */
void zebra_sysmgr_init(void);

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_sysmgr_start(void);

/*
 * Module stop, called from the main pthread. This is synchronous:
 * once it returns, the pthread has stopped and exited.
 */
void zebra_sysmgr_stop(void);

/*
 * Module cleanup, called from the zebra main pthread. When it returns,
 * all module cleanup is complete.
 */
void zebra_sysmgr_finish(void);

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Operations that the system manager can process.
 */
enum sysmgr_op_e {
	SM_OP_NONE = 0,
	SM_OP_TEST_SEND,
};

/*
 * Result codes returned to the zebra main context.
 */
enum zebra_sysmgr_result {
	ZEBRA_SYSMGR_STATUS_NONE = 0,
	ZEBRA_SYSMGR_REQUEST_QUEUED,
	ZEBRA_SYSMGR_REQUEST_SUCCESS,
	ZEBRA_SYSMGR_REQUEST_FAILURE,
};

/*
 * Context blocks are exchanged between zebra and the system manager thread.
 */
PREDECL_DLIST(sysmgr_ctx_list);

struct zebra_sysmgr_ctx;

/* Allocate a context object */
struct zebra_sysmgr_ctx *zebra_sysmgr_ctx_alloc(void);

/*
 * Reset an allocated context object for re-use.
 */
void zebra_sysmgr_ctx_reset(struct zebra_sysmgr_ctx *ctx);

/*
 * Free a context object and set the caller's pointer to NULL.
 */
void zebra_sysmgr_ctx_fini(struct zebra_sysmgr_ctx **pctx);

/* Queue helper with internal mutex */
struct zebra_sysmgr_ctx_q {
	pthread_mutex_t mutex;
	struct sysmgr_ctx_list_head list;
};

void zebra_sysmgr_ctx_q_init(struct zebra_sysmgr_ctx_q *q);
void zebra_sysmgr_ctx_q_fini(struct zebra_sysmgr_ctx_q *q);
void zebra_sysmgr_ctx_q_enqueue(struct zebra_sysmgr_ctx_q *q, struct zebra_sysmgr_ctx *ctx);
struct zebra_sysmgr_ctx *zebra_sysmgr_ctx_q_dequeue(struct zebra_sysmgr_ctx_q *q);
void zebra_sysmgr_ctx_q_append(struct zebra_sysmgr_ctx_q *to, struct sysmgr_ctx_list_head *from);
uint32_t zebra_sysmgr_ctx_q_count(struct zebra_sysmgr_ctx_q *q);

/*
 * Enqueue a context for processing by the sysmgr pthread.
 */
void zebra_sysmgr_enqueue_ctx(struct zebra_sysmgr_ctx *ctx);

const char *zebra_sysmgr_op2str(enum sysmgr_op_e op);

/*
 * Send a test message to the sysmgr pthread.
 */
void zebra_sysmgr_test_send(enum sysmgr_op_e op);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SYSMGR_H */
