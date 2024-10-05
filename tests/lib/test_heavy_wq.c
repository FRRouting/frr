// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

/* This programme shows the effects of 'heavy' long-running functions
 * on the cooperative threading model.
 *
 * Run it with a config file containing 'password whatever', telnet to it
 * (it defaults to port 4000) and enter the 'clear foo string' command.
 * then type whatever and observe that the vty interface is unresponsive
 * for quite a period of time, due to the clear_something command
 * taking a very long time to complete.
 */
#include <zebra.h>

#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "log.h"
#include "workqueue.h"
#include <math.h>

#include "tests.h"

DEFINE_MGROUP(TEST_HEAVYWQ, "heavy-wq test");
DEFINE_MTYPE_STATIC(TEST_HEAVYWQ, WQ_NODE, "heavy_wq_node");
DEFINE_MTYPE_STATIC(TEST_HEAVYWQ, WQ_NODE_STR, "heavy_wq_node->str");

extern struct event_loop *master;
static struct work_queue *heavy_wq;

struct heavy_wq_node {
	char *str;
	int i;
};

enum { ITERS_FIRST = 0,
       ITERS_ERR = 100,
       ITERS_LATER = 400,
       ITERS_PRINT = 10,
       ITERS_MAX = 1000,
};

static void heavy_wq_add(struct vty *vty, const char *str, int i)
{
	struct heavy_wq_node *hn;

	hn = XCALLOC(MTYPE_WQ_NODE, sizeof(struct heavy_wq_node));

	hn->i = i;
	hn->str = XSTRDUP(MTYPE_WQ_NODE_STR, str);

	work_queue_add(heavy_wq, hn);

	return;
}

static void slow_func_del(struct work_queue *wq, void *data)
{
	struct heavy_wq_node *hn = data;
	assert(hn && hn->str);
	printf("%s: %s\n", __func__, hn->str);
	XFREE(MTYPE_WQ_NODE_STR, hn->str);
	XFREE(MTYPE_WQ_NODE, hn);
}

static wq_item_status slow_func(struct work_queue *wq, void *data)
{
	struct heavy_wq_node *hn = data;
	double x = 1;
	int j;

	assert(hn && hn->str);

	for (j = 0; j < 300; j++)
		x += sin(x) * j;

	if ((hn->i % ITERS_PRINT) == 0)
		printf("%s did %d, x = %g\n", hn->str, hn->i, x);

	return WQ_SUCCESS;
}

static void clear_something(struct vty *vty, const char *str)
{
	int i;

	/* this could be like iterating through 150k of route_table
	 * or worse, iterating through a list of peers, to bgp_stop them with
	 * each having 150k route tables to process...
	 */
	for (i = ITERS_FIRST; i < ITERS_MAX; i++)
		heavy_wq_add(vty, str, i);
}

DEFUN (clear_foo,
       clear_foo_cmd,
       "clear foo LINE...",
       "clear command\n"
       "arbitrary string\n")
{
	char *str;
	if (!argc) {
		vty_out(vty, "%% string argument required\n");
		return CMD_WARNING;
	}

	str = argv_concat(argv, argc, 0);

	clear_something(vty, str);
	XFREE(MTYPE_TMP, str);
	return CMD_SUCCESS;
}

static int heavy_wq_init(void)
{
	heavy_wq = work_queue_new(master, "heavy_work_queue");

	heavy_wq->spec.workfunc = &slow_func;
	heavy_wq->spec.del_item_data = &slow_func_del;
	heavy_wq->spec.max_retries = 3;
	heavy_wq->spec.hold = 1000;

	return 0;
}

void test_init(void)
{
	install_element(VIEW_NODE, &clear_foo_cmd);
	heavy_wq_init();
}
