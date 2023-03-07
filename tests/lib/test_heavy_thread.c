// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

/* This programme shows the effects of 'heavy' long-running functions
 * on the cooperative threading model, as demonstrated by heavy.c, and how
 * they can be mitigated using a background thread.
 *
 * Run it with a config file containing 'password whatever', telnet to it
 * (it defaults to port 4000) and enter the 'clear foo string' command.
 * then type whatever and observe that, unlike heavy.c, the vty interface
 * remains responsive.
 */
#include <zebra.h>
#include <math.h>

#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "log.h"

#include "tests.h"

extern struct event_loop *master;

enum { ITERS_FIRST = 0,
       ITERS_ERR = 100,
       ITERS_LATER = 400,
       ITERS_PRINT = 10,
       ITERS_MAX = 1000,
};

struct work_state {
	struct vty *vty;
	char *str;
	int i;
};

static void slow_func(struct vty *vty, const char *str, const int i)
{
	double x = 1;
	int j;

	for (j = 0; j < 300; j++)
		x += sin(x) * j;

	if ((i % ITERS_LATER) == 0)
		printf("%s: %d, temporary error, save this somehow and do it later..\n",
		       __func__, i);

	if ((i % ITERS_ERR) == 0)
		printf("%s: hard error\n", __func__);

	if ((i % ITERS_PRINT) == 0)
		printf("%s did %d, x = %g\n", str, i, x);
}

static void clear_something(struct event *thread)
{
	struct work_state *ws = EVENT_ARG(thread);

	/* this could be like iterating through 150k of route_table
	 * or worse, iterating through a list of peers, to bgp_stop them with
	 * each having 150k route tables to process...
	 */
	while (ws->i < ITERS_MAX) {
		slow_func(ws->vty, ws->str, ws->i);
		ws->i++;
		if (event_should_yield(thread)) {
			event_add_timer_msec(master, clear_something, ws, 0,
					     NULL);
			return;
		}
	}

	/* All done! */
	XFREE(MTYPE_TMP, ws->str);
	XFREE(MTYPE_TMP, ws);
}

DEFUN (clear_foo,
       clear_foo_cmd,
       "clear foo LINE...",
       "clear command\n"
       "arbitrary string\n")
{
	char *str;
	struct work_state *ws;

	if (!argc) {
		vty_out(vty, "%% string argument required\n");
		return CMD_WARNING;
	}

	str = argv_concat(argv, argc, 0);

	ws = XMALLOC(MTYPE_TMP, sizeof(*ws));

	ws->str = XSTRDUP(MTYPE_TMP, str);

	ws->vty = vty;
	ws->i = ITERS_FIRST;

	event_add_timer_msec(master, clear_something, ws, 0, NULL);

	return CMD_SUCCESS;
}

void test_init(void)
{
	install_element(VIEW_NODE, &clear_foo_cmd);
}
