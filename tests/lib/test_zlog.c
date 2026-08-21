// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zlog tests.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 */
#include <zebra.h>
#include <sys/wait.h>

#include "lib/memory.h"
#include "lib/xref.h"
#include "lib/log.h"
#include "lib/network.h"
#include "lib/zlog_targets.h"
#include "lib/zlog_live.h"
#include "lib/zlog_recirculate.h"
#include "lib/frrevent.h"

/* maximum amount of data to hexdump */
#define MAXDATA 16384

/*
 * Test hexdump functionality.
 *
 * At the moment, not crashing is considered success.
 */
static bool test_zlog_hexdump(void)
{
	unsigned int nl = 1;

	do {
		uint8_t d[nl];

		for (unsigned int i = 0; i < nl; i++)
			d[i] = frr_weak_random();
		zlog_hexdump(d, nl - 1);

		nl += 1 + (nl / 2);
	} while (nl <= MAXDATA);

	return true;
}

static bool test_zlog_recirculate(void)
{
	int sockpair[2];
	int ret;
	pid_t child, waited;
	struct event_loop *loop;
	struct event evt;

	/* NB: SOCK_DGRAM doesn't give HUP events => use SOCK_SEQPACKET */
	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, PF_UNSPEC, sockpair);
	assertf(ret == 0, "socketpair: %m");

	child = fork();
	assertf(child >= 0, "fork: %m");
	if (child == 0) {
		static struct zlog_live_cfg child_log;

		close(sockpair[0]);
		zlog_live_open_fd(&child_log, LOG_DEBUG, sockpair[1]);
		zlog_info("test from child");
		zlog_info("test %-4100s from child", "truncation");
		exit(0);
	}

	close(sockpair[1]);
	zlog_aux_init(NULL, LOG_DEBUG);

	loop = event_master_create(NULL);
	zlog_recirculate_subscribe(loop, sockpair[0]);

	/* this will exit when no events are left to handle, i.e. the child
	 * closes the logging socket (hence having to use SOCK_SEQPACKET)
	 */
	while (event_fetch(loop, &evt))
		event_call(&evt);

	event_master_free(loop);

	/* no close(), fd is closed by zlog_live handler when it goes dead */

	waited = waitpid(child, &ret, 0);
	assertf(waited == child, "waitpid(%jd, &ret, 0) = %jd (errno: %m)", (intmax_t)child,
		(intmax_t)waited);
	assertf(WIFEXITED(ret) && WEXITSTATUS(ret) == 0, "ret = %#x", ret);

	return true;
}

static const struct zlog_test {
	bool (*testfn)(void);
	const char *name;
} tests[] = {
	{ test_zlog_hexdump, "hexdump" },
	{ test_zlog_recirculate, "recirculate" },
};

XREF_SETUP();

int main(int argc, char **argv)
{
	int rc = 0;

	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	for (unsigned int i = 0; i < array_size(tests); i++) {
		/* clear back to disabled, in case previous test changed it */
		zlog_aux_init(NULL, ZLOG_DISABLED);

		if (tests[i].testfn()) {
			printf("test %s passed\n", tests[i].name);
		} else {
			printf("test %s FAILED\n", tests[i].name);
			rc = 1;
		}
		fflush(stdout);
	}
	return rc;
}
