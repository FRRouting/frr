// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zlog tests.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 */
#include <zebra.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>

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
	bool seqpacket = true;
	pid_t child, waited;
	struct event_loop *loop;
	struct event evt;

	/* SOCK_SEQPACKET first, and SOCK_DGRAM where it is not supported
	 * (macOS).
	 */
	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, PF_UNSPEC, sockpair);
	if (ret < 0 && (errno == EPROTONOSUPPORT || errno == EPROTOTYPE ||
			errno == ESOCKTNOSUPPORT)) {
		int bufsize = 65536;

		seqpacket = false;
		ret = socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, sockpair);

		if (ret == 0) {
			setsockopt(sockpair[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
			setsockopt(sockpair[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
		}
	}
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

	if (seqpacket) {
		/* this will exit when no events are left to handle, i.e. the
		 * child closes the logging socket (hence SOCK_SEQPACKET)
		 */
		while (event_fetch(loop, &evt))
			event_call(&evt);

		/* no close(), fd is closed by zlog_live handler when it goes
		 * dead
		 */
	}

	waited = waitpid(child, &ret, 0);
	assertf(waited == child, "waitpid(%jd, &ret, 0) = %jd (errno: %m)", (intmax_t)child,
		(intmax_t)waited);
	assertf(WIFEXITED(ret) && WEXITSTATUS(ret) == 0, "ret = %#x", ret);

	if (!seqpacket) {
		char peek;

		/* SOCK_DGRAM gives no close notification, but the child has
		 * exited now, so everything it logged is queued on the socket.
		 */
		while (recv(sockpair[0], &peek, 1, MSG_PEEK | MSG_DONTWAIT) > 0) {
			if (!event_fetch(loop, &evt))
				break;
			event_call(&evt);
		}
		close(sockpair[0]);
	}

	event_master_free(loop);

	return true;
}

#ifdef HAVE_POSIX_FALLOCATE
/* replaces libc's posix_fallocate() in this program, to make it fail */
static int test_fallocate_err;
static unsigned int test_fallocate_calls;

int posix_fallocate(int fd, off_t offset, off_t len)
{
	test_fallocate_calls++;
	return test_fallocate_err;
}
#endif

/* log target: counts messages, notes an error with the expected text */
static struct zlog_target test_target;
static unsigned int test_target_nmsgs;
static const char *test_target_errtext;
static bool test_target_errseen;

static void test_target_logfn(struct zlog_target *zt, struct zlog_msg *msgs[], size_t nmsgs)
{
	char text[256];
	const char *p;
	size_t len;

	for (size_t i = 0; i < nmsgs; i++) {
		test_target_nmsgs++;

		/* message text is not NUL terminated */
		p = zlog_msg_text(msgs[i], &len);
		snprintfrr(text, sizeof(text), "%.*s", (int)len, p);
		if (zlog_msg_prio(msgs[i]) == LOG_ERR && strstr(text, test_target_errtext))
			test_target_errseen = true;
	}
}

static unsigned int test_count_files(const char *path)
{
	struct dirent *ent;
	unsigned int count = 0;
	DIR *dir;

	dir = opendir(path);
	assertf(dir, "opendir(%s): %m", path);

	while ((ent = readdir(dir)))
		if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, ".."))
			count++;

	closedir(dir);
	return count;
}

static bool test_tls_check(bool cond, const char *errtext, const char *what)
{
	if (!cond) {
		printf("tls buffer, \"%s\": %s\n", errtext, what);
		fflush(stdout);
	}
	return cond;
}

/*
 * zlog_tls_buffer_init() keeps the log buffer in its file if the space was
 * reserved, or if it cannot be reserved on this system or filesystem.  On any
 * other error it must log the error, remove the file and use the anonymous
 * buffer.  An info message is held until the flush only if there is a buffer.
 */
static bool test_zlog_tls_buffer(void)
{
	static const struct {
		int err;
		bool file;
	} cases[] = {
#ifdef HAVE_POSIX_FALLOCATE
		{ ENOSPC, false },
		{ EINVAL, true },
#endif
		{ EOPNOTSUPP, true },
	};
	char dir[] = "/tmp/test_zlog.XXXXXX";
	char errtext[128];
	unsigned int nfiles, nmsgs;
	bool file, ok = true;

	assertf(mkdtemp(dir), "mkdtemp(%s): %m", dir);
	zlog_tmpdirfd = open(dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	assertf(zlog_tmpdirfd >= 0, "open(%s): %m", dir);

	zlog_aux_init(NULL, LOG_DEBUG);

	test_target.prio_min = LOG_DEBUG;
	test_target.logfn = test_target_logfn;
	zlog_target_replace(NULL, &test_target);

	for (unsigned int i = 0; i < array_size(cases); i++) {
		file = cases[i].file;
		nfiles = file ? 1 : 0;
#ifdef HAVE_POSIX_FALLOCATE
		test_fallocate_err = cases[i].err;
		test_fallocate_calls = 0;
#endif
		snprintfrr(errtext, sizeof(errtext), "%s", strerror(cases[i].err));
		test_target_errtext = errtext;
		test_target_errseen = false;

		zlog_tls_buffer_init();

#ifdef HAVE_POSIX_FALLOCATE
		ok &= test_tls_check(test_fallocate_calls == 1, errtext,
				     "posix_fallocate() was not called once");
#endif
		ok &= test_tls_check(test_target_errseen == !file, errtext,
				     file ? "an error was logged" : "the error was not logged");
		ok &= test_tls_check(test_count_files(dir) == nfiles, errtext,
				     file ? "no buffer file" : "a buffer file was left");

		nmsgs = test_target_nmsgs;
		zlog_info("test tls buffer after \"%s\"", errtext);
		ok &= test_tls_check(test_target_nmsgs == nmsgs, errtext,
				     "the message was not held in a buffer");
		zlog_tls_buffer_flush();
		ok &= test_tls_check(test_target_nmsgs == nmsgs + 1, errtext,
				     "the message did not come out with the flush");

		zlog_tls_buffer_fini();
		ok &= test_tls_check(test_count_files(dir) == 0, errtext,
				     "the buffer file was not removed");
	}

	zlog_target_replace(&test_target, NULL);

	close(zlog_tmpdirfd);
	zlog_tmpdirfd = -1;
	rmdir(dir);

	return ok;
}

static const struct zlog_test {
	bool (*testfn)(void);
	const char *name;
} tests[] = {
	{ test_zlog_hexdump, "hexdump" },
	{ test_zlog_recirculate, "recirculate" },
	{ test_zlog_tls_buffer, "tls buffer" },
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
