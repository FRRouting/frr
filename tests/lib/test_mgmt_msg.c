// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * September 28 2026, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2026, LabN Consulting, L.L.C.
 *
 * Tests for connection handling in lib/mgmt_msg.c
 */
#include <zebra.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "debug.h"
#include "frrevent.h"
#include "mgmt_msg.h"
#include "stream.h"

#define MAX_MSG_SZ 4096

struct test_msg {
	struct mgmt_msg_hdr hdr;
	uint64_t payload;
};

static struct event_loop *master;
static struct debug dbg;
static bool done;

static void init_msgs(struct test_msg *m, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		m[i].hdr.marker = MGMT_MSG_MARKER(MGMT_MSG_VERSION_NATIVE);
		m[i].hdr.len = sizeof(*m);
		m[i].payload = i;
	}
}

static void ev_timeout(struct event *event)
{
	fprintf(stderr, "timeout waiting for test to complete\n");
	exit(1);
}

static void run_loop_until_done(void)
{
	struct event *tmr = NULL;
	struct event t;

	done = false;
	event_add_timer(master, ev_timeout, NULL, 5, &tmr);
	while (!done && event_fetch(master, &t))
		event_call(&t);
	event_cancel(&tmr);
}

/* ------------------------------------------------------------------ */
/* Test 1: handler disconnects with more messages queued in the batch */
/* ------------------------------------------------------------------ */

/*
 * Mimics mgmtd's backend adapter: the state is deleted (along with the conn)
 * during notify_disconnect callback.
 */
struct adapter {
	const char *name;
	struct msg_conn *conn;
};

static struct msg_server server;
static int nhandled, nnotify;

static void dih_handle_msg(uint8_t version, uint8_t *data, size_t len, struct msg_conn *conn)
{
	struct adapter *a = conn->user;

	nhandled++;

	/* if this fails we are being called on a deleted adapter */
	assert(a->name);
	assert(len == sizeof(uint64_t));

	/* first message resets the connection */
	msg_conn_disconnect(conn, false);

	/* the connection is closed but verify notify has been deferred */
	assert(nnotify == 0);
	assert(conn->fd == -1);
}

static int dih_notify_disconnect(struct msg_conn *conn)
{
	struct adapter *a = conn->user;

	nnotify++;
	a->name = NULL;
	assert(a->conn == conn);
	msg_server_conn_delete(conn);
	free(a);
	done = true;
	return 0;
}

static struct msg_conn *dih_create(int fd, union sockunion *su)
{
	struct adapter *a = calloc(1, sizeof(*a));

	a->name = "client";
	a->conn = msg_server_conn_create(master, fd, dih_notify_disconnect, dih_handle_msg, 10, 10,
					 MAX_MSG_SZ, a, "test-server");
	return a->conn;
}

static void test_disconnect_in_handler(void)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	struct test_msg m[3];
	char sopath[sizeof(sun.sun_path)];
	int fd;

	snprintfrr(sopath, sizeof(sopath), "/tmp/test_mgmt_msg-%d.sock", getpid());
	unlink(sopath);
	assert(msg_server_init(&server, sopath, master, dih_create, "test-server", &dbg) == 0);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd >= 0);
	strlcpy(sun.sun_path, sopath, sizeof(sun.sun_path));
	assert(connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0);

	/* All messages in a single write so they arrive in one read batch. */
	init_msgs(m, array_size(m));
	assert(write(fd, m, sizeof(m)) == (ssize_t)sizeof(m));

	run_loop_until_done();

	assert(nhandled == 1);
	assert(nnotify == 1);

	close(fd);
	msg_server_cleanup(&server);
	unlink(sopath);

	printf("disconnect-in-handler: OK\n");
}

/* ------------------------------------------------------------ */
/* Test 2: disconnect flushes unsent and unprocessed messages   */
/* ------------------------------------------------------------ */

static int fl_nnotify;

static void fl_handle_msg(uint8_t version, uint8_t *data, size_t len, struct msg_conn *conn)
{
	assert(!"handler must not be called for flushed messages");
}

static int fl_notify_disconnect(struct msg_conn *conn)
{
	fl_nnotify++;
	return 0;
}

static void test_disconnect_flushes_queues(void)
{
	struct mgmt_msg_state *ms;
	struct msg_conn *conn;
	struct test_msg m[2];
	int sv[2];

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	conn = msg_server_conn_create(master, sv[0], fl_notify_disconnect, fl_handle_msg, 10, 10,
				      MAX_MSG_SZ, NULL, "test-pair");
	ms = &conn->mstate;
	init_msgs(m, array_size(m));

	/* Queue outgoing messages, the write event is never run. */
	assert(msg_conn_send_msg(conn, MGMT_MSG_VERSION_NATIVE, &m[0].payload,
				 sizeof(m[0].payload), NULL, false) == 0);
	assert(msg_conn_send_msg(conn, MGMT_MSG_VERSION_NATIVE, &m[1].payload,
				 sizeof(m[1].payload), NULL, false) == 0);
	assert(ms->outs || stream_fifo_head(&ms->outq));
	assert(conn->write_ev);

	/* Receive two complete messages plus a partial header, unprocessed. */
	assert(write(sv[1], m, sizeof(m)) == (ssize_t)sizeof(m));
	assert(write(sv[1], m, 4) == 4);
	assert(mgmt_msg_read(ms, sv[0], false) == MSR_SCHED_BOTH);
	assert(mgmt_msg_read(ms, sv[0], false) == MSR_SCHED_BOTH);
	assert(mgmt_msg_read(ms, sv[0], false) == MSR_SCHED_STREAM);
	assert(ms->inq.count == 2);
	assert(stream_get_endp(ms->ins) == 4);

	msg_conn_disconnect(conn, false);

	assert(fl_nnotify == 1);
	assert(conn->fd == -1);
	assert(!conn->read_ev && !conn->write_ev && !conn->proc_msg_ev);
	/* nothing left to replay on a new connection */
	assert(!ms->outs || stream_get_endp(ms->outs) == 0);
	assert(!stream_fifo_head(&ms->outq));
	/* nothing left to deliver to the handler */
	assert(!stream_fifo_head(&ms->inq));
	assert(stream_get_endp(ms->ins) == 0);

	/* second disconnect is a no-op */
	msg_conn_disconnect(conn, false);
	assert(fl_nnotify == 1);

	msg_server_conn_delete(conn);
	close(sv[1]);

	printf("disconnect-flushes-queues: OK\n");
}

int main(int argc, char **argv)
{
	master = event_master_create(NULL);

	test_disconnect_in_handler();
	test_disconnect_flushes_queues();

	event_master_free(master);
	return 0;
}
