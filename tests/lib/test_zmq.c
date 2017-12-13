/*
 * ZeroMQ event test
 * Copyright (C) 2017  David Lamparter, for NetDEF, Inc.
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
#include "memory.h"
#include "sigevent.h"
#include "frr_zmq.h"

DEFINE_MTYPE_STATIC(LIB, TESTBUF, "zmq test buffer")
DEFINE_MTYPE_STATIC(LIB, ZMQMSG, "zmq message")

static struct thread_master *master;

static void msg_buf_free(void *data, void *hint)
{
	XFREE(MTYPE_TESTBUF, data);
}

static int recv_delim(void *zmqsock)
{
	/* receive delim */
	zmq_msg_t zdelim;
	int more;
	zmq_msg_init(&zdelim);
	zmq_msg_recv(&zdelim, zmqsock, 0);
	more = zmq_msg_more(&zdelim);
	zmq_msg_close(&zdelim);
	return more;
}
static void send_delim(void *zmqsock)
{
	/* Send delim */
	zmq_msg_t zdelim;
	zmq_msg_init(&zdelim);
	zmq_msg_send(&zdelim, zmqsock, ZMQ_SNDMORE);
	zmq_msg_close(&zdelim);
}
static void run_client(int syncfd)
{
	int i, j;
	char buf[32];
	char dummy;
	void *zmqctx = NULL;
	void *zmqsock;
	int more;

	read(syncfd, &dummy, 1);

	zmqctx = zmq_ctx_new();
	zmq_ctx_set(zmqctx, ZMQ_IPV6, 1);

	zmqsock = zmq_socket(zmqctx, ZMQ_DEALER);
	if (zmq_connect(zmqsock, "tcp://127.0.0.1:17171")) {
		perror("zmq_connect");
		exit(1);
	}

	/* single-part */
	for (i = 0; i < 8; i++) {
		snprintf(buf, sizeof(buf), "msg #%d %c%c%c", i, 'a' + i,
			 'b' + i, 'c' + i);
		printf("client send: %s\n", buf);
		fflush(stdout);
		send_delim(zmqsock);
		zmq_send(zmqsock, buf, strlen(buf) + 1, 0);
		more = recv_delim(zmqsock);
		while (more) {
			zmq_recv(zmqsock, buf, sizeof(buf), 0);
			printf("client recv: %s\n", buf);
			size_t len = sizeof(more);
			if (zmq_getsockopt(zmqsock, ZMQ_RCVMORE, &more, &len))
				break;
		}
	}

	/* multipart */
	for (i = 2; i < 5; i++) {
		printf("---\n");
		send_delim(zmqsock);
		zmq_msg_t part;
		for (j = 1; j <= i; j++) {
			char *dyn = XMALLOC(MTYPE_TESTBUF, 32);

			snprintf(dyn, 32, "part %d/%d", j, i);
			printf("client send: %s\n", dyn);
			fflush(stdout);

			zmq_msg_init_data(&part, dyn, strlen(dyn) + 1,
					  msg_buf_free, NULL);
			zmq_msg_send(&part, zmqsock, j < i ? ZMQ_SNDMORE : 0);
		}

		recv_delim(zmqsock);
		do {
			char *data;

			zmq_msg_recv(&part, zmqsock, 0);
			data = zmq_msg_data(&part);
			more = zmq_msg_more(&part);
			printf("client recv (more: %d): %s\n", more, data);
		} while (more);
		zmq_msg_close(&part);
	}

	/* write callback */
	printf("---\n");
	snprintf(buf, 32, "Done receiving");
	printf("client send: %s\n", buf);
	fflush(stdout);
	send_delim(zmqsock);
	zmq_send(zmqsock, buf, strlen(buf) + 1, 0);
	/* wait for message from server */
	more = recv_delim(zmqsock);
	while (more) {
		zmq_recv(zmqsock, buf, sizeof(buf), 0);
		printf("client recv: %s\n", buf);
		size_t len = sizeof(more);
		if (zmq_getsockopt(zmqsock, ZMQ_RCVMORE, &more, &len))
			break;
	}

	zmq_close(zmqsock);
	zmq_ctx_term(zmqctx);
}

static struct frrzmq_cb *cb;

static void recv_id_and_delim(void *zmqsock, zmq_msg_t *msg_id)
{
	/* receive id */
	zmq_msg_init(msg_id);
	zmq_msg_recv(msg_id, zmqsock, 0);
	/* receive delim */
	recv_delim(zmqsock);
}
static void send_id_and_delim(void *zmqsock, zmq_msg_t *msg_id)
{
	/* Send Id */
	zmq_msg_send(msg_id, zmqsock, ZMQ_SNDMORE);
	send_delim(zmqsock);
}
static void serverwritefn(void *arg, void *zmqsock)
{
	zmq_msg_t *msg_id = (zmq_msg_t *)arg;
	char buf[32] = "Test write callback";
	size_t i;

	for (i = 0; i < strlen(buf); i++)
		buf[i] = toupper(buf[i]);
	printf("server send: %s\n", buf);
	fflush(stdout);
	send_id_and_delim(zmqsock, msg_id);
	zmq_send(zmqsock, buf, strlen(buf) + 1, 0);

	/* send just once */
	frrzmq_thread_cancel(&cb, &cb->write);

	zmq_msg_close(msg_id);
	XFREE(MTYPE_ZMQMSG, msg_id);
}
static void serverpartfn(void *arg, void *zmqsock, zmq_msg_t *msg,
			 unsigned partnum)
{
	static int num = 0;
	int more = zmq_msg_more(msg);
	char *in = zmq_msg_data(msg);
	size_t i;
	zmq_msg_t reply;
	char *out;

	/* Id */
	if (partnum == 0) {
		send_id_and_delim(zmqsock, msg);
		return;
	}
	/* Delim */
	if (partnum == 1)
		return;


	printf("server recv part %u (more: %d): %s\n", partnum, more, in);
	fflush(stdout);

	out = XMALLOC(MTYPE_TESTBUF, strlen(in) + 1);
	for (i = 0; i < strlen(in); i++)
		out[i] = toupper(in[i]);
	out[i] = '\0';
	zmq_msg_init_data(&reply, out, strlen(out) + 1, msg_buf_free, NULL);
	zmq_msg_send(&reply, zmqsock, ZMQ_SNDMORE);

	if (more)
		return;

	out = XMALLOC(MTYPE_TESTBUF, 32);
	snprintf(out, 32, "msg# was %u", partnum);
	zmq_msg_init_data(&reply, out, strlen(out) + 1, msg_buf_free, NULL);
	zmq_msg_send(&reply, zmqsock, 0);

	zmq_msg_close(&reply);

	if (++num < 7)
		return;

	/* write callback test */
	char buf[32];
	zmq_msg_t *msg_id = XMALLOC(MTYPE_ZMQMSG, sizeof(zmq_msg_t));
	recv_id_and_delim(zmqsock, msg_id);
	zmq_recv(zmqsock, buf, sizeof(buf), 0);
	printf("server recv: %s\n", buf);
	fflush(stdout);

	frrzmq_thread_add_write_msg(master, serverwritefn, NULL, msg_id,
				    zmqsock, &cb);
}

static void serverfn(void *arg, void *zmqsock)
{
	static int num = 0;

	zmq_msg_t msg_id;
	char buf[32];
	size_t i;

	recv_id_and_delim(zmqsock, &msg_id);
	zmq_recv(zmqsock, buf, sizeof(buf), 0);

	printf("server recv: %s\n", buf);
	fflush(stdout);
	for (i = 0; i < strlen(buf); i++)
		buf[i] = toupper(buf[i]);
	send_id_and_delim(zmqsock, &msg_id);
	zmq_msg_close(&msg_id);
	zmq_send(zmqsock, buf, strlen(buf) + 1, 0);

	if (++num < 4)
		return;

	/* change to multipart callback */
	frrzmq_thread_cancel(&cb, &cb->read);
	frrzmq_thread_cancel(&cb, &cb->write);

	frrzmq_thread_add_read_part(master, serverpartfn, NULL, NULL, zmqsock,
				    &cb);
}

static void sigchld(void)
{
	printf("child exited.\n");
	frrzmq_thread_cancel(&cb, &cb->read);
	frrzmq_thread_cancel(&cb, &cb->write);
}

static struct quagga_signal_t sigs[] = {
	{
		.signal = SIGCHLD,
		.handler = sigchld,
	},
};

static void run_server(int syncfd)
{
	void *zmqsock;
	char dummy = 0;
	struct thread t;

	master = thread_master_create(NULL);
	signal_init(master, array_size(sigs), sigs);
	frrzmq_init();

	zmqsock = zmq_socket(frrzmq_context, ZMQ_ROUTER);
	if (zmq_bind(zmqsock, "tcp://*:17171")) {
		perror("zmq_bind");
		exit(1);
	}

	frrzmq_thread_add_read_msg(master, serverfn, NULL, NULL, zmqsock, &cb);

	write(syncfd, &dummy, sizeof(dummy));
	while (thread_fetch(master, &t))
		thread_call(&t);

	zmq_close(zmqsock);
	frrzmq_finish();
	thread_master_free(master);
	log_memstats_stderr("test");
}

int main(void)
{
	int syncpipe[2];
	pid_t child;

	if (pipe(syncpipe)) {
		perror("pipe");
		exit(1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		exit(1);
	} else if (child == 0) {
		run_client(syncpipe[0]);
		exit(0);
	}

	run_server(syncpipe[1]);
	exit(0);
}
