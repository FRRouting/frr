// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD data plane listener.
 *
 * A minimal stand-in for a real BFD data plane, used by the topology
 * tests. It accepts the bfdd data plane connection, tracks the sessions
 * bfdd registers, reports them up, answers session counter requests,
 * and dumps what it has seen on SIGUSR1 so a test can inspect it.
 *
 * It runs no BFD state machine and sends no BFD packets: a session is
 * declared up as soon as it is registered. That is enough for the
 * daemon to treat it as established, which is what lets a test reach
 * the code paths that only run when a data plane is attached.
 *
 * Copyright (C) 2026 Abdul Wasey <awasey8905@gmail.com>
 */

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "lib/libfrr.h"

#include "bfddp_packet.h"

XREF_SETUP();

#define BFD_DPLANE_DEFAULT_PORT 50700
#define BFD_DPLANE_MAX_SESSIONS 256
#define BFD_DPLANE_MSG_TYPES	8
#define BFD_DPLANE_BUFSIZ	65536

static const char *const msgtype_str[BFD_DPLANE_MSG_TYPES] = {
	"ECHO_REQUEST",		"ECHO_REPLY",	    "DP_ADD_SESSION",
	"DP_DELETE_SESSION",	"BFD_STATE_CHANGE", "DP_REQUEST_SESSION_COUNTERS",
	"BFD_SESSION_COUNTERS", "UNKNOWN",
};

struct listener_glob {
	FILE *output_file;
	const char *dump_file;
	int server_sock;
	int client_sock;
	bool connected;

	unsigned long connections;
	unsigned long msg_count[BFD_DPLANE_MSG_TYPES];
	unsigned long counter_replies;
	unsigned long state_changes;
	unsigned long bytes_in;

	/* Handed out as the remote discriminator, one per session. */
	uint32_t next_rid;

	uint32_t sessions[BFD_DPLANE_MAX_SESSIONS];
	size_t session_count;
};

static struct listener_glob glob_space;
static struct listener_glob *glob = &glob_space;

static const char *get_timestamp(void)
{
	static char buf[64];
	time_t now = time(NULL);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

	return buf;
}

static bool session_add(uint32_t lid)
{
	size_t i;

	for (i = 0; i < glob->session_count; i++)
		if (glob->sessions[i] == lid)
			return false;

	if (glob->session_count >= BFD_DPLANE_MAX_SESSIONS)
		return false;

	glob->sessions[glob->session_count++] = lid;

	return true;
}

static void session_del(uint32_t lid)
{
	size_t i;

	for (i = 0; i < glob->session_count; i++) {
		if (glob->sessions[i] != lid)
			continue;

		glob->sessions[i] = glob->sessions[glob->session_count - 1];
		glob->session_count--;
		return;
	}
}

/* Signal handler for SIGUSR1: write everything seen so far. */
static void sigusr1_handler(int signum)
{
	FILE *out = glob->output_file;
	FILE *dump_fp = NULL;
	size_t i;

	(void)signum;

	if (glob->dump_file) {
		dump_fp = fopen(glob->dump_file, "w");
		if (dump_fp) {
			out = dump_fp;
			setbuf(dump_fp, NULL);
		}
	}

	fprintf(out, "\n=== BFD Data Plane Listener Dump ===\n");
	fprintf(out, "Timestamp: %s\n", get_timestamp());
	fprintf(out, "Connections accepted: %lu\n", glob->connections);
	fprintf(out, "Connection state: %s\n", glob->connected ? "connected" : "disconnected");
	fprintf(out, "Bytes received: %lu\n", glob->bytes_in);
	fprintf(out, "Counter replies sent: %lu\n", glob->counter_replies);
	fprintf(out, "State changes sent: %lu\n", glob->state_changes);

	fprintf(out, "Messages received:\n");
	for (i = 0; i < BFD_DPLANE_MSG_TYPES; i++)
		fprintf(out, "  %s: %lu\n", msgtype_str[i], glob->msg_count[i]);

	fprintf(out, "Sessions registered: %zu\n", glob->session_count);
	for (i = 0; i < glob->session_count; i++)
		fprintf(out, "  lid: %u\n", glob->sessions[i]);

	fprintf(out, "====================================\n\n");
	fflush(out);

	if (dump_fp)
		fclose(dump_fp);
}

FRR_NORETURN
static void sigterm_handler(int signum)
{
	(void)signum;

	if (glob->client_sock >= 0)
		close(glob->client_sock);
	if (glob->server_sock >= 0)
		close(glob->server_sock);

	exit(0);
}

static bool create_listen_sock(int port, int *sock_p)
{
	int sock;
	int one = 1;
	struct sockaddr_in addr = {};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
		return false;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
		fprintf(stderr, "Failed to set SO_REUSEADDR: %s\n", strerror(errno));
		close(sock);
		return false;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		fprintf(stderr, "Failed to bind to port %d: %s\n", port, strerror(errno));
		close(sock);
		return false;
	}

	if (listen(sock, 5)) {
		fprintf(stderr, "Failed to listen: %s\n", strerror(errno));
		close(sock);
		return false;
	}

	*sock_p = sock;

	return true;
}

/*
 * Answer a counter request. The values are all zero: the tests care that
 * a well formed reply arrives and that the connection survives, not what
 * the numbers are.
 */
static bool send_counters_reply(int sock, uint16_t id, uint32_t lid)
{
	struct bfddp_message msg = {};
	uint16_t len = sizeof(struct bfddp_message_header) + sizeof(struct bfddp_session_counters);

	msg.header.version = BFD_DP_VERSION;
	msg.header.type = htons(BFD_SESSION_COUNTERS);
	msg.header.id = id;
	msg.header.length = htons(len);
	msg.data.session_counters.lid = lid;

	if (write(sock, &msg, len) != len) {
		fprintf(glob->output_file, "Failed to send counters: %s\n", strerror(errno));
		return false;
	}

	glob->counter_replies++;

	return true;
}

static bool send_echo_reply(int sock, const struct bfddp_message *req)
{
	struct bfddp_message msg = {};
	uint16_t len = sizeof(struct bfddp_message_header) + sizeof(struct bfddp_echo);

	msg.header.version = BFD_DP_VERSION;
	msg.header.type = htons(ECHO_REPLY);
	msg.header.id = req->header.id;
	msg.header.length = htons(len);
	msg.data.echo = req->data.echo;

	return write(sock, &msg, len) == len;
}

/*
 * Report a session as up.
 *
 * A real data plane runs the BFD state machine and tells the daemon when
 * a session changes state. This one has no peer to talk to, so it simply
 * declares the session up as soon as it is registered and echoes the
 * timers back. That is enough for the daemon to treat the session as
 * established, which is what the tests need.
 */
static bool send_state_change(int sock, const struct bfddp_session *session)
{
	struct bfddp_message msg = {};
	uint16_t len = sizeof(struct bfddp_message_header) + sizeof(struct bfddp_state_change);

	msg.header.version = BFD_DP_VERSION;
	msg.header.type = htons(BFD_STATE_CHANGE);
	msg.header.id = 0; /* asynchronous, not a reply */
	msg.header.length = htons(len);

	msg.data.state.lid = session->lid;
	msg.data.state.rid = htonl(glob->next_rid++);
	msg.data.state.state = STATE_UP;
	msg.data.state.diagnostics = 0;
	msg.data.state.detection_multiplier = session->detect_mult;
	msg.data.state.desired_tx = session->min_tx;
	msg.data.state.required_rx = session->min_rx;
	msg.data.state.required_echo_rx = 0;

	if (write(sock, &msg, len) != len) {
		fprintf(glob->output_file, "Failed to send state change: %s\n", strerror(errno));
		return false;
	}

	glob->state_changes++;

	return true;
}

static void handle_message(int sock, const struct bfddp_message *msg)
{
	uint16_t type = ntohs(msg->header.type);

	if (type < BFD_DPLANE_MSG_TYPES - 1)
		glob->msg_count[type]++;
	else
		glob->msg_count[BFD_DPLANE_MSG_TYPES - 1]++;

	switch (type) {
	case ECHO_REQUEST:
		send_echo_reply(sock, msg);
		break;
	case DP_ADD_SESSION:
		if (session_add(ntohl(msg->data.session.lid)))
			send_state_change(sock, &msg->data.session);
		break;
	case DP_DELETE_SESSION:
		session_del(ntohl(msg->data.session.lid));
		break;
	case DP_REQUEST_SESSION_COUNTERS:
		send_counters_reply(sock, msg->header.id, msg->data.counters_req.lid);
		break;
	default:
		break;
	}
}

static void handle_connection(int sock)
{
	uint8_t buf[BFD_DPLANE_BUFSIZ];
	size_t buflen = 0;

	while (true) {
		ssize_t rv;
		size_t offset = 0;

		rv = read(sock, buf + buflen, sizeof(buf) - buflen);
		if (rv == 0) {
			fprintf(glob->output_file, "Connection closed\n");
			break;
		}
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			fprintf(glob->output_file, "Read failed: %s\n", strerror(errno));
			break;
		}

		buflen += (size_t)rv;
		glob->bytes_in += (size_t)rv;

		while (buflen - offset >= sizeof(struct bfddp_message_header)) {
			struct bfddp_message msg;
			struct bfddp_message_header hdr;
			uint16_t msglen;

			/*
			 * Copy rather than cast: the message starts at an
			 * arbitrary offset in the byte buffer, and the
			 * structures hold 32 and 64 bit fields that must
			 * not be read unaligned.
			 */
			memcpy(&hdr, buf + offset, sizeof(hdr));
			msglen = ntohs(hdr.length);

			if (hdr.version != BFD_DP_VERSION || msglen < sizeof(hdr) ||
			    msglen > sizeof(msg)) {
				fprintf(glob->output_file, "Framing error: version %d length %d\n",
					hdr.version, msglen);
				return;
			}

			if (buflen - offset < msglen)
				break;

			memcpy(&msg, buf + offset, msglen);
			handle_message(sock, &msg);
			offset += msglen;
		}

		if (offset) {
			memmove(buf, buf + offset, buflen - offset);
			buflen -= offset;
		}

		/*
		 * A message larger than the buffer cannot be assembled, and
		 * the protocol has none that big.
		 */
		if (buflen == sizeof(buf)) {
			fprintf(glob->output_file, "Buffer full with an incomplete message\n");
			return;
		}
	}
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	bool fork_daemon = false;
	const char *output_file = NULL;
	int port = BFD_DPLANE_DEFAULT_PORT;
	int r;

	memset(glob, 0, sizeof(*glob));
	glob->output_file = stdout;
	glob->server_sock = -1;
	glob->client_sock = -1;
	glob->next_rid = 1;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		fprintf(stderr, "Failed to set up SIGUSR1 handler: %s\n", strerror(errno));
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) < 0 || sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGHUP, &sa, NULL) < 0) {
		fprintf(stderr, "Failed to set up signal handlers: %s\n", strerror(errno));
		exit(1);
	}

	signal(SIGPIPE, SIG_IGN);

	while ((r = getopt(argc, argv, "do:p:z:")) != -1) {
		switch (r) {
		case 'd':
			fork_daemon = true;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'z':
			glob->dump_file = optarg;
			break;
		}
	}

	if (output_file) {
		glob->output_file = fopen(output_file, "w");
		if (!glob->output_file) {
			fprintf(stderr, "Failed to open output file %s: %s\n", output_file,
				strerror(errno));
			exit(1);
		}
	}

	setbuf(glob->output_file, NULL);

	/*
	 * Bind before forking. The daemon that connects to us is started
	 * as soon as the parent exits, so the socket has to be accepting
	 * by then or that first connection attempt is refused.
	 */
	if (!create_listen_sock(port, &glob->server_sock))
		exit(1);

	if (fork_daemon) {
		if (fork())
			exit(0);

		if (glob->dump_file) {
			char *copy = strdup(glob->dump_file);
			char pid_path[PATH_MAX];
			FILE *pid_file;

			snprintf(pid_path, sizeof(pid_path), "%s/bfd_dplane_listener.pid",
				 dirname(copy));

			pid_file = fopen(pid_path, "w");
			if (pid_file) {
				fprintf(pid_file, "%d\n", getpid());
				fclose(pid_file);
			} else {
				fprintf(stderr, "Failed to write PID file %s: %s\n", pid_path,
					strerror(errno));
			}
			free(copy);
		}
	}

	fprintf(glob->output_file, "Listening on 127.0.0.1:%d\n", port);

	while (true) {
		struct sockaddr_in from = {};
		socklen_t fromlen = sizeof(from);
		int sock;

		sock = accept(glob->server_sock, (struct sockaddr *)&from, &fromlen);
		if (sock < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "Failed to accept: %s\n", strerror(errno));
			exit(1);
		}

		glob->connections++;
		glob->connected = true;
		glob->client_sock = sock;
		fprintf(glob->output_file, "Connection %lu accepted\n", glob->connections);

		handle_connection(sock);

		glob->connected = false;
		glob->client_sock = -1;
		close(sock);
	}

	return 0;
}
