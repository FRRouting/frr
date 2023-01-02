/* C-Ares integration to Quagga mainloop
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ares.h>
#include <ares_version.h>

#include "vector.h"
#include "thread.h"
#include "lib_errors.h"
#include "resolver.h"
#include "command.h"
#include "xref.h"

XREF_SETUP();

struct resolver_state {
	ares_channel channel;
	struct thread_master *master;
	struct thread *timeout;
	vector read_threads, write_threads;
};

static struct resolver_state state;
static bool resolver_debug;

#define THREAD_RUNNING ((struct thread *)-1)

static void resolver_update_timeouts(struct resolver_state *r);

static int resolver_cb_timeout(struct thread *t)
{
	struct resolver_state *r = THREAD_ARG(t);

	r->timeout = THREAD_RUNNING;
	ares_process(r->channel, NULL, NULL);
	r->timeout = NULL;
	resolver_update_timeouts(r);

	return 0;
}

static int resolver_cb_socket_readable(struct thread *t)
{
	struct resolver_state *r = THREAD_ARG(t);
	int fd = THREAD_FD(t);

	vector_set_index(r->read_threads, fd, THREAD_RUNNING);
	ares_process_fd(r->channel, fd, ARES_SOCKET_BAD);
	if (vector_lookup(r->read_threads, fd) == THREAD_RUNNING) {
		t = NULL;
		thread_add_read(r->master, resolver_cb_socket_readable, r, fd,
				&t);
		vector_set_index(r->read_threads, fd, t);
	}
	resolver_update_timeouts(r);

	return 0;
}

static int resolver_cb_socket_writable(struct thread *t)
{
	struct resolver_state *r = THREAD_ARG(t);
	int fd = THREAD_FD(t);

	vector_set_index(r->write_threads, fd, THREAD_RUNNING);
	ares_process_fd(r->channel, ARES_SOCKET_BAD, fd);
	if (vector_lookup(r->write_threads, fd) == THREAD_RUNNING) {
		t = NULL;
		thread_add_write(r->master, resolver_cb_socket_writable, r, fd,
				 &t);
		vector_set_index(r->write_threads, fd, t);
	}
	resolver_update_timeouts(r);

	return 0;
}

static void resolver_update_timeouts(struct resolver_state *r)
{
	struct timeval *tv, tvbuf;

	if (r->timeout == THREAD_RUNNING)
		return;

	THREAD_OFF(r->timeout);
	tv = ares_timeout(r->channel, NULL, &tvbuf);
	if (tv) {
		unsigned int timeoutms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
		thread_add_timer_msec(r->master, resolver_cb_timeout, r,
				      timeoutms, &r->timeout);
	}
}

static void ares_socket_cb(void *data, ares_socket_t fd, int readable,
			   int writable)
{
	struct resolver_state *r = (struct resolver_state *)data;
	struct thread *t;

	if (readable) {
		t = vector_lookup_ensure(r->read_threads, fd);
		if (!t) {
			thread_add_read(r->master, resolver_cb_socket_readable,
					r, fd, &t);
			vector_set_index(r->read_threads, fd, t);
		}
	} else {
		t = vector_lookup(r->read_threads, fd);
		if (t) {
			if (t != THREAD_RUNNING) {
				THREAD_OFF(t);
			}
			vector_unset(r->read_threads, fd);
		}
	}

	if (writable) {
		t = vector_lookup_ensure(r->write_threads, fd);
		if (!t) {
			thread_add_read(r->master, resolver_cb_socket_writable,
					r, fd, &t);
			vector_set_index(r->write_threads, fd, t);
		}
	} else {
		t = vector_lookup(r->write_threads, fd);
		if (t) {
			if (t != THREAD_RUNNING) {
				THREAD_OFF(t);
			}
			vector_unset(r->write_threads, fd);
		}
	}
}


static void ares_address_cb(void *arg, int status, int timeouts,
			    struct hostent *he)
{
	struct resolver_query *query = (struct resolver_query *)arg;
	union sockunion addr[16];
	void (*callback)(struct resolver_query *, const char *, int,
			 union sockunion *);
	size_t i;

	callback = query->callback;
	query->callback = NULL;

	if (status != ARES_SUCCESS) {
		if (resolver_debug)
			zlog_debug("[%p] Resolving failed (%s)",
				   query, ares_strerror(status));

		callback(query, ares_strerror(status), -1, NULL);
		return;
	}

	for (i = 0; i < array_size(addr) && he->h_addr_list[i] != NULL; i++) {
		memset(&addr[i], 0, sizeof(addr[i]));
		addr[i].sa.sa_family = he->h_addrtype;
		switch (he->h_addrtype) {
		case AF_INET:
			memcpy(&addr[i].sin.sin_addr,
			       (uint8_t *)he->h_addr_list[i], he->h_length);
			break;
		case AF_INET6:
			memcpy(&addr[i].sin6.sin6_addr,
			       (uint8_t *)he->h_addr_list[i], he->h_length);
			break;
		}
	}

	if (resolver_debug)
		zlog_debug("[%p] Resolved with %d results", query, (int)i);

	callback(query, NULL, i, &addr[0]);
}

static int resolver_cb_literal(struct thread *t)
{
	struct resolver_query *query = THREAD_ARG(t);
	void (*callback)(struct resolver_query *, const char *, int,
			 union sockunion *);

	callback = query->callback;
	query->callback = NULL;

	callback(query, ARES_SUCCESS, 1, &query->literal_addr);
	return 0;
}

void resolver_resolve(struct resolver_query *query, int af,
		      const char *hostname,
		      void (*callback)(struct resolver_query *, const char *,
				       int, union sockunion *))
{
	int ret;

	if (query->callback != NULL) {
		flog_err(
			EC_LIB_RESOLVER,
			"Trying to resolve '%s', but previous query was not finished yet",
			hostname);
		return;
	}

	query->callback = callback;
	query->literal_cb = NULL;

	ret = str2sockunion(hostname, &query->literal_addr);
	if (ret == 0) {
		if (resolver_debug)
			zlog_debug("[%p] Resolving '%s' (IP literal)",
				   query, hostname);

		/* for consistency with proper name lookup, don't call the
		 * callback immediately; defer to thread loop
		 */
		thread_add_timer_msec(state.master, resolver_cb_literal,
				      query, 0, &query->literal_cb);
		return;
	}

	if (resolver_debug)
		zlog_debug("[%p] Resolving '%s'", query, hostname);

	ares_gethostbyname(state.channel, hostname, af, ares_address_cb, query);
	resolver_update_timeouts(&state);
}

DEFUN(debug_resolver,
      debug_resolver_cmd,
      "[no] debug resolver",
      NO_STR
      DEBUG_STR
      "Debug DNS resolver actions\n")
{
	resolver_debug = (argc == 2);
	return CMD_SUCCESS;
}

static int resolver_config_write_debug(struct vty *vty);
static struct cmd_node resolver_debug_node = {
	.name = "resolver debug",
	.node = RESOLVER_DEBUG_NODE,
	.prompt = "",
	.config_write = resolver_config_write_debug,
};

static int resolver_config_write_debug(struct vty *vty)
{
	if (resolver_debug)
		vty_out(vty, "debug resolver\n");
	return 1;
}


void resolver_init(struct thread_master *tm)
{
	struct ares_options ares_opts;

	state.master = tm;
	state.read_threads = vector_init(1);
	state.write_threads = vector_init(1);

	ares_opts = (struct ares_options){
		.sock_state_cb = &ares_socket_cb,
		.sock_state_cb_data = &state,
		.timeout = 2,
		.tries = 3,
	};

	ares_init_options(&state.channel, &ares_opts,
			  ARES_OPT_SOCK_STATE_CB | ARES_OPT_TIMEOUT
				  | ARES_OPT_TRIES);

	install_node(&resolver_debug_node);
	install_element(CONFIG_NODE, &debug_resolver_cmd);
	install_element(ENABLE_NODE, &debug_resolver_cmd);
}
