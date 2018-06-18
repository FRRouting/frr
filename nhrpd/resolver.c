/* C-Ares integration to Quagga mainloop
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <ares.h>
#include <ares_version.h>

#include "vector.h"
#include "thread.h"
#include "nhrpd.h"

struct resolver_state {
	ares_channel channel;
	struct thread *timeout;
	vector read_threads, write_threads;
};

static struct resolver_state state;

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
		thread_add_read(master, resolver_cb_socket_readable, r, fd, &t);
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
		thread_add_write(master, resolver_cb_socket_writable, r, fd,
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
		thread_add_timer_msec(master, resolver_cb_timeout, r, timeoutms,
				      &r->timeout);
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
			thread_add_read(master, resolver_cb_socket_readable, r,
					fd, &t);
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
			thread_add_read(master, resolver_cb_socket_writable, r,
					fd, &t);
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

void resolver_init(void)
{
	struct ares_options ares_opts;

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
}


static void ares_address_cb(void *arg, int status, int timeouts,
			    struct hostent *he)
{
	struct resolver_query *query = (struct resolver_query *)arg;
	union sockunion addr[16];
	size_t i;

	if (status != ARES_SUCCESS) {
		debugf(NHRP_DEBUG_COMMON, "[%p] Resolving failed", query);
		query->callback(query, -1, NULL);
		query->callback = NULL;
		return;
	}

	for (i = 0; i < ZEBRA_NUM_OF(addr) && he->h_addr_list[i] != NULL; i++) {
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

	debugf(NHRP_DEBUG_COMMON, "[%p] Resolved with %d results", query,
	       (int)i);
	query->callback(query, i, &addr[0]);
	query->callback = NULL;
}

void resolver_resolve(struct resolver_query *query, int af,
		      const char *hostname,
		      void (*callback)(struct resolver_query *, int,
				       union sockunion *))
{
	if (query->callback != NULL) {
		zlog_err(
			"Trying to resolve '%s', but previous query was not finished yet",
			hostname);
		return;
	}

	debugf(NHRP_DEBUG_COMMON, "[%p] Resolving '%s'", query, hostname);

	query->callback = callback;
	ares_gethostbyname(state.channel, hostname, af, ares_address_cb, query);
	resolver_update_timeouts(&state);
}
