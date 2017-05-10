/*	$OpenBSD$ */

/*
 * Copyright (c) 2012 Claudio Jeker <claudio@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"

struct accept_ev {
	LIST_ENTRY(accept_ev)	 entry;
	struct thread		*ev;
	int			(*accept_cb)(struct thread *);
	void			*arg;
	int			 fd;
};

struct {
	LIST_HEAD(, accept_ev)	 queue;
	struct thread		*evt;
} accept_queue;

static void	accept_arm(void);
static void	accept_unarm(void);
static int	accept_cb(struct thread *);
static int	accept_timeout(struct thread *);

void
accept_init(void)
{
	LIST_INIT(&accept_queue.queue);
}

int
accept_add(int fd, int (*cb)(struct thread *), void *arg)
{
	struct accept_ev	*av;

	if ((av = calloc(1, sizeof(*av))) == NULL)
		return (-1);
	av->fd = fd;
	av->accept_cb = cb;
	av->arg = arg;
	LIST_INSERT_HEAD(&accept_queue.queue, av, entry);

	av->ev = NULL;
	thread_add_read(master, accept_cb, av, av->fd, &av->ev);

	log_debug("%s: accepting on fd %d", __func__, fd);

	return (0);
}

void
accept_del(int fd)
{
	struct accept_ev	*av;

	LIST_FOREACH(av, &accept_queue.queue, entry)
		if (av->fd == fd) {
			log_debug("%s: %d removed from queue", __func__, fd);
			THREAD_READ_OFF(av->ev);
			LIST_REMOVE(av, entry);
			free(av);
			return;
		}
}

void
accept_pause(void)
{
	log_debug(__func__);
	accept_unarm();
	accept_queue.evt = NULL;
	thread_add_timer(master, accept_timeout, NULL, 1, &accept_queue.evt);
}

void
accept_unpause(void)
{
	if (accept_queue.evt != NULL) {
		log_debug(__func__);
		THREAD_TIMER_OFF(accept_queue.evt);
		accept_arm();
	}
}

static void
accept_arm(void)
{
	struct accept_ev	*av;
	LIST_FOREACH(av, &accept_queue.queue, entry) {
		av->ev = NULL;
		thread_add_read(master, accept_cb, av, av->fd, &av->ev);
	}
}

static void
accept_unarm(void)
{
	struct accept_ev	*av;
	LIST_FOREACH(av, &accept_queue.queue, entry)
		THREAD_READ_OFF(av->ev);
}

static int
accept_cb(struct thread *thread)
{
	struct accept_ev	*av = THREAD_ARG(thread);
	av->ev = NULL;
	thread_add_read(master, accept_cb, av, av->fd, &av->ev);
	av->accept_cb(thread);

	return (0);
}

static int
accept_timeout(struct thread *thread)
{
	accept_queue.evt = NULL;

	log_debug(__func__);
	accept_arm();

	return (0);
}
