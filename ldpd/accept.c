// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2012 Claudio Jeker <claudio@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"

struct accept_ev {
	LIST_ENTRY(accept_ev)	 entry;
	struct event *ev;
	void (*accept_cb)(struct event *);
	void			*arg;
	int			 fd;
};

struct {
	LIST_HEAD(, accept_ev)	 queue;
	struct event *evt;
} accept_queue;

static void	accept_arm(void);
static void	accept_unarm(void);
static void accept_cb(struct event *);
static void accept_timeout(struct event *);

void
accept_init(void)
{
	LIST_INIT(&accept_queue.queue);
}

int accept_add(int fd, void (*cb)(struct event *), void *arg)
{
	struct accept_ev	*av;

	if ((av = calloc(1, sizeof(*av))) == NULL)
		return (-1);
	av->fd = fd;
	av->accept_cb = cb;
	av->arg = arg;
	LIST_INSERT_HEAD(&accept_queue.queue, av, entry);

	event_add_read(master, accept_cb, av, av->fd, &av->ev);

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
			EVENT_OFF(av->ev);
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
	event_add_timer(master, accept_timeout, NULL, 1, &accept_queue.evt);
}

void
accept_unpause(void)
{
	if (accept_queue.evt != NULL) {
		log_debug(__func__);
		EVENT_OFF(accept_queue.evt);
		accept_arm();
	}
}

static void
accept_arm(void)
{
	struct accept_ev	*av;
	LIST_FOREACH(av, &accept_queue.queue, entry) {
		event_add_read(master, accept_cb, av, av->fd, &av->ev);
	}
}

static void
accept_unarm(void)
{
	struct accept_ev	*av;
	LIST_FOREACH(av, &accept_queue.queue, entry)
		EVENT_OFF(av->ev);
}

static void accept_cb(struct event *thread)
{
	struct accept_ev *av = EVENT_ARG(thread);
	event_add_read(master, accept_cb, av, av->fd, &av->ev);
	av->accept_cb(thread);
}

static void accept_timeout(struct event *thread)
{
	accept_queue.evt = NULL;

	log_debug(__func__);
	accept_arm();
}
