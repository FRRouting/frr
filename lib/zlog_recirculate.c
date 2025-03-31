// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2024  David Lamparter, for NetDEF, Inc.
 */

#include "zebra.h"

#include "log.h"
#include "frrevent.h"

#include "zlog_recirculate.h"

/* This is only the event loop part;  it's split off from
 * zlog_recirculate_live_msg since there's an integration boundary;  this
 * half deals with events, the other half with zlog interna.
 *
 * As of writing, this runs in ldpd in the *parent* process and receives log
 * messages from the lde/ldpe subprocesses.  It is not used anywhere else
 * (yet?)
 */
static void zlog_recirculate_recv(struct event *ev)
{
	uint8_t rxbuf[4096];
	ssize_t n_rd;
	int fd = EVENT_FD(ev);

	/* see below for -2, "\n\0" are added */
	n_rd = read(fd, rxbuf, sizeof(rxbuf) - 2);
	if (n_rd == 0) {
		/* EOF */
		close(fd);
		/* event_add_read not called yet, nothing to cancel */
		return;
	}
	if (n_rd < 0 && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
		/* error */
		zlog_warn("error on log relay socket %d: %m", fd);
		close(fd);
		/* event_add_read not called yet, nothing to cancel */
		return;
	}

	event_add_read(ev->master, zlog_recirculate_recv, NULL, fd, NULL);
	if (n_rd < 0)
		return;

	/* log infrastructure has an implicit \n\0 at the end */
	rxbuf[n_rd] = '\n';
	rxbuf[n_rd + 1] = '\0';
	zlog_recirculate_live_msg(rxbuf, n_rd);
}

void zlog_recirculate_subscribe(struct event_loop *el, int fd)
{
	event_add_read(el, zlog_recirculate_recv, NULL, fd, NULL);
}
