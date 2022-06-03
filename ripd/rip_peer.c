/* RIP peer support
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "command.h"
#include "linklist.h"
#include "thread.h"
#include "memory.h"

#include "ripd/ripd.h"

DEFINE_MTYPE_STATIC(RIPD, RIP_PEER, "RIP peer");

static struct rip_peer *rip_peer_new(void)
{
	return XCALLOC(MTYPE_RIP_PEER, sizeof(struct rip_peer));
}

static void rip_peer_free(struct rip_peer *peer)
{
	THREAD_OFF(peer->t_timeout);
	XFREE(MTYPE_RIP_PEER, peer);
}

struct rip_peer *rip_peer_lookup(struct rip *rip, struct in_addr *addr)
{
	struct rip_peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(rip->peer_list, node, nnode, peer)) {
		if (IPV4_ADDR_SAME(&peer->addr, addr))
			return peer;
	}
	return NULL;
}

struct rip_peer *rip_peer_lookup_next(struct rip *rip, struct in_addr *addr)
{
	struct rip_peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(rip->peer_list, node, nnode, peer)) {
		if (htonl(peer->addr.s_addr) > htonl(addr->s_addr))
			return peer;
	}
	return NULL;
}

/* RIP peer is timeout. */
static void rip_peer_timeout(struct thread *t)
{
	struct rip_peer *peer;

	peer = THREAD_ARG(t);
	listnode_delete(peer->rip->peer_list, peer);
	rip_peer_free(peer);
}

/* Get RIP peer.  At the same time update timeout thread. */
static struct rip_peer *rip_peer_get(struct rip *rip, struct in_addr *addr)
{
	struct rip_peer *peer;

	peer = rip_peer_lookup(rip, addr);

	if (peer) {
		THREAD_OFF(peer->t_timeout);
	} else {
		peer = rip_peer_new();
		peer->rip = rip;
		peer->addr = *addr;
		listnode_add_sort(rip->peer_list, peer);
	}

	/* Update timeout thread. */
	thread_add_timer(master, rip_peer_timeout, peer, RIP_PEER_TIMER_DEFAULT,
			 &peer->t_timeout);

	/* Last update time set. */
	time(&peer->uptime);

	return peer;
}

void rip_peer_update(struct rip *rip, struct sockaddr_in *from, uint8_t version)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, &from->sin_addr);
	peer->version = version;
}

void rip_peer_bad_route(struct rip *rip, struct sockaddr_in *from)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, &from->sin_addr);
	peer->recv_badroutes++;
}

void rip_peer_bad_packet(struct rip *rip, struct sockaddr_in *from)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, &from->sin_addr);
	peer->recv_badpackets++;
}

/* Display peer uptime. */
static char *rip_peer_uptime(struct rip_peer *peer, char *buf, size_t len)
{
	time_t uptime;

	/* If there is no connection has been done before print `never'. */
	if (peer->uptime == 0) {
		snprintf(buf, len, "never   ");
		return buf;
	}

	/* Get current time. */
	uptime = time(NULL);
	uptime -= peer->uptime;

	frrtime_to_interval(uptime, buf, len);

	return buf;
}

void rip_peer_display(struct vty *vty, struct rip *rip)
{
	struct rip_peer *peer;
	struct listnode *node, *nnode;
#define RIP_UPTIME_LEN 25
	char timebuf[RIP_UPTIME_LEN];

	for (ALL_LIST_ELEMENTS(rip->peer_list, node, nnode, peer)) {
		vty_out(vty, "    %-16pI4 %9d %9d %9d   %s\n",
			&peer->addr, peer->recv_badpackets,
			peer->recv_badroutes, ZEBRA_RIP_DISTANCE_DEFAULT,
			rip_peer_uptime(peer, timebuf, RIP_UPTIME_LEN));
	}
}

int rip_peer_list_cmp(struct rip_peer *p1, struct rip_peer *p2)
{
	if (p2->addr.s_addr == p1->addr.s_addr)
		return 0;

	return (htonl(p1->addr.s_addr) < htonl(p2->addr.s_addr)) ? -1 : 1;
}

void rip_peer_list_del(void *arg)
{
	rip_peer_free(arg);
}
