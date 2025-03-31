// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPng peer support
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

/* RIPng support added by Vincent Jardin <vincent.jardin@6wind.com>
 * Copyright (C) 2002 6WIND
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "command.h"
#include "linklist.h"
#include "frrevent.h"
#include "memory.h"
#include "frrdistance.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nexthop.h"

DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_PEER, "RIPng peer");

static struct ripng_peer *ripng_peer_new(void)
{
	return XCALLOC(MTYPE_RIPNG_PEER, sizeof(struct ripng_peer));
}

static void ripng_peer_free(struct ripng_peer *peer)
{
	EVENT_OFF(peer->t_timeout);
	XFREE(MTYPE_RIPNG_PEER, peer);
}

struct ripng_peer *ripng_peer_lookup(struct ripng *ripng, struct in6_addr *addr)
{
	struct ripng_peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ripng->peer_list, node, nnode, peer)) {
		if (IPV6_ADDR_SAME(&peer->addr, addr))
			return peer;
	}
	return NULL;
}

struct ripng_peer *ripng_peer_lookup_next(struct ripng *ripng,
					  struct in6_addr *addr)
{
	struct ripng_peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ripng->peer_list, node, nnode, peer)) {
		if (addr6_cmp(&peer->addr, addr) > 0)
			return peer;
	}
	return NULL;
}

/* RIPng peer is timeout.
 * Garbage collector.
 **/
static void ripng_peer_timeout(struct event *t)
{
	struct ripng_peer *peer;

	peer = EVENT_ARG(t);
	listnode_delete(peer->ripng->peer_list, peer);
	ripng_peer_free(peer);
}

/* Get RIPng peer.  At the same time update timeout thread. */
static struct ripng_peer *ripng_peer_get(struct ripng *ripng,
					 struct in6_addr *addr)
{
	struct ripng_peer *peer;

	peer = ripng_peer_lookup(ripng, addr);

	if (peer) {
		EVENT_OFF(peer->t_timeout);
	} else {
		peer = ripng_peer_new();
		peer->ripng = ripng;
		peer->addr = *addr;
		listnode_add_sort(ripng->peer_list, peer);
	}

	/* Update timeout thread. */
	event_add_timer(master, ripng_peer_timeout, peer,
			RIPNG_PEER_TIMER_DEFAULT, &peer->t_timeout);

	/* Last update time set. */
	time(&peer->uptime);

	return peer;
}

void ripng_peer_update(struct ripng *ripng, struct sockaddr_in6 *from,
		       uint8_t version)
{
	struct ripng_peer *peer;
	peer = ripng_peer_get(ripng, &from->sin6_addr);
	peer->version = version;
}

void ripng_peer_bad_route(struct ripng *ripng, struct sockaddr_in6 *from)
{
	struct ripng_peer *peer;
	peer = ripng_peer_get(ripng, &from->sin6_addr);
	peer->recv_badroutes++;
}

void ripng_peer_bad_packet(struct ripng *ripng, struct sockaddr_in6 *from)
{
	struct ripng_peer *peer;
	peer = ripng_peer_get(ripng, &from->sin6_addr);
	peer->recv_badpackets++;
}

/* Display peer uptime. */
static char *ripng_peer_uptime(struct ripng_peer *peer, char *buf, size_t len)
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

void ripng_peer_display(struct vty *vty, struct ripng *ripng)
{
	struct ripng_peer *peer;
	struct listnode *node, *nnode;
#define RIPNG_UPTIME_LEN 25
	char timebuf[RIPNG_UPTIME_LEN];

	for (ALL_LIST_ELEMENTS(ripng->peer_list, node, nnode, peer)) {
		vty_out(vty, "    %pI6 \n%14s %10d %10d %10d      %s\n",
			&peer->addr, " ", peer->recv_badpackets,
			peer->recv_badroutes, ZEBRA_RIPNG_DISTANCE_DEFAULT,
			ripng_peer_uptime(peer, timebuf, RIPNG_UPTIME_LEN));
	}
}

int ripng_peer_list_cmp(struct ripng_peer *p1, struct ripng_peer *p2)
{
	return memcmp(&p1->addr, &p2->addr, sizeof(struct in6_addr));
}

void ripng_peer_list_del(void *arg)
{
	ripng_peer_free(arg);
}
