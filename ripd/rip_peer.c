// SPDX-License-Identifier: GPL-2.0-or-later
/* RIP peer support
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "command.h"
#include "linklist.h"
#include "frrevent.h"
#include "memory.h"
#include "table.h"
#include "frrdistance.h"

#include "ripd/ripd.h"
#include "ripd/rip_bfd.h"

DEFINE_MTYPE_STATIC(RIPD, RIP_PEER, "RIP peer");

static struct rip_peer *rip_peer_new(void)
{
	return XCALLOC(MTYPE_RIP_PEER, sizeof(struct rip_peer));
}

void rip_peer_free(struct rip_peer *peer)
{
	bfd_sess_free(&peer->bfd_session);
	EVENT_OFF(peer->t_timeout);
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
static void rip_peer_timeout(struct event *t)
{
	struct rip_peer *peer;

	peer = EVENT_ARG(t);
	listnode_delete(peer->rip->peer_list, peer);
	rip_peer_free(peer);
}

/* Get RIP peer.  At the same time update timeout thread. */
static struct rip_peer *rip_peer_get(struct rip *rip, struct rip_interface *ri,
				     struct in_addr *addr)
{
	struct rip_peer *peer;

	peer = rip_peer_lookup(rip, addr);

	if (peer) {
		EVENT_OFF(peer->t_timeout);
	} else {
		peer = rip_peer_new();
		peer->rip = rip;
		peer->ri = ri;
		peer->addr = *addr;
		rip_bfd_session_update(peer);
		listnode_add_sort(rip->peer_list, peer);
	}

	/* Update timeout thread. */
	event_add_timer(master, rip_peer_timeout, peer, RIP_PEER_TIMER_DEFAULT,
			&peer->t_timeout);

	/* Last update time set. */
	time(&peer->uptime);

	return peer;
}

void rip_peer_update(struct rip *rip, struct rip_interface *ri,
		     struct sockaddr_in *from, uint8_t version)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, ri, &from->sin_addr);
	peer->version = version;
}

void rip_peer_bad_route(struct rip *rip, struct rip_interface *ri,
			struct sockaddr_in *from)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, ri, &from->sin_addr);
	peer->recv_badroutes++;
}

void rip_peer_bad_packet(struct rip *rip, struct rip_interface *ri,
			 struct sockaddr_in *from)
{
	struct rip_peer *peer;
	peer = rip_peer_get(rip, ri, &from->sin_addr);
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
		vty_out(vty, "    %-17pI4 %9d %9d %9d %11s\n",
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

void rip_peer_delete_routes(const struct rip_peer *peer)
{
	struct route_node *route_node;

	for (route_node = route_top(peer->rip->table); route_node;
	     route_node = route_next(route_node)) {
		struct rip_info *route_entry;
		struct listnode *listnode;
		struct listnode *listnode_next;
		struct list *list;

		list = route_node->info;
		if (list == NULL)
			continue;

		for (ALL_LIST_ELEMENTS(list, listnode, listnode_next,
				       route_entry)) {
			if (!rip_route_rte(route_entry))
				continue;
			if (route_entry->from.s_addr != peer->addr.s_addr)
				continue;

			if (listcount(list) == 1) {
				EVENT_OFF(route_entry->t_timeout);
				EVENT_OFF(route_entry->t_garbage_collect);
				listnode_delete(list, route_entry);
				if (list_isempty(list)) {
					list_delete((struct list **)&route_node
							    ->info);
					route_unlock_node(route_node);
				}
				rip_info_free(route_entry);

				/* Signal the output process to trigger an
				 * update (see section 2.5). */
				rip_event(peer->rip, RIP_TRIGGERED_UPDATE, 0);
			} else
				rip_ecmp_delete(peer->rip, route_entry);
			break;
		}
	}
}
