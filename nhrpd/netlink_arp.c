// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP netlink/neighbor table arpd code
 * Copyright (c) 2014-2016 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef GNU_LINUX
#include <linux/rtnetlink.h>
#endif

#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "frrevent.h"
#include "stream.h"
#include "prefix.h"
#include "nhrpd.h"
#include "netlink.h"

int netlink_nflog_group = 0;
static int netlink_log_fd = -1;

void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma)
{
	nhrp_send_zebra_nbr(proto, nbma, ifp);
}

void netlink_set_nflog_group(int nlgroup)
{
	if (netlink_log_fd >= 0 && netlink_nflog_group) {
		nhrp_zebra_register_log(VRF_DEFAULT, netlink_nflog_group, false);
		netlink_log_fd = -1;
	}
	netlink_nflog_group = nlgroup;
	if (netlink_nflog_group) {
		nhrp_zebra_register_log(VRF_DEFAULT, netlink_nflog_group, true);
		netlink_log_fd = 1;
	}
}

int nhrp_neighbor_operation(ZAPI_CALLBACK_ARGS)
{
	union sockunion addr = {}, lladdr = {};
	struct interface *ifp;
	int state, ndm_state;
	struct nhrp_cache *c;
	struct zapi_neigh_ip api = {};

	zclient_neigh_ip_decode(zclient->ibuf, &api);

	if (api.ip_len != IPV4_MAX_BYTELEN && api.ip_len != 0)
		return 0;

	if (api.ip_in.ipa_type == AF_UNSPEC)
		return 0;
	sockunion_family(&addr) = api.ip_in.ipa_type;
	memcpy((uint8_t *)sockunion_get_addr(&addr), &api.ip_in.ip.addr,
	       family2addrsize(api.ip_in.ipa_type));

	sockunion_family(&lladdr) = api.ip_out.ipa_type;
	if (api.ip_out.ipa_type != AF_UNSPEC)
		memcpy((uint8_t *)sockunion_get_addr(&lladdr),
		       &api.ip_out.ip.addr,
		       family2addrsize(api.ip_out.ipa_type));

	ifp = if_lookup_by_index(api.index, vrf_id);
	ndm_state = api.ndm_state;

	if (!ifp)
		return 0;
	c = nhrp_cache_get(ifp, &addr, 0);
	if (!c)
		return 0;
	debugf(NHRP_DEBUG_KERNEL,
	       "Netlink: %s %pSU dev %s lladdr %pSU nud 0x%x cache used %u type %u",
	       (cmd == ZEBRA_NEIGH_GET)	    ? "who-has"
	       : (cmd == ZEBRA_NEIGH_ADDED) ? "new-neigh"
					    : "del-neigh",
	       &addr, ifp->name, &lladdr, ndm_state, c->used, c->cur.type);
	if (cmd == ZEBRA_NEIGH_GET) {
		if (c->cur.type >= NHRP_CACHE_CACHED) {
			nhrp_cache_set_used(c, 1);
			debugf(NHRP_DEBUG_KERNEL,
			       "Netlink: update binding for %pSU dev %s from c %pSU peer.vc.nbma %pSU to lladdr %pSU",
			       &addr, ifp->name, &c->cur.remote_nbma_natoa,
			       &c->cur.peer->vc->remote.nbma, &lladdr);

			if (lladdr.sa.sa_family == AF_UNSPEC)
				/* nothing from zebra, so use nhrp peer */
				lladdr = c->cur.peer->vc->remote.nbma;

			/* In case of shortcuts, nbma is given by lladdr, not
			 * vc->remote.nbma.
			 */
			netlink_update_binding(ifp, &addr, &lladdr);
		}
	} else {
		state = (cmd == ZEBRA_NEIGH_ADDED) ? ndm_state
						   : ZEBRA_NEIGH_STATE_FAILED;
		if (ndm_state != ZEBRA_NEIGH_STATE_STALE)
			nhrp_cache_set_used(
				c, state == ZEBRA_NEIGH_STATE_REACHABLE);
	}
	return 0;
}
