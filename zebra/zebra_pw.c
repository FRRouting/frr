/* Zebra PW code
 * Copyright (C) 2016 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "thread.h"
#include "vrf.h"

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_pw.h"

DEFINE_MTYPE_STATIC(LIB, PW, "Pseudowire")

DEFINE_HOOK(pw_install, (struct zebra_pw * pw), (pw))
DEFINE_HOOK(pw_uninstall, (struct zebra_pw * pw), (pw))

extern struct zebra_t zebrad;

static void zebra_pw_install(struct zebra_pw *);
static void zebra_pw_uninstall(struct zebra_pw *);
static int zebra_pw_install_retry(struct thread *);
static int zebra_pw_check_reachability(struct zebra_pw *);
static void zebra_pw_update_status(struct zebra_pw *, int);

static inline int zebra_pw_compare(const struct zebra_pw *a,
				   const struct zebra_pw *b)
{
	return (strcmp(a->ifname, b->ifname));
}

RB_GENERATE(zebra_pw_head, zebra_pw, entry, zebra_pw_compare)

struct zebra_pw *zebra_pw_add(struct zebra_vrf *zvrf, const char *ifname,
			      uint8_t protocol, struct zserv *client)
{
	struct zebra_pw *pw;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: adding pseudowire %s protocol %s",
			   zvrf_id(zvrf), ifname, zebra_route_string(protocol));

	pw = XCALLOC(MTYPE_PW, sizeof(*pw));
	strlcpy(pw->ifname, ifname, sizeof(pw->ifname));
	pw->protocol = protocol;
	pw->vrf_id = zvrf_id(zvrf);
	pw->client = client;
	pw->status = PW_STATUS_UP;

	RB_INSERT(zebra_pw_head, &zvrf->pseudowires, pw);

	return pw;
}

void zebra_pw_del(struct zebra_vrf *zvrf, struct zebra_pw *pw)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: deleting pseudowire %s protocol %s", pw->vrf_id,
			   pw->ifname, zebra_route_string(pw->protocol));

	/* remove nexthop tracking */
	zebra_deregister_rnh_pseudowire(pw->vrf_id, pw);

	/* uninstall */
	if (pw->status == PW_STATUS_UP)
		hook_call(pw_uninstall, pw);
	else if (pw->install_retry_timer)
		THREAD_TIMER_OFF(pw->install_retry_timer);

	/* unlink and release memory */
	RB_REMOVE(zebra_pw_head, &zvrf->pseudowires, pw);
	XFREE(MTYPE_PW, pw);
}

void zebra_pw_change(struct zebra_pw *pw, ifindex_t ifindex, int type, int af,
		     union g_addr *nexthop, uint32_t local_label,
		     uint32_t remote_label, uint8_t flags,
		     union pw_protocol_fields *data)
{
	zebra_deregister_rnh_pseudowire(pw->vrf_id, pw);

	pw->ifindex = ifindex;
	pw->type = type;
	pw->af = af;
	pw->nexthop = *nexthop;
	pw->local_label = local_label;
	pw->remote_label = remote_label;
	pw->flags = flags;
	pw->data = *data;

	if (pw->enabled)
		zebra_register_rnh_pseudowire(pw->vrf_id, pw);
	else
		zebra_pw_uninstall(pw);
}

struct zebra_pw *zebra_pw_find(struct zebra_vrf *zvrf, const char *ifname)
{
	struct zebra_pw pw;
	strlcpy(pw.ifname, ifname, sizeof(pw.ifname));
	return (RB_FIND(zebra_pw_head, &zvrf->pseudowires, &pw));
}

void zebra_pw_update(struct zebra_pw *pw)
{
	if (zebra_pw_check_reachability(pw) < 0) {
		zebra_pw_uninstall(pw);
		/* wait for NHT and try again later */
	} else {
		/*
		 * Install or reinstall the pseudowire (e.g. to update
		 * parameters like the nexthop or the use of the control word).
		 */
		zebra_pw_install(pw);
	}
}

static void zebra_pw_install(struct zebra_pw *pw)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: installing pseudowire %s protocol %s",
			   pw->vrf_id, pw->ifname,
			   zebra_route_string(pw->protocol));

	if (hook_call(pw_install, pw)) {
		zebra_pw_install_failure(pw);
		return;
	}

	if (pw->status == PW_STATUS_DOWN)
		zebra_pw_update_status(pw, PW_STATUS_UP);
}

static void zebra_pw_uninstall(struct zebra_pw *pw)
{
	if (pw->status == PW_STATUS_DOWN)
		return;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: uninstalling pseudowire %s protocol %s",
			   pw->vrf_id, pw->ifname,
			   zebra_route_string(pw->protocol));

	/* ignore any possible error */
	hook_call(pw_uninstall, pw);

	if (pw->enabled)
		zebra_pw_update_status(pw, PW_STATUS_DOWN);
}

/*
 * Installation of the pseudowire in the kernel or hardware has failed. This
 * function will notify the pseudowire client about the failure and schedule
 * to retry the installation later. This function can be called by an external
 * agent that performs the pseudowire installation in an asynchronous way.
 */
void zebra_pw_install_failure(struct zebra_pw *pw)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug(
			"%u: failed installing pseudowire %s, "
			"scheduling retry in %u seconds",
			pw->vrf_id, pw->ifname, PW_INSTALL_RETRY_INTERVAL);

	/* schedule to retry later */
	THREAD_TIMER_OFF(pw->install_retry_timer);
	pw->install_retry_timer =
		thread_add_timer(zebrad.master, zebra_pw_install_retry, pw,
				 PW_INSTALL_RETRY_INTERVAL);

	zebra_pw_update_status(pw, PW_STATUS_DOWN);
}

static int zebra_pw_install_retry(struct thread *thread)
{
	struct zebra_pw *pw = THREAD_ARG(thread);

	pw->install_retry_timer = NULL;
	zebra_pw_install(pw);

	return 0;
}

static void zebra_pw_update_status(struct zebra_pw *pw, int status)
{
	pw->status = status;
	if (pw->client)
		zsend_pw_update(pw->client, pw);
}

static int zebra_pw_check_reachability(struct zebra_pw *pw)
{
	struct rib *rib;
	struct nexthop *nexthop, *tnexthop;
	int recursing;

	/* TODO: consider GRE/L2TPv3 tunnels in addition to MPLS LSPs */

	/* find route to the remote end of the pseudowire */
	rib = rib_match(family2afi(pw->af), SAFI_UNICAST, pw->vrf_id,
			&pw->nexthop, NULL);
	if (!rib) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_warn("%s: no route found for %s", __func__,
				  pw->ifname);
		return -1;
	}

	/*
	 * Need to ensure that there's a label binding for all nexthops.
	 * Otherwise, ECMP for this route could render the pseudowire unusable.
	 */
	for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing)) {
		if (!nexthop->nh_label) {
			if (IS_ZEBRA_DEBUG_PW)
				zlog_warn("%s: unlabeled route for %s",
					  __func__, pw->ifname);
			return -1;
		}
	}

	return 0;
}

void zebra_pw_client_close(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw, *tmp;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	{
		zvrf = vrf->info;
		RB_FOREACH_SAFE(pw, zebra_pw_head, &zvrf->pseudowires, tmp)
		{
			if (pw->client != client)
				continue;
			zebra_pw_del(zvrf, pw);
		}
	}
}

void zebra_pw_init(struct zebra_vrf *zvrf)
{
	RB_INIT(&zvrf->pseudowires);
}

void zebra_pw_exit(struct zebra_vrf *zvrf)
{
	struct zebra_pw *pw;

	while ((pw = RB_ROOT(&zvrf->pseudowires)) != NULL)
		zebra_pw_del(zvrf, pw);
}
