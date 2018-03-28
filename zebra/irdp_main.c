/*
 *
 * Copyright (C) 2000  Robert Olsson.
 * Swedish University of Agricultural Sciences
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

/*
 * This work includes work with the following copywrite:
 *
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 *
 */

/*
 * Thanks to Jens Låås at Swedish University of Agricultural Sciences
 * for reviewing and tests.
 */


#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "sockopt.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "zebra_memory.h"
#include "stream.h"
#include "ioctl.h"
#include "connected.h"
#include "log.h"
#include "zclient.h"
#include "thread.h"
#include "privs.h"
#include "libfrr.h"
#include "version.h"
#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/irdp.h"
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "if.h"
#include "sockunion.h"
#include "log.h"

/* GLOBAL VARS */

extern struct zebra_privs_t zserv_privs;

struct thread *t_irdp_raw;

/* Timer interval of irdp. */
int irdp_timer_interval = IRDP_DEFAULT_INTERVAL;

int irdp_sock_init(void)
{
	int ret, i;
	int save_errno;
	int sock;

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("irdp_sock_init: could not raise privs, %s",
			 safe_strerror(errno));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	save_errno = errno;

	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("irdp_sock_init: could not lower privs, %s",
			 safe_strerror(errno));

	if (sock < 0) {
		zlog_warn("IRDP: can't create irdp socket %s",
			  safe_strerror(save_errno));
		return sock;
	};

	i = 1;
	ret = setsockopt(sock, IPPROTO_IP, IP_TTL, (void *)&i, sizeof(i));
	if (ret < 0) {
		zlog_warn("IRDP: can't do irdp sockopt %s",
			  safe_strerror(errno));
		close(sock);
		return ret;
	};

	ret = setsockopt_ifindex(AF_INET, sock, 1);
	if (ret < 0) {
		zlog_warn("IRDP: can't do irdp sockopt %s",
			  safe_strerror(errno));
		close(sock);
		return ret;
	};

	t_irdp_raw = NULL;
	thread_add_read(zebrad.master, irdp_read_raw, NULL, sock, &t_irdp_raw);

	return sock;
}


static int get_pref(struct irdp_interface *irdp, struct prefix *p)
{
	struct listnode *node;
	struct Adv *adv;

	/* Use default preference or use the override pref */

	if (irdp->AdvPrefList == NULL)
		return irdp->Preference;

	for (ALL_LIST_ELEMENTS_RO(irdp->AdvPrefList, node, adv))
		if (p->u.prefix4.s_addr == adv->ip.s_addr)
			return adv->pref;

	return irdp->Preference;
}

/* Make ICMP Router Advertisement Message. */
static int make_advertisement_packet(struct interface *ifp, struct prefix *p,
				     struct stream *s)
{
	struct zebra_if *zi = ifp->info;
	struct irdp_interface *irdp = zi->irdp;
	int size;
	int pref;
	uint16_t checksum;

	pref = get_pref(irdp, p);

	stream_putc(s, ICMP_ROUTERADVERT); /* Type. */
	stream_putc(s, 0);		   /* Code. */
	stream_putw(s, 0);		   /* Checksum. */
	stream_putc(s, 1);		   /* Num address. */
	stream_putc(s, 2);		   /* Address Entry Size. */

	if (irdp->flags & IF_SHUTDOWN)
		stream_putw(s, 0);
	else
		stream_putw(s, irdp->Lifetime);

	stream_putl(s, htonl(p->u.prefix4.s_addr)); /* Router address. */
	stream_putl(s, pref);

	/* in_cksum return network byte order value */
	size = 16;
	checksum = in_cksum(s->data, size);
	stream_putw_at(s, 2, htons(checksum));

	return size;
}

static void irdp_send(struct interface *ifp, struct prefix *p, struct stream *s)
{
	struct zebra_if *zi = ifp->info;
	struct irdp_interface *irdp = zi->irdp;
	char buf[PREFIX_STRLEN];
	uint32_t dst;
	uint32_t ttl = 1;

	if (!irdp)
		return;
	if (!(ifp->flags & IFF_UP))
		return;

	if (irdp->flags & IF_BROADCAST)
		dst = INADDR_BROADCAST;
	else
		dst = htonl(INADDR_ALLHOSTS_GROUP);

	if (irdp->flags & IF_DEBUG_MESSAGES)
		zlog_debug("IRDP: TX Advert on %s %s Holdtime=%d Preference=%d",
			   ifp->name, prefix2str(p, buf, sizeof buf),
			   irdp->flags & IF_SHUTDOWN ? 0 : irdp->Lifetime,
			   get_pref(irdp, p));

	send_packet(ifp, s, dst, p, ttl);
}

static void irdp_advertisement(struct interface *ifp, struct prefix *p)
{
	struct stream *s;
	s = stream_new(128);
	make_advertisement_packet(ifp, p, s);
	irdp_send(ifp, p, s);
	stream_free(s);
}

int irdp_send_thread(struct thread *t_advert)
{
	uint32_t timer, tmp;
	struct interface *ifp = THREAD_ARG(t_advert);
	struct zebra_if *zi = ifp->info;
	struct irdp_interface *irdp = zi->irdp;
	struct prefix *p;
	struct listnode *node, *nnode;
	struct connected *ifc;

	if (!irdp)
		return 0;

	irdp->flags &= ~IF_SOLICIT;

	if (ifp->connected)
		for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, ifc)) {
			p = ifc->address;

			if (p->family != AF_INET)
				continue;

			irdp_advertisement(ifp, p);
			irdp->irdp_sent++;
		}

	tmp = irdp->MaxAdvertInterval - irdp->MinAdvertInterval;
	timer = random() % (tmp + 1);
	timer = irdp->MinAdvertInterval + timer;

	if (irdp->irdp_sent < MAX_INITIAL_ADVERTISEMENTS
	    && timer > MAX_INITIAL_ADVERT_INTERVAL)
		timer = MAX_INITIAL_ADVERT_INTERVAL;

	if (irdp->flags & IF_DEBUG_MISC)
		zlog_debug("IRDP: New timer for %s set to %u\n", ifp->name,
			   timer);

	irdp->t_advertise = NULL;
	thread_add_timer(zebrad.master, irdp_send_thread, ifp, timer,
			 &irdp->t_advertise);
	return 0;
}

void irdp_advert_off(struct interface *ifp)
{
	struct zebra_if *zi = ifp->info;
	struct irdp_interface *irdp = zi->irdp;
	struct listnode *node, *nnode;
	int i;
	struct connected *ifc;
	struct prefix *p;

	if (!irdp)
		return;

	if (irdp->t_advertise)
		thread_cancel(irdp->t_advertise);
	irdp->t_advertise = NULL;

	if (ifp->connected)
		for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, ifc)) {
			p = ifc->address;

			/* Output some packets with Lifetime 0
			   we should add a wait...
			*/

			for (i = 0; i < IRDP_LAST_ADVERT_MESSAGES; i++) {
				irdp->irdp_sent++;
				irdp_advertisement(ifp, p);
			}
		}
}


void process_solicit(struct interface *ifp)
{
	struct zebra_if *zi = ifp->info;
	struct irdp_interface *irdp = zi->irdp;
	uint32_t timer;

	if (!irdp)
		return;

	/* When SOLICIT is active we reject further incoming solicits
	   this keeps down the answering rate so we don't have think
	   about DoS attacks here. */

	if (irdp->flags & IF_SOLICIT)
		return;

	irdp->flags |= IF_SOLICIT;
	if (irdp->t_advertise)
		thread_cancel(irdp->t_advertise);
	irdp->t_advertise = NULL;

	timer = (random() % MAX_RESPONSE_DELAY) + 1;

	irdp->t_advertise = NULL;
	thread_add_timer(zebrad.master, irdp_send_thread, ifp, timer,
			 &irdp->t_advertise);
}

static int irdp_finish(void)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *zi;
	struct irdp_interface *irdp;

	zlog_info("IRDP: Received shutdown notification.");

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
		FOR_ALL_INTERFACES (vrf, ifp) {
			zi = ifp->info;

			if (!zi)
				continue;
			irdp = zi->irdp;
			if (!irdp)
				continue;

			if (irdp->flags & IF_ACTIVE) {
				irdp->flags |= IF_SHUTDOWN;
				irdp_advert_off(ifp);
			}
		}
	return 0;
}

static int irdp_init(struct thread_master *master)
{
	irdp_if_init();

	hook_register(frr_early_fini, irdp_finish);
	return 0;
}

static int irdp_module_init(void)
{
	hook_register(frr_late_init, irdp_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "zebra_irdp", .version = FRR_VERSION,
		 .description = "zebra IRDP module", .init = irdp_module_init, )
