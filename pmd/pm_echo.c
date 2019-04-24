/*
 * PMD Echo - Path Monitoring Echo Functions
 * Copyright 2019 6WIND S.A.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include <memory.h>
#include <vrf.h>
#include <frrevent.h>
#include <checksum.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "pmd/pm.h"
#include "pmd/pm_memory.h"
#include "pmd/pm_echo.h"

struct event *t_dummy;

int pm_debug_echo;

static void _pm_echo_remove(struct pm_echo *pme)
{
	struct pm_session *pm = pme->back_ptr;

	if (pm)
		pm->oper_ctxt = NULL;
	pm_id_list_delete(pme);
	if (pme->rx_buf)
		XFREE(MTYPE_PM_PACKET, pme->rx_buf);
	if (pme->tx_buf)
		XFREE(MTYPE_PM_PACKET, pme->tx_buf);
	memset(pme, 0, sizeof(struct pm_echo));
	XFREE(MTYPE_PM_ECHO, pme);
}

void pm_echo_tmo(struct event *event)
{
	struct pm_echo *pme = EVENT_ARG(event);

	if (pme->echofd < 0)
		return;
	if (pme->oper_receive) {
		zlog_info("PMD: packet already received. cancel tmo");
		return;
	}
	pme->stats_rx_timeout++;
	if (pme->last_alarm != PM_ECHO_TIMEOUT)
		zlog_info("echo packet to %pSU timed out",
			  &pme->peer);
	pme->last_alarm = PM_ECHO_TIMEOUT;
}

void pm_echo_receive(struct event *event)
{
	int fd = EVENT_FD(event);
	struct pm_echo *pme = EVENT_ARG(event);
	struct pm_session *pm = pme->back_ptr;
	struct sockaddr from;
	struct icmphdr *icmp;
	socklen_t fromlen = sizeof(from);
	int hlen, ret = 0;
	struct iphdr *ip;

	if (sockunion_family(&pme->peer) == AF_INET
	     && pme->echofd < 0)
		/* context flushed; prevent from read */
		fd = -1;
	if (fd >= 0)
		event_add_read(master, pm_echo_receive, pme,
				fd, &pme->t_echo_receive);
	if (!pme->rx_buf)
		pme->rx_buf = XCALLOC(MTYPE_PM_PACKET, pme->packet_size);
	else
		memset(pme->rx_buf, 0, pme->packet_size);
	icmp = (struct icmphdr *)pme->rx_buf;
	ret = recvfrom(fd, pme->rx_buf,
		       pme->packet_size, 0, &from, &fromlen);
	if (ret < 0 || fd < 0) {
		zlog_err("PMD: error when receiving ICMP echo.");
		return;
	}
	monotime(&pme->end);
	if (sockunion_family(&pme->peer) == AF_INET) {
		ip = (struct iphdr *)pme->rx_buf;
		hlen = ip->ihl << 2;
		/* check that destination address matches
		 * our local address configured
		 */
		if (ip->saddr != pme->peer.sin.sin_addr.s_addr) {
			if (pm_debug_echo)
				zlog_err("PMD: wrong src address %pI4, expected %pI4. retrying",
						&ip->saddr, &pme->peer.sin.sin_addr);
			return;
		}
		if (sockunion_family(&pm->key.local) == AF_INET &&
		    ip->daddr != pm->key.local.sin.sin_addr.s_addr) {
			if (pm_debug_echo)
				zlog_err("PMD: wrong dst address %pI4, expected %pI4. retrying",
					&ip->daddr, &pm->key.local.sin.sin_addr);
			return;
		}
		icmp = (struct icmphdr *)(pme->rx_buf + hlen);
		if (ret < hlen + ICMP_MINLEN) {
			zlog_err("PMD: packet too short. retrying");
			return;
		}
		if (icmp->type != ICMP_ECHOREPLY) {
			if (pm_debug_echo)
				zlog_err("PMD: ICMP from %pI4 to %pI4 ECHO REPLY expected (type %u)",
						&pme->peer.sin.sin_addr, &ip->daddr, icmp->type);
			return;
		}
		if (icmp->un.echo.id != (pme->discriminator_id & 0xffff)) {
			if (pm_debug_echo) {
				zlog_err("PMD: received ID %u whereas local ID is %u, discard",
					 icmp->un.echo.id,
					 pme->discriminator_id & 0xffff);
			}
			return;
		}
		if (icmp->un.echo.sequence != (pme->icmp_sequence - 1)) {
			if (pm_debug_echo)
				zlog_err("PMD: ICMP from %pI4 to %pI4 rx seq %u, expected %u",
					 &pme->peer.sin.sin_addr, &ip->daddr,
					 icmp->un.echo.sequence,
					 pme->icmp_sequence - 1);
			return;
		}
	}
	pme->stats_rx++;
	pme->last_rtt.tv_sec = pme->end.tv_sec - pme->start.tv_sec;
	if (pme->end.tv_usec - pme->start.tv_usec > 0)
		pme->last_rtt.tv_usec = pme->end.tv_usec - pme->start.tv_usec;
	else {
		pme->last_rtt.tv_usec = 1000000 -
			(pme->start.tv_usec - pme->end.tv_usec);
		pme->last_rtt.tv_sec--;
	}
	if (pme->last_rtt.tv_sec > pme->timeout ||
	    ((pme->last_rtt.tv_sec == pm->timeout) &&
	     (pme->last_rtt.tv_usec > 0))) {
		if (!pme->oper_receive)
			pme->stats_rx_timeout++;
		if (pme->last_alarm != PM_ECHO_TIMEOUT) {
			zlog_info("echo packet to %pSU timed out",
					&pme->peer);
		}
		pme->last_alarm = PM_ECHO_TIMEOUT;
		return;
	}
	if (pme->last_alarm != PM_ECHO_OK)
		zlog_info("echo packet to %pSU OK",
				&pme->peer);
	pme->last_alarm = PM_ECHO_OK;
	pme->oper_receive = true;
	EVENT_OFF(pme->t_echo_tmo);
}

const char *pm_echo_get_alarm_str(struct pm_session *pm)
{
	struct pm_echo *pme = pm->oper_ctxt;

	if (!pme)
		return "";

	switch (pme->last_alarm) {
	case PM_ECHO_NONE:
		return "echo none";
	case PM_ECHO_TIMEOUT:
		return "echo timeout";
	case PM_ECHO_OK:
		return "echo ok";
	case PM_ECHO_NHT_UNREACHABLE:
		return "echo unreachable";
	}

	return "";
}

static union g_addr *pm_echo_choose_src_ip_interface(struct interface *ifp,
						     int family)
{
	struct connected *ifc;
	union g_addr *src_ip = NULL;

	if (!ifp)
		return NULL;
	frr_each (if_connected, ifp->connected, ifc) {
		if (!ifc->address)
			continue;
		if (family != ifc->address->family)
			continue;
		if (family == AF_INET) {
			src_ip = (union g_addr *)&ifc->address->u.prefix4;
			break;
		}
	}
	return src_ip;
}

static union g_addr *pm_echo_choose_src_ip(struct pm_session *pm)
{
	struct vrf *vrf;
	struct interface *ifp = NULL;
	union g_addr *src_ip = NULL;

	/* choose first configured one */
	if (sockunion_family(&pm->key.local) == AF_INET) {
		src_ip = (union g_addr *)&pm->key.local.sin.sin_addr;
		return src_ip;
	}
	/* otherwise pick up in vrf, either in configured interface
	 * or on the available addresses of the system
	 */
	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return NULL;
	if (pm->key.ifname[0])
		ifp = if_lookup_by_name(pm->key.ifname, vrf->vrf_id);
	if (!ifp) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			src_ip = pm_echo_choose_src_ip_interface(ifp,
					 sockunion_family(&pm->key.peer));
			/* stop at first address found */
			if (src_ip)
				return src_ip;
		}
		return NULL;
	}
	return pm_echo_choose_src_ip_interface(ifp,
			       sockunion_family(&pm->key.peer));
}

/* close if necessary previous socket
 * and create new one
 * return -1 if an error has produced
 */
static int pm_echo_reset_socket(struct pm_echo *pme)
{
	struct pm_session *pm = pme->back_ptr;
	int ret = 0, ip_proto, family;
	char *bind_interface = NULL;
	struct vrf *vrf;
	int use_iphdr = 1;

	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (pm->key.ifname[0])
		bind_interface = (char *)pm->key.ifname;
	else if (pm->key.vrfname[0])
		bind_interface = (char *)pm->key.vrfname;

	if (sockunion_family(&pm->key.peer) == AF_INET) {
		family = AF_INET;
		ip_proto = IPPROTO_ICMP; /* ICMP */
	}

	if (pme->echofd > 0)
		close(pme->echofd);

	frr_with_privs(&pm_privs) {
		pme->echofd = vrf_socket(family, SOCK_RAW,
					 ip_proto,
					 vrf->vrf_id, bind_interface);
	}
	if (pme->echofd == -1) {
		zlog_err("PMD: pm_echo, failed to allocate socket");
		return -1;
	}
	if (family == AF_INET)
		ret = setsockopt(pme->echofd, IPPROTO_IP, IP_HDRINCL,
				 &use_iphdr, sizeof(use_iphdr));
	if (ret < 0)
		zlog_err("PMD: pm_echo, use IP_HDRINCL for session to %pSU failed (err %d)",
				&pme->peer, errno);
	return 0;
}

void pm_echo_send(struct event *event)
{
	struct pm_echo *pme = EVENT_ARG(event);
	struct pm_session *pm = pme->back_ptr;
	struct iphdr *iph;
	struct icmphdr *icmp = NULL;
	int ret = 0;
	size_t siz;
	union g_addr *src_ip = NULL;

	if (pme->echofd < 0)
		return;

	if (!pme->tx_buf)
		pme->tx_buf = XCALLOC(MTYPE_PM_PACKET, pme->packet_size);
	else
		memset(pme->tx_buf, 0, pme->packet_size);

	if (sockunion_family(&pme->peer) != AF_INET)
		return;
	if (pme->oper_bind == false ||
	    pme->oper_connect == false) {
		ret = pm_echo_reset_socket(pme);
		if (ret < 0)
			goto label_end_tried_sending;
	}

	if (pme->oper_bind == false) {
		if (sockunion_family(&pm->key.local) == AF_INET)
			ret = bind(pme->echofd,
				   (struct sockaddr *)&pm->key.local.sa,
				   sizeof(struct sockaddr_in));
		if (ret < 0) {
			zlog_warn("PMD: pm_echo, bind with %pSU failed (err %d)",
					&pm->key.local, errno);
			pme->oper_bind = false;
			goto label_end_tried_sending;
		} else {
			pme->oper_bind = true;
		}
	}

	if (pme->oper_connect == false) {
		if (sockunion_family(&pme->gw) == AF_INET)
			ret = connect(pme->echofd,
				      (struct sockaddr *)&pme->peer,
				      sizeof(struct sockaddr_in));
		if (ret < 0) {
			zlog_warn("PMD: pm_echo, connect with %pSU failed (err %d)",
					&pme->gw, errno);
			pme->oper_connect = false;
			goto label_end_tried_sending;
		} else
			pme->oper_connect = true;
	}

	if (sockunion_family(&pme->peer) == AF_INET) {
		iph = (struct iphdr *)pme->tx_buf;
		icmp = (struct icmphdr *)(pme->tx_buf + sizeof(struct iphdr));
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = pm->tos_val;
		iph->id = random();
		iph->ttl = 64;
		iph->protocol = IPPROTO_ICMP;
		iph->daddr = pme->peer.sin.sin_addr.s_addr;
		/* source ip not set systematically */
		src_ip = pm_echo_choose_src_ip(pm);
		if (!src_ip) {
			zlog_warn("cancel ICMP echo send to %pSU without src IP",
					&pme->peer);
			goto label_end_tried_sending;
		} else
			iph->saddr = src_ip->ipv4.s_addr;
		iph->check = in_cksum((void *)iph, sizeof(struct iphdr));
		siz = sizeof(struct sockaddr_in);
		icmp->type = ICMP_ECHO;
		icmp->code = 0;
		icmp->un.echo.id = pme->discriminator_id & 0xffff;
		icmp->un.echo.sequence = pme->icmp_sequence++;
		icmp->checksum = 0;
		icmp->checksum = in_cksum((void *)icmp,
					  pme->packet_size - sizeof(struct iphdr));
	}

	pme->oper_receive = false;
	pme->oper_timeout = false;

	event_add_read(master, pm_echo_receive, pme,
			pme->echofd,
			&pme->t_echo_receive);

	monotime(&pme->start);
	ret = sendto(pme->echofd, (char *)pme->tx_buf,
		     pme->packet_size, 0,
		     &pme->gw.sa, siz);
	if (ret < 0) {
		zlog_err("PMD: error when sending ICMP echo to %pSU (%x)",
				&pme->peer, errno);
		pme->last_errno = errno;
	} else {
		pme->last_errno = 0;
		pme->stats_tx++;
	}
 label_end_tried_sending:
	if (ret >= 0) /* launch timeout if emission was successfull */
		event_add_timer_msec(master, pm_echo_tmo, pme, pme->timeout,
				      &pme->t_echo_tmo);

	event_add_timer_msec(master, pm_echo_send, pme, pme->interval,
			      &pme->t_echo_send);
}

void pm_echo_stop(struct pm_session *pm, char *errormsg,
		  int errormsg_len, bool force)
{
	struct pm_echo *pme = pm->oper_ctxt;

	if (!pme)
		return;
	EVENT_OFF(pme->t_echo_tmo);
	EVENT_OFF(pme->t_echo_send);
	EVENT_OFF(pme->t_echo_receive);
	close(pme->echofd);
	pme->echofd = -1;
	pme->back_ptr = NULL;
	pm->oper_ctxt = NULL;
	snprintf(errormsg, errormsg_len,
		 "echo session to %pSU : pkt %u sent, %u rcvd",
		 &pme->peer,
		 pme->stats_tx, pme->stats_rx);
	_pm_echo_remove(pme);
}

int pm_echo(struct pm_session *pm, char *errormsg, int errormsg_len)
{
	struct pm_echo pme;
	struct pm_echo *pme_ptr;
	union sockunion peer, gw;

	pm_initialise(pm, true, errormsg, errormsg_len);
	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_VALIDATE))
		return -1;

	memset(&pme, 0, sizeof(pme));

	pm_get_peer(pm, &peer);
	pm_get_gw(pm, &gw);

	pme_ptr = XCALLOC(MTYPE_PM_ECHO, sizeof(struct pm_echo));
	memcpy(pme_ptr, &pme, sizeof(pme));
	pme_ptr->back_ptr = pm;
	pme_ptr->discriminator_id = pm_id_list_gen_id();
	pme_ptr->icmp_sequence = 0;

	pme_ptr->timeout = pm->timeout;
	pme_ptr->interval = pm->interval;
	pme_ptr->packet_size = pm->packet_size;
	pme_ptr->peer = peer;
	pme_ptr->gw = gw;
	pme_ptr->oper_connect = false;
	pme_ptr->oper_bind = false;
	pm_id_list_insert(pme_ptr);

	event_add_timer(master, pm_echo_send, pme_ptr, 0,
			 &pme_ptr->t_echo_send);
	pm->oper_ctxt = (void *)pme_ptr;
	return 0;
}

void pm_echo_dump(struct vty *vty, struct pm_session *pm)
{
	struct pm_echo *pme = pm->oper_ctxt;

	if (!pme)
		return;
	vty_out(vty, "\tpacket-size %u, interval %u",
		pme->packet_size, pme->interval);
	vty_out(vty, ", timeout %u\n", pm->timeout);
	vty_out(vty, "\tpkt %u sent, %u rcvd (timeout %u)\n",
		pme->stats_tx, pme->stats_rx, pme->stats_rx_timeout);
	vty_out(vty, "\tlast round trip time %lu sec, %lu usec\n",
		pme->last_rtt.tv_sec, pme->last_rtt.tv_usec);
}
