/*
 * PMD Echo - Path Monitoring Echo Functions
 * Copyright (C) 6WIND 2019
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
#include <thread.h>
#include <checksum.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

#include "pmd/pm.h"
#include "pmd/pm_memory.h"
#include "pmd/pm_echo.h"


/* IPv6 local definition.
 * pseudo header and ipv6 header have same size
 */
struct ipv6header {
	unsigned char priority:4, version:4;
	unsigned char flow[3];
	unsigned short int length;
	unsigned char nexthdr;
	unsigned char hoplimit;
	unsigned int saddr[4];
	unsigned int daddr[4];
};

struct ipv6pseudoheader {
	unsigned int saddr[4];
	unsigned int daddr[4];
	unsigned int upper_layer_packet_length;
	unsigned char useless_1;
	unsigned char useless_2;
	unsigned char useless_3;
	unsigned char proto;
};

struct thread *t_dummy;

int pm_debug_echo;

static void _pm_echo_remove(struct pm_echo *pme)
{
	struct pm_session *pm = pme->back_ptr;

	if (pm)
		pm->oper_ctxt = NULL;
	pm_id_list_delete(pme);
	if (pme->rtt_stats)
		pm_rtt_free_ctx(pme->rtt_stats);
	if (pme->rx_buf)
		XFREE(MTYPE_PM_PACKET, pme->rx_buf);
	if (pme->tx_buf)
		XFREE(MTYPE_PM_PACKET, pme->tx_buf);
	memset(pme, 0, sizeof(struct pm_echo));
	XFREE(MTYPE_PM_ECHO, pme);
}

static bool pm_check_retries(struct pm_echo *pme, uint8_t counter,
			     bool retry_up)
{
	struct pm_session *pm = (struct pm_session *)pme->back_ptr;

	/* if status is already down and check is for down
	 * or if status is already up and check is for up
	 * then do not increment
	 */
	if ((pm->ses_state == PM_UP && retry_up) ||
	    (pm->ses_state == PM_DOWN && !retry_up))
		return false;
	/* if there is a switch, then reset counter */
	if ((pme->retry.retry_up_in_progress && !retry_up) ||
	    (pme->retry.retry_down_in_progress && retry_up)) {
		pme->retry.retry_count = 0;
		if (retry_up) {
			pme->retry.retry_down_in_progress = false;
			pme->retry.retry_up_in_progress = true;
		} else {
			pme->retry.retry_up_in_progress = false;
			pme->retry.retry_down_in_progress = true;
		}
	}
	if (pme->retry.retry_already_counted)
		pme->retry.retry_already_counted = false;
	else {
		pme->retry.retry_already_counted = true;
		pme->retry.retry_count++;
	}
	/* check down or up context */
	if (pme->retry.retry_count < counter) {
		THREAD_OFF(pme->t_echo_tmo);
		return true;
	}
	/* else fall on timeout */
	return false;
}

int pm_echo_tmo(struct thread *thread)
{
	struct pm_echo *pme = THREAD_ARG(thread);
	char buf[SU_ADDRSTRLEN];

	if (pme->echofd < 0)
		return 0;
	/* else fall on timeout */
	if (pme->oper_receive) {
		zlog_info("PMD: packet already received. cancel tmo");
		return 0;
	}
	pme->stats_rx_timeout++;
	if (pm_check_retries(pme, pme->retries_down, false))
		return 0;
	if (pme->last_alarm != PM_ECHO_TIMEOUT &&
	    pme->last_alarm != PM_ECHO_NHT_UNREACHABLE)
		zlog_info("echo packet to %s timed out",
			  sockunion2str(&pme->peer, buf, sizeof(buf)));
	if (pme->last_alarm != PM_ECHO_NHT_UNREACHABLE)
		pme->last_alarm = PM_ECHO_TIMEOUT;
	/* reset pme retries context */
	pme->retry.retry_count = 0;
	pme->retry.retry_down_in_progress = false;
	pme->retry.retry_up_in_progress = false;
	return 0;
}

int pm_echo_receive(struct thread *thread)
{
	int fd = THREAD_FD(thread);
	struct pm_echo *pme = THREAD_ARG(thread);
	struct pm_session *pm = pme->back_ptr;
	struct sockaddr from;
	struct icmphdr *icmp;
	struct icmp6_hdr *icmp6;
	socklen_t fromlen = sizeof(from);
	int hlen, ret = 0;
	struct iphdr *ip;
	char buf[INET6_ADDRSTRLEN];

	if ((sockunion_family(&pme->peer) == AF_INET
	     && pme->echofd < 0) ||
	    (sockunion_family(&pme->peer) == AF_INET6
	     && pme->echofd_rx_ipv6 < 0)) {
		/* context flushed; prevent from read */
		fd = -1;
	}
	if (fd >= 0)
		thread_add_read(master, pm_echo_receive, pme,
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
		return 0;
	}
	monotime(&pme->end);
	if (sockunion_family(&pme->peer) == AF_INET) {
		ip = (struct iphdr *)pme->rx_buf;
		hlen = ip->ihl << 2;
		/* check that destination address matches
		 * our local address configured
		 */
		if (ip->saddr != pme->peer.sin.sin_addr.s_addr) {
			if (pm_debug_echo) {
				char buf2[INET6_ADDRSTRLEN];
				struct in_addr saddr;

				saddr.s_addr = ip->saddr;
				inet_ntop(AF_INET, &saddr, buf, sizeof(buf));
				inet_ntop(AF_INET, &pme->peer.sin.sin_addr,
					  buf2, sizeof(buf2));
				zlog_err("PMD: wrong src address %s, expected %s. retrying",
					 buf, buf2);
			}
			return 0;
		}
		if (sockunion_family(&pm->key.local) == AF_INET &&
		    ip->daddr != pm->key.local.sin.sin_addr.s_addr) {
			if (pm_debug_echo) {
				char buf2[INET6_ADDRSTRLEN];
				struct in_addr daddr;

				daddr.s_addr = ip->daddr;
				inet_ntop(AF_INET, &daddr, buf, sizeof(buf));
				inet_ntop(AF_INET, &pm->key.local.sin.sin_addr,
					  buf2, sizeof(buf2));
				zlog_err("PMD: wrong dst address %s, expected %s. retrying",
					 buf, buf2);
			}
			return 0;
		}
		icmp = (struct icmphdr *)(pme->rx_buf + hlen);
		if (ret < hlen + ICMP_MINLEN) {
			zlog_err("PMD: packet too short. retrying");
			return 0;
		}
		if (icmp->type != ICMP_ECHOREPLY) {
			if (pm_debug_echo) {
				char buf2[INET6_ADDRSTRLEN];
				struct in_addr daddr;

				daddr.s_addr = ip->daddr;
				inet_ntop(AF_INET, &pme->peer.sin.sin_addr,
					  buf, sizeof(buf));
				inet_ntop(AF_INET, &daddr, buf2, sizeof(buf2));
				zlog_err("PMD: ICMP from %s to %s ECHO REPLY expected (type %u)",
					 buf, buf2, icmp->type);
			}
			return 0;
		}
		if (icmp->un.echo.id != (pme->discriminator_id & 0xffff)) {
			if (pm_debug_echo) {
				zlog_err("PMD: received ID %u whereas local ID is %u, discard",
					 icmp->un.echo.id,
					 pme->discriminator_id & 0xffff);
			}
			return 0;
		}
		if (icmp->un.echo.sequence != (pme->icmp_sequence - 1)) {
			if (pm_debug_echo) {
				char buf2[INET6_ADDRSTRLEN];
				struct in_addr daddr;

				daddr.s_addr = ip->daddr;
				inet_ntop(AF_INET, &pme->peer.sin.sin_addr,
					  buf, sizeof(buf));
				inet_ntop(AF_INET, &daddr, buf2, sizeof(buf2));
				zlog_err("PMD: ICMP from %s to %s rx seq %u, expected %u",
					 buf, buf2,
					 icmp->un.echo.sequence,
					 pme->icmp_sequence - 1);
			}
			return 0;
		}
	} else {
		icmp6 = (struct icmp6_hdr *)(pme->rx_buf);
		if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
			if (pm_debug_echo) {
				inet_ntop(AF_INET, &pme->peer.sin.sin_addr,
					  buf, sizeof(buf));
				zlog_err("PMD: ICMP from %s ECHO REPLY expected (type %u)",
					 buf, icmp->type);
			}
			return 0;
		}
		if (icmp6->icmp6_id != (pme->discriminator_id & 0xffff)) {
			if (pm_debug_echo) {
				zlog_err("PMD: received ID %u whereas local ID is %u, discard",
					 icmp6->icmp6_id,
					 pme->discriminator_id & 0xffff);
			}
			return 0;
		}
		if (icmp6->icmp6_seq != (pme->icmp_sequence - 1)) {
			if (pm_debug_echo) {
				inet_ntop(AF_INET, &pme->peer.sin.sin_addr,
					  buf, sizeof(buf));
				zlog_err("PMD: ICMP from %s rx seq %u, expected %u",
					 buf,
					 icmp6->icmp6_seq,
					 pme->icmp_sequence - 1);
			}
			return 0;
		}
	}
	pme->stats_rx++;
	pm_rtt_calculate(&pme->start, &pme->end,
			 &pme->last_rtt, NULL);
	pm_rtt_update_stats(pme->rtt_stats, &pme->last_rtt, NULL);
	if (pme->last_rtt.tv_sec * 1000 > pme->timeout ||
	    ((pme->last_rtt.tv_sec * 1000 == pm->timeout) &&
	     (pme->last_rtt.tv_usec > 0))) {
		if (!pme->oper_receive)
			pme->stats_rx_timeout++;
		if (pm_check_retries(pme, pme->retries_down, false))
			return 0;
		if (pme->last_alarm != PM_ECHO_TIMEOUT) {
			zlog_info("echo packet to %s timed out",
				  sockunion2str(&pme->peer,
						buf, sizeof(buf)));
		}
		if (pme->last_alarm != PM_ECHO_NHT_UNREACHABLE)
			pme->last_alarm = PM_ECHO_TIMEOUT;
		return 0;
	}
	if (pm_check_retries(pme, pme->retries_up, true))
		return 0;
	if (pme->last_alarm != PM_ECHO_OK)
		zlog_info("echo packet to %s OK",
			  sockunion2str(&pme->peer, buf, sizeof(buf)));
	pme->last_alarm = PM_ECHO_OK;
	pme->oper_receive = true;
	/* reset pme retries contexts */
	pme->retry.retry_count = 0;
	pme->retry.retry_up_in_progress = false;
	pme->retry.retry_down_in_progress = false;
	THREAD_OFF(pme->t_echo_tmo);
	return 0;
}

char *pm_echo_get_alarm_str(struct pm_session *pm, char *buf, size_t len)
{
	struct pm_echo *pme = pm->oper_ctxt;

	memset(buf, 0, len);

	if (!pme)
		return buf;
	switch (pme->last_alarm) {
	case PM_ECHO_NONE:
		snprintf(buf, len, "echo none");
		break;
	case PM_ECHO_TIMEOUT:
		snprintf(buf, len, "echo timeout");
		break;
	case PM_ECHO_OK:
		snprintf(buf, len, "echo ok");
		break;
	case PM_ECHO_NHT_UNREACHABLE:
		snprintf(buf, len, "echo unreachable");
		break;
	default:
		break;
	}
	return buf;
}

static union g_addr *pm_echo_choose_src_ip_interface(struct interface *ifp,
					     int family,
					     bool link_local)
{
	struct connected *ifc;
	struct listnode *node;
	union g_addr *src_ip = NULL;

	if (!ifp)
		return NULL;
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		if (!ifc->address)
			continue;
		if (family != ifc->address->family)
			continue;
		if (family == AF_INET) {
			src_ip = (union g_addr *)&ifc->address->u.prefix4;
			break;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && link_local) {
			src_ip = (union g_addr *)&ifc->address->u.prefix6;
			break;
		}
		if (!IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && !link_local) {
			src_ip = (union g_addr *)&ifc->address->u.prefix6;
			break;
		}
	}
	return src_ip;
}

static union g_addr *pm_echo_choose_src_ip(struct pm_session *pm)
{
	struct vrf *vrf;
	struct interface *ifp = NULL;
	bool ipv6_link_local = false;
	union g_addr *src_ip = NULL;

	/* choose first configured one */
	if (sockunion_family(&pm->key.local) == AF_INET) {
		src_ip = (union g_addr *)&pm->key.local.sin.sin_addr;
		return src_ip;
	}
	if (sockunion_family(&pm->key.local) == AF_INET6) {
		src_ip = (union g_addr *)&pm->key.local.sin6.sin6_addr;
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
					 sockunion_family(&pm->key.peer),
					 ipv6_link_local);
			/* stop at first address found */
			if (src_ip)
				return src_ip;
		}
		return NULL;
	}
	if ((sockunion_family(&pm->key.peer) == AF_INET6) &&
	    IN6_IS_ADDR_LINKLOCAL(&pm->key.peer.sin6))
		ipv6_link_local = true;
	return pm_echo_choose_src_ip_interface(ifp,
				       sockunion_family(&pm->key.peer),
				       ipv6_link_local);
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
	} else {
		family = AF_INET6;
		ip_proto = IPPROTO_RAW; /* _ICMP6 */
	}

	if (pme->echofd > 0)
		close(pme->echofd);
	if (pme->echofd_rx_ipv6 > 0)
		close(pme->echofd_rx_ipv6);

	frr_with_privs(&pm_privs) {
		pme->echofd = vrf_socket(family, SOCK_RAW,
					 ip_proto,
					 vrf->vrf_id, bind_interface);
	}
	if (pme->echofd == -1) {
		zlog_err("PMD: pm_echo, failed to allocate socket");
		return -1;
	}
	/* create extra socket for reception */
	if (family == AF_INET6) {
		frr_with_privs(&pm_privs) {
			pme->echofd_rx_ipv6 = vrf_socket(family,
							 SOCK_RAW,
							 IPPROTO_ICMPV6,
							 vrf->vrf_id,
							 bind_interface);
		}
		if (pme->echofd_rx_ipv6 == -1) {
			zlog_err("PMD: pm_echo, failed to allocate socket (%u)",
				 errno);
			close(pme->echofd);
			return -1;
		}
	}
	if (family == AF_INET)
		ret = setsockopt(pme->echofd, IPPROTO_IP, IP_HDRINCL,
				 &use_iphdr, sizeof(use_iphdr));
	else
		/* section 1 of RFC 3542, IP_HDRINCL is not guaranteed
		 * this piece of code works on Linux, but not on other
		 * systems
		 */
		ret = setsockopt(pme->echofd, IPPROTO_IPV6, IP_HDRINCL,
				 &use_iphdr, sizeof(use_iphdr));
	if (ret < 0) {
		char buf[SU_ADDRSTRLEN];

		sockunion2str(&pme->peer, buf, sizeof(buf));
		zlog_err("PMD: pm_echo, use IP_HDRINCL for session to %s failed (err %d)",
			 buf, errno);
	}
	return 0;
}

int pm_echo_send(struct thread *thread)
{
	struct pm_echo *pme = THREAD_ARG(thread);
	struct pm_session *pm = pme->back_ptr;
	struct iphdr *iph;
	struct ipv6header *ip6h;
	struct icmphdr *icmp;
	struct icmp6_hdr *icmp6;
	struct ipv6pseudoheader *p_ip6h;
	int ret = 0;
	size_t siz;
	union g_addr *src_ip = NULL;
	int family;

	if (pme->echofd < 0)
		return 0;

	if (!pme->tx_buf)
		pme->tx_buf = XCALLOC(MTYPE_PM_PACKET, pme->packet_size);
	else
		memset(pme->tx_buf, 0, pme->packet_size);

	if (sockunion_family(&pme->peer) == AF_INET)
		family = AF_INET;
	else
		family = AF_INET6;
	if (pme->oper_bind == false ||
	    pme->oper_connect == false) {
		ret = pm_echo_reset_socket(pme);
		if (ret < 0)
			goto label_end_tried_sending;
	}

	if (pme->oper_bind == false) {
		if (sockunion_family(&pm->key.local) == AF_INET6) {
			ret = bind(pme->echofd,
				   (struct sockaddr *)&pm->key.local.sa,
				   sizeof(struct sockaddr_in6));
			if (ret > 0)
				ret = bind(pme->echofd_rx_ipv6,
					   (struct sockaddr *)&pm->key.local.sa,
					   sizeof(struct sockaddr_in6));
		} else if (sockunion_family(&pm->key.local) == AF_INET)
			ret = bind(pme->echofd,
				   (struct sockaddr *)&pm->key.local.sa,
				   sizeof(struct sockaddr_in));
		if (ret < 0) {
			char buf[SU_ADDRSTRLEN];

			sockunion2str(&pm->key.local, buf, sizeof(buf));
			zlog_warn("PMD: pm_echo, bind with %s failed (err %d)",
				  buf, errno);
			pme->oper_bind = false;
			goto label_end_tried_sending;
		} else {
			pme->oper_bind = true;
		}
	}

	if (pme->oper_connect == false) {
		/* XXX issues when using connect() with RAW ICMPV6 socket */
		if (sockunion_family(&pme->gw) == AF_INET)
			ret = connect(pme->echofd,
				      (struct sockaddr *)&pme->peer,
				      sizeof(struct sockaddr_in));
		if (ret < 0) {
			char buf[SU_ADDRSTRLEN];

			sockunion2str(&pme->gw, buf, sizeof(buf));
			zlog_warn("PMD: pm_echo, connect with %s failed (err %d)",
				  buf, errno);
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
			char buf[SU_ADDRSTRLEN];

			sockunion2str(&pme->peer, buf, sizeof(buf));
			zlog_warn("cancel ICMP echo send to %s without src IP",
				  buf);
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
	} else {
		/* calculation of icmp6 checksum is done with pseudo header
		 * as part of https://tools.ietf.org/html/rfc2460#section-8.1
		 */
		p_ip6h = (struct ipv6pseudoheader *)(pme->tx_buf);
		icmp6 = (struct icmp6_hdr *)(pme->tx_buf + sizeof(struct ipv6pseudoheader));
		memcpy(&p_ip6h->daddr, &pme->peer.sin6.sin6_addr,
		       sizeof(struct in6_addr));
		src_ip = pm_echo_choose_src_ip(pm);
		if (!src_ip) {
			char buf[SU_ADDRSTRLEN];

			sockunion2str(&pme->peer, buf, sizeof(buf));
			zlog_warn("cancel sending ICMP echo to %s without src IP",
				  buf);
			goto label_end_tried_sending;
		} else
			memcpy(&p_ip6h->saddr, &src_ip->ipv6.s6_addr,
			       sizeof(struct in6_addr));
		p_ip6h->upper_layer_packet_length = htonl(pme->packet_size
					  - sizeof(struct ipv6header));
		p_ip6h->proto = IPPROTO_ICMPV6;

		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6->icmp6_code = 0;
		icmp6->icmp6_id = pme->discriminator_id & 0xffff;
		icmp6->icmp6_seq = pme->icmp_sequence++;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_cksum = in_cksum((void *)p_ip6h, pme->packet_size);
		memset(pme->tx_buf, 0, sizeof(struct ipv6header));
		ip6h = (struct ipv6header *)pme->tx_buf;
		icmp6 = (struct icmp6_hdr *)(pme->tx_buf
					     + sizeof(struct ipv6header));
		ip6h->version = 6;
		ip6h->priority = 0;
		ip6h->flow[0] = htons(pm->tos_val);
		ip6h->flow[1] = 0;
		ip6h->flow[2] = 0;
		ip6h->length = htons(pme->packet_size
				     - sizeof(struct ipv6header));
		ip6h->nexthdr = IPPROTO_ICMPV6;
		ip6h->hoplimit = 255;
		memcpy(&ip6h->daddr, &pme->peer.sin6.sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(&ip6h->saddr, &src_ip->ipv6.s6_addr,
		       sizeof(struct in6_addr));
		siz = sizeof(struct sockaddr_in6);
	}

	pme->oper_receive = false;
	pme->oper_timeout = false;

	thread_add_read(master, pm_echo_receive, pme,
			family == AF_INET6 ?
			pme->echofd_rx_ipv6 : pme->echofd,
			&pme->t_echo_receive);

	monotime(&pme->start);
	ret = sendto(pme->echofd, (char *)pme->tx_buf,
		     pme->packet_size, 0,
		     &pme->gw.sa, siz);
	if (ret < 0) {
		char buf[SU_ADDRSTRLEN];

		sockunion2str(&pme->peer, buf, sizeof(buf));
		zlog_err("PMD: error when sending ICMP echo to %s (%x)",
			 buf, errno);
		pme->last_errno = errno;
	} else {
		pme->last_errno = 0;
		pme->stats_tx++;
	}
 label_end_tried_sending:
	pme->retry.retry_already_counted = false;
	if (ret >= 0) /* launch timeout if emission was successfull */
		thread_add_timer_msec(master, pm_echo_tmo, pme, pme->timeout,
				      &pme->t_echo_tmo);

	thread_add_timer_msec(master, pm_echo_send, pme, pme->interval,
			      &pme->t_echo_send);
	return 0;
}

void pm_echo_stop(struct pm_session *pm, char *errormsg,
		  int errormsg_len, bool force)
{
	struct pm_echo *pme = pm->oper_ctxt;
	char buf[SU_ADDRSTRLEN];

	if (!pme)
		return;
	THREAD_OFF(pme->t_echo_tmo);
	THREAD_OFF(pme->t_echo_send);
	THREAD_OFF(pme->t_echo_receive);
	close(pme->echofd);
	pme->echofd = -1;
	if (pme->echofd_rx_ipv6 > 0) {
		close(pme->echofd_rx_ipv6);
		pme->echofd_rx_ipv6 = -1;
	}
	pme->back_ptr = NULL;
	pm->oper_ctxt = NULL;
	snprintf(errormsg, errormsg_len,
		 "echo session to %s : pkt %u sent, %u rcvd",
		 sockunion2str(&pme->peer, buf, sizeof(buf)),
		 pme->stats_tx, pme->stats_rx);
	return _pm_echo_remove(pme);
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
	pme_ptr->retries_up = pm->retries_up;
	pme_ptr->retries_down = pm->retries_down;
	pme_ptr->rtt_stats = pm_rtt_allocate_ctx();
	pme_ptr->gw = gw;
	pme_ptr->oper_connect = false;
	pme_ptr->oper_bind = false;

	pm_id_list_insert(pme_ptr);

	thread_add_timer(master, pm_echo_send, pme_ptr, 0,
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
	vty_out(vty, "\t");
	pm_rtt_display_stats(vty, pme->rtt_stats);
}

/* keep pme session on suspend */
void pm_echo_trigger_nht_unreachable(struct pm_session *pm)
{
	struct pm_echo *pme = pm->oper_ctxt;
	char buf[SU_ADDRSTRLEN];

	if (!pme)
		return;

	if (pme->last_alarm == PM_ECHO_OK)
		zlog_info("echo packet to %s unreachable",
			  sockunion2str(&pme->peer, buf, sizeof(buf)));
	if (pme->last_alarm != PM_ECHO_TIMEOUT)
		pme->last_alarm = PM_ECHO_NHT_UNREACHABLE;
}
