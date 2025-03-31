// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Sending and Receiving OSPF Packets.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "monotime.h"
#include "frrevent.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"
#include "checksum.h"
#ifdef CRYPTO_INTERNAL
#include "md5.h"
#endif
#include "vrf.h"
#include "lib_errors.h"
#include "plist.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_auth.h"

/*
 * OSPF Fragmentation / fragmented writes
 *
 * ospfd can support writing fragmented packets, for cases where
 * kernel will not fragment IP_HDRINCL and/or multicast destined
 * packets (ie TTBOMK all kernels, BSD, SunOS, Linux). However,
 * SunOS, probably BSD too, clobber the user supplied IP ID and IP
 * flags fields, hence user-space fragmentation will not work.
 * Only Linux is known to leave IP header unmolested.
 * Further, fragmentation really should be done the kernel, which already
 * supports it, and which avoids nasty IP ID state problems.
 *
 * Fragmentation of OSPF packets can be required on networks with router
 * with many many interfaces active in one area, or on networks with links
 * with low MTUs.
 */
#ifdef GNU_LINUX
#define WANT_OSPF_WRITE_FRAGMENT
#endif

/* Packet Type String. */
const struct message ospf_packet_type_str[] = {
	{OSPF_MSG_HELLO, "Hello"},
	{OSPF_MSG_DB_DESC, "Database Description"},
	{OSPF_MSG_LS_REQ, "Link State Request"},
	{OSPF_MSG_LS_UPD, "Link State Update"},
	{OSPF_MSG_LS_ACK, "Link State Acknowledgment"},
	{0}};

/* Minimum (besides OSPF_HEADER_SIZE) lengths for OSPF packets of
   particular types, offset is the "type" field of a packet. */
static const uint16_t ospf_packet_minlen[] = {
	0,
	OSPF_HELLO_MIN_SIZE,
	OSPF_DB_DESC_MIN_SIZE,
	OSPF_LS_REQ_MIN_SIZE,
	OSPF_LS_UPD_MIN_SIZE,
	OSPF_LS_ACK_MIN_SIZE,
};

/* Minimum (besides OSPF_LSA_HEADER_SIZE) lengths for LSAs of particular
   types, offset is the "LSA type" field. */
static const uint16_t ospf_lsa_minlen[] = {
	0,                             /* OSPF_UNKNOWN_LSA */
	OSPF_ROUTER_LSA_MIN_SIZE,      /* OSPF_ROUTER_LSA */
	OSPF_NETWORK_LSA_MIN_SIZE,     /* OSPF_NETWORK_LSA */
	OSPF_SUMMARY_LSA_MIN_SIZE,     /* OSPF_SUMMARY_LSA */
	OSPF_SUMMARY_LSA_MIN_SIZE,     /* OSPF_ASBR_SUMMARY_LSA */
	OSPF_AS_EXTERNAL_LSA_MIN_SIZE, /* OSPF_AS_EXTERNAL_LSA */
	0,                             /* Unsupported, OSPF_GROUP_MEMBER_LSA */
	OSPF_AS_EXTERNAL_LSA_MIN_SIZE, /* OSPF_AS_NSSA_LSA */
	0,                             /* Unsupported, OSPF_EXTERNAL_ATTRIBURES_LSA */
	OSPF_OPAQUE_LSA_MIN_SIZE,      /* OSPF_OPAQUE_LINK_LSA */
	OSPF_OPAQUE_LSA_MIN_SIZE,      /* OSPF_OPAQUE_AREA_LSA */
	OSPF_OPAQUE_LSA_MIN_SIZE,      /* OSPF_OPAQUE_AS_LSA */
};

static struct ospf_packet *ospf_packet_new(size_t size)
{
	struct ospf_packet *new;

	new = XCALLOC(MTYPE_OSPF_PACKET, sizeof(struct ospf_packet));
	new->s = stream_new(size);

	return new;
}

void ospf_packet_free(struct ospf_packet *op)
{
	if (op->s)
		stream_free(op->s);

	XFREE(MTYPE_OSPF_PACKET, op);
}

struct ospf_fifo *ospf_fifo_new(void)
{
	struct ospf_fifo *new;

	new = XCALLOC(MTYPE_OSPF_FIFO, sizeof(struct ospf_fifo));
	return new;
}

/* Add new packet to fifo. */
void ospf_fifo_push(struct ospf_fifo *fifo, struct ospf_packet *op)
{
	if (fifo->tail)
		fifo->tail->next = op;
	else
		fifo->head = op;

	fifo->tail = op;

	fifo->count++;
}

/* Add new packet to head of fifo. */
static void ospf_fifo_push_head(struct ospf_fifo *fifo, struct ospf_packet *op)
{
	op->next = fifo->head;

	if (fifo->tail == NULL)
		fifo->tail = op;

	fifo->head = op;

	fifo->count++;
}

/* Delete first packet from fifo. */
struct ospf_packet *ospf_fifo_pop(struct ospf_fifo *fifo)
{
	struct ospf_packet *op;

	op = fifo->head;

	if (op) {
		fifo->head = op->next;

		if (fifo->head == NULL)
			fifo->tail = NULL;

		fifo->count--;
	}

	return op;
}

/* Return first fifo entry. */
struct ospf_packet *ospf_fifo_head(struct ospf_fifo *fifo)
{
	return fifo->head;
}

/* Flush ospf packet fifo. */
void ospf_fifo_flush(struct ospf_fifo *fifo)
{
	struct ospf_packet *op;
	struct ospf_packet *next;

	for (op = fifo->head; op; op = next) {
		next = op->next;
		ospf_packet_free(op);
	}
	fifo->head = fifo->tail = NULL;
	fifo->count = 0;
}

/* Free ospf packet fifo. */
void ospf_fifo_free(struct ospf_fifo *fifo)
{
	ospf_fifo_flush(fifo);

	XFREE(MTYPE_OSPF_FIFO, fifo);
}

static void ospf_packet_add(struct ospf_interface *oi, struct ospf_packet *op)
{
	/* Add packet to end of queue. */
	ospf_fifo_push(oi->obuf, op);

	/* Debug of packet fifo*/
	/* ospf_fifo_debug (oi->obuf); */
}

static void ospf_packet_add_top(struct ospf_interface *oi,
				struct ospf_packet *op)
{
	/* Add packet to head of queue. */
	ospf_fifo_push_head(oi->obuf, op);

	/* Debug of packet fifo*/
	/* ospf_fifo_debug (oi->obuf); */
}

static void ospf_packet_delete(struct ospf_interface *oi)
{
	struct ospf_packet *op;

	op = ospf_fifo_pop(oi->obuf);

	if (op)
		ospf_packet_free(op);
}

static struct ospf_packet *ospf_packet_dup(struct ospf_packet *op)
{
	struct ospf_packet *new;

	if (stream_get_endp(op->s) != op->length)
		/* XXX size_t */
		zlog_debug(
			"ospf_packet_dup stream %lu ospf_packet %u size mismatch",
			(unsigned long)STREAM_SIZE(op->s), op->length);

	/* Reserve space for MD5/HMAC SHA authentication that may be added later. */
	new = ospf_packet_new(stream_get_endp(op->s) + KEYCHAIN_MAX_HASH_SIZE);
	stream_copy(new->s, op->s);

	new->dst = op->dst;
	new->length = op->length;

	return new;
}

/* XXX inline */
static unsigned int ospf_packet_authspace(struct ospf_interface *oi)
{
	int auth = 0;

	if (ospf_auth_type(oi) == OSPF_AUTH_CRYPTOGRAPHIC)
		auth = KEYCHAIN_MAX_HASH_SIZE;

	return auth;
}

static unsigned int ospf_packet_max(struct ospf_interface *oi)
{
	int max;

	max = oi->ifp->mtu - ospf_packet_authspace(oi);

	max -= (OSPF_HEADER_SIZE + sizeof(struct ip));

	return max;
}

static void ospf_ls_req_timer(struct event *thread)
{
	struct ospf_neighbor *nbr;

	nbr = EVENT_ARG(thread);
	nbr->t_ls_req = NULL;

	/* Send Link State Request. */
	if (ospf_ls_request_count(nbr))
		ospf_ls_req_send(nbr);

	/* Set Link State Request retransmission timer. */
	OSPF_NSM_TIMER_ON(nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);
}

void ospf_ls_req_event(struct ospf_neighbor *nbr)
{
	EVENT_OFF(nbr->t_ls_req);
	event_add_event(master, ospf_ls_req_timer, nbr, 0, &nbr->t_ls_req);
}

/*
 * OSPF neighbor link state retransmission timer handler. Unicast
 * unacknowledged LSAs to the neigbhors.
 */
void ospf_ls_rxmt_timer(struct event *thread)
{
	struct ospf_neighbor *nbr;
	int retransmit_interval, retransmit_window, rxmt_lsa_count = 0;

	nbr = EVENT_ARG(thread);
	nbr->t_ls_rxmt = NULL;
	retransmit_interval = nbr->v_ls_rxmt;
	retransmit_window = OSPF_IF_PARAM(nbr->oi, retransmit_window);

	/* Send Link State Update. */
	if (ospf_ls_retransmit_count(nbr) > 0) {
		struct ospf_lsa_list_entry *ls_rxmt_list_entry;
		struct timeval current_time, latest_rxmt_time, next_rxmt_time;
		struct timeval rxmt_interval = { retransmit_interval, 0 };
		struct timeval rxmt_window;
		struct list *update;

		/*
		 * Set the retransmission window based on the configured value
		 * in milliseconds.
		 */
		rxmt_window.tv_sec = retransmit_window / 1000;
		rxmt_window.tv_usec = (retransmit_window % 1000) * 1000;

		/*
		 * Calculate the latest retransmit time for LSAs transmited in
		 * this timer pass by adding the retransmission window to the
		 * current time. Calculate the next retransmission time by adding
		 * the retransmit interval to the current time.
		 */
		monotime(&current_time);
		timeradd(&current_time, &rxmt_window, &latest_rxmt_time);
		timeradd(&current_time, &rxmt_interval, &next_rxmt_time);

		update = list_new();
		while ((ls_rxmt_list_entry =
				ospf_lsa_list_first(&nbr->ls_rxmt_list))) {
			if (timercmp(&ls_rxmt_list_entry->list_entry_time,
				     &latest_rxmt_time, >))
				break;

			listnode_add(update, ls_rxmt_list_entry->lsa);
			rxmt_lsa_count++;

			/*
			 * Set the next retransmit time for the LSA and move it
			 * to the end of the neighbor's retransmission list.
			 */
			ls_rxmt_list_entry->list_entry_time = next_rxmt_time;
			ospf_lsa_list_del(&nbr->ls_rxmt_list,
					  ls_rxmt_list_entry);
			ospf_lsa_list_add_tail(&nbr->ls_rxmt_list,
					       ls_rxmt_list_entry);
			nbr->ls_rxmt_lsa++;
			nbr->oi->ls_rxmt_lsa++;
		}

		if (listcount(update) > 0)
			ospf_ls_upd_send(nbr, update, OSPF_SEND_PACKET_DIRECT,
					 0);
		list_delete(&update);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("RXmtL(%lu) NBR(%pI4(%s)) timer event - sent %u LSAs",
			   ospf_ls_retransmit_count(nbr), &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf), rxmt_lsa_count);

	/* Set LS Update retransmission timer. */
	ospf_ls_retransmit_set_timer(nbr);
}

void ospf_ls_ack_delayed_timer(struct event *thread)
{
	struct ospf_interface *oi;

	oi = EVENT_ARG(thread);
	oi->t_ls_ack_delayed = NULL;

	/* Send Link State Acknowledgment. */
	if (ospf_lsa_list_count(&oi->ls_ack_delayed))
		ospf_ls_ack_send_delayed(oi);
}

#ifdef WANT_OSPF_WRITE_FRAGMENT
static void ospf_write_frags(int fd, struct ospf_packet *op, struct ip *iph,
			     struct msghdr *msg, unsigned int maxdatasize,
			     unsigned int mtu, int flags, uint8_t type)
{
#define OSPF_WRITE_FRAG_SHIFT 3
	uint16_t offset;
	struct iovec *iovp;
	int ret;

	assert(op->length == stream_get_endp(op->s));
	assert(msg->msg_iovlen == 2);

	/* we can but try.
	 *
	 * SunOS, BSD and BSD derived kernels likely will clear ip_id, as
	 * well as the IP_MF flag, making this all quite pointless.
	 *
	 * However, for a system on which IP_MF is left alone, and ip_id left
	 * alone or else which sets same ip_id for each fragment this might
	 * work, eg linux.
	 *
	 * XXX-TODO: It would be much nicer to have the kernel's use their
	 * existing fragmentation support to do this for us. Bugs/RFEs need to
	 * be raised against the various kernels.
	 */

	/* set More Frag */
	iph->ip_off |= IP_MF;

	/* ip frag offset is expressed in units of 8byte words */
	offset = maxdatasize >> OSPF_WRITE_FRAG_SHIFT;

	iovp = &msg->msg_iov[1];

	while ((stream_get_endp(op->s) - stream_get_getp(op->s))
	       > maxdatasize) {
		/* data length of this frag is to next offset value */
		iovp->iov_len = offset << OSPF_WRITE_FRAG_SHIFT;
		iph->ip_len = iovp->iov_len + sizeof(struct ip);
		assert(iph->ip_len <= mtu);

		sockopt_iphdrincl_swab_htosys(iph);

		ret = sendmsg(fd, msg, flags);

		sockopt_iphdrincl_swab_systoh(iph);

		if (ret < 0)
			flog_err(
				EC_LIB_SOCKET,
				"*** %s: sendmsg failed to %pI4, id %d, off %d, len %d, mtu %u failed with %s",
				__func__, &iph->ip_dst, iph->ip_id, iph->ip_off,
				iph->ip_len, mtu, safe_strerror(errno));

		if (IS_DEBUG_OSPF_PACKET(type - 1, SEND)) {
			zlog_debug("%s: sent id %d, off %d, len %d to %pI4",
				   __func__, iph->ip_id, iph->ip_off,
				   iph->ip_len, &iph->ip_dst);
		}

		iph->ip_off += offset;
		stream_forward_getp(op->s, iovp->iov_len);
		iovp->iov_base = stream_pnt(op->s);
	}

	/* setup for final fragment */
	iovp->iov_len = stream_get_endp(op->s) - stream_get_getp(op->s);
	iph->ip_len = iovp->iov_len + sizeof(struct ip);
	iph->ip_off &= (~IP_MF);
}
#endif /* WANT_OSPF_WRITE_FRAGMENT */

static void ospf_write(struct event *thread)
{
	struct ospf *ospf = EVENT_ARG(thread);
	struct ospf_interface *oi;
	struct ospf_packet *op;
	struct sockaddr_in sa_dst;
	struct ip iph;
	struct msghdr msg;
	struct iovec iov[2];
	uint8_t type;
	int ret, fd;
	int flags = 0;
	struct listnode *node;
#ifdef WANT_OSPF_WRITE_FRAGMENT
	static uint16_t ipid = 0;
	uint16_t maxdatasize;
#endif /* WANT_OSPF_WRITE_FRAGMENT */
#define OSPF_WRITE_IPHL_SHIFT 2
	int pkt_count = 0;

#ifdef GNU_LINUX
	unsigned char cmsgbuf[64] = {};
	struct cmsghdr *cm = (struct cmsghdr *)cmsgbuf;
	struct in_pktinfo *pi;
#endif
	fd = ospf->fd;

	if (fd < 0 || ospf->oi_running == 0) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s failed to send, fd %d, instance %u",
				   __func__, fd, ospf->oi_running);
		return;
	}

	node = listhead(ospf->oi_write_q);
	assert(node);
	oi = listgetdata(node);

#ifdef WANT_OSPF_WRITE_FRAGMENT
	/* seed ipid static with low order bits of time */
	if (ipid == 0)
		ipid = (time(NULL) & 0xffff);
#endif /* WANT_OSPF_WRITE_FRAGMENT */

	while ((pkt_count < ospf->write_oi_count) && oi) {
		pkt_count++;
#ifdef WANT_OSPF_WRITE_FRAGMENT
		/* convenience - max OSPF data per packet */
		maxdatasize = oi->ifp->mtu - sizeof(struct ip);
#endif /* WANT_OSPF_WRITE_FRAGMENT */

		/* Reset socket fd to use. */
		fd = ospf->fd;

		/* Check for per-interface socket */
		if (ospf->intf_socket_enabled &&
		    (IF_OSPF_IF_INFO(oi->ifp))->oii_fd > 0)
			fd = (IF_OSPF_IF_INFO(oi->ifp))->oii_fd;

		/* Get one packet from queue. */
		op = ospf_fifo_head(oi->obuf);
		assert(op);
		assert(op->length >= OSPF_HEADER_SIZE);

		if (op->dst.s_addr == htonl(OSPF_ALLSPFROUTERS)
		    || op->dst.s_addr == htonl(OSPF_ALLDROUTERS))
			ospf_if_ipmulticast(fd, oi->address, oi->ifp->ifindex);

		/* Rewrite the md5 signature & update the seq */
		ospf_auth_make(oi, op);

		/* Retrieve OSPF packet type. */
		stream_set_getp(op->s, 1);
		type = stream_getc(op->s);

		/* reset get pointer */
		stream_set_getp(op->s, 0);

		memset(&iph, 0, sizeof(iph));
		memset(&sa_dst, 0, sizeof(sa_dst));

		sa_dst.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		sa_dst.sin_len = sizeof(sa_dst);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		sa_dst.sin_addr = op->dst;
		sa_dst.sin_port = htons(0);

		/* Set DONTROUTE flag if dst is unicast. */
		if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
			if (!IN_MULTICAST(htonl(op->dst.s_addr)))
				flags = MSG_DONTROUTE;

		iph.ip_hl = sizeof(struct ip) >> OSPF_WRITE_IPHL_SHIFT;
		/* it'd be very strange for header to not be 4byte-word aligned
		 * but.. */
		if (sizeof(struct ip)
		    > (unsigned int)(iph.ip_hl << OSPF_WRITE_IPHL_SHIFT))
			iph.ip_hl++; /* we presume sizeof(struct ip) cant
					overflow ip_hl.. */

		iph.ip_v = IPVERSION;
		iph.ip_tos = IPTOS_PREC_INTERNETCONTROL;
		iph.ip_len = (iph.ip_hl << OSPF_WRITE_IPHL_SHIFT) + op->length;

#if defined(__DragonFly__)
		/*
		 * DragonFly's raw socket expects ip_len/ip_off in network byte
		 * order.
		 */
		iph.ip_len = htons(iph.ip_len);
#endif

#ifdef WANT_OSPF_WRITE_FRAGMENT
		/* XXX-MT: not thread-safe at all..
		 * XXX: this presumes this is only programme sending OSPF
		 * packets
		 * otherwise, no guarantee ipid will be unique
		 */
		iph.ip_id = ++ipid;
#endif /* WANT_OSPF_WRITE_FRAGMENT */

		iph.ip_off = 0;
		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			iph.ip_ttl = OSPF_VL_IP_TTL;
		else
			iph.ip_ttl = OSPF_IP_TTL;
		iph.ip_p = IPPROTO_OSPFIGP;
		iph.ip_sum = 0;
		iph.ip_src.s_addr = oi->address->u.prefix4.s_addr;
		iph.ip_dst.s_addr = op->dst.s_addr;

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = (caddr_t)&sa_dst;
		msg.msg_namelen = sizeof(sa_dst);
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		iov[0].iov_base = (char *)&iph;
		iov[0].iov_len = iph.ip_hl << OSPF_WRITE_IPHL_SHIFT;
		iov[1].iov_base = stream_pnt(op->s);
		iov[1].iov_len = op->length;

#ifdef GNU_LINUX
		msg.msg_control = (caddr_t)cm;
		cm->cmsg_level = SOL_IP;
		cm->cmsg_type = IP_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		pi = (struct in_pktinfo *)CMSG_DATA(cm);
		pi->ipi_ifindex = oi->ifp->ifindex;

		msg.msg_controllen = cm->cmsg_len;
#endif

/* Sadly we can not rely on kernels to fragment packets
 * because of either IP_HDRINCL and/or multicast
 * destination being set.
 */

#ifdef WANT_OSPF_WRITE_FRAGMENT
		if (op->length > maxdatasize)
			ospf_write_frags(fd, op, &iph, &msg, maxdatasize,
					 oi->ifp->mtu, flags, type);
#endif /* WANT_OSPF_WRITE_FRAGMENT */

		/* send final fragment (could be first) */
		sockopt_iphdrincl_swab_htosys(&iph);
		ret = sendmsg(fd, &msg, flags);
		sockopt_iphdrincl_swab_systoh(&iph);
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s to %pI4, id %d, off %d, len %d, interface %s, mtu %u:",
				__func__, &iph.ip_dst, iph.ip_id, iph.ip_off,
				iph.ip_len, oi->ifp->name, oi->ifp->mtu);

		/* sendmsg will return EPERM if firewall is blocking sending.
		 * This is a normal situation when 'ip nhrp map multicast xxx'
		 * is being used to send multicast packets to DMVPN peers. In
		 * that case the original message is blocked with iptables rule
		 * causing the EPERM result
		 */
		if (ret < 0 && errno != EPERM)
			flog_err(
				EC_LIB_SOCKET,
				"*** sendmsg in %s failed to %pI4, id %d, off %d, len %d, interface %s, mtu %u: %s",
				__func__, &iph.ip_dst, iph.ip_id, iph.ip_off,
				iph.ip_len, oi->ifp->name, oi->ifp->mtu,
				safe_strerror(errno));

		/* Show debug sending packet. */
		if (IS_DEBUG_OSPF_PACKET(type - 1, SEND)) {
			if (IS_DEBUG_OSPF_PACKET(type - 1, DETAIL)) {
				zlog_debug(
					"-----------------------------------------------------");
				stream_set_getp(op->s, 0);
				ospf_packet_dump(op->s);
			}

			zlog_debug("%s sent to [%pI4] via [%s].",
				   lookup_msg(ospf_packet_type_str, type, NULL),
				   &op->dst, IF_NAME(oi));

			if (IS_DEBUG_OSPF_PACKET(type - 1, DETAIL))
				zlog_debug(
					"-----------------------------------------------------");
		}

		switch (type) {
		case OSPF_MSG_HELLO:
			oi->hello_out++;
			break;
		case OSPF_MSG_DB_DESC:
			oi->db_desc_out++;
			break;
		case OSPF_MSG_LS_REQ:
			oi->ls_req_out++;
			break;
		case OSPF_MSG_LS_UPD:
			oi->ls_upd_out++;
			break;
		case OSPF_MSG_LS_ACK:
			oi->ls_ack_out++;
			break;
		default:
			break;
		}

		/* Now delete packet from queue. */
		ospf_packet_delete(oi);

		/* Move this interface to the tail of write_q to
		       serve everyone in a round robin fashion */
		list_delete_node(ospf->oi_write_q, node);
		if (ospf_fifo_head(oi->obuf) == NULL) {
			oi->on_write_q = 0;
			oi = NULL;
		} else
			listnode_add(ospf->oi_write_q, oi);

		/* Setup to service from the head of the queue again */
		if (!list_isempty(ospf->oi_write_q)) {
			node = listhead(ospf->oi_write_q);
			oi = listgetdata(node);
		}
	}

	/* If packets still remain in queue, call write thread. */
	if (!list_isempty(ospf->oi_write_q))
		event_add_write(master, ospf_write, ospf, ospf->fd,
				&ospf->t_write);
}

/* OSPF Hello message read -- RFC2328 Section 10.5. */
static void ospf_hello(struct ip *iph, struct ospf_header *ospfh,
		       struct stream *s, struct ospf_interface *oi, int size)
{
	struct ospf_hello *hello;
	struct ospf_neighbor *nbr;
	int old_state;
	struct prefix p;

	/* increment statistics. */
	oi->hello_in++;

	hello = (struct ospf_hello *)stream_pnt(s);

	/* If Hello is myself, silently discard. */
	if (IPV4_ADDR_SAME(&ospfh->router_id, &oi->ospf->router_id)) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV)) {
			zlog_debug(
				"ospf_header[%s/%pI4]: selforiginated, dropping.",
				lookup_msg(ospf_packet_type_str, ospfh->type,
					   NULL),
				&iph->ip_src);
		}
		return;
	}

	/* get neighbor prefix. */
	p.family = AF_INET;
	p.prefixlen = ip_masklen(hello->network_mask);
	p.u.prefix4 = iph->ip_src;

	/* Compare network mask. */
	/* Checking is ignored for Point-to-Point and Virtual link. */
	/* Checking is also ignored for Point-to-Multipoint with /32 prefix */
	if (oi->type != OSPF_IFTYPE_POINTOPOINT
	    && oi->type != OSPF_IFTYPE_VIRTUALLINK
	    && !(oi->type == OSPF_IFTYPE_POINTOMULTIPOINT
		 && oi->address->prefixlen == IPV4_MAX_BITLEN))
		if (oi->address->prefixlen != p.prefixlen) {
			flog_warn(
				EC_OSPF_PACKET,
				"Packet %pI4 [Hello:RECV]: NetworkMask mismatch on %s (configured prefix length is %d, but hello packet indicates %d).",
				&ospfh->router_id, IF_NAME(oi),
				(int)oi->address->prefixlen, (int)p.prefixlen);
			return;
		}

	/* Compare Router Dead Interval. */
	if (OSPF_IF_PARAM(oi, v_wait) != ntohl(hello->dead_interval)) {
		flog_warn(
			EC_OSPF_PACKET,
			"Packet %pI4 [Hello:RECV]: RouterDeadInterval mismatch on %s (expected %u, but received %u).",
			&ospfh->router_id, IF_NAME(oi),
			OSPF_IF_PARAM(oi, v_wait), ntohl(hello->dead_interval));
		return;
	}

	/* Compare Hello Interval - ignored if fast-hellos are set. */
	if (OSPF_IF_PARAM(oi, fast_hello) == 0) {
		if (OSPF_IF_PARAM(oi, v_hello)
		    != ntohs(hello->hello_interval)) {
			flog_warn(
				EC_OSPF_PACKET,
				"Packet %pI4 [Hello:RECV]: HelloInterval mismatch on %s (expected %u, but received %u).",
				&ospfh->router_id, IF_NAME(oi),
				OSPF_IF_PARAM(oi, v_hello),
				ntohs(hello->hello_interval));
			return;
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Packet %pI4 [Hello:RECV]: Options on %s %s vrf %s",
			   &ospfh->router_id, IF_NAME(oi),
			   ospf_options_dump(hello->options),
			   ospf_vrf_id_to_name(oi->ospf->vrf_id));

/* Compare options. */
#define REJECT_IF_TBIT_ON	1 /* XXX */
#ifdef REJECT_IF_TBIT_ON
	if (CHECK_FLAG(hello->options, OSPF_OPTION_MT)) {
		/*
		 * This router does not support non-zero TOS.
		 * Drop this Hello packet not to establish neighbor
		 * relationship.
		 */
		flog_warn(EC_OSPF_PACKET,
			  "Packet %pI4 [Hello:RECV]: T-bit ON on %s, drop it.",
			  &ospfh->router_id, IF_NAME(oi));
		return;
	}
#endif /* REJECT_IF_TBIT_ON */

	if (CHECK_FLAG(oi->ospf->config, OSPF_OPAQUE_CAPABLE) &&
	    OSPF_IF_PARAM(oi, opaque_capable) &&
	    CHECK_FLAG(hello->options, OSPF_OPTION_O)) {
		/*
		 * This router does know the correct usage of O-bit
		 * the bit should be set in DD packet only.
		 */
		flog_warn(EC_OSPF_PACKET,
			  "Packet %pI4 [Hello:RECV]: O-bit abuse? on %s",
			  &ospfh->router_id, IF_NAME(oi));
#ifdef STRICT_OBIT_USAGE_CHECK
		return; /* Reject this packet. */
#else			/* STRICT_OBIT_USAGE_CHECK */
		UNSET_FLAG(hello->options, OSPF_OPTION_O); /* Ignore O-bit. */
#endif			/* STRICT_OBIT_USAGE_CHECK */
	}

	/* new for NSSA is to ensure that NP is on and E is off */

	if (oi->area->external_routing == OSPF_AREA_NSSA) {
		if (!(CHECK_FLAG(OPTIONS(oi), OSPF_OPTION_NP)
		      && CHECK_FLAG(hello->options, OSPF_OPTION_NP)
		      && !CHECK_FLAG(OPTIONS(oi), OSPF_OPTION_E)
		      && !CHECK_FLAG(hello->options, OSPF_OPTION_E))) {
			flog_warn(
				EC_OSPF_PACKET,
				"NSSA-Packet-%pI4[Hello:RECV]: my options: %x, his options %x",
				&ospfh->router_id, OPTIONS(oi),
				hello->options);
			return;
		}
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("NSSA-Hello:RECV:Packet from %pI4:",
				   &ospfh->router_id);
	} else
		/* The setting of the E-bit found in the Hello Packet's Options
		   field must match this area's ExternalRoutingCapability A
		   mismatch causes processing to stop and the packet to be
		   dropped. The setting of the rest of the bits in the Hello
		   Packet's Options field should be ignored. */
		if (CHECK_FLAG(OPTIONS(oi), OSPF_OPTION_E)
		    != CHECK_FLAG(hello->options, OSPF_OPTION_E)) {
		flog_warn(
			EC_OSPF_PACKET,
			"Packet %pI4 [Hello:RECV]: my options: %x, his options %x",
			&ospfh->router_id, OPTIONS(oi),
			hello->options);
		return;
	}

	/* get neighbour struct */
	nbr = ospf_nbr_get(oi, ospfh, iph, &p);

	/* neighbour must be valid, ospf_nbr_get creates if none existed */
	assert(nbr);

	old_state = nbr->state;

	/* Add event to thread. */
	OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_HelloReceived);

	/*  RFC2328  Section 9.5.1
	    If the router is not eligible to become Designated Router,
	    (snip)   It	must also send an Hello	Packet in reply	to an
	    Hello Packet received from any eligible neighbor (other than
	    the	current	Designated Router and Backup Designated	Router).  */
	if (oi->type == OSPF_IFTYPE_NBMA)
		if (PRIORITY(oi) == 0 && hello->priority > 0
		    && IPV4_ADDR_CMP(&DR(oi), &iph->ip_src)
		    && IPV4_ADDR_CMP(&BDR(oi), &iph->ip_src))
			OSPF_NSM_TIMER_ON(nbr->t_hello_reply,
					  ospf_hello_reply_timer,
					  OSPF_HELLO_REPLY_DELAY);

	/* on NBMA network type, it happens to receive bidirectional Hello
	   packet
	   without advance 1-Way Received event.
	   To avoid incorrect DR-seletion, raise 1-Way Received event.*/
	if (oi->type == OSPF_IFTYPE_NBMA
	    && (old_state == NSM_Down || old_state == NSM_Attempt)) {
		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_OneWayReceived);
		nbr->priority = hello->priority;
		nbr->d_router = hello->d_router;
		nbr->bd_router = hello->bd_router;
		return;
	}

	if (ospf_nbr_bidirectional(&oi->ospf->router_id, hello->neighbors,
				   size - OSPF_HELLO_MIN_SIZE)) {
		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_TwoWayReceived);
		nbr->options |= hello->options;
	} else {
		/* If the router is DR_OTHER, RESTARTER will not wait
		 * until it receives the hello from it if it receives
		 * from DR and BDR.
		 * So, helper might receives ONW_WAY hello from
		 * RESTARTER. So not allowing to change the state if it
		 * receives one_way hellow when it acts as HELPER for
		 * that specific neighbor.
		 */
		if (!OSPF_GR_IS_ACTIVE_HELPER(nbr))
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_OneWayReceived);
		/* Set neighbor information. */
		nbr->priority = hello->priority;
		nbr->d_router = hello->d_router;
		nbr->bd_router = hello->bd_router;
		return;
	}

	if (OSPF_GR_IS_ACTIVE_HELPER(nbr)) {
		/* As per the GR Conformance Test Case 7.2. Section 3
		 * "Also, if X was the Designated Router on network segment S
		 * when the helping relationship began, Y maintains X as the
		 * Designated Router until the helping relationship is
		 * terminated."
		 * When I am helper for this neighbor, I should not trigger the
		 * ISM Events. Also Intentionally not setting the priority and
		 * other fields so that when the neighbor exits the Grace
		 * period, it can handle if there is any change before GR and
		 * after GR. */
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Neighbor is under GR Restart, hence ignoring the ISM Events",
				__PRETTY_FUNCTION__);
	} else {
		/* If neighbor itself declares DR and no BDR exists,
		   cause event BackupSeen */
		if (IPV4_ADDR_SAME(&nbr->address.u.prefix4, &hello->d_router))
			if (hello->bd_router.s_addr == INADDR_ANY
			    && oi->state == ISM_Waiting)
				OSPF_ISM_EVENT_SCHEDULE(oi, ISM_BackupSeen);

		/* neighbor itself declares BDR. */
		if (oi->state == ISM_Waiting
		    && IPV4_ADDR_SAME(&nbr->address.u.prefix4,
				      &hello->bd_router))
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_BackupSeen);

		/* had not previously. */
		if ((IPV4_ADDR_SAME(&nbr->address.u.prefix4, &hello->d_router)
		     && IPV4_ADDR_CMP(&nbr->address.u.prefix4, &nbr->d_router))
		    || (IPV4_ADDR_CMP(&nbr->address.u.prefix4, &hello->d_router)
			&& IPV4_ADDR_SAME(&nbr->address.u.prefix4,
					  &nbr->d_router)))
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);

		/* had not previously. */
		if ((IPV4_ADDR_SAME(&nbr->address.u.prefix4, &hello->bd_router)
		     && IPV4_ADDR_CMP(&nbr->address.u.prefix4, &nbr->bd_router))
		    || (IPV4_ADDR_CMP(&nbr->address.u.prefix4,
				      &hello->bd_router)
			&& IPV4_ADDR_SAME(&nbr->address.u.prefix4,
					  &nbr->bd_router)))
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);

		/* Neighbor priority check. */
		if (nbr->priority >= 0 && nbr->priority != hello->priority)
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);
	}

	/* Set neighbor information. */
	nbr->priority = hello->priority;
	nbr->d_router = hello->d_router;
	nbr->bd_router = hello->bd_router;

	/*
	 * RFC 3623 - Section 2:
	 * "If the restarting router determines that it was the Designated
	 * Router on a given segment prior to the restart, it elects
	 * itself as the Designated Router again.  The restarting router
	 * knows that it was the Designated Router if, while the
	 * associated interface is in Waiting state, a Hello packet is
	 * received from a neighbor listing the router as the Designated
	 * Router".
	 */
	if (oi->area->ospf->gr_info.restart_in_progress
	    && oi->state == ISM_Waiting
	    && IPV4_ADDR_SAME(&hello->d_router, &oi->address->u.prefix4))
		DR(oi) = hello->d_router;
}

/* Save DD flags/options/Seqnum received. */
static void ospf_db_desc_save_current(struct ospf_neighbor *nbr,
				      struct ospf_db_desc *dd)
{
	nbr->last_recv.flags = dd->flags;
	nbr->last_recv.options = dd->options;
	nbr->last_recv.dd_seqnum = ntohl(dd->dd_seqnum);
}

/* Process rest of DD packet. */
static void ospf_db_desc_proc(struct stream *s, struct ospf_interface *oi,
			      struct ospf_neighbor *nbr,
			      struct ospf_db_desc *dd, uint16_t size)
{
	struct ospf_lsa *new, *find;
	struct lsa_header *lsah;

	stream_forward_getp(s, OSPF_DB_DESC_MIN_SIZE);
	for (size -= OSPF_DB_DESC_MIN_SIZE; size >= OSPF_LSA_HEADER_SIZE;
	     size -= OSPF_LSA_HEADER_SIZE) {
		lsah = (struct lsa_header *)stream_pnt(s);
		stream_forward_getp(s, OSPF_LSA_HEADER_SIZE);

		/* Unknown LS type. */
		if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA) {
			flog_warn(EC_OSPF_PACKET,
				  "Packet [DD:RECV]: Unknown LS type %d.",
				  lsah->type);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			return;
		}

		if (IS_OPAQUE_LSA(lsah->type)
		    && !CHECK_FLAG(nbr->options, OSPF_OPTION_O)) {
			flog_warn(EC_OSPF_PACKET,
				  "LSA[Type%d:%pI4] from %pI4: Opaque capability mismatch?",
				  lsah->type, &lsah->id, &lsah->adv_router);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			return;
		}

		switch (lsah->type) {
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_OPAQUE_AS_LSA:
			/* Check for stub area.  Reject if AS-External from stub
			   but
			   allow if from NSSA. */
			if (oi->area->external_routing == OSPF_AREA_STUB) {
				flog_warn(
					EC_OSPF_PACKET,
					"Packet [DD:RECV]: LSA[Type%d:%pI4] from %s area.",
					lsah->type, &lsah->id,
					(oi->area->external_routing
					 == OSPF_AREA_STUB)
						? "STUB"
						: "NSSA");
				OSPF_NSM_EVENT_SCHEDULE(nbr,
							NSM_SeqNumberMismatch);
				return;
			}
			break;
		default:
			break;
		}

		/* Create LS-request object. */
		new = ospf_ls_request_new(lsah);

		/* Lookup received LSA, then add LS request list. */
		find = ospf_lsa_lookup_by_header(oi->area, lsah);

		/* ospf_lsa_more_recent is fine with NULL pointers */
		switch (ospf_lsa_more_recent(find, new)) {
		case -1:
			/* Neighbour has a more recent LSA, we must request it
			 */
			ospf_ls_request_add(nbr, new);
			fallthrough;
		case 0:
			/* If we have a copy of this LSA, it's either less
			 * recent
			 * and we're requesting it from neighbour (the case
			 * above), or
			 * it's as recent and we both have same copy (this
			 * case).
			 *
			 * In neither of these two cases is there any point in
			 * describing our copy of the LSA to the neighbour in a
			 * DB-Summary packet, if we're still intending to do so.
			 *
			 * See: draft-ogier-ospf-dbex-opt-00.txt, describing the
			 * backward compatible optimisation to OSPF DB Exchange
			 * /
			 * DB Description process implemented here.
			 */
			if (find)
				ospf_lsdb_delete(&nbr->db_sum, find);
			ospf_lsa_discard(new);
			break;
		default:
			/* We have the more recent copy, nothing specific to do:
			 * - no need to request neighbours stale copy
			 * - must leave DB summary list copy alone
			 */
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"Packet [DD:RECV]: LSA received Type %d, ID %pI4 is not recent.",
					lsah->type, &lsah->id);
			ospf_lsa_discard(new);
		}
	}

	/* Master */
	if (IS_SET_DD_MS(nbr->dd_flags)) {
		nbr->dd_seqnum++;

		/* Both sides have no More, then we're done with Exchange */
		if (!IS_SET_DD_M(dd->flags) && !IS_SET_DD_M(nbr->dd_flags))
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_ExchangeDone);
		else
			ospf_db_desc_send(nbr);
	}
	/* Slave */
	else {
		nbr->dd_seqnum = ntohl(dd->dd_seqnum);

		/* Send DD packet in reply.
		 *
		 * Must be done to acknowledge the Master's DD, regardless of
		 * whether we have more LSAs ourselves to describe.
		 *
		 * This function will clear the 'More' bit, if after this DD
		 * we have no more LSAs to describe to the master..
		 */
		ospf_db_desc_send(nbr);

		/* Slave can raise ExchangeDone now, if master is also done */
		if (!IS_SET_DD_M(dd->flags) && !IS_SET_DD_M(nbr->dd_flags))
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_ExchangeDone);
	}

	/* Save received neighbor values from DD. */
	ospf_db_desc_save_current(nbr, dd);

	if (!nbr->t_ls_req)
		ospf_ls_req_send(nbr);
}

static int ospf_db_desc_is_dup(struct ospf_db_desc *dd,
			       struct ospf_neighbor *nbr)
{
	/* Is DD duplicated? */
	if (dd->options == nbr->last_recv.options
	    && dd->flags == nbr->last_recv.flags
	    && dd->dd_seqnum == htonl(nbr->last_recv.dd_seqnum))
		return 1;

	return 0;
}

/* OSPF Database Description message read -- RFC2328 Section 10.6. */
static void ospf_db_desc(struct ip *iph, struct ospf_header *ospfh,
			 struct stream *s, struct ospf_interface *oi,
			 uint16_t size)
{
	struct ospf_db_desc *dd;
	struct ospf_neighbor *nbr;

	/* Increment statistics. */
	oi->db_desc_in++;

	dd = (struct ospf_db_desc *)stream_pnt(s);

	nbr = ospf_nbr_lookup(oi, iph, ospfh);
	if (nbr == NULL) {
		flog_warn(EC_OSPF_PACKET, "Packet[DD]: Unknown Neighbor %pI4",
			  &ospfh->router_id);
		return;
	}

	/* Check MTU. */
	if ((OSPF_IF_PARAM(oi, mtu_ignore) == 0)
	    && (ntohs(dd->mtu) > oi->ifp->mtu)) {
		flog_warn(
			EC_OSPF_PACKET,
			"Packet[DD]: Neighbor %pI4 MTU %u is larger than [%s]'s MTU %u",
			&nbr->router_id, ntohs(dd->mtu), IF_NAME(oi),
			oi->ifp->mtu);
		return;
	}

	/*
	 * XXX HACK by Hasso Tepper. Setting N/P bit in NSSA area DD packets is
	 * not
	 * required. In fact at least JunOS sends DD packets with P bit clear.
	 * Until proper solution is developped, this hack should help.
	 *
	 * Update: According to the RFCs, N bit is specified /only/ for Hello
	 * options, unfortunately its use in DD options is not specified. Hence
	 * some
	 * implementations follow E-bit semantics and set it in DD options, and
	 * some
	 * treat it as unspecified and hence follow the directive "default for
	 * options is clear", ie unset.
	 *
	 * Reset the flag, as ospfd follows E-bit semantics.
	 */
	if ((oi->area->external_routing == OSPF_AREA_NSSA)
	    && (CHECK_FLAG(nbr->options, OSPF_OPTION_NP))
	    && (!CHECK_FLAG(dd->options, OSPF_OPTION_NP))) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Packet[DD]: Neighbour %pI4: Has NSSA capability, sends with N bit clear in DD options",
				&nbr->router_id);
		SET_FLAG(dd->options, OSPF_OPTION_NP);
	}

#ifdef REJECT_IF_TBIT_ON
	if (CHECK_FLAG(dd->options, OSPF_OPTION_MT)) {
		/*
		 * In Hello protocol, optional capability must have checked
		 * to prevent this T-bit enabled router be my neighbor.
		 */
		flog_warn(EC_OSPF_PACKET, "Packet[DD]: Neighbor %pI4: T-bit on?",
			  &nbr->router_id);
		return;
	}
#endif /* REJECT_IF_TBIT_ON */

	if (CHECK_FLAG(dd->options, OSPF_OPTION_O) &&
	    (!CHECK_FLAG(oi->ospf->config, OSPF_OPAQUE_CAPABLE) ||
	     !OSPF_IF_PARAM(oi, opaque_capable))) {
		/*
		 * This node is not configured to handle O-bit, for now.
		 * Clear it to ignore unsupported capability proposed by
		 * neighbor.
		 */
		UNSET_FLAG(dd->options, OSPF_OPTION_O);
	}

	if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
		zlog_info(
			"%s:Packet[DD]: Neighbor %pI4 state is %s, seq_num:0x%x, local:0x%x",
			ospf_get_name(oi->ospf), &nbr->router_id,
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
			ntohl(dd->dd_seqnum), nbr->dd_seqnum);

	/* Process DD packet by neighbor status. */
	switch (nbr->state) {
	case NSM_Down:
	case NSM_Attempt:
	case NSM_TwoWay:
		if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
			zlog_info(
				"Packet[DD]: Neighbor %pI4 state is %s, packet discarded.",
				&nbr->router_id,
				lookup_msg(ospf_nsm_state_msg, nbr->state,
					   NULL));
		break;
	case NSM_Init:
		OSPF_NSM_EVENT_EXECUTE(nbr, NSM_TwoWayReceived);
		/* If the new state is ExStart, the processing of the current
		   packet should then continue in this new state by falling
		   through to case ExStart below.  */
		if (nbr->state != NSM_ExStart)
			break;
		fallthrough;
	case NSM_ExStart:
		/* Initial DBD */
		if ((IS_SET_DD_ALL(dd->flags) == OSPF_DD_FLAG_ALL)
		    && (size == OSPF_DB_DESC_MIN_SIZE)) {
			if (IPV4_ADDR_CMP(&nbr->router_id, &oi->ospf->router_id)
			    > 0) {
				/* We're Slave---obey */
				if (CHECK_FLAG(oi->ospf->config,
					       OSPF_LOG_ADJACENCY_DETAIL))
					zlog_info(
						"Packet[DD]: Neighbor %pI4 Negotiation done (Slave).",
						&nbr->router_id);

				nbr->dd_seqnum = ntohl(dd->dd_seqnum);

				/* Reset I/MS */
				UNSET_FLAG(nbr->dd_flags,
					   (OSPF_DD_FLAG_MS | OSPF_DD_FLAG_I));
			} else {
				/* We're Master, ignore the initial DBD from
				 * Slave */
				if (CHECK_FLAG(oi->ospf->config,
					       OSPF_LOG_ADJACENCY_DETAIL))
					zlog_info(
						"Packet[DD]: Neighbor %pI4: Initial DBD from Slave, ignoring.",
						&nbr->router_id);
				break;
			}
		}
		/* Ack from the Slave */
		else if (!IS_SET_DD_MS(dd->flags) && !IS_SET_DD_I(dd->flags)
			 && ntohl(dd->dd_seqnum) == nbr->dd_seqnum
			 && IPV4_ADDR_CMP(&nbr->router_id, &oi->ospf->router_id)
				    < 0) {
			zlog_info(
				"Packet[DD]: Neighbor %pI4 Negotiation done (Master).",
				&nbr->router_id);
			/* Reset I, leaving MS */
			UNSET_FLAG(nbr->dd_flags, OSPF_DD_FLAG_I);
		} else {
			flog_warn(EC_OSPF_PACKET,
				  "Packet[DD]: Neighbor %pI4 Negotiation fails.",
				  &nbr->router_id);
			break;
		}

		/* This is where the real Options are saved */
		nbr->options = dd->options;

		if (CHECK_FLAG(oi->ospf->config, OSPF_OPAQUE_CAPABLE) &&
		    OSPF_IF_PARAM(oi, opaque_capable)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"Neighbor[%pI4] is %sOpaque-capable.",
					&nbr->router_id,
					CHECK_FLAG(nbr->options, OSPF_OPTION_O)
						? ""
						: "NOT ");

			if (!CHECK_FLAG(nbr->options, OSPF_OPTION_O)
			    && IPV4_ADDR_SAME(&DR(oi),
					      &nbr->address.u.prefix4)) {
				flog_warn(
					EC_OSPF_PACKET,
					"DR-neighbor[%pI4] is NOT opaque-capable; Opaque-LSAs cannot be reliably advertised in this network.",
					&nbr->router_id);
				/* This situation is undesirable, but not a real
				 * error. */
			}
		}

		OSPF_NSM_EVENT_EXECUTE(nbr, NSM_NegotiationDone);

		/* continue processing rest of packet. */
		ospf_db_desc_proc(s, oi, nbr, dd, size);
		break;
	case NSM_Exchange:
		if (ospf_db_desc_is_dup(dd, nbr)) {
			if (IS_SET_DD_MS(nbr->dd_flags))
				/* Master: discard duplicated DD packet. */
				zlog_info(
					"Packet[DD] (Master): Neighbor %pI4 packet duplicated.",
					&nbr->router_id);
			else
			/* Slave: cause to retransmit the last Database
			   Description. */
			{
				zlog_info(
					"Packet[DD] [Slave]: Neighbor %pI4 packet duplicated.",
					&nbr->router_id);
				ospf_db_desc_resend(nbr);
			}
			break;
		}

		/* Otherwise DD packet should be checked. */
		/* Check Master/Slave bit mismatch */
		if (IS_SET_DD_MS(dd->flags)
		    != IS_SET_DD_MS(nbr->last_recv.flags)) {
			flog_warn(EC_OSPF_PACKET,
				  "Packet[DD]: Neighbor %pI4 MS-bit mismatch.",
				  &nbr->router_id);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"Packet[DD]: dd->flags=%d, nbr->dd_flags=%d",
					dd->flags, nbr->dd_flags);
			break;
		}

		/* Check initialize bit is set. */
		if (IS_SET_DD_I(dd->flags)) {
			zlog_info("Packet[DD]: Neighbor %pI4 I-bit set.",
				  &nbr->router_id);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			break;
		}

		/* Check DD Options. */
		if (dd->options != nbr->options) {
			flog_warn(EC_OSPF_PACKET,
				  "Packet[DD]: Neighbor %pI4 options mismatch.",
				  &nbr->router_id);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			break;
		}

		/* Check DD sequence number. */
		if ((IS_SET_DD_MS(nbr->dd_flags)
		     && ntohl(dd->dd_seqnum) != nbr->dd_seqnum)
		    || (!IS_SET_DD_MS(nbr->dd_flags)
			&& ntohl(dd->dd_seqnum) != nbr->dd_seqnum + 1)) {
			flog_warn(
				EC_OSPF_PACKET,
				"Packet[DD]: Neighbor %pI4 sequence number mismatch.",
				&nbr->router_id);
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
			break;
		}

		/* Continue processing rest of packet. */
		ospf_db_desc_proc(s, oi, nbr, dd, size);
		break;
	case NSM_Loading:
	case NSM_Full:
		if (ospf_db_desc_is_dup(dd, nbr)) {
			if (IS_SET_DD_MS(nbr->dd_flags)) {
				/* Master should discard duplicate DD packet. */
				zlog_info(
					"Packet[DD]: Neighbor %pI4 duplicated, packet discarded.",
					&nbr->router_id);
				break;
			} else {
				if (monotime_since(&nbr->last_send_ts, NULL)
				    < nbr->v_inactivity * 1000000LL) {
					/* In states Loading and Full the slave
					   must resend
					   its last Database Description packet
					   in response to
					   duplicate Database Description
					   packets received
					   from the master.  For this reason the
					   slave must
					   wait RouterDeadInterval seconds
					   before freeing the
					   last Database Description packet.
					   Reception of a
					   Database Description packet from the
					   master after
					   this interval will generate a
					   SeqNumberMismatch
					   neighbor event. RFC2328 Section 10.8
					   */
					ospf_db_desc_resend(nbr);
					break;
				}
			}
		}

		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_SeqNumberMismatch);
		break;
	default:
		flog_warn(EC_OSPF_PACKET,
			  "Packet[DD]: Neighbor %pI4 NSM illegal status %u.",
			  &nbr->router_id, nbr->state);
		break;
	}
}

#define OSPF_LSA_KEY_SIZE       12 /* type(4) + id(4) + ar(4) */

/* OSPF Link State Request Read -- RFC2328 Section 10.7. */
static void ospf_ls_req(struct ip *iph, struct ospf_header *ospfh,
			struct stream *s, struct ospf_interface *oi,
			uint16_t size)
{
	struct ospf_neighbor *nbr;
	uint32_t ls_type;
	struct in_addr ls_id;
	struct in_addr adv_router;
	struct ospf_lsa *find;
	struct list *ls_upd;
	unsigned int length;

	/* Increment statistics. */
	oi->ls_req_in++;

	nbr = ospf_nbr_lookup(oi, iph, ospfh);
	if (nbr == NULL) {
		flog_warn(EC_OSPF_PACKET,
			  "Link State Request: Unknown Neighbor %pI4",
			  &ospfh->router_id);
		return;
	}

	/* Neighbor State should be Exchange or later. */
	if (nbr->state != NSM_Exchange && nbr->state != NSM_Loading
	    && nbr->state != NSM_Full) {
		flog_warn(
			EC_OSPF_PACKET,
			"Link State Request received from %pI4: Neighbor state is %s, packet discarded.",
			&ospfh->router_id,
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL));
		return;
	}

	/* Send Link State Update for ALL requested LSAs. */
	ls_upd = list_new();
	length = OSPF_HEADER_SIZE + OSPF_LS_UPD_MIN_SIZE;

	while (size >= OSPF_LSA_KEY_SIZE) {
		/* Get one slice of Link State Request. */
		ls_type = stream_getl(s);
		ls_id.s_addr = stream_get_ipv4(s);
		adv_router.s_addr = stream_get_ipv4(s);

		/* Verify LSA type. */
		if (ls_type < OSPF_MIN_LSA || ls_type >= OSPF_MAX_LSA) {
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_BadLSReq);
			list_delete(&ls_upd);
			return;
		}

		/* Search proper LSA in LSDB. */
		find = ospf_lsa_lookup(oi->ospf, oi->area, ls_type, ls_id,
				       adv_router);
		if (find == NULL) {
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_BadLSReq);
			list_delete(&ls_upd);
			return;
		}

		/* Packet overflows MTU size, send immediately. */
		if (length + ntohs(find->data->length) > ospf_packet_max(oi)) {
			ospf_ls_upd_send(nbr, ls_upd,
					 OSPF_SEND_PACKET_DIRECT, 0);

			/* Only remove list contents.  Keep ls_upd. */
			list_delete_all_node(ls_upd);

			length = OSPF_HEADER_SIZE + OSPF_LS_UPD_MIN_SIZE;
		}

		/* Append LSA to update list. */
		listnode_add(ls_upd, find);
		length += ntohs(find->data->length);

		size -= OSPF_LSA_KEY_SIZE;
	}

	/* Send rest of Link State Update. */
	if (listcount(ls_upd) > 0) {
		ospf_ls_upd_send(nbr, ls_upd, OSPF_SEND_PACKET_DIRECT, 0);

		list_delete(&ls_upd);
	} else
		list_delete(&ls_upd);
}

/* Get the list of LSAs from Link State Update packet.
   And process some validation -- RFC2328 Section 13. (1)-(2). */
static struct list *ospf_ls_upd_list_lsa(struct ospf_neighbor *nbr,
					 struct stream *s,
					 struct ospf_interface *oi, size_t size)
{
	uint16_t count, sum;
	uint32_t length;
	struct lsa_header *lsah;
	struct ospf_lsa *lsa;
	struct list *lsas;

	lsas = list_new();

	count = stream_getl(s);
	size -= OSPF_LS_UPD_MIN_SIZE; /* # LSAs */

	for (; size >= OSPF_LSA_HEADER_SIZE && count > 0;
	     size -= length, stream_forward_getp(s, length), count--) {
		lsah = (struct lsa_header *)stream_pnt(s);
		length = ntohs(lsah->length);

		if (length > size) {
			flog_warn(
				EC_OSPF_PACKET,
				"Link State Update: LSA length exceeds packet size.");
			break;
		}

		if (length < OSPF_LSA_HEADER_SIZE) {
			flog_warn(EC_OSPF_PACKET,
				  "Link State Update: LSA length too small.");
			break;
		}

		/* Validate the LSA's LS checksum. */
		sum = lsah->checksum;
		if (!ospf_lsa_checksum_valid(lsah)) {
			/* (bug #685) more details in a one-line message make it
			 * possible
			 * to identify problem source on the one hand and to
			 * have a better
			 * chance to compress repeated messages in syslog on the
			 * other */
			flog_warn(
				EC_OSPF_PACKET,
				"Link State Update: LSA checksum error %x/%x, ID=%pI4 from: nbr %pI4, router ID %pI4, adv router %pI4",
				sum, lsah->checksum, &lsah->id,
				&nbr->src, &nbr->router_id,
				&lsah->adv_router);
			continue;
		}

		/* Examine the LSA's LS type. */
		if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA) {
			flog_warn(EC_OSPF_PACKET,
				  "Link State Update: Unknown LS type %d",
				  lsah->type);
			continue;
		}

		/*
		 * What if the received LSA's age is greater than MaxAge?
		 * Treat it as a MaxAge case -- endo.
		 */
		if (ntohs(lsah->ls_age) > OSPF_LSA_MAXAGE)
			lsah->ls_age = htons(OSPF_LSA_MAXAGE);

		if (CHECK_FLAG(nbr->options, OSPF_OPTION_O)) {
#ifdef STRICT_OBIT_USAGE_CHECK
			if ((IS_OPAQUE_LSA(lsah->type)
			     && !CHECK_FLAG(lsah->options, OSPF_OPTION_O))
			    || (!IS_OPAQUE_LSA(lsah->type)
				&& CHECK_FLAG(lsah->options, OSPF_OPTION_O))) {
				/*
				 * This neighbor must know the exact usage of
				 * O-bit;
				 * the bit will be set in Type-9,10,11 LSAs
				 * only.
				 */
				flog_warn(EC_OSPF_PACKET,
					  "LSA[Type%d:%pI4]: O-bit abuse?",
					  lsah->type, &lsah->id);
				continue;
			}
#endif /* STRICT_OBIT_USAGE_CHECK */

			/* Do not take in AS External Opaque-LSAs if we are a
			 * stub. */
			if (lsah->type == OSPF_OPAQUE_AS_LSA
			    && nbr->oi->area->external_routing
				       != OSPF_AREA_DEFAULT) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"LSA[Type%d:%pI4]: We are a stub, don't take this LSA.",
						lsah->type,
						&lsah->id);
				continue;
			}
		} else if (IS_OPAQUE_LSA(lsah->type)) {
			flog_warn(
				EC_OSPF_PACKET,
				"LSA[Type%d:%pI4] from %pI4: Opaque capability mismatch?",
				lsah->type, &lsah->id, &lsah->adv_router);
			continue;
		}

		/* Create OSPF LSA instance. */
		lsa = ospf_lsa_new_and_data(length);

		lsa->vrf_id = oi->ospf->vrf_id;
		/* We may wish to put some error checking if type NSSA comes in
		   and area not in NSSA mode */
		switch (lsah->type) {
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_OPAQUE_AS_LSA:
			lsa->area = NULL;
			break;
		case OSPF_OPAQUE_LINK_LSA:
			lsa->oi = oi; /* Remember incoming interface for
					 flooding control. */
			fallthrough;
		default:
			lsa->area = oi->area;
			break;
		}

		memcpy(lsa->data, lsah, length);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"LSA[Type%d:%pI4]: %p new LSA created with Link State Update",
				lsa->data->type, &lsa->data->id,
				(void *)lsa);
		listnode_add(lsas, lsa);
	}

	return lsas;
}

/* Cleanup Update list. */
static void ospf_upd_list_clean(struct list *lsas)
{
	struct listnode *node, *nnode;
	struct ospf_lsa *lsa;

	for (ALL_LIST_ELEMENTS(lsas, node, nnode, lsa))
		ospf_lsa_discard(lsa);

	list_delete(&lsas);
}

/* OSPF Link State Update message read -- RFC2328 Section 13. */
static void ospf_ls_upd(struct ospf *ospf, struct ip *iph,
			struct ospf_header *ospfh, struct stream *s,
			struct ospf_interface *oi, uint16_t size)
{
	struct ospf_neighbor *nbr;
	struct list *lsas;
	struct listnode *node, *nnode;
	struct ospf_lsa *lsa = NULL;
	/* unsigned long ls_req_found = 0; */

	/* Dis-assemble the stream, update each entry, re-encapsulate for
	 * flooding */

	/* Increment statistics. */
	oi->ls_upd_in++;

	/* Check neighbor. */
	nbr = ospf_nbr_lookup(oi, iph, ospfh);
	if (nbr == NULL) {
		flog_warn(EC_OSPF_PACKET,
			  "Link State Update: Unknown Neighbor %pI4 on int: %s",
			  &ospfh->router_id, IF_NAME(oi));
		return;
	}

	/* Check neighbor state. */
	if (nbr->state < NSM_Exchange) {
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug(
				"Link State Update: Neighbor[%pI4] state %s is less than Exchange",
				&ospfh->router_id,
				lookup_msg(ospf_nsm_state_msg, nbr->state,
					   NULL));
		return;
	}

	/* Get list of LSAs from Link State Update packet. - Also performs
	 * Stages 1 (validate LSA checksum) and 2 (check for LSA consistent
	 * type) of section 13.
	 */
	lsas = ospf_ls_upd_list_lsa(nbr, s, oi, size);

	if (lsas == NULL)
		return;
#define DISCARD_LSA(L, N)                                                              \
	{                                                                              \
		if (IS_DEBUG_OSPF_EVENT)                                               \
			zlog_debug(                                                    \
				"ospf_lsa_discard() in ospf_ls_upd() point %d: lsa %p" \
				" Type-%d",                                            \
				N, (void *)lsa, (int)lsa->data->type);                 \
		ospf_lsa_discard(L);                                                   \
		continue;                                                              \
	}

	/* Process each LSA received in the one packet.
	 *
	 * Numbers in parentheses, e.g. (1), (2), etc., and the corresponding
	 * text below are from the steps in RFC 2328, Section 13.
	 */
	for (ALL_LIST_ELEMENTS(lsas, node, nnode, lsa)) {
		struct ospf_lsa *ls_ret, *current;
		int ret = 1;

		if (IS_DEBUG_OSPF(lsa, LSA))
			zlog_debug("LSA Type-%d from %pI4, ID: %pI4, ADV: %pI4",
				   lsa->data->type, &ospfh->router_id,
				   &lsa->data->id, &lsa->data->adv_router);

		listnode_delete(lsas,
				lsa); /* We don't need it in list anymore */

		/* (1) Validate Checksum - Done above by ospf_ls_upd_list_lsa()
		 */

		/* (2) LSA Type  - Done above by ospf_ls_upd_list_lsa() */

		/* (3) Do not take in AS External LSAs if we are a stub or NSSA.
		 */

		/* Do not take in AS NSSA if this neighbor and we are not NSSA
		 */

		/* Do take in Type-7's if we are an NSSA  */

		/* If we are also an ABR, later translate them to a Type-5
		 * packet */

		/* Later, an NSSA Re-fresh can Re-fresh Type-7's and an ABR will
		   translate them to a separate Type-5 packet.  */

		if (lsa->data->type == OSPF_AS_EXTERNAL_LSA)
			/* Reject from STUB or NSSA */
			if (nbr->oi->area->external_routing
			    != OSPF_AREA_DEFAULT) {
				if (IS_DEBUG_OSPF_NSSA)
					zlog_debug(
						"Incoming External LSA Discarded: We are NSSA/STUB Area");
				DISCARD_LSA(lsa, 1);
			}

		if (lsa->data->type == OSPF_AS_NSSA_LSA)
			if (nbr->oi->area->external_routing != OSPF_AREA_NSSA) {
				if (IS_DEBUG_OSPF_NSSA)
					zlog_debug(
						"Incoming NSSA LSA Discarded:  Not NSSA Area");
				DISCARD_LSA(lsa, 2);
			}

		/* VU229804: Router-LSA Adv-ID must be equal to LS-ID */
		if (lsa->data->type == OSPF_ROUTER_LSA)
			if (!IPV4_ADDR_SAME(&lsa->data->id,
					    &lsa->data->adv_router)) {
				flog_err(
					EC_OSPF_ROUTER_LSA_MISMATCH,
					"Incoming Router-LSA from %pI4 with Adv-ID[%pI4] != LS-ID[%pI4]",
					&ospfh->router_id, &lsa->data->id,
					&lsa->data->adv_router);
				flog_err(
					EC_OSPF_DOMAIN_CORRUPT,
					"OSPF domain compromised by attack or corruption. Verify correct operation of -ALL- OSPF routers.");
				DISCARD_LSA(lsa, 0);
			}

		/* Find the LSA in the current database. */

		current = ospf_lsa_lookup_by_header(oi->area, lsa->data);

		/* (4) If the LSA's LS age is equal to MaxAge, and there is
		   currently
		   no instance of the LSA in the router's link state database,
		   and none of router's neighbors are in states Exchange or
		   Loading,
		   then take the following actions: */

		if (IS_LSA_MAXAGE(lsa) && !current
		    && ospf_check_nbr_status(oi->ospf)) {
			/* (4a) Response Link State Acknowledgment. */
			ospf_ls_ack_send_direct(nbr, lsa);

			/* (4b) Discard LSA. */
			if (IS_DEBUG_OSPF(lsa, LSA)) {
				zlog_debug(
					"Link State Update[%s]: LS age is equal to MaxAge.",
					dump_lsa_key(lsa));
			}
			DISCARD_LSA(lsa, 3);
		}

		if (IS_OPAQUE_LSA(lsa->data->type)
		    && IPV4_ADDR_SAME(&lsa->data->adv_router,
				      &oi->ospf->router_id)) {
			/*
			 * Even if initial flushing seems to be completed, there
			 * might
			 * be a case that self-originated LSA with MaxAge still
			 * remain
			 * in the routing domain.
			 * Just send an LSAck message to cease retransmission.
			 */
			if (IS_LSA_MAXAGE(lsa)) {
				zlog_info("LSA[%s]: Boomerang effect?",
					  dump_lsa_key(lsa));
				ospf_ls_ack_send_direct(nbr, lsa);
				ospf_lsa_discard(lsa);

				if (current != NULL && !IS_LSA_MAXAGE(current))
					ospf_opaque_lsa_refresh_schedule(
						current);
				continue;
			}

			/*
			 * If an instance of self-originated Opaque-LSA is not
			 * found
			 * in the LSDB, there are some possible cases here.
			 *
			 * 1) This node lost opaque-capability after restart.
			 * 2) Else, a part of opaque-type is no more supported.
			 * 3) Else, a part of opaque-id is no more supported.
			 *
			 * Anyway, it is still this node's responsibility to
			 * flush it.
			 * Otherwise, the LSA instance remains in the routing
			 * domain
			 * until its age reaches to MaxAge.
			 */
			/* XXX: We should deal with this for *ALL* LSAs, not
			 * just opaque */
			if (current == NULL) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"LSA[%s]: Previously originated Opaque-LSA, not found in the LSDB.",
						dump_lsa_key(lsa));

				SET_FLAG(lsa->flags, OSPF_LSA_SELF);

				ospf_ls_ack_send_direct(nbr, lsa);

				if (!ospf->gr_info.restart_in_progress) {
					ospf_opaque_self_originated_lsa_received(
						nbr, lsa);
					continue;
				}
			}
		}

		/* It might be happen that received LSA is self-originated
		 * network LSA, but
		 * router ID is changed. So, we should check if LSA is a
		 * network-LSA whose
		 * Link State ID is one of the router's own IP interface
		 * addresses but whose
		 * Advertising Router is not equal to the router's own Router ID
		 * According to RFC 2328 12.4.2 and 13.4 this LSA should be
		 * flushed.
		 */

		if (lsa->data->type == OSPF_NETWORK_LSA) {
			struct listnode *oinode, *oinnode;
			struct ospf_interface *out_if;
			int Flag = 0;

			for (ALL_LIST_ELEMENTS(oi->ospf->oiflist, oinode,
					       oinnode, out_if)) {
				if (out_if == NULL)
					break;

				if ((IPV4_ADDR_SAME(&out_if->address->u.prefix4,
						    &lsa->data->id))
				    && (!(IPV4_ADDR_SAME(
					       &oi->ospf->router_id,
					       &lsa->data->adv_router)))) {
					if (out_if->network_lsa_self) {
						ospf_lsa_flush_area(
							lsa, out_if->area);
						if (IS_DEBUG_OSPF_EVENT)
							zlog_debug(
								"ospf_lsa_discard() in ospf_ls_upd() point 9: lsa %p Type-%d",
								(void *)lsa,
								(int)lsa->data
									->type);
						ospf_lsa_discard(lsa);
						Flag = 1;
					}
					break;
				}
			}
			if (Flag)
				continue;
		}

		/* (5) Find the instance of this LSA that is currently contained
		   in the router's link state database.  If there is no
		   database copy, or the received LSA is more recent than
		   the database copy the following steps must be performed.
		   (The sub steps from RFC 2328 section 13 step (5) will be
		   performed in
		   ospf_flood() ) */

		if (current == NULL
		    || (ret = ospf_lsa_more_recent(current, lsa)) < 0) {
			/* CVE-2017-3224 */
			if (current && (IS_LSA_MAX_SEQ(current))
			    && (IS_LSA_MAX_SEQ(lsa)) && !IS_LSA_MAXAGE(lsa)) {
				zlog_debug(
					"Link State Update[%s]: has Max Seq and higher checksum but not MaxAge. Dropping it",
					dump_lsa_key(lsa));

				DISCARD_LSA(lsa, 4);
			}

			/* Actual flooding procedure. */
			if (ospf_flood(oi->ospf, nbr, current, lsa)
			    < 0) /* Trap NSSA later. */
				DISCARD_LSA(lsa, 5);

			/* GR: check for network topology change. */
			if (ospf->gr_info.restart_in_progress &&
			    ((lsa->data->type == OSPF_ROUTER_LSA ||
			      lsa->data->type == OSPF_NETWORK_LSA)))
				ospf_gr_check_lsdb_consistency(oi->ospf,
							       oi->area);

			continue;
		}

		/* (6) Else, If there is an instance of the LSA on the sending
		   neighbor's Link state request list, an error has occurred in
		   the Database Exchange process.  In this case, restart the
		   Database Exchange process by generating the neighbor event
		   BadLSReq for the sending neighbor and stop processing the
		   Link State Update packet. */

		if (ospf_ls_request_lookup(nbr, lsa)) {
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_BadLSReq);
			flog_warn(
				EC_OSPF_PACKET,
				"LSA[%s] instance exists on Link state request list",
				dump_lsa_key(lsa));

			/* Clean list of LSAs. */
			ospf_upd_list_clean(lsas);
			/* this lsa is not on lsas list already. */
			ospf_lsa_discard(lsa);
			return;
		}

		/* If the received LSA is the same instance as the database copy
		   (i.e., neither one is more recent) the following two steps
		   should be performed: */

		if (ret == 0) {
			/* If the LSA is listed in the Link state retransmission
			   list
			   for the receiving adjacency, the router itself is
			   expecting
			   an acknowledgment for this LSA.  The router should
			   treat the
			   received LSA as an acknowledgment by removing the LSA
			   from
			   the Link state retransmission list.  This is termed
			   an
			   "implied acknowledgment". */

			ls_ret = ospf_ls_retransmit_lookup(nbr, lsa);

			if (ls_ret != NULL) {
				ospf_ls_retransmit_delete(nbr, ls_ret);

				/* Delayed acknowledgment sent if advertisement
				   received
				   from Designated Router, otherwise do nothing.
				   */
				if (oi->state == ISM_Backup)
					if (NBR_IS_DR(nbr))
						ospf_ls_ack_send_direct(nbr,
									lsa);

				DISCARD_LSA(lsa, 6);
			} else
			/* Acknowledge the receipt of the LSA by sending a
			   Link State Acknowledgment packet back out the
			   receiving
			   interface. */
			{
				ospf_ls_ack_send_direct(nbr, lsa);
				DISCARD_LSA(lsa, 7);
			}
		}

		/* The database copy is more recent.  If the database copy
		   has LS age equal to MaxAge and LS sequence number equal to
		   MaxSequenceNumber, simply discard the received LSA without
		   acknowledging it. (In this case, the LSA's LS sequence number
		   is
		   wrapping, and the MaxSequenceNumber LSA must be completely
		   flushed before any new LSA instance can be introduced). */

		else if (ret > 0) /* Database copy is more recent */
		{
			if (IS_LSA_MAXAGE(current)
			    && current->data->ls_seqnum
				       == htonl(OSPF_MAX_SEQUENCE_NUMBER)) {
				DISCARD_LSA(lsa, 8);
			}
			/* Otherwise, as long as the database copy has not been
			   sent in a
			   Link State Update within the last MinLSArrival
			   seconds, send the
			   database copy back to the sending neighbor,
			   encapsulated within
			   a Link State Update Packet. The Link State Update
			   Packet should
			   be sent directly to the neighbor. In so doing, do not
			   put the
			   database copy of the LSA on the neighbor's link state
			   retransmission list, and do not acknowledge the
			   received (less
			   recent) LSA instance. */
			else {
				if (monotime_since(&current->tv_orig, NULL)
				    >= ospf->min_ls_arrival * 1000LL)
					/* Trap NSSA type later.*/
					ospf_ls_upd_send_lsa(
						nbr, current,
						OSPF_SEND_PACKET_DIRECT);
				DISCARD_LSA(lsa, 9);
			}
		}
	}
#undef DISCARD_LSA

	assert(listcount(lsas) == 0);
	list_delete(&lsas);
}

/* OSPF Link State Acknowledgment message read -- RFC2328 Section 13.7. */
static void ospf_ls_ack(struct ip *iph, struct ospf_header *ospfh,
			struct stream *s, struct ospf_interface *oi,
			uint16_t size)
{
	struct ospf_neighbor *nbr;

	/* increment statistics. */
	oi->ls_ack_in++;

	nbr = ospf_nbr_lookup(oi, iph, ospfh);
	if (nbr == NULL) {
		flog_warn(EC_OSPF_PACKET,
			  "Link State Acknowledgment: Unknown Neighbor %pI4",
			  &ospfh->router_id);
		return;
	}

	if (nbr->state < NSM_Exchange) {
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug(
				"Link State Acknowledgment: Neighbor[%pI4] state %s is less than Exchange",
				&ospfh->router_id,
				lookup_msg(ospf_nsm_state_msg, nbr->state,
					   NULL));
		return;
	}

	while (size >= OSPF_LSA_HEADER_SIZE) {
		struct ospf_lsa *lsa, *lsr;

		lsa = ospf_lsa_new();
		lsa->data = (struct lsa_header *)stream_pnt(s);
		lsa->vrf_id = oi->ospf->vrf_id;

		/* lsah = (struct lsa_header *) stream_pnt (s); */
		size -= OSPF_LSA_HEADER_SIZE;
		stream_forward_getp(s, OSPF_LSA_HEADER_SIZE);

		if (lsa->data->type < OSPF_MIN_LSA
		    || lsa->data->type >= OSPF_MAX_LSA) {
			lsa->data = NULL;
			ospf_lsa_discard(lsa);
			continue;
		}

		lsr = ospf_ls_retransmit_lookup(nbr, lsa);

		if (lsr != NULL && ospf_lsa_more_recent(lsr, lsa) == 0) {
			ospf_ls_retransmit_delete(nbr, lsr);
			ospf_check_and_gen_init_seq_lsa(oi, lsa);
		}

		lsa->data = NULL;
		ospf_lsa_discard(lsa);
	}

	return;
}

static struct stream *ospf_recv_packet(struct ospf *ospf, int fd,
				       struct interface **ifp,
				       struct stream *ibuf)
{
	int ret;
	struct ip *iph;
	uint16_t ip_len;
	ifindex_t ifindex = 0;
	struct iovec iov;
	/* Header and data both require alignment. */
	char buff[CMSG_SPACE(SOPT_SIZE_CMSG_IFINDEX_IPV4())];
	struct msghdr msgh;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = (caddr_t)buff;
	msgh.msg_controllen = sizeof(buff);

	ret = stream_recvmsg(ibuf, fd, &msgh, MSG_DONTWAIT,
			     OSPF_MAX_PACKET_SIZE + 1);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			flog_warn(EC_OSPF_PACKET, "stream_recvmsg failed: %s",
				  safe_strerror(errno));
		return NULL;
	}
	if ((unsigned int)ret < sizeof(struct ip)) {
		flog_warn(
			EC_OSPF_PACKET,
			"%s: discarding runt packet of length %d (ip header size is %u)",
			__func__, ret, (unsigned int)sizeof(iph));
		return NULL;
	}

	/* Note that there should not be alignment problems with this assignment
	   because this is at the beginning of the stream data buffer. */
	iph = (struct ip *)STREAM_DATA(ibuf);
	sockopt_iphdrincl_swab_systoh(iph);

	ip_len = iph->ip_len;

#if defined(__FreeBSD__) && (__FreeBSD_version < 1000000)
	/*
	 * Kernel network code touches incoming IP header parameters,
	 * before protocol specific processing.
	 *
	 *   1) Convert byteorder to host representation.
	 *      --> ip_len, ip_id, ip_off
	 *
	 *   2) Adjust ip_len to strip IP header size!
	 *      --> If user process receives entire IP packet via RAW
	 *          socket, it must consider adding IP header size to
	 *          the "ip_len" field of "ip" structure.
	 *
	 * For more details, see <netinet/ip_input.c>.
	 */
	ip_len = ip_len + (iph->ip_hl << 2);
#endif

#if defined(__DragonFly__)
	/*
	 * in DragonFly's raw socket, ip_len/ip_off are read
	 * in network byte order.
	 * As OpenBSD < 200311 adjust ip_len to strip IP header size!
	 */
	ip_len = ntohs(iph->ip_len) + (iph->ip_hl << 2);
#endif

	ifindex = getsockopt_ifindex(AF_INET, &msgh);

	*ifp = if_lookup_by_index(ifindex, ospf->vrf_id);

	if (ret != ip_len) {
		flog_warn(
			EC_OSPF_PACKET,
			"%s read length mismatch: ip_len is %d, but recvmsg returned %d",
			__func__, ip_len, ret);
		return NULL;
	}

	if (IS_DEBUG_OSPF_PACKET(0, RECV))
		zlog_debug("%s: fd %d(%s) on interface %d(%s)", __func__, fd,
			   ospf_get_name(ospf), ifindex,
			   *ifp ? (*ifp)->name : "Unknown");
	return ibuf;
}

static struct ospf_interface *
ospf_associate_packet_vl(struct ospf *ospf, struct interface *ifp,
			 struct ip *iph, struct ospf_header *ospfh)
{
	struct ospf_interface *rcv_oi;
	struct ospf_vl_data *vl_data;
	struct ospf_area *vl_area;
	struct listnode *node;

	if (IN_MULTICAST(ntohl(iph->ip_dst.s_addr))
	    || !OSPF_IS_AREA_BACKBONE(ospfh))
		return NULL;

	/* look for local OSPF interface matching the destination
	 * to determine Area ID. We presume therefore the destination address
	 * is unique, or at least (for "unnumbered" links), not used in other
	 * areas
	 */
	if ((rcv_oi = ospf_if_lookup_by_local_addr(ospf, NULL, iph->ip_dst))
	    == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data)) {
		vl_area =
			ospf_area_lookup_by_area_id(ospf, vl_data->vl_area_id);
		if (!vl_area)
			continue;

		if (OSPF_AREA_SAME(&vl_area, &rcv_oi->area)
		    && IPV4_ADDR_SAME(&vl_data->vl_peer, &ospfh->router_id)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("associating packet with %s",
					   IF_NAME(vl_data->vl_oi));
			if (!CHECK_FLAG(vl_data->vl_oi->ifp->flags, IFF_UP)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"This VL is not up yet, sorry");
				return NULL;
			}

			return vl_data->vl_oi;
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("couldn't find any VL to associate the packet with");

	return NULL;
}

static int ospf_check_area_id(struct ospf_interface *oi,
			      struct ospf_header *ospfh)
{
	/* Check match the Area ID of the receiving interface. */
	if (OSPF_AREA_SAME(&oi->area, &ospfh))
		return 1;

	return 0;
}

/* Unbound socket will accept any Raw IP packets if proto is matched.
   To prevent it, compare src IP address and i/f address with masking
   i/f network mask. */
static int ospf_check_network_mask(struct ospf_interface *oi,
				   struct in_addr ip_src)
{
	struct in_addr mask, me, him;

	if (oi->type == OSPF_IFTYPE_POINTOPOINT
	    || oi->type == OSPF_IFTYPE_VIRTUALLINK)
		return 1;

	/* Ignore mask check for max prefix length (32) */
	if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT
	    && oi->address->prefixlen == IPV4_MAX_BITLEN)
		return 1;

	masklen2ip(oi->address->prefixlen, &mask);

	me.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
	him.s_addr = ip_src.s_addr & mask.s_addr;

	if (IPV4_ADDR_SAME(&me, &him))
		return 1;

	return 0;
}

/* Verify, that given link/TOS records are properly sized/aligned and match
   Router-LSA "# links" and "# TOS" fields as specified in RFC2328 A.4.2. */
static unsigned ospf_router_lsa_links_examin(struct router_lsa_link *link,
					     uint16_t linkbytes,
					     const uint16_t num_links)
{
	unsigned counted_links = 0, thislinklen;

	while (linkbytes >= OSPF_ROUTER_LSA_LINK_SIZE) {
		thislinklen =
			OSPF_ROUTER_LSA_LINK_SIZE + 4 * link->m[0].tos_count;
		if (thislinklen > linkbytes) {
			if (IS_DEBUG_OSPF_PACKET(0, RECV))
				zlog_debug("%s: length error in link block #%u",
					   __func__, counted_links);
			return MSG_NG;
		}
		link = (struct router_lsa_link *)((caddr_t)link + thislinklen);
		linkbytes -= thislinklen;
		counted_links++;
	}
	if (counted_links != num_links) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: %u link blocks declared, %u present",
				   __func__, num_links, counted_links);
		return MSG_NG;
	}
	return MSG_OK;
}

/* Verify, that the given LSA is properly sized/aligned (including type-specific
   minimum length constraint). */
static unsigned ospf_lsa_examin(struct lsa_header *lsah, const uint16_t lsalen,
				const uint8_t headeronly)
{
	unsigned ret;
	struct router_lsa *rlsa;
	if (lsah->type < OSPF_MAX_LSA && ospf_lsa_minlen[lsah->type]
	    && lsalen < OSPF_LSA_HEADER_SIZE + ospf_lsa_minlen[lsah->type]) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: undersized (%u B) %s", __func__, lsalen,
				   lookup_msg(ospf_lsa_type_msg, lsah->type,
					      NULL));
		return MSG_NG;
	}
	switch (lsah->type) {
	case OSPF_ROUTER_LSA: {
		/*
		 * RFC2328 A.4.2, LSA header + 4 bytes followed by N>=0
		 * (12+)-byte link blocks
		 */
		size_t linkbytes_len = lsalen - OSPF_LSA_HEADER_SIZE
				       - OSPF_ROUTER_LSA_MIN_SIZE;

		/*
		 * LSA link blocks are variable length but always multiples of
		 * 4; basic sanity check
		 */
		if (linkbytes_len % 4 != 0)
			return MSG_NG;

		if (headeronly)
			return MSG_OK;

		rlsa = (struct router_lsa *)lsah;

		ret = ospf_router_lsa_links_examin(
			(struct router_lsa_link *)rlsa->link,
			linkbytes_len,
			ntohs(rlsa->links));
		break;
	}
	case OSPF_AS_EXTERNAL_LSA:
	/* RFC2328 A.4.5, LSA header + 4 bytes followed by N>=1 12-bytes long
	 * blocks */
	case OSPF_AS_NSSA_LSA:
		/* RFC3101 C, idem */
		ret = (lsalen - OSPF_LSA_HEADER_SIZE
		       - OSPF_AS_EXTERNAL_LSA_MIN_SIZE)
				      % 12
			      ? MSG_NG
			      : MSG_OK;
		break;
	/* Following LSA types are considered OK length-wise as soon as their
	 * minimum
	 * length constraint is met and length of the whole LSA is a multiple of
	 * 4
	 * (basic LSA header size is already a multiple of 4). */
	case OSPF_NETWORK_LSA:
	/* RFC2328 A.4.3, LSA header + 4 bytes followed by N>=1 router-IDs */
	case OSPF_SUMMARY_LSA:
	case OSPF_ASBR_SUMMARY_LSA:
	/* RFC2328 A.4.4, LSA header + 4 bytes followed by N>=1 4-bytes TOS
	 * blocks */
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
	case OSPF_OPAQUE_AS_LSA:
		/* RFC5250 A.2, "some number of octets (of application-specific
		 * data) padded to 32-bit alignment." This is considered
		 * equivalent
		 * to 4-byte alignment of all other LSA types, see
		 * OSPF-ALIGNMENT.txt
		 * file for the detailed analysis of this passage. */
		ret = lsalen % 4 ? MSG_NG : MSG_OK;
		break;
	default:
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: unsupported LSA type 0x%02x", __func__,
				   lsah->type);
		return MSG_NG;
	}
	if (ret != MSG_OK && IS_DEBUG_OSPF_PACKET(0, RECV))
		zlog_debug("%s: alignment error in %s", __func__,
			   lookup_msg(ospf_lsa_type_msg, lsah->type, NULL));
	return ret;
}

/* Verify if the provided input buffer is a valid sequence of LSAs. This
   includes verification of LSA blocks length/alignment and dispatching
   of deeper-level checks. */
static unsigned
ospf_lsaseq_examin(struct lsa_header *lsah, /* start of buffered data */
		   size_t length, const uint8_t headeronly,
		   /* When declared_num_lsas is not 0, compare it to the real
		      number of LSAs
		      and treat the difference as an error. */
		   const uint32_t declared_num_lsas)
{
	uint32_t counted_lsas = 0;

	while (length) {
		uint16_t lsalen;
		if (length < OSPF_LSA_HEADER_SIZE) {
			if (IS_DEBUG_OSPF_PACKET(0, RECV))
				zlog_debug(
					"%s: undersized (%zu B) trailing (#%u) LSA header",
					__func__, length, counted_lsas);
			return MSG_NG;
		}
		/* save on ntohs() calls here and in the LSA validator */
		lsalen = ntohs(lsah->length);
		if (lsalen < OSPF_LSA_HEADER_SIZE) {
			if (IS_DEBUG_OSPF_PACKET(0, RECV))
				zlog_debug(
					"%s: malformed LSA header #%u, declared length is %u B",
					__func__, counted_lsas, lsalen);
			return MSG_NG;
		}
		if (headeronly) {
			/* less checks here and in ospf_lsa_examin() */
			if (MSG_OK != ospf_lsa_examin(lsah, lsalen, 1)) {
				if (IS_DEBUG_OSPF_PACKET(0, RECV))
					zlog_debug(
						"%s: malformed header-only LSA #%u",
						__func__, counted_lsas);
				return MSG_NG;
			}
			lsah = (struct lsa_header *)((caddr_t)lsah
						     + OSPF_LSA_HEADER_SIZE);
			length -= OSPF_LSA_HEADER_SIZE;
		} else {
			/* make sure the input buffer is deep enough before
			 * further checks */
			if (lsalen > length) {
				if (IS_DEBUG_OSPF_PACKET(0, RECV))
					zlog_debug(
						"%s: anomaly in LSA #%u: declared length is %u B, buffered length is %zu B",
						__func__, counted_lsas, lsalen,
						length);
				return MSG_NG;
			}
			if (MSG_OK != ospf_lsa_examin(lsah, lsalen, 0)) {
				if (IS_DEBUG_OSPF_PACKET(0, RECV))
					zlog_debug("%s: malformed LSA #%u",
						   __func__, counted_lsas);
				return MSG_NG;
			}
			lsah = (struct lsa_header *)((caddr_t)lsah + lsalen);
			length -= lsalen;
		}
		counted_lsas++;
	}

	if (declared_num_lsas && counted_lsas != declared_num_lsas) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug(
				"%s: #LSAs declared (%u) does not match actual (%u)",
				__func__, declared_num_lsas, counted_lsas);
		return MSG_NG;
	}
	return MSG_OK;
}

/* Verify a complete OSPF packet for proper sizing/alignment. */
static unsigned ospf_packet_examin(struct ospf_header *oh,
				   const unsigned bytesonwire)
{
	uint16_t bytesdeclared, bytesauth;
	unsigned ret;
	struct ospf_ls_update *lsupd;

	/* Length, 1st approximation. */
	if (bytesonwire < OSPF_HEADER_SIZE) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: undersized (%u B) packet", __func__,
				   bytesonwire);
		return MSG_NG;
	}
	/* Now it is safe to access header fields. Performing length check,
	 * allow
	 * for possible extra bytes of crypto auth/padding, which are not
	 * counted
	 * in the OSPF header "length" field. */
	if (oh->version != OSPF_VERSION) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: invalid (%u) protocol version",
				   __func__, oh->version);
		return MSG_NG;
	}
	bytesdeclared = ntohs(oh->length);
	if (ntohs(oh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
		bytesauth = 0;
	else {
		if (oh->u.crypt.auth_data_len > KEYCHAIN_MAX_HASH_SIZE) {
			if (IS_DEBUG_OSPF_PACKET(0, RECV))
				zlog_debug(
					"%s: unsupported crypto auth length (%u B)",
					__func__, oh->u.crypt.auth_data_len);
			return MSG_NG;
		}
		bytesauth = oh->u.crypt.auth_data_len;
	}
	if (bytesdeclared + bytesauth > bytesonwire) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug(
				"%s: packet length error (%u real, %u+%u declared)",
				__func__, bytesonwire, bytesdeclared,
				bytesauth);
		return MSG_NG;
	}
	/* Length, 2nd approximation. The type-specific constraint is checked
	   against declared length, not amount of bytes on wire. */
	if (oh->type >= OSPF_MSG_HELLO && oh->type <= OSPF_MSG_LS_ACK
	    && bytesdeclared
		       < OSPF_HEADER_SIZE + ospf_packet_minlen[oh->type]) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: undersized (%u B) %s packet", __func__,
				   bytesdeclared,
				   lookup_msg(ospf_packet_type_str, oh->type,
					      NULL));
		return MSG_NG;
	}
	switch (oh->type) {
	case OSPF_MSG_HELLO:
		/* RFC2328 A.3.2, packet header + OSPF_HELLO_MIN_SIZE bytes
		   followed
		   by N>=0 router-IDs. */
		ret = (bytesdeclared - OSPF_HEADER_SIZE - OSPF_HELLO_MIN_SIZE)
				      % 4
			      ? MSG_NG
			      : MSG_OK;
		break;
	case OSPF_MSG_DB_DESC:
		/* RFC2328 A.3.3, packet header + OSPF_DB_DESC_MIN_SIZE bytes
		   followed
		   by N>=0 header-only LSAs. */
		ret = ospf_lsaseq_examin(
			(struct lsa_header *)((caddr_t)oh + OSPF_HEADER_SIZE
					      + OSPF_DB_DESC_MIN_SIZE),
			bytesdeclared - OSPF_HEADER_SIZE
				- OSPF_DB_DESC_MIN_SIZE,
			1, /* header-only LSAs */
			0);
		break;
	case OSPF_MSG_LS_REQ:
		/* RFC2328 A.3.4, packet header followed by N>=0 12-bytes
		 * request blocks. */
		ret = (bytesdeclared - OSPF_HEADER_SIZE - OSPF_LS_REQ_MIN_SIZE)
				      % OSPF_LSA_KEY_SIZE
			      ? MSG_NG
			      : MSG_OK;
		break;
	case OSPF_MSG_LS_UPD:
		/* RFC2328 A.3.5, packet header + OSPF_LS_UPD_MIN_SIZE bytes
		   followed
		   by N>=0 full LSAs (with N declared beforehand). */
		lsupd = (struct ospf_ls_update *)((caddr_t)oh
						  + OSPF_HEADER_SIZE);
		ret = ospf_lsaseq_examin(
			(struct lsa_header *)((caddr_t)lsupd
					      + OSPF_LS_UPD_MIN_SIZE),
			bytesdeclared - OSPF_HEADER_SIZE - OSPF_LS_UPD_MIN_SIZE,
			0,		       /* full LSAs */
			ntohl(lsupd->num_lsas) /* 32 bits */
			);
		break;
	case OSPF_MSG_LS_ACK:
		/* RFC2328 A.3.6, packet header followed by N>=0 header-only
		 * LSAs. */
		ret = ospf_lsaseq_examin(
			(struct lsa_header *)((caddr_t)oh + OSPF_HEADER_SIZE
					      + OSPF_LS_ACK_MIN_SIZE),
			bytesdeclared - OSPF_HEADER_SIZE - OSPF_LS_ACK_MIN_SIZE,
			1, /* header-only LSAs */
			0);
		break;
	default:
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug("%s: invalid packet type 0x%02x", __func__,
				   oh->type);
		return MSG_NG;
	}
	if (ret != MSG_OK && IS_DEBUG_OSPF_PACKET(0, RECV))
		zlog_debug("%s: malformed %s packet", __func__,
			   lookup_msg(ospf_packet_type_str, oh->type, NULL));
	return ret;
}

/* OSPF Header verification. */
static int ospf_verify_header(struct stream *ibuf, struct ospf_interface *oi,
			      struct ip *iph, struct ospf_header *ospfh)
{
	/* Check Area ID. */
	if (!ospf_check_area_id(oi, ospfh)) {
		flog_warn(EC_OSPF_PACKET,
			  "interface %s: ospf_read invalid Area ID %pI4",
			  IF_NAME(oi), &ospfh->area_id);
		return -1;
	}

	/* Check network mask, Silently discarded. */
	if (!ospf_check_network_mask(oi, iph->ip_src)) {
		flog_warn(
			EC_OSPF_PACKET,
			"interface %s: ospf_read network address is not same [%pI4]",
			IF_NAME(oi), &iph->ip_src);
		return -1;
	}

	/* Check authentication. The function handles logging actions, where
	 * required. */
	if (!ospf_auth_check(oi, iph, ospfh))
		return -1;

	return 0;
}

enum ospf_read_return_enum {
	OSPF_READ_ERROR,
	OSPF_READ_CONTINUE,
};

static enum ospf_read_return_enum ospf_read_helper(struct ospf *ospf)
{
	int ret;
	struct stream *ibuf;
	struct ospf_interface *oi;
	struct ip *iph;
	struct ospf_header *ospfh;
	uint16_t length;
	struct connected *c;
	struct interface *ifp = NULL;

	stream_reset(ospf->ibuf);
	ibuf = ospf_recv_packet(ospf, ospf->fd, &ifp, ospf->ibuf);
	if (ibuf == NULL)
		return OSPF_READ_ERROR;

	/*
	 * This raw packet is known to be at least as big as its
	 * IP header. Note that there should not be alignment problems with
	 * this assignment because this is at the beginning of the
	 * stream data buffer.
	 */
	iph = (struct ip *)STREAM_DATA(ibuf);
	/*
	 * Note that sockopt_iphdrincl_swab_systoh was called in
	 * ospf_recv_packet.
	 */
	if (ifp == NULL) {
		/*
		 * Handle cases where the platform does not support
		 * retrieving the ifindex, and also platforms (such as
		 * Solaris 8) that claim to support ifindex retrieval but do
		 * not.
		 */
		c = if_lookup_address((void *)&iph->ip_src, AF_INET,
				      ospf->vrf_id);
		if (c)
			ifp = c->ifp;
		if (ifp == NULL) {
			if (IS_DEBUG_OSPF_PACKET(0, RECV))
				zlog_debug(
					"%s: Unable to determine incoming interface from: %pI4(%s)",
					__func__, &iph->ip_src,
					ospf_get_name(ospf));
			return OSPF_READ_CONTINUE;
		}
	}

	if (ospf->vrf_id == VRF_DEFAULT && ospf->vrf_id != ifp->vrf->vrf_id) {
		/*
		 * We may have a situation where l3mdev_accept == 1
		 * let's just kindly drop the packet and move on.
		 * ospf really really really does not like when
		 * we receive the same packet multiple times.
		 */
		return OSPF_READ_CONTINUE;
	}

	/* Self-originated packet should be discarded silently. */
	if (ospf_if_lookup_by_local_addr(ospf, NULL, iph->ip_src)) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV)) {
			zlog_debug(
				"ospf_read[%pI4]: Dropping self-originated packet",
				&iph->ip_src);
		}
		return OSPF_READ_CONTINUE;
	}

	/* Check that we have enough for an IP header */
	if ((unsigned int)(iph->ip_hl << 2) >= STREAM_READABLE(ibuf)) {
		if ((unsigned int)(iph->ip_hl << 2) == STREAM_READABLE(ibuf)) {
			flog_warn(
				EC_OSPF_PACKET,
				"Rx'd IP packet with OSPF protocol number but no payload");
		} else {
			flog_warn(
				EC_OSPF_PACKET,
				"IP header length field claims header is %u bytes, but we only have %zu",
				(unsigned int)(iph->ip_hl << 2),
				STREAM_READABLE(ibuf));
		}

		return OSPF_READ_ERROR;
	}
	stream_forward_getp(ibuf, iph->ip_hl << 2);

	ospfh = (struct ospf_header *)stream_pnt(ibuf);
	if (MSG_OK
	    != ospf_packet_examin(ospfh, stream_get_endp(ibuf)
						 - stream_get_getp(ibuf)))
		return OSPF_READ_CONTINUE;
	/* Now it is safe to access all fields of OSPF packet header. */

	/* associate packet with ospf interface */
	oi = ospf_if_lookup_recv_if(ospf, iph->ip_src, ifp);

	/*
	 * If a neighbor filter prefix-list is configured, apply it to the IP
	 * source address and ignore the packet if it doesn't match.
	 */
	if (oi && oi->nbr_filter) {
		struct prefix ip_src_prefix = { AF_INET, IPV4_MAX_BITLEN, { 0 } };

		ip_src_prefix.u.prefix4 = iph->ip_src;
		if (prefix_list_apply(oi->nbr_filter,
				      (struct prefix *)&(ip_src_prefix)) !=
		    PREFIX_PERMIT)
			return OSPF_READ_CONTINUE;
	}

	/*
	 * ospf_verify_header() relies on a valid "oi" and thus can be called
	 * only after the passive/backbone/other checks below are passed.
	 * These checks in turn access the fields of unverified "ospfh"
	 * structure for their own purposes and must remain very accurate
	 * in doing this.
	 */

	/* If incoming interface is passive one, ignore it. */
	if (oi && OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_PASSIVE) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"ignoring packet from router %pI4 sent to %pI4, received on a passive interface, %pI4",
				&ospfh->router_id, &iph->ip_dst,
				&oi->address->u.prefix4);

		if (iph->ip_dst.s_addr == htonl(OSPF_ALLSPFROUTERS)) {
			/* Try to fix multicast membership.
			 * Some OS:es may have problems in this area,
			 * make sure it is removed.
			 */
			OI_MEMBER_JOINED(oi, MEMBER_ALLROUTERS);
			ospf_if_set_multicast(oi);
		}
		return OSPF_READ_CONTINUE;
	}


	/* if no local ospf_interface,
	 * or header area is backbone but ospf_interface is not
	 * check for VLINK interface
	 */
	if (oi == NULL) {
		if ((oi = ospf_associate_packet_vl(ospf, ifp, iph, ospfh))
		    == NULL) {
			if (!ospf->instance && IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"Packet from [%pI4] received on link %s but no ospf_interface",
					&iph->ip_src, ifp->name);
			return OSPF_READ_CONTINUE;
		}
	} else if (OSPF_IS_AREA_ID_BACKBONE(ospfh->area_id) &&
		   !OSPF_IS_AREA_ID_BACKBONE(oi->area->area_id)) {
		oi = ospf_associate_packet_vl(ospf, ifp, iph, ospfh);
		if (oi == NULL) {
			flog_warn(EC_OSPF_PACKET,
				  "interface %s: ospf_read invalid Area ID %pI4",
				  ifp->name, &ospfh->area_id);
			return OSPF_READ_CONTINUE;
		}
	}

	/*
	 * else it must be a local ospf interface, check it was
	 * received on correct link
	 */
	else if (oi->ifp != ifp) {
		if (IS_DEBUG_OSPF_EVENT)
			flog_warn(EC_OSPF_PACKET,
				  "Packet from [%pI4] received on wrong link %s",
				  &iph->ip_src, ifp->name);
		return OSPF_READ_CONTINUE;
	} else if (oi->state == ISM_Down) {
		flog_warn(
			EC_OSPF_PACKET,
			"Ignoring packet from %pI4 to %pI4 received on interface that is down [%s]; interface flags are %s",
			&iph->ip_src, &iph->ip_dst, ifp->name,
			if_flag_dump(ifp->flags));
		/* Fix multicast memberships? */
		if (iph->ip_dst.s_addr == htonl(OSPF_ALLSPFROUTERS))
			OI_MEMBER_JOINED(oi, MEMBER_ALLROUTERS);
		else if (iph->ip_dst.s_addr == htonl(OSPF_ALLDROUTERS))
			OI_MEMBER_JOINED(oi, MEMBER_DROUTERS);
		if (oi->multicast_memberships)
			ospf_if_set_multicast(oi);
		return OSPF_READ_CONTINUE;
	}

	/*
	 * If the received packet is destined for AllDRouters, the
	 * packet should be accepted only if the received ospf
	 * interface state is either DR or Backup -- endo.
	 *
	 * I wonder who endo is?
	 */
	if (iph->ip_dst.s_addr == htonl(OSPF_ALLDROUTERS)
	    && (oi->state != ISM_DR && oi->state != ISM_Backup)) {
		flog_warn(
			EC_OSPF_PACKET,
			"Dropping packet for AllDRouters from [%pI4] via [%s] (ISM: %s)",
			&iph->ip_src, IF_NAME(oi),
			lookup_msg(ospf_ism_state_msg, oi->state, NULL));
		/* Try to fix multicast membership. */
		SET_FLAG(oi->multicast_memberships, MEMBER_DROUTERS);
		ospf_if_set_multicast(oi);
		return OSPF_READ_CONTINUE;
	}

	/* Verify more OSPF header fields. */
	ret = ospf_verify_header(ibuf, oi, iph, ospfh);
	if (ret < 0) {
		if (IS_DEBUG_OSPF_PACKET(0, RECV))
			zlog_debug(
				"ospf_read[%pI4]: Header check failed, dropping.",
				&iph->ip_src);
		return OSPF_READ_CONTINUE;
	}

	/* Show debug receiving packet. */
	if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV)) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, DETAIL)) {
			zlog_debug(
				"-----------------------------------------------------");
			ospf_packet_dump(ibuf);
		}

		zlog_debug("%s received from [%pI4] via [%s]",
			   lookup_msg(ospf_packet_type_str, ospfh->type, NULL),
			   &ospfh->router_id, IF_NAME(oi));
		zlog_debug(" src [%pI4],", &iph->ip_src);
		zlog_debug(" dst [%pI4]", &iph->ip_dst);

		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, DETAIL))
			zlog_debug(
				"-----------------------------------------------------");
	}

	stream_forward_getp(ibuf, OSPF_HEADER_SIZE);

	/* Adjust size to message length. */
	length = ntohs(ospfh->length) - OSPF_HEADER_SIZE;

	/* Read rest of the packet and call each sort of packet routine.
	 */
	switch (ospfh->type) {
	case OSPF_MSG_HELLO:
		ospf_hello(iph, ospfh, ibuf, oi, length);
		break;
	case OSPF_MSG_DB_DESC:
		ospf_db_desc(iph, ospfh, ibuf, oi, length);
		break;
	case OSPF_MSG_LS_REQ:
		ospf_ls_req(iph, ospfh, ibuf, oi, length);
		break;
	case OSPF_MSG_LS_UPD:
		ospf_ls_upd(ospf, iph, ospfh, ibuf, oi, length);
		break;
	case OSPF_MSG_LS_ACK:
		ospf_ls_ack(iph, ospfh, ibuf, oi, length);
		break;
	default:
		flog_warn(
			EC_OSPF_PACKET,
			"interface %s(%s): OSPF packet header type %d is illegal",
			IF_NAME(oi), ospf_get_name(ospf), ospfh->type);
		break;
	}

	return OSPF_READ_CONTINUE;
}

/* Starting point of packet process function. */
void ospf_read(struct event *thread)
{
	struct ospf *ospf;
	int32_t count = 0;
	enum ospf_read_return_enum ret;

	/* first of all get interface pointer. */
	ospf = EVENT_ARG(thread);

	/* prepare for next packet. */
	event_add_read(master, ospf_read, ospf, ospf->fd, &ospf->t_read);

	while (count < ospf->write_oi_count) {
		count++;
		ret = ospf_read_helper(ospf);
		switch (ret) {
		case OSPF_READ_ERROR:
			return;
		case OSPF_READ_CONTINUE:
			break;
		}
	}
}

/* Make OSPF header. */
static void ospf_make_header(int type, struct ospf_interface *oi,
			     struct stream *s)
{
	struct ospf_header *ospfh;

	ospfh = (struct ospf_header *)STREAM_DATA(s);

	ospfh->version = (uint8_t)OSPF_VERSION;
	ospfh->type = (uint8_t)type;

	ospfh->router_id = oi->ospf->router_id;

	ospfh->checksum = 0;
	ospfh->area_id = oi->area->area_id;
	ospfh->auth_type = htons(ospf_auth_type(oi));

	memset(ospfh->u.auth_data, 0, OSPF_AUTH_SIMPLE_SIZE);

	stream_forward_endp(s, OSPF_HEADER_SIZE);
}

/* Fill rest of OSPF header. */
static void ospf_fill_header(struct ospf_interface *oi, struct stream *s,
			     uint16_t length)
{
	struct ospf_header *ospfh;

	ospfh = (struct ospf_header *)STREAM_DATA(s);

	/* Fill length. */
	ospfh->length = htons(length);

	/* Calculate checksum. */
	if (ntohs(ospfh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
		ospfh->checksum = in_cksum(ospfh, length);
	else
		ospfh->checksum = 0;

	/* Add Authentication Data. */
	oi->keychain = NULL;
	oi->key = NULL;
	ospf_auth_make_data(oi, ospfh);
}

static int ospf_make_hello(struct ospf_interface *oi, struct stream *s)
{
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	uint16_t length = OSPF_HELLO_MIN_SIZE;
	struct in_addr mask;
	unsigned long p;
	int flag = 0;

	/* Set netmask of interface. */
	if (!(CHECK_FLAG(oi->connected->flags, ZEBRA_IFA_UNNUMBERED)
	      && oi->type == OSPF_IFTYPE_POINTOPOINT)
	    && oi->type != OSPF_IFTYPE_VIRTUALLINK)
		masklen2ip(oi->address->prefixlen, &mask);
	else
		memset((char *)&mask, 0, sizeof(struct in_addr));
	stream_put_ipv4(s, mask.s_addr);

	/* Set Hello Interval. */
	if (OSPF_IF_PARAM(oi, fast_hello) == 0)
		stream_putw(s, OSPF_IF_PARAM(oi, v_hello));
	else
		stream_putw(s, 0); /* hello-interval of 0 for fast-hellos */

	/* Check if flood-reduction is enabled,
	 * if yes set the DC bit in the options.
	 */
	if (OSPF_FR_CONFIG(oi->ospf, oi->area))
		SET_FLAG(OPTIONS(oi), OSPF_OPTION_DC);
	else if (CHECK_FLAG(OPTIONS(oi), OSPF_OPTION_DC))
		UNSET_FLAG(OPTIONS(oi), OSPF_OPTION_DC);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: options: %x, int: %s", __func__, OPTIONS(oi),
			   IF_NAME(oi));

	/* Set Options. */
	stream_putc(s, OPTIONS(oi));

	/* Set Router Priority. */
	stream_putc(s, PRIORITY(oi));

	/* Set Router Dead Interval. */
	stream_putl(s, OSPF_IF_PARAM(oi, v_wait));

	/* Set Designated Router. */
	stream_put_ipv4(s, DR(oi).s_addr);

	p = stream_get_endp(s);

	/* Set Backup Designated Router. */
	stream_put_ipv4(s, BDR(oi).s_addr);

	/* Add neighbor seen. */
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr)
			continue;

		/* Ignore the 0.0.0.0 node */
		if (nbr->router_id.s_addr == INADDR_ANY)
			continue;

		/* Ignore Down neighbor */
		if (nbr->state == NSM_Attempt)
			continue;

		/* This is myself for DR election */
		if (nbr->state == NSM_Down)
			continue;

		if (IPV4_ADDR_SAME(&nbr->router_id, &oi->ospf->router_id))
			continue;
		/* Check neighbor is  sane? */
		if (nbr->d_router.s_addr != INADDR_ANY &&
		    IPV4_ADDR_SAME(&nbr->d_router, &oi->address->u.prefix4) &&
		    IPV4_ADDR_SAME(&nbr->bd_router, &oi->address->u.prefix4))
			flag = 1;

		/* Hello packet overflows interface MTU.
		 */
		if (length + sizeof(uint32_t) > ospf_packet_max(oi)) {
			flog_err(
				EC_OSPF_LARGE_HELLO,
				"Oversized Hello packet! Larger than MTU. Not sending it out");
			return 0;
		}

		stream_put_ipv4(s, nbr->router_id.s_addr);
		length += 4;
	}

	/* Let neighbor generate BackupSeen. */
	if (flag == 1)
		stream_putl_at(s, p, 0); /* ipv4 address, normally */

	return length;
}

static int ospf_make_db_desc(struct ospf_interface *oi,
			     struct ospf_neighbor *nbr, struct stream *s)
{
	struct ospf_lsa *lsa;
	uint16_t length = OSPF_DB_DESC_MIN_SIZE;
	uint8_t options;
	unsigned long pp;
	int i;
	struct ospf_lsdb *lsdb;

	/* Set Interface MTU. */
	if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
		stream_putw(s, 0);
	else
		stream_putw(s, oi->ifp->mtu);

	/* Set Options. */
	options = OPTIONS(oi);
	if (CHECK_FLAG(oi->ospf->config, OSPF_OPAQUE_CAPABLE) &&
	    OSPF_IF_PARAM(oi, opaque_capable))
		SET_FLAG(options, OSPF_OPTION_O);
	if (OSPF_FR_CONFIG(oi->ospf, oi->area))
		SET_FLAG(options, OSPF_OPTION_DC);
	stream_putc(s, options);

	/* DD flags */
	pp = stream_get_endp(s);
	stream_putc(s, nbr->dd_flags);

	/* Set DD Sequence Number. */
	stream_putl(s, nbr->dd_seqnum);

	/* shortcut unneeded walk of (empty) summary LSDBs */
	if (ospf_db_summary_isempty(nbr))
		goto empty;

	/* Describe LSA Header from Database Summary List. */
	lsdb = &nbr->db_sum;

	for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
		struct route_table *table = lsdb->type[i].db;
		struct route_node *rn;

		for (rn = route_top(table); rn; rn = route_next(rn))
			if ((lsa = rn->info) != NULL) {
				if (IS_OPAQUE_LSA(lsa->data->type)
				    && (!CHECK_FLAG(options, OSPF_OPTION_O))) {
					/* Suppress advertising
					 * opaque-information. */
					/* Remove LSA from DB summary list. */
					ospf_lsdb_delete(lsdb, lsa);
					continue;
				}

				if (!CHECK_FLAG(lsa->flags, OSPF_LSA_DISCARD)) {
					struct lsa_header *lsah;
					uint16_t ls_age;

					/* DD packet overflows interface MTU. */
					if (length + OSPF_LSA_HEADER_SIZE
					    > ospf_packet_max(oi))
						break;

					/* Keep pointer to LS age. */
					lsah = (struct lsa_header
							*)(STREAM_DATA(s)
							   + stream_get_endp(
								     s));

					/* Proceed stream pointer. */
					stream_put(s, lsa->data,
						   OSPF_LSA_HEADER_SIZE);
					length += OSPF_LSA_HEADER_SIZE;

					/* Set LS age. */
					ls_age = LS_AGE(lsa);
					lsah->ls_age = htons(ls_age);
				}

				/* Remove LSA from DB summary list. */
				ospf_lsdb_delete(lsdb, lsa);
			}
	}

	/* Update 'More' bit */
	if (ospf_db_summary_isempty(nbr)) {
	empty:
		if (nbr->state >= NSM_Exchange) {
			UNSET_FLAG(nbr->dd_flags, OSPF_DD_FLAG_M);
			/* Rewrite DD flags */
			stream_putc_at(s, pp, nbr->dd_flags);
		} else {
			assert(IS_SET_DD_M(nbr->dd_flags));
		}
	}
	return length;
}

static int ospf_make_ls_req_func(struct stream *s, uint16_t *length,
				 unsigned long delta, struct ospf_neighbor *nbr,
				 struct ospf_lsa *lsa)
{
	struct ospf_interface *oi;

	oi = nbr->oi;

	/* LS Request packet overflows interface MTU
	 * delta is just number of bytes required for 1 LS Req
	 * ospf_packet_max will return the number of bytes can
	 * be accommodated without ospf header. So length+delta
	 * can be compared to ospf_packet_max
	 * to check if it can fit another lsreq in the same packet.
	 */

	if (*length + delta > ospf_packet_max(oi))
		return 0;

	stream_putl(s, lsa->data->type);
	stream_put_ipv4(s, lsa->data->id.s_addr);
	stream_put_ipv4(s, lsa->data->adv_router.s_addr);

	ospf_lsa_unlock(&nbr->ls_req_last);
	nbr->ls_req_last = ospf_lsa_lock(lsa);

	*length += 12;
	return 1;
}

static int ospf_make_ls_req(struct ospf_neighbor *nbr, struct stream *s)
{
	struct ospf_lsa *lsa;
	uint16_t length = OSPF_LS_REQ_MIN_SIZE;
	unsigned long delta = 12;
	struct route_table *table;
	struct route_node *rn;
	int i;
	struct ospf_lsdb *lsdb;

	lsdb = &nbr->ls_req;

	for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
		table = lsdb->type[i].db;
		for (rn = route_top(table); rn; rn = route_next(rn))
			if ((lsa = (rn->info)) != NULL)
				if (ospf_make_ls_req_func(s, &length, delta,
							  nbr, lsa)
				    == 0) {
					route_unlock_node(rn);
					break;
				}
	}
	return length;
}

static int ls_age_increment(struct ospf_lsa *lsa, int delay)
{
	int age;

	age = IS_LSA_MAXAGE(lsa) ? OSPF_LSA_MAXAGE : LS_AGE(lsa) + delay;

	return (age > OSPF_LSA_MAXAGE ? OSPF_LSA_MAXAGE : age);
}

static int ospf_make_ls_upd(struct ospf_interface *oi, struct list *update,
			    struct stream *s)
{
	struct ospf_lsa *lsa;
	struct listnode *node;
	uint16_t length = 0;
	unsigned int size_noauth;
	unsigned long delta = stream_get_endp(s);
	unsigned long pp;
	int count = 0;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	pp = stream_get_endp(s);
	stream_forward_endp(s, OSPF_LS_UPD_MIN_SIZE);
	length += OSPF_LS_UPD_MIN_SIZE;

	/* Calculate amount of packet usable for data. */
	size_noauth = stream_get_size(s) - ospf_packet_authspace(oi);

	while ((node = listhead(update)) != NULL) {
		struct lsa_header *lsah;
		uint16_t ls_age;

		lsa = listgetdata(node);
		assert(lsa->data);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: List Iteration %d LSA[%s]", __func__,
				   count, dump_lsa_key(lsa));

		/* Will it fit? Minimum it has to fit at least one */
		if ((length + delta + ntohs(lsa->data->length) > size_noauth) &&
				(count > 0))
			break;

		/* Keep pointer to LS age. */
		lsah = (struct lsa_header *)(STREAM_DATA(s)
					     + stream_get_endp(s));

		/* Put LSA to Link State Request. */
		stream_put(s, lsa->data, ntohs(lsa->data->length));

		/* Set LS age. */
		/* each hop must increment an lsa_age by transmit_delay
		   of OSPF interface */
		ls_age = ls_age_increment(lsa,
					  OSPF_IF_PARAM(oi, transmit_delay));
		lsah->ls_age = htons(ls_age);

		length += ntohs(lsa->data->length);
		count++;

		list_delete_node(update, node);
		ospf_lsa_unlock(&lsa); /* oi->ls_upd_queue */
	}

	/* Now set #LSAs. */
	stream_putl_at(s, pp, count);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
	return length;
}

static int ospf_make_ls_ack(struct ospf_interface *oi,
			    struct ospf_lsa_list_head *ls_ack_list,
			    bool direct_ack, bool delete_ack, struct stream *s)
{
	struct ospf_lsa_list_entry *ls_ack_list_first;
	struct ospf_lsa_list_entry *ls_ack_list_entry;
	uint16_t length = OSPF_LS_ACK_MIN_SIZE;
	struct ospf_lsa *lsa;
	struct in_addr first_dst_addr = { INADDR_ANY };

	/*
	 * For direct LS Acks, assure the destination address doesn't
	 * change between queued acknowledgments.
	 */
	if (direct_ack) {
		ls_ack_list_first = ospf_lsa_list_first(ls_ack_list);
		if (ls_ack_list_first)
			first_dst_addr.s_addr =
				ls_ack_list_first->list_entry_dst.s_addr;
	}

	frr_each_safe (ospf_lsa_list, ls_ack_list, ls_ack_list_entry) {
		lsa = ls_ack_list_entry->lsa;
		assert(lsa);

		if (direct_ack && (ls_ack_list_entry->list_entry_dst.s_addr !=
				   first_dst_addr.s_addr))
			break;

		/* LS Ack packet overflows interface MTU
		 * delta is just number of bytes required for
		 * 1 LS Ack(1 LS Hdr) ospf_packet_max will return
		 * the number of bytes can be accommodated without
		 * ospf header. So length+delta can be compared
		 * against ospf_packet_max to check if it can fit
		 * another ls header in the same packet.
		 */
		if ((length + OSPF_LSA_HEADER_SIZE) > ospf_packet_max(oi))
			break;

		stream_put(s, lsa->data, OSPF_LSA_HEADER_SIZE);
		length += OSPF_LSA_HEADER_SIZE;

		if (delete_ack) {
			ospf_lsa_list_del(ls_ack_list, ls_ack_list_entry);
			XFREE(MTYPE_OSPF_LSA_LIST, ls_ack_list_entry);
			ospf_lsa_unlock(&lsa);
		}
	}

	return length;
}

/*
 * On non-braodcast networks, the same LS acks must be sent to multiple
 * neighbors and deletion must be deferred until after the LS Ack packet
 * is sent to all neighbors.
 */
static void ospf_delete_ls_ack_delayed(struct ospf_interface *oi)
{
	struct ospf_lsa_list_entry *ls_ack_list_entry;
	struct ospf_lsa *lsa;
	uint16_t length = OSPF_LS_ACK_MIN_SIZE;

	frr_each_safe (ospf_lsa_list, &oi->ls_ack_delayed, ls_ack_list_entry) {
		lsa = ls_ack_list_entry->lsa;
		assert(lsa);
		if ((length + OSPF_LSA_HEADER_SIZE) > ospf_packet_max(oi))
			break;

		length += OSPF_LSA_HEADER_SIZE;
		ospf_lsa_list_del(&oi->ls_ack_delayed, ls_ack_list_entry);
		XFREE(MTYPE_OSPF_LSA_LIST, ls_ack_list_entry);
		ospf_lsa_unlock(&lsa);
	}
}

static void ospf_hello_send_sub(struct ospf_interface *oi, in_addr_t addr)
{
	struct ospf_packet *op;
	uint16_t length = OSPF_HEADER_SIZE;

	/* Check if config is still being processed */
	if (event_is_scheduled(t_ospf_cfg)) {
		if (IS_DEBUG_OSPF_PACKET(0, SEND))
			zlog_debug(
				"Suppressing hello to %pI4 on %s during config load",
				&(addr), IF_NAME(oi));

		return;
	}

	op = ospf_packet_new(oi->ifp->mtu);

	/* Prepare OSPF common header. */
	ospf_make_header(OSPF_MSG_HELLO, oi, op->s);

	/* Prepare OSPF Hello body. */
	length += ospf_make_hello(oi, op->s);
	if (length == OSPF_HEADER_SIZE) {
		/* Hello overshooting MTU */
		ospf_packet_free(op);
		return;
	}

	/* Fill OSPF header. */
	ospf_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	op->dst.s_addr = addr;

	if (IS_DEBUG_OSPF_EVENT) {
		if (oi->ospf->vrf_id)
			zlog_debug(
				"%s: Hello Tx interface %s ospf vrf %s id %u",
				__func__, oi->ifp->name,
				ospf_vrf_id_to_name(oi->ospf->vrf_id),
				oi->ospf->vrf_id);
	}
	/* Add packet to the top of the interface output queue, so that they
	 * can't get delayed by things like long queues of LS Update packets
	 */
	ospf_packet_add_top(oi, op);

	/* Hook thread to write packet. */
	OSPF_ISM_WRITE_ON(oi->ospf);
}

static void ospf_poll_send(struct ospf_nbr_nbma *nbr_nbma)
{
	struct ospf_interface *oi;

	oi = nbr_nbma->oi;
	assert(oi);

	/* If this is passive interface, do not send OSPF Hello. */
	if (OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_PASSIVE)
		return;

	if (nbr_nbma->nbr != NULL && nbr_nbma->nbr->state != NSM_Down)
		return;

	if (oi->type == OSPF_IFTYPE_NBMA) {
		if (PRIORITY(oi) == 0)
			return;

		if (nbr_nbma->priority == 0 && oi->state != ISM_DR &&
		    oi->state != ISM_Backup)
			return;

	} else if (oi->type != OSPF_IFTYPE_POINTOMULTIPOINT ||
		   !oi->p2mp_non_broadcast)
		return;

	ospf_hello_send_sub(oi, nbr_nbma->addr.s_addr);
}

void ospf_poll_timer(struct event *thread)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = EVENT_ARG(thread);
	nbr_nbma->t_poll = NULL;

	if (IS_DEBUG_OSPF(nsm, NSM_TIMERS))
		zlog_debug("NSM[%s:%pI4]: Timer (Poll timer expire)",
			   IF_NAME(nbr_nbma->oi), &nbr_nbma->addr);

	ospf_poll_send(nbr_nbma);

	if (nbr_nbma->v_poll > 0)
		OSPF_POLL_TIMER_ON(nbr_nbma->t_poll, ospf_poll_timer,
				   nbr_nbma->v_poll);
}


void ospf_hello_reply_timer(struct event *thread)
{
	struct ospf_neighbor *nbr;

	nbr = EVENT_ARG(thread);
	nbr->t_hello_reply = NULL;

	if (IS_DEBUG_OSPF(nsm, NSM_TIMERS))
		zlog_debug("NSM[%s:%pI4]: Timer (hello-reply timer expire)",
			   IF_NAME(nbr->oi), &nbr->router_id);

	ospf_hello_send_sub(nbr->oi, nbr->address.u.prefix4.s_addr);
}

/* Send OSPF Hello. */
void ospf_hello_send(struct ospf_interface *oi)
{
	/* If this is passive interface, do not send OSPF Hello. */
	if (OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_PASSIVE)
		return;

	if (OSPF_IF_NON_BROADCAST(oi)) {
		struct ospf_neighbor *nbr;
		struct route_node *rn;

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if (!nbr)
				continue;

			if (nbr == oi->nbr_self)
				continue;

			if (nbr->state == NSM_Down)
				continue;

			/*
			 * Always send to all neighbors on Point-to-Multipoint
			 * non-braodcast networks.
			 */
			if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
				ospf_hello_send_sub(oi, nbr->address.u.prefix4
								.s_addr);
			else {
				/*
				 * RFC 2328  Section 9.5.1
				 * If the router is not eligible to become Designated
				 * Router, it must periodically send Hello Packets to
				 * both the Designated Router and the Backup
				 * Designated Router (if they exist).
				 */
				if (PRIORITY(oi) == 0 &&
				    IPV4_ADDR_CMP(&DR(oi),
						  &nbr->address.u.prefix4) &&
				    IPV4_ADDR_CMP(&BDR(oi),
						  &nbr->address.u.prefix4))
					continue;

				/*
				 * If the router is eligible to become Designated
				 * Router, it must periodically send Hello Packets to
				 * all neighbors that are also eligible. In addition,
				 * if the router is itself the Designated Router or
				 * Backup Designated Router, it must also send periodic
				 * Hello Packets to all other neighbors.
				 */
				if (nbr->priority == 0 &&
				    oi->state == ISM_DROther)
					continue;

				/* if oi->state == Waiting, send
				 * hello to all neighbors */
				ospf_hello_send_sub(oi, nbr->address.u.prefix4
								.s_addr);
			}
		}
	} else {
		/* Decide destination address. */
		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			ospf_hello_send_sub(oi, oi->vl_data->peer_addr.s_addr);
		else
			ospf_hello_send_sub(oi, htonl(OSPF_ALLSPFROUTERS));
	}
}

/* Send OSPF Database Description. */
void ospf_db_desc_send(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi;
	struct ospf_packet *op;
	uint16_t length = OSPF_HEADER_SIZE;

	oi = nbr->oi;
	op = ospf_packet_new(oi->ifp->mtu);

	/* Prepare OSPF common header. */
	ospf_make_header(OSPF_MSG_DB_DESC, oi, op->s);

	/* Prepare OSPF Database Description body. */
	length += ospf_make_db_desc(oi, nbr, op->s);

	/* Fill OSPF header. */
	ospf_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	/* Decide destination address. */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT)
		op->dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else
		op->dst = nbr->address.u.prefix4;

	/* Add packet to the interface output queue. */
	ospf_packet_add(oi, op);

	/* Hook thread to write packet. */
	OSPF_ISM_WRITE_ON(oi->ospf);

	/* Remove old DD packet, then copy new one and keep in neighbor
	 * structure. */
	if (nbr->last_send)
		ospf_packet_free(nbr->last_send);
	nbr->last_send = ospf_packet_dup(op);
	monotime(&nbr->last_send_ts);
	if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
		zlog_info(
			"%s:Packet[DD]: %pI4 DB Desc send with seqnum:%x , flags:%x",
			ospf_get_name(oi->ospf), &nbr->router_id,
			nbr->dd_seqnum, nbr->dd_flags);
}

/* Re-send Database Description. */
void ospf_db_desc_resend(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi;

	oi = nbr->oi;

	/* Add packet to the interface output queue. */
	ospf_packet_add(oi, ospf_packet_dup(nbr->last_send));

	/* Hook thread to write packet. */
	OSPF_ISM_WRITE_ON(oi->ospf);
	if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
		zlog_info(
			"%s:Packet[DD]: %pI4 DB Desc resend with seqnum:%x , flags:%x",
			ospf_get_name(oi->ospf), &nbr->router_id,
			nbr->dd_seqnum, nbr->dd_flags);
}

/* Send Link State Request. */
void ospf_ls_req_send(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi;
	struct ospf_packet *op;
	uint16_t length = OSPF_HEADER_SIZE;

	oi = nbr->oi;
	op = ospf_packet_new(oi->ifp->mtu);

	/* Prepare OSPF common header. */
	ospf_make_header(OSPF_MSG_LS_REQ, oi, op->s);

	/* Prepare OSPF Link State Request body. */
	length += ospf_make_ls_req(nbr, op->s);
	if (length == OSPF_HEADER_SIZE) {
		ospf_packet_free(op);
		return;
	}

	/* Fill OSPF header. */
	ospf_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	/* Decide destination address. */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT)
		op->dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else
		op->dst = nbr->address.u.prefix4;

	/* Add packet to the interface output queue. */
	ospf_packet_add(oi, op);

	/* Hook thread to write packet. */
	OSPF_ISM_WRITE_ON(oi->ospf);

	/* Add Link State Request Retransmission Timer. */
	OSPF_NSM_TIMER_ON(nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);
}

/* Send Link State Update with an LSA. */
void ospf_ls_upd_send_lsa(struct ospf_neighbor *nbr, struct ospf_lsa *lsa,
			  int flag)
{
	struct list *update;

	update = list_new();

	listnode_add(update, lsa);

	/*ospf instance is going down, send self originated
	 * MAXAGE LSA update to neighbors to remove from LSDB */
	if (nbr->oi->ospf->inst_shutdown && IS_LSA_MAXAGE(lsa))
		ospf_ls_upd_send(nbr, update, flag, 1);
	else
		ospf_ls_upd_send(nbr, update, flag, 0);

	list_delete(&update);
}

/* Determine size for packet. Must be at least big enough to accommodate next
 * LSA on list, which may be bigger than MTU size.
 *
 * Return pointer to new ospf_packet
 * NULL if we can not allocate, eg because LSA is bigger than imposed limit
 * on packet sizes (in which case offending LSA is deleted from update list)
 */
static struct ospf_packet *ospf_ls_upd_packet_new(struct list *update,
						  struct ospf_interface *oi)
{
	struct ospf_lsa *lsa;
	struct listnode *ln;
	size_t size;
	static char warned = 0;

	lsa = listgetdata((ln = listhead(update)));
	assert(lsa->data);

	if ((OSPF_LS_UPD_MIN_SIZE + ntohs(lsa->data->length))
	    > ospf_packet_max(oi)) {
		if (!warned) {
			flog_warn(
				EC_OSPF_LARGE_LSA,
				"%s: oversized LSA encountered!will need to fragment. Not optimal. Try divide up your network with areas. Use 'debug ospf packet send' to see details, or look at 'show ip ospf database ..'",
				__func__);
			warned = 1;
		}

		if (IS_DEBUG_OSPF_PACKET(0, SEND))
			zlog_debug(
				"%s: oversized LSA id:%pI4, %d bytes originated by %pI4, will be fragmented!",
				__func__, &lsa->data->id,
				ntohs(lsa->data->length),
				&lsa->data->adv_router);

		/*
		 * Allocate just enough to fit this LSA only, to avoid including
		 * other
		 * LSAs in fragmented LSA Updates.
		 */
		size = ntohs(lsa->data->length)
		       + (oi->ifp->mtu - ospf_packet_max(oi))
		       + OSPF_LS_UPD_MIN_SIZE;
	} else
		size = oi->ifp->mtu;

	if (size > OSPF_MAX_PACKET_SIZE) {
		flog_warn(
			EC_OSPF_LARGE_LSA,
			"%s: oversized LSA id:%pI4 too big, %d bytes, packet size %ld, dropping it completely. OSPF routing is broken!",
			__func__, &lsa->data->id, ntohs(lsa->data->length),
			(long int)size);
		list_delete_node(update, ln);
		return NULL;
	}

	/* IP header is built up separately by ospf_write(). This means, that we
	 * must
	 * reduce the "affordable" size just calculated by length of an IP
	 * header.
	 * This makes sure, that even if we manage to fill the payload with LSA
	 * data
	 * completely, the final packet (our data plus IP header) still fits
	 * into
	 * outgoing interface MTU. This correction isn't really meaningful for
	 * an
	 * oversized LSA, but for consistency the correction is done for both
	 * cases.
	 *
	 * P.S. OSPF_MAX_PACKET_SIZE above already includes IP header size
	 */
	return ospf_packet_new(size - sizeof(struct ip));
}

void ospf_ls_upd_queue_send(struct ospf_interface *oi, struct list *update,
			    struct in_addr addr, int send_lsupd_now)
{
	struct ospf_packet *op;
	uint16_t length = OSPF_HEADER_SIZE;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("listcount = %d, [%s]dst %pI4", listcount(update),
			   IF_NAME(oi), &addr);

	/* Check that we have really something to process */
	if (listcount(update) == 0)
		return;

	op = ospf_ls_upd_packet_new(update, oi);

	/* Prepare OSPF common header. */
	ospf_make_header(OSPF_MSG_LS_UPD, oi, op->s);

	/* Prepare OSPF Link State Update body.
	 * Includes Type-7 translation.
	 */
	length += ospf_make_ls_upd(oi, update, op->s);

	/* Fill OSPF header. */
	ospf_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	/* Decide destination address. */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT)
		op->dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else
		op->dst.s_addr = addr.s_addr;

	/* Add packet to the interface output queue. */
	ospf_packet_add(oi, op);
	/* Call ospf_write() right away to send ospf packets to neighbors */
	if (send_lsupd_now) {
		struct event os_packet_thd;

		os_packet_thd.arg = (void *)oi->ospf;
		if (oi->on_write_q == 0) {
			listnode_add(oi->ospf->oi_write_q, oi);
			oi->on_write_q = 1;
		}
		ospf_write(&os_packet_thd);
		/*
		 * We are fake calling ospf_write with a fake
		 * thread.  Imagine that we have oi_a already
		 * enqueued and we have turned on the write
		 * thread(t_write).
		 * Now this function calls this for oi_b
		 * so the on_write_q has oi_a and oi_b on
		 * it, ospf_write runs and clears the packets
		 * for both oi_a and oi_b.  Removing them from
		 * the on_write_q.  After this thread of execution
		 * finishes we will execute the t_write thread
		 * with nothing in the on_write_q causing an
		 * assert.  So just make sure that the t_write
		 * is actually turned off.
		 */
		if (list_isempty(oi->ospf->oi_write_q))
			EVENT_OFF(oi->ospf->t_write);
	} else {
		/* Hook thread to write packet. */
		OSPF_ISM_WRITE_ON(oi->ospf);
	}
}

static void ospf_ls_upd_send_queue_event(struct event *thread)
{
	struct ospf_interface *oi = EVENT_ARG(thread);
	struct route_node *rn;
	struct route_node *rnext;
	struct list *update;
	char again = 0;

	oi->t_ls_upd_event = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s start", __func__);

	for (rn = route_top(oi->ls_upd_queue); rn; rn = rnext) {
		rnext = route_next(rn);

		if (rn->info == NULL)
			continue;

		update = (struct list *)rn->info;

		ospf_ls_upd_queue_send(oi, update, rn->p.u.prefix4, 0);

		/* list might not be empty. */
		if (listcount(update) == 0) {
			list_delete((struct list **)&rn->info);
			route_unlock_node(rn);
		} else
			again = 1;
	}

	if (again != 0) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: update lists not cleared, %d nodes to try again, raising new event",
				__func__, again);
		oi->t_ls_upd_event = NULL;
		event_add_event(master, ospf_ls_upd_send_queue_event, oi, 0,
				&oi->t_ls_upd_event);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s stop", __func__);
}

void ospf_ls_upd_send(struct ospf_neighbor *nbr, struct list *update, int flag,
		      int send_lsupd_now)
{
	struct ospf_interface *oi;
	struct ospf_lsa *lsa;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct listnode *node;

	oi = nbr->oi;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;

	/* Decide destination address. */
	if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
		p.prefix = oi->vl_data->peer_addr;
	else if (oi->type == OSPF_IFTYPE_POINTOPOINT)
		p.prefix.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else if (flag == OSPF_SEND_PACKET_DIRECT)
		p.prefix = nbr->address.u.prefix4;
	else if (oi->state == ISM_DR || oi->state == ISM_Backup)
		p.prefix.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
		p.prefix.s_addr = htonl(OSPF_ALLSPFROUTERS);
	else
		p.prefix.s_addr = htonl(OSPF_ALLDROUTERS);

	if (OSPF_IF_NON_BROADCAST(oi)) {
		if (flag == OSPF_SEND_PACKET_INDIRECT)
			flog_warn(EC_OSPF_PACKET,
				  "* LS-Update is directly sent on non-broadcast network.");
		if (IPV4_ADDR_SAME(&oi->address->u.prefix4, &p.prefix))
			flog_warn(EC_OSPF_PACKET,
				  "* LS-Update is sent to myself.");
	}

	rn = route_node_get(oi->ls_upd_queue, (struct prefix *)&p);

	if (rn->info == NULL)
		rn->info = list_new();
	else
		route_unlock_node(rn);

	for (ALL_LIST_ELEMENTS_RO(update, node, lsa))
		listnode_add(rn->info,
			     ospf_lsa_lock(lsa)); /* oi->ls_upd_queue */
	if (send_lsupd_now) {
		struct list *send_update_list;
		struct route_node *rnext;

		for (rn = route_top(oi->ls_upd_queue); rn; rn = rnext) {
			rnext = route_next(rn);

			if (rn->info == NULL)
				continue;

			send_update_list = (struct list *)rn->info;

			ospf_ls_upd_queue_send(oi, send_update_list,
					       rn->p.u.prefix4, 1);
		}
	} else
		event_add_event(master, ospf_ls_upd_send_queue_event, oi, 0,
				&oi->t_ls_upd_event);
}

static void ospf_ls_ack_send_list(struct ospf_interface *oi,
				  struct ospf_lsa_list_head *ls_ack_list,
				  bool direct_ack, bool delete_ack,
				  struct in_addr dst)
{
	struct ospf_packet *op;
	struct ospf_lsa_list_entry *ls_ack_list_first;
	uint16_t length = OSPF_HEADER_SIZE;

	op = ospf_packet_new(oi->ifp->mtu);

	/* Prepare OSPF common header. */
	ospf_make_header(OSPF_MSG_LS_ACK, oi, op->s);

	/* Determine the destination address - for direct acks,
	 * the list entries always include the distination address.
	 */
	if (direct_ack) {
		ls_ack_list_first = ospf_lsa_list_first(ls_ack_list);
		op->dst.s_addr = ls_ack_list_first->list_entry_dst.s_addr;
	} else
		op->dst.s_addr = dst.s_addr;

	/* Prepare OSPF Link State Acknowledgment body. */
	length += ospf_make_ls_ack(oi, ls_ack_list, direct_ack, delete_ack,
				   op->s);

	/* Fill OSPF header. */
	ospf_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	/* Add packet to the interface output queue. */
	ospf_packet_add(oi, op);

	/* Hook thread to write packet. */
	OSPF_ISM_WRITE_ON(oi->ospf);
}

static void ospf_ls_ack_send_direct_event(struct event *thread)
{
	struct ospf_interface *oi = EVENT_ARG(thread);
	struct in_addr dst = { INADDR_ANY };

	oi->t_ls_ack_direct = NULL;

	while (ospf_lsa_list_count(&oi->ls_ack_direct))
		ospf_ls_ack_send_list(oi, &(oi->ls_ack_direct), true, true, dst);
}

void ospf_ls_ack_send_direct(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	struct ospf_lsa_list_entry *ls_ack_list_entry;
	struct ospf_interface *oi = nbr->oi;

	if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
		zlog_debug("%s:Add LSA[Type%d:%pI4:%pI4]: seq 0x%x age %u NBR %pI4 (%s) ack queue",
			   __func__, lsa->data->type, &lsa->data->id,
			   &lsa->data->adv_router, ntohl(lsa->data->ls_seqnum),
			   ntohs(lsa->data->ls_age), &nbr->router_id,
			   IF_NAME(nbr->oi));

	/*
	 * On Point-to-Multipoint broadcast-capabile interfaces,
	 * where direct acks from are sent to the ALLSPFRouters
	 * address and one direct ack send event, may include LSAs
	 * from multiple neighbors, there is a possibility of the same
	 * LSA being processed more than once in the same send event.
	 * In this case, the instances subsequent to the first can be
	 * ignored.
	 */
	if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT && !oi->p2mp_non_broadcast) {
		struct ospf_lsa_list_entry *ls_ack_list_entry;
		struct ospf_lsa *ack_queue_lsa;

		frr_each (ospf_lsa_list, &oi->ls_ack_direct, ls_ack_list_entry) {
			ack_queue_lsa = ls_ack_list_entry->lsa;
			if ((lsa == ack_queue_lsa) ||
			    ((lsa->data->type == ack_queue_lsa->data->type) &&
			     (lsa->data->id.s_addr ==
			      ack_queue_lsa->data->id.s_addr) &&
			     (lsa->data->adv_router.s_addr ==
			      ack_queue_lsa->data->adv_router.s_addr) &&
			     (lsa->data->ls_seqnum ==
			      ack_queue_lsa->data->ls_seqnum))) {
				if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
					zlog_debug("%s:LSA[Type%d:%pI4:%pI4]: seq 0x%x age %u NBR %pI4 (%s) ack queue duplicate",
						   __func__, lsa->data->type,
						   &lsa->data->id,
						   &lsa->data->adv_router,
						   ntohl(lsa->data->ls_seqnum),
						   ntohs(lsa->data->ls_age),
						   &nbr->router_id,
						   IF_NAME(nbr->oi));
				return;
			}
		}
	}

	if (IS_GRACE_LSA(lsa)) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("%s, Sending GRACE ACK to Restarter.",
				   __func__);
	}

	ls_ack_list_entry = XCALLOC(MTYPE_OSPF_LSA_LIST,
				    sizeof(struct ospf_lsa_list_entry));

	/*
	 * Determine the destination address - Direct LS acknowledgments
	 * are sent the AllSPFRouters multicast address on Point-to-Point
	 * and Point-to-Multipoint broadcast-capable interfaces. For all other
	 * interface types, they are unicast directly to the neighbor.
	 */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
	    (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT &&
	     !oi->p2mp_non_broadcast))
		ls_ack_list_entry->list_entry_dst.s_addr =
			htonl(OSPF_ALLSPFROUTERS);
	else
		ls_ack_list_entry->list_entry_dst.s_addr =
			nbr->address.u.prefix4.s_addr;

	ls_ack_list_entry->lsa = ospf_lsa_lock(lsa);
	ospf_lsa_list_add_tail(&nbr->oi->ls_ack_direct, ls_ack_list_entry);

	if (oi->t_ls_ack_direct == NULL)
		event_add_event(master, ospf_ls_ack_send_direct_event, oi, 0,
				&oi->t_ls_ack_direct);
}

/* Send Link State Acknowledgment delayed. */
void ospf_ls_ack_send_delayed(struct ospf_interface *oi)
{
	struct in_addr dst;

	/* Decide destination address. */
	/* RFC2328 Section 13.5                           On non-broadcast
	      networks, delayed Link State Acknowledgment packets must be
	      unicast	separately over	each adjacency (i.e., neighbor whose
	      state is >= Exchange).  */
	if (OSPF_IF_NON_BROADCAST(oi)) {
		struct ospf_neighbor *nbr;
		struct route_node *rn;

		while (ospf_lsa_list_count(&oi->ls_ack_delayed)) {
			for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
				nbr = rn->info;

				if (!nbr)
					continue;

				if (nbr != oi->nbr_self &&
				    nbr->state >= NSM_Exchange)
					ospf_ls_ack_send_list(oi,
							      &oi->ls_ack_delayed,
							      false, false,
							      nbr->address.u
								      .prefix4);
			}
			ospf_delete_ls_ack_delayed(oi);
		}
	} else {
		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			dst.s_addr = oi->vl_data->peer_addr.s_addr;
		else if (oi->state == ISM_DR || oi->state == ISM_Backup)
			dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
		else if (oi->type == OSPF_IFTYPE_POINTOPOINT)
			dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
		else if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
			dst.s_addr = htonl(OSPF_ALLSPFROUTERS);
		else
			dst.s_addr = htonl(OSPF_ALLDROUTERS);

		while (ospf_lsa_list_count(&oi->ls_ack_delayed))
			ospf_ls_ack_send_list(oi, &oi->ls_ack_delayed, false,
					      true, dst);
	}
}

/*
 * On pt-to-pt links, all OSPF control packets are sent to the multicast
 * address. As a result, the kernel does not need to learn the interface
 * MAC of the OSPF neighbor. However, in our world, this will delay
 * convergence. Take the case when due to a link flap, all routes now
 * want to use an interface which was deemed to be costlier prior to this
 * event. For routes that will be installed, the missing MAC will have
 * punt-to-CPU set on them. This may overload the CPU control path that
 * can be avoided if the MAC was known apriori.
 */
void ospf_proactively_arp(struct ospf_neighbor *nbr)
{
	if (!nbr || !nbr->oi->ospf->proactive_arp)
		return;

	ospf_zebra_send_arp(nbr->oi->ifp, &nbr->address);
}
