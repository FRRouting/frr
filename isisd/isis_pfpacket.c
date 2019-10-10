/*
 * IS-IS Rout(e)ing protocol - isis_pfpacket.c
 *
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology
 *                            Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#if ISIS_METHOD == ISIS_METHOD_PFPACKET
#include <net/ethernet.h> /* the L2 protocols */
#include <netpacket/packet.h>

#include <linux/filter.h>

#include "log.h"
#include "network.h"
#include "stream.h"
#include "if.h"
#include "lib_errors.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"

#include "privs.h"

/* tcpdump -i eth0 'isis' -dd */
static struct sock_filter isisfilter[] = {
	/* NB: we're in SOCK_DGRAM, so src/dst mac + length are stripped
	 * off!
	 * (OTOH it's a bit more lower-layer agnostic and might work
	 * over GRE?) */
	/*	{ 0x28, 0, 0, 0x0000000c - 14 }, */
	/*	{ 0x25, 5, 0, 0x000005dc }, */
	{0x28, 0, 0, 0x0000000e - 14}, {0x15, 0, 3, 0x0000fefe},
	{0x30, 0, 0, 0x00000011 - 14}, {0x15, 0, 1, 0x00000083},
	{0x6, 0, 0, 0x00040000},       {0x6, 0, 0, 0x00000000},
};

static struct sock_fprog bpf = {
	.len = array_size(isisfilter),
	.filter = isisfilter,
};

/*
 * Table 9 - Architectural constants for use with ISO 8802 subnetworks
 * ISO 10589 - 8.4.8
 */

uint8_t ALL_L1_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x14};
uint8_t ALL_L2_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x15};
uint8_t ALL_ISS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05};
uint8_t ALL_ESS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x04};

static uint8_t discard_buff[8192];

/*
 * if level is 0 we are joining p2p multicast
 * FIXME: and the p2p multicast being ???
 */
static int isis_multicast_join(int fd, int registerto, int if_num)
{
	struct packet_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = if_num;
	if (registerto) {
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		if (registerto == 1)
			memcpy(&mreq.mr_address, ALL_L1_ISS, ETH_ALEN);
		else if (registerto == 2)
			memcpy(&mreq.mr_address, ALL_L2_ISS, ETH_ALEN);
		else if (registerto == 3)
			memcpy(&mreq.mr_address, ALL_ISS, ETH_ALEN);
		else
			memcpy(&mreq.mr_address, ALL_ESS, ETH_ALEN);

	} else {
		mreq.mr_type = PACKET_MR_ALLMULTI;
	}
#ifdef EXTREME_DEBUG
	zlog_debug(
		"isis_multicast_join(): fd=%d, reg_to=%d, if_num=%d, "
		"address = %02x:%02x:%02x:%02x:%02x:%02x",
		fd, registerto, if_num, mreq.mr_address[0], mreq.mr_address[1],
		mreq.mr_address[2], mreq.mr_address[3], mreq.mr_address[4],
		mreq.mr_address[5]);
#endif /* EXTREME_DEBUG */
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
		       sizeof(struct packet_mreq))) {
		zlog_warn("isis_multicast_join(): setsockopt(): %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	return ISIS_OK;
}

static int open_packet_socket(struct isis_circuit *circuit)
{
	struct sockaddr_ll s_addr;
	int fd, retval = ISIS_OK;

	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (fd < 0) {
		zlog_warn("open_packet_socket(): socket() failed %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
		zlog_warn("open_packet_socket(): SO_ATTACH_FILTER failed: %s",
			  safe_strerror(errno));
	}

	/*
	 * Bind to the physical interface
	 */
	memset(&s_addr, 0, sizeof(struct sockaddr_ll));
	s_addr.sll_family = AF_PACKET;
	s_addr.sll_protocol = htons(ETH_P_ALL);
	s_addr.sll_ifindex = circuit->interface->ifindex;

	if (bind(fd, (struct sockaddr *)(&s_addr), sizeof(struct sockaddr_ll))
	    < 0) {
		zlog_warn("open_packet_socket(): bind() failed: %s",
			  safe_strerror(errno));
		close(fd);
		return ISIS_WARNING;
	}

	circuit->fd = fd;

	if (if_is_broadcast(circuit->interface)) {
		/*
		 * Join to multicast groups
		 * according to
		 * 8.4.2 - Broadcast subnetwork IIH PDUs
		 * FIXME: is there a case only one will fail??
		 */
		/* joining ALL_L1_ISS */
		retval |= isis_multicast_join(circuit->fd, 1,
					      circuit->interface->ifindex);
		/* joining ALL_L2_ISS */
		retval |= isis_multicast_join(circuit->fd, 2,
					      circuit->interface->ifindex);
		/* joining ALL_ISS (used in RFC 5309 p2p-over-lan as well) */
		retval |= isis_multicast_join(circuit->fd, 3,
					      circuit->interface->ifindex);
	} else {
		retval = isis_multicast_join(circuit->fd, 0,
					     circuit->interface->ifindex);
	}

	return retval;
}

/*
 * Create the socket and set the tx/rx funcs
 */
int isis_sock_init(struct isis_circuit *circuit)
{
	int retval = ISIS_OK;

	frr_with_privs(&isisd_privs) {

		retval = open_packet_socket(circuit);

		if (retval != ISIS_OK) {
			zlog_warn("%s: could not initialize the socket",
				  __func__);
			break;
		}

	/* Assign Rx and Tx callbacks are based on real if type */
		if (if_is_broadcast(circuit->interface)) {
			circuit->tx = isis_send_pdu_bcast;
			circuit->rx = isis_recv_pdu_bcast;
		} else if (if_is_pointopoint(circuit->interface)) {
			circuit->tx = isis_send_pdu_p2p;
			circuit->rx = isis_recv_pdu_p2p;
		} else {
			zlog_warn("isis_sock_init(): unknown circuit type");
			retval = ISIS_WARNING;
			break;
		}
	}

	return retval;
}

static inline int llc_check(uint8_t *llc)
{
	if (*llc != ISO_SAP || *(llc + 1) != ISO_SAP || *(llc + 2) != 3)
		return 0;

	return 1;
}

int isis_recv_pdu_bcast(struct isis_circuit *circuit, uint8_t *ssnpa)
{
	int bytesread, addr_len;
	struct sockaddr_ll s_addr;
	uint8_t llc[LLC_LEN];

	addr_len = sizeof(s_addr);

	memset(&s_addr, 0, sizeof(struct sockaddr_ll));

	bytesread =
		recvfrom(circuit->fd, (void *)&llc, LLC_LEN, MSG_PEEK,
			 (struct sockaddr *)&s_addr, (socklen_t *)&addr_len);

	if ((bytesread < 0)
	    || (s_addr.sll_ifindex != (int)circuit->interface->ifindex)) {
		if (bytesread < 0) {
			zlog_warn(
				"isis_recv_packet_bcast(): ifname %s, fd %d, "
				"bytesread %d, recvfrom(): %s",
				circuit->interface->name, circuit->fd,
				bytesread, safe_strerror(errno));
		}
		if (s_addr.sll_ifindex != (int)circuit->interface->ifindex) {
			zlog_warn(
				"packet is received on multiple interfaces: "
				"socket interface %d, circuit interface %d, "
				"packet type %u",
				s_addr.sll_ifindex, circuit->interface->ifindex,
				s_addr.sll_pkttype);
		}

		/* get rid of the packet */
		bytesread = recvfrom(circuit->fd, discard_buff,
				     sizeof(discard_buff), MSG_DONTWAIT,
				     (struct sockaddr *)&s_addr,
				     (socklen_t *)&addr_len);

		if (bytesread < 0)
			zlog_warn("isis_recv_pdu_bcast(): recvfrom() failed");

		return ISIS_WARNING;
	}
	/*
	 * Filtering by llc field, discard packets sent by this host (other
	 * circuit)
	 */
	if (!llc_check(llc) || s_addr.sll_pkttype == PACKET_OUTGOING) {
		/*  Read the packet into discard buff */
		bytesread = recvfrom(circuit->fd, discard_buff,
				     sizeof(discard_buff), MSG_DONTWAIT,
				     (struct sockaddr *)&s_addr,
				     (socklen_t *)&addr_len);
		if (bytesread < 0)
			zlog_warn("isis_recv_pdu_bcast(): recvfrom() failed");
		return ISIS_WARNING;
	}

	/* Ensure that we have enough space for a pdu padded to fill the mtu */
	unsigned int max_size =
		circuit->interface->mtu > circuit->interface->mtu6
			? circuit->interface->mtu
			: circuit->interface->mtu6;
	uint8_t temp_buff[max_size];
	bytesread =
		recvfrom(circuit->fd, temp_buff, max_size, MSG_DONTWAIT,
			 (struct sockaddr *)&s_addr, (socklen_t *)&addr_len);
	if (bytesread < 0) {
		zlog_warn("%s: recvfrom() failed", __func__);
		return ISIS_WARNING;
	}
	/* then we lose the LLC */
	stream_write(circuit->rcv_stream, temp_buff + LLC_LEN,
		     bytesread - LLC_LEN);
	memcpy(ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

	return ISIS_OK;
}

int isis_recv_pdu_p2p(struct isis_circuit *circuit, uint8_t *ssnpa)
{
	int bytesread, addr_len;
	struct sockaddr_ll s_addr;

	memset(&s_addr, 0, sizeof(struct sockaddr_ll));
	addr_len = sizeof(s_addr);

	/* we can read directly to the stream */
	(void)stream_recvfrom(
		circuit->rcv_stream, circuit->fd, circuit->interface->mtu, 0,
		(struct sockaddr *)&s_addr, (socklen_t *)&addr_len);

	if (s_addr.sll_pkttype == PACKET_OUTGOING) {
		/*  Read the packet into discard buff */
		bytesread = recvfrom(circuit->fd, discard_buff,
				     sizeof(discard_buff), MSG_DONTWAIT,
				     (struct sockaddr *)&s_addr,
				     (socklen_t *)&addr_len);
		if (bytesread < 0)
			zlog_warn("isis_recv_pdu_p2p(): recvfrom() failed");
		return ISIS_WARNING;
	}

	/* If we don't have protocol type 0x00FE which is
	 * ISO over GRE we exit with pain :)
	 */
	if (ntohs(s_addr.sll_protocol) != 0x00FE) {
		zlog_warn("isis_recv_pdu_p2p(): protocol mismatch(): %X",
			  ntohs(s_addr.sll_protocol));
		return ISIS_WARNING;
	}

	memcpy(ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

	return ISIS_OK;
}

int isis_send_pdu_bcast(struct isis_circuit *circuit, int level)
{
	struct msghdr msg;
	struct iovec iov[2];
	char temp_buff[LLC_LEN];

	/* we need to do the LLC in here because of P2P circuits, which will
	 * not need it
	 */
	struct sockaddr_ll sa;

	stream_set_getp(circuit->snd_stream, 0);
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family = AF_PACKET;

	size_t frame_size = stream_get_endp(circuit->snd_stream) + LLC_LEN;
	sa.sll_protocol = htons(isis_ethertype(frame_size));
	sa.sll_ifindex = circuit->interface->ifindex;
	sa.sll_halen = ETH_ALEN;
	/* RFC5309 section 4.1 recommends ALL_ISS */
	if (circuit->circ_type == CIRCUIT_T_P2P)
		memcpy(&sa.sll_addr, ALL_ISS, ETH_ALEN);
	else if (level == 1)
		memcpy(&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
	else
		memcpy(&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);

	/* on a broadcast circuit */
	/* first we put the LLC in */
	temp_buff[0] = 0xFE;
	temp_buff[1] = 0xFE;
	temp_buff[2] = 0x03;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	iov[0].iov_base = temp_buff;
	iov[0].iov_len = LLC_LEN;
	iov[1].iov_base = circuit->snd_stream->data;
	iov[1].iov_len = stream_get_endp(circuit->snd_stream);

	if (sendmsg(circuit->fd, &msg, 0) < 0) {
		zlog_warn("IS-IS pfpacket: could not transmit packet on %s: %s",
			  circuit->interface->name, safe_strerror(errno));
		if (ERRNO_IO_RETRY(errno))
			return ISIS_WARNING;
		return ISIS_ERROR;
	}
	return ISIS_OK;
}

int isis_send_pdu_p2p(struct isis_circuit *circuit, int level)
{
	struct sockaddr_ll sa;
	ssize_t rv;

	stream_set_getp(circuit->snd_stream, 0);
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = circuit->interface->ifindex;
	sa.sll_halen = ETH_ALEN;
	if (level == 1)
		memcpy(&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
	else
		memcpy(&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);


	/* lets try correcting the protocol */
	sa.sll_protocol = htons(0x00FE);
	rv = sendto(circuit->fd, circuit->snd_stream->data,
		    stream_get_endp(circuit->snd_stream), 0,
		    (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
	if (rv < 0) {
		zlog_warn("IS-IS pfpacket: could not transmit packet on %s: %s",
			  circuit->interface->name, safe_strerror(errno));
		if (ERRNO_IO_RETRY(errno))
			return ISIS_WARNING;
		return ISIS_ERROR;
	}
	return ISIS_OK;
}

#endif /* ISIS_METHOD == ISIS_METHOD_PFPACKET */
