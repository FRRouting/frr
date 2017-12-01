/*
 * IP MSDP packet helper
 * Copyright (C) 2016 Cumulus Networks, Inc.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <lib/log.h>
#include <lib/network.h>
#include <lib/stream.h>
#include <lib/thread.h>
#include <lib/vty.h>

#include "pimd.h"
#include "pim_str.h"

#include "pim_msdp.h"
#include "pim_msdp_packet.h"
#include "pim_msdp_socket.h"

static char *pim_msdp_pkt_type_dump(enum pim_msdp_tlv type, char *buf,
				    int buf_size)
{
	switch (type) {
	case PIM_MSDP_V4_SOURCE_ACTIVE:
		snprintf(buf, buf_size, "%s", "SA");
		break;
	case PIM_MSDP_V4_SOURCE_ACTIVE_REQUEST:
		snprintf(buf, buf_size, "%s", "SA_REQ");
		break;
	case PIM_MSDP_V4_SOURCE_ACTIVE_RESPONSE:
		snprintf(buf, buf_size, "%s", "SA_RESP");
		break;
	case PIM_MSDP_KEEPALIVE:
		snprintf(buf, buf_size, "%s", "KA");
		break;
	case PIM_MSDP_RESERVED:
		snprintf(buf, buf_size, "%s", "RSVD");
		break;
	case PIM_MSDP_TRACEROUTE_PROGRESS:
		snprintf(buf, buf_size, "%s", "TRACE_PROG");
		break;
	case PIM_MSDP_TRACEROUTE_REPLY:
		snprintf(buf, buf_size, "%s", "TRACE_REPLY");
		break;
	default:
		snprintf(buf, buf_size, "UNK-%d", type);
	}
	return buf;
}

static void pim_msdp_pkt_sa_dump_one(struct stream *s)
{
	struct prefix_sg sg;

	/* just throw away the three reserved bytes */
	stream_get3(s);
	/* throw away the prefix length also */
	stream_getc(s);

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.grp.s_addr = stream_get_ipv4(s);
	sg.src.s_addr = stream_get_ipv4(s);

	zlog_debug("  sg %s", pim_str_sg_dump(&sg));
}

static void pim_msdp_pkt_sa_dump(struct stream *s)
{
	int entry_cnt;
	int i;
	struct in_addr rp; /* Last RP address associated with this SA */

	entry_cnt = stream_getc(s);
	rp.s_addr = stream_get_ipv4(s);

	if (PIM_DEBUG_MSDP_PACKETS) {
		char rp_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<rp?>", rp, rp_str, sizeof(rp_str));
		zlog_debug("  entry_cnt %d rp %s", entry_cnt, rp_str);
	}

	/* dump SAs */
	for (i = 0; i < entry_cnt; ++i) {
		pim_msdp_pkt_sa_dump_one(s);
	}
}

static void pim_msdp_pkt_dump(struct pim_msdp_peer *mp, int type, int len,
			      bool rx, struct stream *s)
{
	char type_str[PIM_MSDP_PKT_TYPE_STRLEN];

	pim_msdp_pkt_type_dump(type, type_str, sizeof(type_str));

	zlog_debug("MSDP peer %s pkt %s type %s len %d", mp->key_str,
		   rx ? "rx" : "tx", type_str, len);

	if (!s) {
		return;
	}

	switch (type) {
	case PIM_MSDP_V4_SOURCE_ACTIVE:
		pim_msdp_pkt_sa_dump(s);
		break;
	default:;
	}
}

/* Check file descriptor whether connect is established. */
static void pim_msdp_connect_check(struct pim_msdp_peer *mp)
{
	int status;
	socklen_t slen;
	int ret;

	if (mp->state != PIM_MSDP_CONNECTING) {
		/* if we are here it means we are not in a connecting or
		 * established state
		 * for now treat this as a fatal error */
		pim_msdp_peer_reset_tcp_conn(mp, "invalid-state");
		return;
	}

	PIM_MSDP_PEER_READ_OFF(mp);
	PIM_MSDP_PEER_WRITE_OFF(mp);

	/* Check file descriptor. */
	slen = sizeof(status);
	ret = getsockopt(mp->fd, SOL_SOCKET, SO_ERROR, (void *)&status, &slen);

	/* If getsockopt is fail, this is fatal error. */
	if (ret < 0) {
		zlog_err("can't get sockopt for nonblocking connect");
		pim_msdp_peer_reset_tcp_conn(mp, "connect-failed");
		return;
	}

	/* When status is 0 then TCP connection is established. */
	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_connect_check %s", mp->key_str,
			   status ? "fail" : "success");
	}
	if (status == 0) {
		pim_msdp_peer_established(mp);
	} else {
		pim_msdp_peer_reset_tcp_conn(mp, "connect-failed");
	}
}

static void pim_msdp_pkt_delete(struct pim_msdp_peer *mp)
{
	stream_free(stream_fifo_pop(mp->obuf));
}

static void pim_msdp_pkt_add(struct pim_msdp_peer *mp, struct stream *s)
{
	stream_fifo_push(mp->obuf, s);
}

static void pim_msdp_write_proceed_actions(struct pim_msdp_peer *mp)
{
	if (stream_fifo_head(mp->obuf)) {
		PIM_MSDP_PEER_WRITE_ON(mp);
	}
}

int pim_msdp_write(struct thread *thread)
{
	struct pim_msdp_peer *mp;
	struct stream *s;
	int num;
	enum pim_msdp_tlv type;
	int len;
	int work_cnt = 0;
	int work_max_cnt = 100;

	mp = THREAD_ARG(thread);
	mp->t_write = NULL;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_write", mp->key_str);
	}
	if (mp->fd < 0) {
		return -1;
	}

	/* check if TCP connection is established */
	if (mp->state != PIM_MSDP_ESTABLISHED) {
		pim_msdp_connect_check(mp);
		return 0;
	}

	s = stream_fifo_head(mp->obuf);
	if (!s) {
		pim_msdp_write_proceed_actions(mp);
		return 0;
	}

	sockopt_cork(mp->fd, 1);

	/* Nonblocking write until TCP output buffer is full  */
	do {
		int writenum;

		/* Number of bytes to be sent */
		writenum = stream_get_endp(s) - stream_get_getp(s);

		/* Call write() system call */
		num = write(mp->fd, stream_pnt(s), writenum);
		if (num < 0) {
			/* write failed either retry needed or error */
			if (ERRNO_IO_RETRY(errno)) {
				if (PIM_DEBUG_MSDP_INTERNAL) {
					zlog_debug(
						"MSDP peer %s pim_msdp_write io retry",
						mp->key_str);
				}
				break;
			}

			pim_msdp_peer_reset_tcp_conn(mp, "pkt-tx-failed");
			return 0;
		}

		if (num != writenum) {
			/* Partial write */
			stream_forward_getp(s, num);
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug(
					"MSDP peer %s pim_msdp_partial_write",
					mp->key_str);
			}
			break;
		}

		/* Retrieve msdp packet type. */
		stream_set_getp(s, 0);
		type = stream_getc(s);
		len = stream_getw(s);
		switch (type) {
		case PIM_MSDP_KEEPALIVE:
			mp->ka_tx_cnt++;
			break;
		case PIM_MSDP_V4_SOURCE_ACTIVE:
			mp->sa_tx_cnt++;
			break;
		default:;
		}
		if (PIM_DEBUG_MSDP_PACKETS) {
			pim_msdp_pkt_dump(mp, type, len, false /*rx*/, s);
		}

		/* packet sent delete it. */
		pim_msdp_pkt_delete(mp);

		++work_cnt;
		/* may need to pause if we have done too much work in this
		 * loop */
		if (work_cnt >= work_max_cnt) {
			break;
		}
	} while ((s = stream_fifo_head(mp->obuf)) != NULL);
	pim_msdp_write_proceed_actions(mp);

	sockopt_cork(mp->fd, 0);

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_write wrote %d packets",
			   mp->key_str, work_cnt);
	}

	return 0;
}

static void pim_msdp_pkt_send(struct pim_msdp_peer *mp, struct stream *s)
{
	/* Add packet to the end of list. */
	pim_msdp_pkt_add(mp, s);

	PIM_MSDP_PEER_WRITE_ON(mp);
}

void pim_msdp_pkt_ka_tx(struct pim_msdp_peer *mp)
{
	struct stream *s;

	if (mp->state != PIM_MSDP_ESTABLISHED) {
		/* don't tx anything unless a session is established */
		return;
	}
	s = stream_new(PIM_MSDP_KA_TLV_MAX_SIZE);
	stream_putc(s, PIM_MSDP_KEEPALIVE);
	stream_putw(s, PIM_MSDP_KA_TLV_MAX_SIZE);

	pim_msdp_pkt_send(mp, s);
}

static void pim_msdp_pkt_sa_push_to_one_peer(struct pim_instance *pim,
					     struct pim_msdp_peer *mp)
{
	struct stream *s;

	if (mp->state != PIM_MSDP_ESTABLISHED) {
		/* don't tx anything unless a session is established */
		return;
	}
	s = stream_dup(pim->msdp.work_obuf);
	if (s) {
		pim_msdp_pkt_send(mp, s);
		mp->flags |= PIM_MSDP_PEERF_SA_JUST_SENT;
	}
}

/* push the stream into the obuf fifo of all the peers */
static void pim_msdp_pkt_sa_push(struct pim_instance *pim,
				 struct pim_msdp_peer *mp)
{
	struct listnode *mpnode;

	if (mp) {
		pim_msdp_pkt_sa_push_to_one_peer(pim, mp);
	} else {
		for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, mpnode, mp)) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("MSDP peer %s pim_msdp_pkt_sa_push",
					   mp->key_str);
			}
			pim_msdp_pkt_sa_push_to_one_peer(pim, mp);
		}
	}
}

static int pim_msdp_pkt_sa_fill_hdr(struct pim_instance *pim, int local_cnt)
{
	int curr_tlv_ecnt;

	stream_reset(pim->msdp.work_obuf);
	curr_tlv_ecnt = local_cnt > PIM_MSDP_SA_MAX_ENTRY_CNT
				? PIM_MSDP_SA_MAX_ENTRY_CNT
				: local_cnt;
	local_cnt -= curr_tlv_ecnt;
	stream_putc(pim->msdp.work_obuf, PIM_MSDP_V4_SOURCE_ACTIVE);
	stream_putw(pim->msdp.work_obuf,
		    PIM_MSDP_SA_ENTRY_CNT2SIZE(curr_tlv_ecnt));
	stream_putc(pim->msdp.work_obuf, curr_tlv_ecnt);
	stream_put_ipv4(pim->msdp.work_obuf, pim->msdp.originator_id.s_addr);

	return local_cnt;
}

static void pim_msdp_pkt_sa_fill_one(struct pim_msdp_sa *sa)
{
	stream_put3(sa->pim->msdp.work_obuf, 0 /* reserved */);
	stream_putc(sa->pim->msdp.work_obuf, 32 /* sprefix len */);
	stream_put_ipv4(sa->pim->msdp.work_obuf, sa->sg.grp.s_addr);
	stream_put_ipv4(sa->pim->msdp.work_obuf, sa->sg.src.s_addr);
}

static void pim_msdp_pkt_sa_gen(struct pim_instance *pim,
				struct pim_msdp_peer *mp)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;
	int sa_count;
	int local_cnt = pim->msdp.local_cnt;

	sa_count = 0;
	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("  sa gen  %d", local_cnt);
	}

	local_cnt = pim_msdp_pkt_sa_fill_hdr(pim, local_cnt);

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (!(sa->flags & PIM_MSDP_SAF_LOCAL)) {
			/* current implementation of MSDP is for anycast i.e.
			 * full mesh. so
			 * no re-forwarding of SAs that we learnt from other
			 * peers */
			continue;
		}
		/* add sa into scratch pad */
		pim_msdp_pkt_sa_fill_one(sa);
		++sa_count;
		if (sa_count >= PIM_MSDP_SA_MAX_ENTRY_CNT) {
			pim_msdp_pkt_sa_push(pim, mp);
			/* reset headers */
			sa_count = 0;
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("  sa gen for remainder %d",
					   local_cnt);
			}
			local_cnt = pim_msdp_pkt_sa_fill_hdr(pim, local_cnt);
		}
	}

	if (sa_count) {
		pim_msdp_pkt_sa_push(pim, mp);
	}
	return;
}

static void pim_msdp_pkt_sa_tx_done(struct pim_instance *pim)
{
	struct listnode *mpnode;
	struct pim_msdp_peer *mp;

	/* if SA were sent to the peers we restart ka timer and avoid
	 * unnecessary ka noise */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, mpnode, mp)) {
		if (mp->flags & PIM_MSDP_PEERF_SA_JUST_SENT) {
			mp->flags &= ~PIM_MSDP_PEERF_SA_JUST_SENT;
			pim_msdp_peer_pkt_txed(mp);
		}
	}
}

void pim_msdp_pkt_sa_tx(struct pim_instance *pim)
{
	pim_msdp_pkt_sa_gen(pim, NULL /* mp */);
	pim_msdp_pkt_sa_tx_done(pim);
}

void pim_msdp_pkt_sa_tx_one(struct pim_msdp_sa *sa)
{
	pim_msdp_pkt_sa_fill_hdr(sa->pim, 1 /* cnt */);
	pim_msdp_pkt_sa_fill_one(sa);
	pim_msdp_pkt_sa_push(sa->pim, NULL);
	pim_msdp_pkt_sa_tx_done(sa->pim);
}

/* when a connection is first established we push all SAs immediately */
void pim_msdp_pkt_sa_tx_to_one_peer(struct pim_msdp_peer *mp)
{
	pim_msdp_pkt_sa_gen(mp->pim, mp);
	pim_msdp_pkt_sa_tx_done(mp->pim);
}

static void pim_msdp_pkt_rxed_with_fatal_error(struct pim_msdp_peer *mp)
{
	pim_msdp_peer_reset_tcp_conn(mp, "invalid-pkt-rx");
}

static void pim_msdp_pkt_ka_rx(struct pim_msdp_peer *mp, int len)
{
	mp->ka_rx_cnt++;
	if (len != PIM_MSDP_KA_TLV_MAX_SIZE) {
		pim_msdp_pkt_rxed_with_fatal_error(mp);
		return;
	}
	pim_msdp_peer_pkt_rxed(mp);
}

static void pim_msdp_pkt_sa_rx_one(struct pim_msdp_peer *mp, struct in_addr rp)
{
	int prefix_len;
	struct prefix_sg sg;

	/* just throw away the three reserved bytes */
	stream_get3(mp->ibuf);
	prefix_len = stream_getc(mp->ibuf);

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.grp.s_addr = stream_get_ipv4(mp->ibuf);
	sg.src.s_addr = stream_get_ipv4(mp->ibuf);

	if (prefix_len != 32) {
		/* ignore SA update if the prefix length is not 32 */
		zlog_err("rxed sa update with invalid prefix length %d",
			 prefix_len);
		return;
	}
	if (PIM_DEBUG_MSDP_PACKETS) {
		zlog_debug("  sg %s", pim_str_sg_dump(&sg));
	}
	pim_msdp_sa_ref(mp->pim, mp, &sg, rp);
}

static void pim_msdp_pkt_sa_rx(struct pim_msdp_peer *mp, int len)
{
	int entry_cnt;
	int i;
	struct in_addr rp; /* Last RP address associated with this SA */

	mp->sa_rx_cnt++;

	if (len < PIM_MSDP_SA_TLV_MIN_SIZE) {
		pim_msdp_pkt_rxed_with_fatal_error(mp);
		return;
	}

	entry_cnt = stream_getc(mp->ibuf);
	/* some vendors include the actual multicast data in the tlv (at the
	 * end).
	 * we will ignore such data. in the future we may consider pushing it
	 * down
	 * the RPT */
	if (len < PIM_MSDP_SA_ENTRY_CNT2SIZE(entry_cnt)) {
		pim_msdp_pkt_rxed_with_fatal_error(mp);
		return;
	}
	rp.s_addr = stream_get_ipv4(mp->ibuf);

	if (PIM_DEBUG_MSDP_PACKETS) {
		char rp_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<rp?>", rp, rp_str, sizeof(rp_str));
		zlog_debug("  entry_cnt %d rp %s", entry_cnt, rp_str);
	}

	if (!pim_msdp_peer_rpf_check(mp, rp)) {
		/* if peer-RPF check fails don't process the packet any further
		 */
		if (PIM_DEBUG_MSDP_PACKETS) {
			zlog_debug("  peer RPF check failed");
		}
		return;
	}

	pim_msdp_peer_pkt_rxed(mp);

	/* update SA cache */
	for (i = 0; i < entry_cnt; ++i) {
		pim_msdp_pkt_sa_rx_one(mp, rp);
	}
}

static void pim_msdp_pkt_rx(struct pim_msdp_peer *mp)
{
	enum pim_msdp_tlv type;
	int len;

	/* re-read type and len */
	type = stream_getc_from(mp->ibuf, 0);
	len = stream_getw_from(mp->ibuf, 1);
	if (len < PIM_MSDP_HEADER_SIZE) {
		pim_msdp_pkt_rxed_with_fatal_error(mp);
		return;
	}

	if (len > PIM_MSDP_SA_TLV_MAX_SIZE) {
		/* if tlv size if greater than max just ignore the tlv */
		return;
	}

	if (PIM_DEBUG_MSDP_PACKETS) {
		pim_msdp_pkt_dump(mp, type, len, true /*rx*/, NULL /*s*/);
	}

	switch (type) {
	case PIM_MSDP_KEEPALIVE:
		pim_msdp_pkt_ka_rx(mp, len);
		break;
	case PIM_MSDP_V4_SOURCE_ACTIVE:
		mp->sa_rx_cnt++;
		pim_msdp_pkt_sa_rx(mp, len);
		break;
	default:
		mp->unk_rx_cnt++;
	}
}

/* pim msdp read utility function. */
static int pim_msdp_read_packet(struct pim_msdp_peer *mp)
{
	int nbytes;
	int readsize;
	int old_endp;
	int new_endp;

	old_endp = stream_get_endp(mp->ibuf);
	readsize = mp->packet_size - old_endp;
	if (!readsize) {
		return 0;
	}

	/* Read packet from fd */
	nbytes = stream_read_try(mp->ibuf, mp->fd, readsize);
	new_endp = stream_get_endp(mp->ibuf);
	if (nbytes < 0) {
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP peer %s read failed %d", mp->key_str,
				   nbytes);
		}
		if (nbytes == -2) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug(
					"MSDP peer %s pim_msdp_read io retry old_end: %d new_end: %d",
					mp->key_str, old_endp, new_endp);
			}
			/* transient error retry */
			return -1;
		}
		pim_msdp_pkt_rxed_with_fatal_error(mp);
		return -1;
	}

	if (!nbytes) {
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP peer %s read failed %d", mp->key_str,
				   nbytes);
		}
		pim_msdp_peer_reset_tcp_conn(mp, "peer-down");
		return -1;
	}

	/* We read partial packet. */
	if (stream_get_endp(mp->ibuf) != mp->packet_size) {
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug(
				"MSDP peer %s read partial len %d old_endp %d new_endp %d",
				mp->key_str, mp->packet_size, old_endp,
				new_endp);
		}
		return -1;
	}

	return 0;
}

int pim_msdp_read(struct thread *thread)
{
	struct pim_msdp_peer *mp;
	int rc;
	uint32_t len;

	mp = THREAD_ARG(thread);
	mp->t_read = NULL;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_read", mp->key_str);
	}

	if (mp->fd < 0) {
		return -1;
	}

	/* check if TCP connection is established */
	if (mp->state != PIM_MSDP_ESTABLISHED) {
		pim_msdp_connect_check(mp);
		return 0;
	}

	PIM_MSDP_PEER_READ_ON(mp);

	if (!mp->packet_size) {
		mp->packet_size = PIM_MSDP_HEADER_SIZE;
	}

	if (stream_get_endp(mp->ibuf) < PIM_MSDP_HEADER_SIZE) {
		/* start by reading the TLV header */
		rc = pim_msdp_read_packet(mp);
		if (rc < 0) {
			goto pim_msdp_read_end;
		}

		/* Find TLV type and len  */
		stream_getc(mp->ibuf);
		len = stream_getw(mp->ibuf);
		if (len < PIM_MSDP_HEADER_SIZE) {
			pim_msdp_pkt_rxed_with_fatal_error(mp);
			goto pim_msdp_read_end;
		}
		/* read complete TLV */
		mp->packet_size = len;
	}

	rc = pim_msdp_read_packet(mp);
	if (rc < 0) {
		goto pim_msdp_read_end;
	}

	pim_msdp_pkt_rx(mp);

	/* reset input buffers and get ready for the next packet */
	mp->packet_size = 0;
	stream_reset(mp->ibuf);

pim_msdp_read_end:
	return 0;
}
