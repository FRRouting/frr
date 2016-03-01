/*	$OpenBSD$ */

/*
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

#include "ldpd.h"
#include "ldp.h"
#include "log.h"
#include "ldpe.h"

void
send_notification_full(struct tcp_conn *tcp, struct notify_msg *nm)
{
	struct ibuf	*buf;
	uint16_t	 size;
	int		 err = 0;

	/* calculate size */
	size = LDP_HDR_SIZE + LDP_MSG_SIZE + STATUS_SIZE;
	if (nm->flags & F_NOTIF_PW_STATUS)
		size += PW_STATUS_TLV_SIZE;
	if (nm->flags & F_NOTIF_FEC) {
		size += TLV_HDR_SIZE;
		switch (nm->fec.type) {
		case MAP_TYPE_PWID:
			size += FEC_PWID_ELM_MIN_LEN;
			if (nm->fec.flags & F_MAP_PW_ID)
				size += sizeof(uint32_t);
			break;
		}
	}

	if ((buf = ibuf_open(size)) == NULL)
		fatal(__func__);

	err |= gen_ldp_hdr(buf, size);
	size -= LDP_HDR_SIZE;
	err |= gen_msg_hdr(buf, MSG_TYPE_NOTIFICATION, size);
	err |= gen_status_tlv(buf, nm->status_code, nm->msg_id, nm->msg_type);
	/* optional tlvs */
	if (nm->flags & F_NOTIF_PW_STATUS)
		err |= gen_pw_status_tlv(buf, nm->pw_status);
	if (nm->flags & F_NOTIF_FEC)
		err |= gen_fec_tlv(buf, &nm->fec);
	if (err) {
		ibuf_free(buf);
		return;
	}

	if (tcp->nbr)
		log_debug("msg-out: notification: lsr-id %s, status %s%s",
		    inet_ntoa(tcp->nbr->id), status_code_name(nm->status_code),
		    (nm->status_code & STATUS_FATAL) ? " (fatal)" : "");

	evbuf_enqueue(&tcp->wbuf, buf);
}

/* send a notification without optional tlvs */
void
send_notification(uint32_t status_code, struct tcp_conn *tcp, uint32_t msg_id,
    uint16_t msg_type)
{
	struct notify_msg	 nm;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = status_code;
	nm.msg_id = msg_id;
	nm.msg_type = msg_type;

	send_notification_full(tcp, &nm);
}

void
send_notification_nbr(struct nbr *nbr, uint32_t status_code, uint32_t msg_id,
    uint16_t msg_type)
{
	send_notification(status_code, nbr->tcp, msg_id, msg_type);
	nbr_fsm(nbr, NBR_EVT_PDU_SENT);
}

int
recv_notification(struct nbr *nbr, char *buf, uint16_t len)
{
	struct ldp_msg		msg;
	struct status_tlv	st;
	struct notify_msg	nm;
	int			tlen;

	memcpy(&msg, buf, sizeof(msg));
	buf += LDP_MSG_SIZE;
	len -= LDP_MSG_SIZE;

	if (len < STATUS_SIZE) {
		session_shutdown(nbr, S_BAD_MSG_LEN, msg.id, msg.type);
		return (-1);
	}
	memcpy(&st, buf, sizeof(st));

	if (ntohs(st.length) > STATUS_SIZE - TLV_HDR_SIZE ||
	    ntohs(st.length) > len - TLV_HDR_SIZE) {
		session_shutdown(nbr, S_BAD_TLV_LEN, msg.id, msg.type);
		return (-1);
	}
	buf += STATUS_SIZE;
	len -= STATUS_SIZE;

	memset(&nm, 0, sizeof(nm));
	nm.status_code = ntohl(st.status_code);

	/* Optional Parameters */
	while (len > 0) {
		struct tlv 	tlv;
		uint16_t	tlv_len;

		if (len < sizeof(tlv)) {
			session_shutdown(nbr, S_BAD_TLV_LEN, msg.id, msg.type);
			return (-1);
		}

		memcpy(&tlv, buf, TLV_HDR_SIZE);
		tlv_len = ntohs(tlv.length);
		if (tlv_len + TLV_HDR_SIZE > len) {
			session_shutdown(nbr, S_BAD_TLV_LEN, msg.id, msg.type);
			return (-1);
		}
		buf += TLV_HDR_SIZE;
		len -= TLV_HDR_SIZE;

		switch (ntohs(tlv.type)) {
		case TLV_TYPE_EXTSTATUS:
		case TLV_TYPE_RETURNEDPDU:
		case TLV_TYPE_RETURNEDMSG:
			/* TODO is there any use for this? */
			break;
		case TLV_TYPE_PW_STATUS:
			if (tlv_len != 4) {
				session_shutdown(nbr, S_BAD_TLV_LEN,
				    msg.id, msg.type);
				return (-1);
			}

			nm.pw_status = ntohl(*(uint32_t *)buf);
			nm.flags |= F_NOTIF_PW_STATUS;
			break;
		case TLV_TYPE_FEC:
			if ((tlen = tlv_decode_fec_elm(nbr, &msg, buf,
			    tlv_len, &nm.fec)) == -1)
				return (-1);
			/* allow only one fec element */
			if (tlen != tlv_len) {
				session_shutdown(nbr, S_BAD_TLV_VAL,
				    msg.id, msg.type);
				return (-1);
			}
			nm.flags |= F_NOTIF_FEC;
			break;
		default:
			if (!(ntohs(tlv.type) & UNKNOWN_FLAG))
				send_notification_nbr(nbr, S_UNKNOWN_TLV,
				    msg.id, msg.type);
			/* ignore unknown tlv */
			break;
		}
		buf += tlv_len;
		len -= tlv_len;
	}

	if (nm.status_code == S_PW_STATUS) {
		if (!(nm.flags & (F_NOTIF_PW_STATUS|F_NOTIF_FEC))) {
			send_notification_nbr(nbr, S_MISS_MSG,
			    msg.id, msg.type);
			return (-1);
		}

		switch (nm.fec.type) {
		case MAP_TYPE_PWID:
			break;
		default:
			send_notification_nbr(nbr, S_BAD_TLV_VAL,
			    msg.id, msg.type);
			return (-1);
		}
	}

	log_warnx("msg-in: notification: lsr-id %s, status %s%s",
	    inet_ntoa(nbr->id), status_code_name(ntohl(st.status_code)),
	    (st.status_code & htonl(STATUS_FATAL)) ? " (fatal)" : "");

	if (st.status_code & htonl(STATUS_FATAL)) {
		if (nbr->state == NBR_STA_OPENSENT)
			nbr_start_idtimer(nbr);

		nbr_fsm(nbr, NBR_EVT_CLOSE_SESSION);
		return (-1);
	}

	if (nm.status_code == S_PW_STATUS)
		ldpe_imsg_compose_lde(IMSG_NOTIFICATION, nbr->peerid, 0,
		    &nm, sizeof(nm));

	return (0);
}

int
gen_status_tlv(struct ibuf *buf, uint32_t status_code, uint32_t msg_id,
    uint16_t msg_type)
{
	struct status_tlv	st;

	memset(&st, 0, sizeof(st));
	st.type = htons(TLV_TYPE_STATUS);
	st.length = htons(STATUS_TLV_LEN);
	st.status_code = htonl(status_code);
	/*
	 * For convenience, msg_id and msg_type are already in network
	 * byte order.
	 */
	st.msg_id = msg_id;
	st.msg_type = msg_type;

	return (ibuf_add(buf, &st, STATUS_SIZE));
}
