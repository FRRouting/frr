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
#include "ldpe.h"
#include "log.h"

static int	gen_init_prms_tlv(struct ibuf *, struct nbr *);

void
send_init(struct nbr *nbr)
{
	struct ibuf		*buf;
	uint16_t		 size;
	int			 err = 0;

	log_debug("%s: lsr-id %s", __func__, inet_ntoa(nbr->id));

	size = LDP_HDR_SIZE + LDP_MSG_SIZE + SESS_PRMS_SIZE;
	if ((buf = ibuf_open(size)) == NULL)
		fatal(__func__);

	err |= gen_ldp_hdr(buf, size);
	size -= LDP_HDR_SIZE;
	err |= gen_msg_hdr(buf, MSG_TYPE_INIT, size);
	size -= LDP_MSG_SIZE;
	err |= gen_init_prms_tlv(buf, nbr);
	if (err) {
		ibuf_free(buf);
		return;
	}

	evbuf_enqueue(&nbr->tcp->wbuf, buf);
}

int
recv_init(struct nbr *nbr, char *buf, uint16_t len)
{
	struct ldp_msg		msg;
	struct sess_prms_tlv	sess;
	uint16_t		max_pdu_len;

	log_debug("%s: lsr-id %s", __func__, inet_ntoa(nbr->id));

	memcpy(&msg, buf, sizeof(msg));
	buf += LDP_MSG_SIZE;
	len -= LDP_MSG_SIZE;

	if (len < SESS_PRMS_SIZE) {
		session_shutdown(nbr, S_BAD_MSG_LEN, msg.id, msg.type);
		return (-1);
	}
	memcpy(&sess, buf, sizeof(sess));
	if (ntohs(sess.length) != SESS_PRMS_LEN) {
		session_shutdown(nbr, S_BAD_TLV_LEN, msg.id, msg.type);
		return (-1);
	}
	if (ntohs(sess.proto_version) != LDP_VERSION) {
		session_shutdown(nbr, S_BAD_PROTO_VER, msg.id, msg.type);
		return (-1);
	}
	if (ntohs(sess.keepalive_time) < MIN_KEEPALIVE) {
		session_shutdown(nbr, S_KEEPALIVE_BAD, msg.id, msg.type);
		return (-1);
	}
	if (sess.lsr_id != leconf->rtr_id.s_addr ||
	    ntohs(sess.lspace_id) != 0) {
		session_shutdown(nbr, S_NO_HELLO, msg.id, msg.type);
		return (-1);
	}

	buf += SESS_PRMS_SIZE;
	len -= SESS_PRMS_SIZE;

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
		case TLV_TYPE_ATMSESSIONPAR:
			session_shutdown(nbr, S_BAD_TLV_VAL, msg.id, msg.type);
			return (-1);
		case TLV_TYPE_FRSESSION:
			session_shutdown(nbr, S_BAD_TLV_VAL, msg.id, msg.type);
			return (-1);
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

	nbr->keepalive = min(nbr_get_keepalive(nbr->af, nbr->id),
	    ntohs(sess.keepalive_time));

	max_pdu_len = ntohs(sess.max_pdu_len);
	/*
	 * RFC 5036 - Section 3.5.3:
	 * "A value of 255 or less specifies the default maximum length of
	 * 4096 octets".
	 */
	if (max_pdu_len <= 255)
		max_pdu_len = LDP_MAX_LEN;
	nbr->max_pdu_len = min(max_pdu_len, LDP_MAX_LEN);

	nbr_fsm(nbr, NBR_EVT_INIT_RCVD);

	return (0);
}

static int
gen_init_prms_tlv(struct ibuf *buf, struct nbr *nbr)
{
	struct sess_prms_tlv	parms;

	memset(&parms, 0, sizeof(parms));
	parms.type = htons(TLV_TYPE_COMMONSESSION);
	parms.length = htons(SESS_PRMS_LEN);
	parms.proto_version = htons(LDP_VERSION);
	parms.keepalive_time = htons(nbr_get_keepalive(nbr->af, nbr->id));
	parms.reserved = 0;
	parms.pvlim = 0;
	parms.max_pdu_len = 0;
	parms.lsr_id = nbr->id.s_addr;
	parms.lspace_id = 0;

	return (ibuf_add(buf, &parms, SESS_PRMS_SIZE));
}
