// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"
#include "ldp_debug.h"

void
send_keepalive(struct nbr *nbr)
{
	struct ibuf	*buf;
	uint16_t	 size;

	size = LDP_HDR_SIZE + LDP_MSG_SIZE;
	if ((buf = ibuf_open(size)) == NULL)
		fatal(__func__);

	gen_ldp_hdr(buf, size);
	size -= LDP_HDR_SIZE;
	gen_msg_hdr(buf, MSG_TYPE_KEEPALIVE, size);

	debug_kalive_send("keepalive: lsr-id %pI4", &nbr->id);

	evbuf_enqueue(&nbr->tcp->wbuf, buf);
	nbr->stats.kalive_sent++;
}

int
recv_keepalive(struct nbr *nbr, char *buf, uint16_t len)
{
	struct ldp_msg msg;

	memcpy(&msg, buf, sizeof(msg));
	if (len != LDP_MSG_SIZE) {
		session_shutdown(nbr, S_BAD_MSG_LEN, msg.id, msg.type);
		return (-1);
	}

	debug_kalive_recv("keepalive: lsr-id %pI4", &nbr->id);

	if (nbr->state != NBR_STA_OPER)
		nbr_fsm(nbr, NBR_EVT_KEEPALIVE_RCVD);

	return (0);
}
