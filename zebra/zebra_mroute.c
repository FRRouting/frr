// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra_mroute code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "vrf.h"
#include "rib.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "zebra/debug.h"

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS)
{
	struct mcast_route_data mroute;
	struct stream *s;
	int suc = -1;

	memset(&mroute, 0, sizeof(mroute));
	STREAM_GETL(msg, mroute.family);

	switch (mroute.family) {
	case AF_INET:
		SET_IPADDR_V4(&mroute.src);
		SET_IPADDR_V4(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v4, msg,
			   sizeof(mroute.src.ipaddr_v4));
		STREAM_GET(&mroute.grp.ipaddr_v4, msg,
			   sizeof(mroute.grp.ipaddr_v4));
		break;
	case AF_INET6:
		SET_IPADDR_V6(&mroute.src);
		SET_IPADDR_V6(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v6, msg,
			   sizeof(mroute.src.ipaddr_v6));
		STREAM_GET(&mroute.grp.ipaddr_v6, msg,
			   sizeof(mroute.grp.ipaddr_v6));
		break;
	default:
		zlog_warn("%s: Invalid address family received while parsing",
			  __func__);
		return;
	}

	STREAM_GETL(msg, mroute.ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Asking for (%pIA,%pIA)[%s(%u)] mroute information",
			   &mroute.src, &mroute.grp, zvrf->vrf->name,
			   zvrf->vrf->vrf_id);

	suc = kernel_get_ipmr_sg_stats(zvrf, &mroute);

stream_failure:
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	stream_reset(s);

	zclient_create_header(s, ZEBRA_IPMR_ROUTE_STATS, zvrf_id(zvrf));

	if (mroute.family == AF_INET) {
		stream_write(s, &mroute.src.ipaddr_v4,
			     sizeof(mroute.src.ipaddr_v4));
		stream_write(s, &mroute.grp.ipaddr_v4,
			     sizeof(mroute.grp.ipaddr_v4));
	} else {
		stream_write(s, &mroute.src.ipaddr_v6,
			     sizeof(mroute.src.ipaddr_v6));
		stream_write(s, &mroute.grp.ipaddr_v6,
			     sizeof(mroute.grp.ipaddr_v6));
	}

	stream_put(s, &mroute.lastused, sizeof(mroute.lastused));
	stream_putl(s, (uint32_t)suc);

	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);
}
