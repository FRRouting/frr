/* zebra_mroute code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
	STREAM_GET(&mroute.sg.src, msg, 4);
	STREAM_GET(&mroute.sg.grp, msg, 4);
	STREAM_GETL(msg, mroute.ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char sbuf[40];
		char gbuf[40];

		strlcpy(sbuf, inet_ntoa(mroute.sg.src), sizeof(sbuf));
		strlcpy(gbuf, inet_ntoa(mroute.sg.grp), sizeof(gbuf));

		zlog_debug("Asking for (%s,%s) mroute information", sbuf, gbuf);
	}

	suc = kernel_get_ipmr_sg_stats(zvrf, &mroute);

stream_failure:
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	stream_reset(s);

	zclient_create_header(s, ZEBRA_IPMR_ROUTE_STATS, zvrf_id(zvrf));
	stream_put_in_addr(s, &mroute.sg.src);
	stream_put_in_addr(s, &mroute.sg.grp);
	stream_put(s, &mroute.lastused, sizeof(mroute.lastused));
	stream_putl(s, suc);

	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);
}
