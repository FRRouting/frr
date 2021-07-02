/*
 * OSPF BGP-IGP IGP metric update handling routines
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
 * 			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"
#include "orr_msg.h"

#include "ospfd.h"
#include "ospf_orr.h"
#include "ospf_dump.h"

extern struct zclient *zclient;

/*
 * BGP-IGP IGP metric msg between BGP and IGP
 */
int ospf_orr_igp_metric_register(struct orr_igp_metric_reg msg)
{
	struct ospf *ospf;
	char buf[PREFIX2STR_BUFFER];

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return 0;

	if (msg.proto != ZEBRA_ROUTE_BGP)
		return 0;

	ospf_orr_debug(
		"%s: Received IGP metric %s message from BGP for location %s",
		__func__, msg.reg ? "Register" : "Unregister",
		prefix2str(&msg.prefix, buf, sizeof(buf)));
	return 0;
}

void ospf_orr_igp_metric_send_update(struct prefix root)
{
	ospf_orr_debug("%s: send IGP metric to BGP for Root", __func__);
	/*
		memset(&update, 0, sizeof(update));
		update.proto = LDP_IGP_SYNC_IF_STATE_REQUEST;

		zclient_send_opaque(zclient, ORR_IGP_METRIC_UPDATE,
			(uint8_t *)&update, sizeof(update));
	*/
}
