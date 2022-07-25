/*
 * IS-IS Rout(e)ing protocol - isis_zebra_fae.c
 *
 * Copyright 2022 6WIND S.A.
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
#include "zebra.h"

#include "zclient.h"
#include "zapi_fae.h"

#include "isis_zebra_fae.h"
#include "isis_route.h"
#include "isis_fae.h"

#ifndef FABRICD

extern struct zclient *zclient;

static void _mk_igp_discriminator(const struct isis_area *const area,
				  struct zapi_fae_igp_discriminator *disc)
{
	disc->vrf_id = area->isis->vrf_id;
	disc->proto = ZF_PROTO_ISIS;
	disc->proto_data.isis.z_area_id = area->z_area_id;
	disc->proto_data.isis.area_tag = area->area_tag;
#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(disc->proto_data.isis.area_tag, area->area_tag,
		ZAPI_FAE_ISIS_AREA_SIZE);
#pragma GCC diagnostic pop
#endif
}

int isis_zebra_fae_ready_send(const struct isis_area *const area, bool ready)
{
	struct zapi_fae_igp_discriminator igp_disc;

#ifdef EXTREME_DEBUG
	zlog_debug("%s vrf %u area %s ready %s", __func__, area->isis->vrf_id,
		   area->area_tag, ready ? "true" : "false");
#endif
	_mk_igp_discriminator(area, &igp_disc);
	return zapi_fae_ready_send(zclient, ready, &igp_disc);
}

int isis_zebra_fae_ready_unicast_send(
	const struct isis_area *const area, bool ready,
	const struct zapi_client_daemon_id *const client_daemon_id)
{
	struct zapi_fae_igp_discriminator igp_disc;

#ifdef EXTREME_DEBUG
	zlog_debug("%s vrf %u area %s ready %s", __func__, area->isis->vrf_id,
		   area->area_tag, ready ? "true" : "false");
#endif
	_mk_igp_discriminator(area, &igp_disc);
	return zapi_fae_ready_unicast_send(zclient, ready, client_daemon_id,
					   &igp_disc);
}
int isis_zebra_fae_update_send(
	const struct isis_area *const area, const struct ipaddr *const endpoint,
	const struct isis_route_info *const rinfo, uint8_t algorithm,
	const struct zapi_client_daemon_id *const client_daemon_id)
{
	struct isis_nexthop *nexthop;
	struct listnode *node;
	int count;
	int result;
	const struct isis_sr_psid_info *const sr =
		rinfo ? &rinfo->sr_algo[algorithm] : NULL;
	struct zapi_fae_igp_discriminator igp_disc;
	struct zapi_fae_query query;
	struct zapi_fae_answer answer;

	_mk_igp_discriminator(area, &igp_disc);
	query.endpoint = *endpoint;
	query.algorithm = algorithm;
	answer.sid_format = 0;

	answer.sid_list.type = ZEBRA_LSP_ISIS_SR;
	answer.sid_list.local_label = sr ? sr->label : 0;

	if (rinfo == NULL || !sr->present || list_isempty(rinfo->nexthops)) {
		answer.sid_list.label_num = 0;
		result = zapi_fae_update_send(zclient, client_daemon_id,
					      &igp_disc, &query, &answer);
#ifdef EXTREME_DEBUG
		zlog_debug("%s update with empty sid list, result=%d", __func__,
			   result);
#endif
		return result;
	}

	count = 0;
	for (ALL_LIST_ELEMENTS_RO(sr->nexthops, node, nexthop)) {
		/* ECMP - send one message per next-hop */
		if (count >= MULTIPATH_NUM)
			break;

		if (nexthop->label_stack) {
			answer.sid_list.label_num =
				nexthop->label_stack->num_labels;
			memcpy(answer.sid_list.labels,
			       nexthop->label_stack->label,
			       sizeof(mpls_label_t)
				       * answer.sid_list.label_num);
		} else if (nexthop->sr.present) {
			answer.sid_list.label_num = 1;
			answer.sid_list.labels[0] = nexthop->sr.label;
		}

		result = zapi_fae_update_send(zclient, client_daemon_id,
					      &igp_disc, &query, &answer);
#ifdef EXTREME_DEBUG
		zlog_debug("%s update with non-empty sid list, result=%d",
			   __func__, result);
#endif
		if (result < 0)
			return result;

		count++;
	}

	return 0;
}

int isis_zebra_fae_process_register(struct stream *s)
{
	struct zapi_client_daemon_id client_daemon_id;
	struct zapi_fae_igp_discriminator igp_disc;
	struct zapi_fae_query query;
	int ret;

	ret = zapi_fae_register_decode(s, &client_daemon_id, &igp_disc,
				       &query);
	if (ret)
		return ret;
	isis_fae_process_register(&client_daemon_id, &igp_disc, &query);
	return ret;
}

int isis_zebra_fae_process_unregister(struct stream *s)
{
	struct zapi_client_daemon_id client_daemon_id;
	struct zapi_fae_igp_discriminator igp_disc;
	struct zapi_fae_query query;
	int ret;

	ret = zapi_fae_register_decode(s, &client_daemon_id, &igp_disc,
				       &query);
	if (ret)
		return ret;
	isis_fae_process_unregister(&client_daemon_id, &igp_disc,
				    &query);
	return ret;
}

int isis_zebra_fae_process_client_ready(struct stream *s)
{
	struct zapi_client_daemon_id client_daemon_id;
	int ret;

	ret = zapi_fae_client_ready_decode(s, &client_daemon_id);
	if (ret)
		return ret;

	isis_fae_process_client_ready(&client_daemon_id);
	return ret;

}

#endif /* !FABRICD */

