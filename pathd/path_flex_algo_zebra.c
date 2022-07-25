/* Flex-algo zebra candidate paths
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "zclient.h"
#include "memory.h"
#include "zapi_fae.h"
#include "vty.h"
#include "zapi_client.h"

#include "pathd/pathd.h"
#include "pathd/path_flex_algo.h"

extern struct zclient *zclient;

/*
 * Sends FAE READY/NOTREADY to zebra. If we are registered, zebra
 * should loop it back to us.
 */
int path_zebra_debug_send_fae_ready(bool do_ready, uint8_t protocol,
				    vrf_id_t vrf_id, const char *area_tag,
				    uint32_t z_area_id)
{
	struct zapi_fae_igp_discriminator d;
	enum zclient_send_status rv;

	d.vrf_id = vrf_id;
	d.proto = protocol;
	if (ZEBRA_ROUTE_ISIS == protocol) {
		if (area_tag) {
			d.proto_data.isis.area_tag = (char *)area_tag;
			d.proto_data.isis.z_area_id = z_area_id;
		} else {
			zlog_debug("%s: isis but no area-tag provided",
				   __func__);
			return -1;
		}
	} else {
		d.proto_data.isis.area_tag = NULL;
		d.proto_data.isis.z_area_id = 0;
	}
	rv = zapi_fae_ready_send(zclient, do_ready, &d);
	FA_D_DEBUG("%s: sent, d.proto=%u, rv=%d", __func__, d.proto, rv);
	if (rv == ZCLIENT_SEND_FAILURE)
		return -1;
	return 0;
}

int path_zebra_handle_fae_ready(bool ready, struct stream *s)
{
	struct zapi_client_daemon_id igp_daemon_id;
	struct zapi_fae_igp_discriminator igp_discriminator;

	FA_D_DEBUG("%s: start", __func__);

	if (zapi_fae_ready_decode(s, &igp_daemon_id, &igp_discriminator)) {
		zlog_err("%s: [rcv FAE %sready: could not decode.", __func__,
			 (ready ? "" : "un"));
		return -1;
	}

	if (ready)
		fa_igp_handle_ready(&igp_daemon_id, &igp_discriminator);
	else
		fa_igp_handle_notready(&igp_daemon_id, &igp_discriminator);

	zapi_fae_igp_discriminator_clean(&igp_discriminator);

	return 0;
}

/*
 * Sends FAE UPDATE to zebra as opaque unicast to self. Zebra should
 * send back.
 */
int path_zebra_debug_send_fae_update(uint8_t protocol, vrf_id_t vrf_id,
				     uint32_t z_area_id,
				     struct ipaddr *endpoint, uint8_t algorithm,
				     struct zapi_srte_tunnel *sid_list)
{
	struct zapi_client_daemon_id igp_daemon_id;
	struct zapi_fae_igp_discriminator d;
	struct zapi_fae_query query;
	struct zapi_fae_answer answer;
	enum zclient_send_status rv;

	igp_daemon_id.proto = zclient->redist_default; /* self */
	igp_daemon_id.instance = zclient->instance;
	igp_daemon_id.session_id = zclient->session_id;

	query.endpoint = *endpoint;
	query.algorithm = algorithm;

	answer.sid_format = 0;
	answer.sid_list = *sid_list;

	d.vrf_id = vrf_id;
	d.proto = protocol;
	if (ZEBRA_ROUTE_ISIS == protocol) {
		d.proto_data.isis.z_area_id = z_area_id;
		d.proto_data.isis.area_tag = NULL;
	}
	rv = zapi_fae_update_send(zclient, &igp_daemon_id, &d, &query,
				  &answer);
	FA_D_DEBUG("%s: sent, d.proto=%u, rv=%d", __func__, d.proto, rv);
	if (rv == ZCLIENT_SEND_FAILURE)
		return -1;
	return 0;
}

int path_zebra_handle_fae_update(struct stream *s)
{
	struct zapi_client_daemon_id igp_daemon_id;
	struct zapi_fae_igp_discriminator igp_discriminator;
	struct zapi_fae_query query;
	struct zapi_fae_answer answer;

	if (zapi_fae_update_decode(s, &igp_daemon_id, &igp_discriminator,
				   &query, &answer)) {
		zlog_err("%s: [rcv FAE update: could not decode.", __func__);
		return -1;
	}
	fa_handle_update(&igp_daemon_id, &igp_discriminator, &query, &answer);
	return 0;
}

void path_zebra_fae_register(bool do_register, struct ipaddr *endpoint,
			     uint8_t algorithm, uint8_t protocol,
			     uint16_t instance, uint32_t session_id,
			     vrf_id_t vrf_id, uint32_t isis_z_area_id)
{
	struct zapi_client_daemon_id igp_daemon_id;
	struct zapi_fae_igp_discriminator igp_discriminator;
	struct zapi_fae_query query;

	igp_daemon_id.proto = protocol;
	igp_daemon_id.instance = instance;
	igp_daemon_id.session_id = session_id;

	igp_discriminator.vrf_id = vrf_id;
	igp_discriminator.proto = protocol;
	if (ZEBRA_ROUTE_ISIS == protocol) {
		igp_discriminator.proto_data.isis.z_area_id = isis_z_area_id;
		igp_discriminator.proto_data.isis.area_tag = NULL;
	}

	query.endpoint = *endpoint;
	query.algorithm = algorithm;

	zapi_fae_register_send(zclient, do_register, &igp_daemon_id,
			       &igp_discriminator, &query);
}
