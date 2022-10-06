/* zapi handling for Flex-algo messages
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

#ifndef __ZAPI_FAE_H
#define __ZAPI_FAE_H

#include "zclient.h" /* for enum zclient_send_status */
#include "zapi_client.h"

/*
 * identify valid protocols for protocol-specific unions in
 * register/unregister/update messages.
 */
#define ZF_PROTO_NONE ZEBRA_ROUTE_ALL
#define ZF_PROTO_ISIS ZEBRA_ROUTE_ISIS

DECLARE_MTYPE(ZAPI_FAE_AREA_TAG);

enum { ZAPI_FAE_NOT_READY = 0,
       ZAPI_FAE_IS_READY,
};

struct zapi_fae_igp_discriminator {
	vrf_id_t vrf_id;
	uint8_t proto;
	union {
		/*
		 * NB union encoding is selected by proto field above.
		 *
		 * The proto field is slightly redundant because FAE_READY
		 * and FAE_UPDATE have it in the IGP daemon ID, but for
		 * FAE_REGISTER it is implied by the protocol of the
		 * receiver.
		 *
		 * Although the right protocol value can be determined for
		 * FAE_REGISTER, using an explicit extra byte above for proto
		 * above makes this structure and its wire format
		 * self-contained and easier to understand.
		 *
		 * If proto is ZF_PROTO_NONE, omit this union in on-the-wire
		 * encoding.
		 */
		struct {
			/*
			 * For FAE_READY, provide the area_id together
			 * with the area_tag string.
			 *
			 * For FAE_UNREADY, FAE_REGISTER, FAE_UNREGISTER,
			 * and FAE_UPDATE, provide only the area_id. The
			 * area_tag string will be ignored when sending
			 * and not provided when receiving these messages.
			 */
			uint32_t z_area_id;
			char *area_tag;
		} isis;
	} proto_data;
};

struct zapi_fae_query {
	struct ipaddr endpoint;
	uint8_t algorithm;
};

struct zapi_fae_answer {
	uint8_t sid_format; /* this structure is for format 0 */
	union {
		struct zapi_srte_tunnel sid_list; /* format 0 */
	};
	ifindex_t ifindex;
};

extern enum zclient_send_status
zapi_fae_client_ready_send(struct zclient *zclient);

extern enum zclient_send_status zapi_fae_ready_send(
	struct zclient *zclient, bool do_ready,
	const struct zapi_fae_igp_discriminator *const igp_discriminator);

extern enum zclient_send_status zapi_fae_ready_unicast_send(
	struct zclient *zclient, bool do_ready,
	const struct zapi_client_daemon_id *const igp_daemon_id,
	const struct zapi_fae_igp_discriminator *const d);

extern int
zapi_fae_client_ready_decode(struct stream *s,
			     struct zapi_client_daemon_id *client_daemon_id);

/*
 * Note! When decoding ISIS ready messages, this function allocates a
 * string that the CALLER MUST FREE
 */
extern int
zapi_fae_ready_decode(struct stream *s,
		      struct zapi_client_daemon_id *igp_daemon_id,
		      struct zapi_fae_igp_discriminator *igp_discriminator);

extern enum zclient_send_status zapi_fae_register_send(
	struct zclient *zclient, bool do_register,
	const struct zapi_client_daemon_id *const igp_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_discriminator,
	const struct zapi_fae_query *const query);

extern int
zapi_fae_register_decode(struct stream *s,
			 struct zapi_client_daemon_id *client_daemon_id,
			 struct zapi_fae_igp_discriminator *igp_discriminator,
			 struct zapi_fae_query *query);

extern enum zclient_send_status zapi_fae_update_send(
	struct zclient *zclient,
	const struct zapi_client_daemon_id *const client_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_discriminator,
	const struct zapi_fae_query *const query,
	const struct zapi_fae_answer *const answer);

extern int zapi_fae_update_decode(
	struct stream *s, struct zapi_client_daemon_id *igp_daemon_id,
	struct zapi_fae_igp_discriminator *igp_discriminator,
	struct zapi_fae_query *query, struct zapi_fae_answer *answer);

extern void
zapi_fae_igp_discriminator_clean(struct zapi_fae_igp_discriminator *d);
#endif /* __ZAPI_FAE_H */
