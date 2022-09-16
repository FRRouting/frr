/* zapi handling for Triggered SR-TE messages
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

#ifndef __ZAPI_TRIGGERED_SRTE_H
#define __ZAPI_TRIGGERED_SRTE_H

#include "mpls.h"
#include "zapi_client.h"

struct zapi_tsrte_daemon_id {
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

struct zapi_srte_protocol_origin {
	uint8_t protocol_origin;
};

extern enum zclient_send_status
zapi_tsrte_client_ready_send(struct zclient *zclient,
			     enum srte_protocol_origin protocol_origin);

enum zclient_send_status zapi_tsrte_bgp_ready_send(struct zclient *zclient);

int zapi_tsrte_client_ready_decode(
	struct stream *s, struct zapi_client_daemon_id *client_daemon_id,
	enum srte_protocol_origin *protocol_origin);

struct zapi_tsrte_register {
	uint32_t color;
	struct ipaddr endpoint;
};

struct zapi_tsrte_update {
	struct zapi_tsrte_register reg;
	mpls_label_t bindingsid;
	char zapi_candidate_name[64];
};

extern enum zclient_send_status
zapi_tsrte_registration_send(struct zclient *zclient, uint32_t color,
			     struct ipaddr *endpoint, bool registration);

extern int zapi_tsrte_registration_decode(struct stream *s, uint32_t *color,
					  struct ipaddr *endpoint);

extern enum zclient_send_status
zapi_tsrte_update_send(struct zclient *zclient, uint32_t color,
		       struct ipaddr *endpoint, mpls_label_t bsid,
		       const char *zapi_policy_name,
		       const char *zapi_segmentlist_name);

extern int zapi_tsrte_update_decode(struct stream *s, uint32_t *srte_color,
				    struct ipaddr *endpoint, mpls_label_t *bsid,
				    char *zapi_segmentlist_name,
				    const int zapi_segmentlist_len_max,
				    char *zapi_policy_name,
				    const int zapi_policy_name_len_max);

#endif /* __ZAPI_TRIGGERED_SRTE_H */
