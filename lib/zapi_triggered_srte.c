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
#include "zebra.h"
#include "zclient.h"
#include "mpls.h"
#include "zapi_client.h"
#include "zapi_triggered_srte.h"

#define _TRIGGERED_SRTE_READY_SIZE                                             \
	(sizeof(struct zapi_client_daemon_id) +    /* srte daemon */           \
	 sizeof(struct zapi_srte_protocol_origin)) /* for bgp */

#define _TRIGGERED_SRTE_REGISTRATION_SIZE                                      \
	(sizeof(struct zapi_client_daemon_id) + /* bgp's */                    \
	 sizeof(struct zapi_tsrte_register)     /* tuple + (un)registration */ \
	)
#define _TRIGGERED_SRTE_UPDATE_SIZE                                            \
	(sizeof(struct zapi_client_daemon_id) + /* bgp's */                    \
	 sizeof(struct zapi_tsrte_register) +   /* tuple + (un)registration */ \
	 sizeof(mpls_label_t) +			/* binding sid */              \
	 SRTE_SEGMENT_LIST_NAME_MAX_LENGTH +    /* policy name instantiated */ \
	 SRTE_POLICY_NAME_MAX_LENGTH		/* policy name instantiated */ \
	)


enum zclient_send_status
zapi_tsrte_client_ready_send(struct zclient *zclient,
			     enum srte_protocol_origin protocol_origin)
{
	struct stream *s = stream_new(_TRIGGERED_SRTE_READY_SIZE);
	enum zclient_send_status status;

	zapi_client_encode_daemon_id(s, zclient);
	stream_putc(s, protocol_origin);
	status = zclient_send_opaque(zclient, TSRTE_CLIENT_READY, s->data,
				   s->endp);

	stream_free(s);

	return status;
}

enum zclient_send_status zapi_tsrte_bgp_ready_send(struct zclient *zclient)
{
	struct stream *s = stream_new(sizeof(struct zapi_client_daemon_id));
	enum zclient_send_status status;

	//	assert(zclient->redist_default == ZEBRA_ROUTE_BGP);
	zapi_client_encode_daemon_id(s, zclient);
	status =
		zclient_send_opaque(zclient, TSRTE_BGP_READY, s->data, s->endp);
	stream_free(s);
	return status;
}

int zapi_tsrte_client_ready_decode(
	struct stream *s, struct zapi_client_daemon_id *client_daemon_id,
	enum srte_protocol_origin *protocol_origin)
{
	int rc;

	rc = zapi_client_decode_daemon_id(s, client_daemon_id);
	if (rc)
		return -1;
	STREAM_GETC(s, (*protocol_origin));
	return 0;
stream_failure:
	return -1;
}

extern enum zclient_send_status
zapi_tsrte_registration_send(struct zclient *zclient, uint32_t color,
			     struct ipaddr *endpoint, bool registration)
{
	struct stream *s = stream_new(_TRIGGERED_SRTE_REGISTRATION_SIZE);
	uint32_t type =
		registration ? TSRTE_BGP_REGISTER : TSRTE_BGP_UNREGISTER;
	enum zclient_send_status status;

	zapi_client_encode_daemon_id(s, zclient);
	stream_putl(s, color);
	stream_put_ipaddr(s, endpoint);

	status = zclient_send_opaque(zclient, type, s->data, s->endp);

	stream_free(s);

	return status;
}

extern int zapi_tsrte_registration_decode(struct stream *s,
					  uint32_t *srte_color,
					  struct ipaddr *endpoint)
{
	int rc;
	struct zapi_client_daemon_id bgp_daemon_id __attribute__((__unused__));
	uint32_t color;

	rc = zapi_client_decode_daemon_id(s, &bgp_daemon_id);
	if (rc)
		return -1;
	STREAM_GETL(s, color);
	if (srte_color)
		*srte_color = color;
	STREAM_GET_IPADDR(s, endpoint);

	return 1;
stream_failure:
	return -1;
}

enum zclient_send_status
zapi_tsrte_update_send(struct zclient *zclient, uint32_t color,
		       struct ipaddr *endpoint, mpls_label_t bsid,
		       const char *zapi_segmentlist_name,
		       const char *zapi_policy_name)
{
	struct stream *s = stream_new(_TRIGGERED_SRTE_UPDATE_SIZE);
	enum zclient_send_status status;

	zapi_client_encode_daemon_id(s, zclient);

	stream_putl(s, color);

	stream_put_ipaddr(s, endpoint);

	stream_putl(s, bsid);

	stream_put(s, zapi_segmentlist_name, SRTE_SEGMENT_LIST_NAME_MAX_LENGTH);

	stream_put(s, zapi_policy_name, SRTE_POLICY_NAME_MAX_LENGTH);

	status = zclient_send_opaque(zclient, TSRTE_BGP_UPDATE, s->data, s->endp);

	stream_free(s);

	return status;
}

extern int zapi_tsrte_update_decode(struct stream *s, uint32_t *srte_color,
				    struct ipaddr *endpoint, mpls_label_t *bsid,
				    char *zapi_segmentlist_name,
				    const int zapi_segmentlist_len_max,
				    char *zapi_policy_name,
				    const int zapi_policy_name_len_max)
{
	int rc;
	uint32_t color;
	struct zapi_client_daemon_id bgp_daemon_id;
	mpls_label_t label;

	rc = zapi_client_decode_daemon_id(s, &bgp_daemon_id);
	if (rc)
		return -1;
	STREAM_GETL(s, color);
	if (srte_color)
		*srte_color = color;
	STREAM_GET_IPADDR(s, endpoint);

	STREAM_GETL(s, label);
	if (bsid)
		*bsid = label;
	if (zapi_segmentlist_len_max < SRTE_SEGMENT_LIST_NAME_MAX_LENGTH)
		return -1;
	STREAM_GET(zapi_segmentlist_name, s, SRTE_SEGMENT_LIST_NAME_MAX_LENGTH);

	if (zapi_policy_name_len_max < SRTE_POLICY_NAME_MAX_LENGTH)
		return -1;
	STREAM_GET(zapi_policy_name, s, SRTE_POLICY_NAME_MAX_LENGTH);

	return 1;
stream_failure:
	return -1;
}
