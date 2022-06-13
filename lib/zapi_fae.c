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

#include <zebra.h>

#include "zclient.h"
#include "lib_errors.h"
#include "zapi_fae.h"

#define ZAPI_FAE_DEBUG 0

DEFINE_MTYPE(LIB, ZAPI_FAE_AREA_TAG, "ZAPI FAE Area tag");

/*
 * These stream structures use the message structure definitions,
 * but we expect that the sizes of the structures could be larger
 * than the actual messages. That's OK: all we need here is for the
 * stream structures to be at least as large as the messages on the
 * wire. The order and packing of the fields is encoded in the
 * calls to the stream_* functions.
 */

#define _FAE_READY_SIZE                                                        \
	(sizeof(struct zapi_fae_daemon_id) +	/* igp's */                \
	 sizeof(struct zapi_fae_igp_discriminator)) /* igp's */

#define _FAE_REGISTER_SIZE                                                     \
	(sizeof(struct zapi_fae_daemon_id) +	 /* client's */            \
	 sizeof(struct zapi_fae_igp_discriminator) + /* igp's */               \
	 sizeof(struct zapi_fae_query))

#define _FAE_UPDATE_SIZE                                                       \
	(sizeof(struct zapi_fae_daemon_id) +	 /* igp's */               \
	 sizeof(struct zapi_fae_igp_discriminator) + /* igp's */               \
	 sizeof(struct zapi_fae_query) + sizeof(struct zapi_fae_answer))


/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Proto    |          Instance             |   Session-ID
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     Session-ID cont'd (32 bits)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void _encode_daemon_id(struct stream *s, struct zclient *zclient)
{
	stream_putc(s, zclient->redist_default);
	stream_putw(s, zclient->instance);
	stream_putl(s, zclient->session_id);
}

static int _decode_daemon_id(struct stream *s, struct zapi_fae_daemon_id *di)
{
	STREAM_GETC(s, di->proto);
	STREAM_GETW(s, di->instance);
	STREAM_GETL(s, di->session_id);
	return 0;

stream_failure:
	return -1;
}

static size_t
_igp_discriminator_size(const struct zapi_fae_igp_discriminator *const d,
			bool is_ready)
{
	size_t total = 0;

	total += 4; /* vrf id */
	total += 1; /* proto */

	switch (d->proto) {
	case ZEBRA_ROUTE_ISIS:
		total += 4; /* z_area_id */
		if (is_ready) {
			size_t sl = strlen(d->proto_data.isis.area_tag);

			/*
			 * area_tag string will be encoded as:
			 * - 2 byte string length
			 * - N byte string
			 */
			assert(sl <= 0xffff);
			total += 2;
			total += sl;
		}
		break;

	case ZEBRA_ROUTE_SRTE:
		break;

	default:
		assert(0); /* add new protocols to this switch statement */
	}
	return total;
}


/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           VRF ID                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Proto     |         (optional proto data)                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
_encode_igp_discriminator(struct stream *s,
			  const struct zapi_fae_igp_discriminator *const d,
			  bool is_ready)
{
	assert(STREAM_WRITEABLE(s) >= _igp_discriminator_size(d, is_ready));

	stream_putl(s, d->vrf_id);
	stream_putc(s, d->proto);

	if (ZEBRA_ROUTE_ISIS == d->proto) {
		stream_putl(s, d->proto_data.isis.z_area_id);
		if (is_ready) {
			size_t sl = strlen(d->proto_data.isis.area_tag);

			assert(sl <= 0xffff);
			stream_putw(s, (uint16_t)sl);
			stream_write(s, d->proto_data.isis.area_tag, sl);
		}
	}
	zlog_debug("%s: d->proto %u", __func__, d->proto);
}

static int _decode_igp_discriminator(struct stream *s,
				     struct zapi_fae_igp_discriminator *d,
				     bool is_ready)
{
	uint16_t sl;
	char *area_tag = NULL;

	STREAM_GETL(s, d->vrf_id);
	STREAM_GETC(s, d->proto);
	zlog_debug("%s: d->proto %u", __func__, d->proto);

	switch (d->proto) {
	case ZEBRA_ROUTE_ISIS:
		STREAM_GETL(s, d->proto_data.isis.z_area_id);
		if (is_ready) {
			STREAM_GETW(s, sl);
			area_tag = XCALLOC(MTYPE_ZAPI_FAE_AREA_TAG, sl + 1);
			STREAM_GET(area_tag, s, sl);
			area_tag[sl] = 0;
			d->proto_data.isis.area_tag = area_tag;
		} else {
			d->proto_data.isis.area_tag = NULL;
		}
		break;
	default:
		memset(&d->proto_data, 0, sizeof(d->proto_data));
	}

	return 0;

stream_failure:
	if (ZEBRA_ROUTE_ISIS == d->proto) {
		d->proto_data.isis.area_tag = NULL;
		XFREE(MTYPE_ZAPI_FAE_AREA_TAG, area_tag);
	}
	return -1;
}


/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //      struct ipaddr endpoint_address {AFI, address}          //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | flex-algo id  |
 * +-+-+-+-+-+-+-+-+
 */
static void _encode_query(struct stream *s,
			  const struct zapi_fae_query *const q)
{
	stream_put_ipaddr(s, &q->endpoint);
	stream_putc(s, q->algorithm);
}

static int _decode_query(struct stream *s, struct zapi_fae_query *q)
{
	STREAM_GET_IPADDR(s, &q->endpoint);
	STREAM_GETC(s, q->algorithm);
	return 0;

stream_failure:
	return -1;
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  SID format   |           SID-list
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                        SID-list, cont'd                        //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int _encode_answer(struct stream *s,
			  const struct zapi_fae_answer *const a)
{
	const struct zapi_srte_tunnel *zt = &a->sid_list;

	stream_putc(s, 0); /* SID format 0 */

	stream_putc(s, zt->type);
	stream_putl(s, zt->local_label);

	if (zt->label_num > MPLS_MAX_LABELS) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: label %u: can't encode %u labels (maximum is %u)",
			 __func__, zt->local_label, zt->label_num,
			 MPLS_MAX_LABELS);
		return -1;
	}
	stream_putw(s, zt->label_num);

	for (int i = 0; i < zt->label_num; i++)
		stream_putl(s, zt->labels[i]);
	return 0;
}

static int _decode_answer(struct stream *s, struct zapi_fae_answer *a)
{
	struct zapi_srte_tunnel *zt = &a->sid_list;

	STREAM_GETC(s, a->sid_format);

	if (a->sid_format != 0) {
		flog_err(EC_LIB_ZAPI_ENCODE, "%s: unknown sid-format %u",
			 __func__, a->sid_format);
		return -1;
	}

	/*
	 * SID-format 0 handler
	 */
	STREAM_GETC(s, zt->type);
	STREAM_GETL(s, zt->local_label);
	STREAM_GETW(s, zt->label_num);
	if (zt->label_num > MPLS_MAX_LABELS) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: label %u: can't decode %u labels (maximum is %u)",
			 __func__, zt->local_label, zt->label_num,
			 MPLS_MAX_LABELS);
		return -1;
	}
	for (int i = 0; i < zt->label_num; i++)
		STREAM_GETL(s, zt->labels[i]);

	return 0;

stream_failure:
	return -1;
}

extern enum zclient_send_status
zapi_fae_client_ready_send(struct zclient *zclient)
{
	struct stream *s = stream_new(_FAE_READY_SIZE);
	enum zclient_send_status status;

	_encode_daemon_id(s, zclient);
	status = zclient_send_opaque(zclient, FAE_CLIENT_READY, s->data, s->endp);

	stream_free(s);

	return status;
}

static void _encode_fae_ready(struct stream *s, struct zclient *zclient,
			      const struct zapi_fae_igp_discriminator *const d)
{
	assert(zclient->redist_default == d->proto);

	_encode_daemon_id(s, zclient);
	_encode_igp_discriminator(s, d, true);
}

enum zclient_send_status
zapi_fae_ready_send(struct zclient *zclient, bool do_ready,
		    const struct zapi_fae_igp_discriminator *const d)
{
	enum zclient_send_status status;
	struct stream *s = stream_new(sizeof(struct zapi_fae_daemon_id)
				      + _igp_discriminator_size(d, true));

	/*
	 * are we who we say we are?
	 */
#if ZAPI_FAE_DEBUG
	if (d->proto_data.isis.area_tag
	    && strncmp(d->proto_data.isis.area_tag, "!debug!", 7))
#endif
		_encode_fae_ready(s, zclient, d);
	status = zclient_send_opaque(
		zclient, do_ready ? FAE_READY : FAE_NOTREADY, s->data, s->endp);
	stream_free(s);
	return status;
}

enum zclient_send_status zapi_fae_ready_unicast_send(
	struct zclient *zclient, bool do_ready,
	const struct zapi_fae_daemon_id *const igp_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_discriminator)
{
	struct stream *s = stream_new(_FAE_READY_SIZE);
	enum zclient_send_status status;

	_encode_fae_ready(s, zclient, igp_discriminator);
	status = zclient_send_opaque_unicast(
		zclient, (do_ready ? FAE_READY : FAE_NOTREADY),
		igp_daemon_id->proto, igp_daemon_id->instance,
		igp_daemon_id->session_id, s->data, s->endp);

	stream_free(s);

	return status;
}

int zapi_fae_client_ready_decode(struct stream *s,
				 struct zapi_fae_daemon_id *client_daemon_id)
{
	int rc;

	rc = _decode_daemon_id(s, client_daemon_id);
	if (rc)
		return -1;

	return 0;
}

/*
 * Note! When decoding ISIS ready messages, this function allocates a
 * string that the CALLER MUST FREE
 */
int zapi_fae_ready_decode(struct stream *s,
			  struct zapi_fae_daemon_id *igp_daemon_id,
			  struct zapi_fae_igp_discriminator *igp_discriminator)
{
	int rc;

	rc = _decode_daemon_id(s, igp_daemon_id);
	if (rc)
		return -1;
	rc = _decode_igp_discriminator(s, igp_discriminator, true);
	if (rc)
		return -1;

#if ZAPI_FAE_DEBUG
	if (igp_discriminator->proto_data.isis.area_tag
	    && !strncmp(igp_discriminator->proto_data.isis.area_tag, "!debug!",
			7)) {
		if ((igp_daemon_id->proto == ZEBRA_ROUTE_SRTE)
		    && (igp_discriminator->proto == ZEBRA_ROUTE_ISIS)) {

			igp_daemon_id->proto = ZEBRA_ROUTE_ISIS;
		}
	}
#endif

	if (igp_daemon_id->proto != igp_discriminator->proto) {
		zlog_warn("%s: daemon id proto %u != discriminator proto %u",
			  __func__, igp_daemon_id->proto,
			  igp_discriminator->proto);
	}

	return 0;
}

enum zclient_send_status
zapi_fae_register_send(struct zclient *zclient, bool do_register,
		       const struct zapi_fae_daemon_id *const igp_daemon_id,
		       const struct zapi_fae_igp_discriminator *const d,
		       const struct zapi_fae_query *const query)
{
	struct stream *s = stream_new(_FAE_REGISTER_SIZE);
	enum zclient_send_status status;

	_encode_daemon_id(s, zclient);
	_encode_igp_discriminator(s, d, false);
	_encode_query(s, query);

	status = zclient_send_opaque_unicast(
		zclient, (do_register ? FAE_REGISTER : FAE_UNREGISTER),
		igp_daemon_id->proto, igp_daemon_id->instance,
		igp_daemon_id->session_id, s->data, s->endp);

	stream_free(s);

	return status;
}

int zapi_fae_register_decode(
	struct stream *s, struct zapi_fae_daemon_id *client_daemon_id,
	struct zapi_fae_igp_discriminator *igp_discriminator,
	struct zapi_fae_query *query)
{
	int rc;

	rc = _decode_daemon_id(s, client_daemon_id);
	if (rc)
		return -1;

	rc = _decode_igp_discriminator(s, igp_discriminator, false);
	if (rc)
		return -1;

	rc = _decode_query(s, query);
	if (rc)
		return -1;

	return 0;
}

enum zclient_send_status
zapi_fae_update_send(struct zclient *zclient,
		     const struct zapi_fae_daemon_id *const client_daemon_id,
		     const struct zapi_fae_igp_discriminator *const d,
		     const struct zapi_fae_query *const query,
		     const struct zapi_fae_answer *const answer)
{
	struct stream *s = stream_new(_FAE_UPDATE_SIZE);
	enum zclient_send_status status;

	/*
	 * are we who we say we are?
	 */
#if ZAPI_FAE_DEBUG
	if (d->proto_data.isis.area_tag
	    && (strncmp(d->proto_data.isis.area_tag, "!debug!", 7)))
#endif
		assert(zclient->redist_default == d->proto);

	_encode_daemon_id(s, zclient);
	_encode_igp_discriminator(s, d, false);
	_encode_query(s, query);
	if (_encode_answer(s, answer)) {
		stream_free(s);
		return ZCLIENT_SEND_FAILURE;
	}

	status = zclient_send_opaque_unicast(
		zclient, FAE_UPDATE, client_daemon_id->proto,
		client_daemon_id->instance, client_daemon_id->session_id,
		s->data, s->endp);

	stream_free(s);

	return status;
}

int zapi_fae_update_decode(struct stream *s,
			   struct zapi_fae_daemon_id *igp_daemon_id,
			   struct zapi_fae_igp_discriminator *igp_discriminator,
			   struct zapi_fae_query *query,
			   struct zapi_fae_answer *answer)
{
	int rc;

	rc = _decode_daemon_id(s, igp_daemon_id);
	if (rc)
		return -1;

	rc = _decode_igp_discriminator(s, igp_discriminator, false);
	if (rc)
		return -1;

	rc = _decode_query(s, query);
	if (rc)
		return -1;

	rc = _decode_answer(s, answer);
	if (rc)
		return -1;

#if ZAPI_FAE_DEBUG
	if (igp_discriminator->proto_data.isis.area_tag
	    && !strncmp(igp_discriminator->proto_data.isis.area_tag, "!debug!",
			7))
		igp_daemon_id->proto = igp_discriminator->proto;
#endif

	if (igp_daemon_id->proto != igp_discriminator->proto)
		return -1;

	return 0;
}

/*
 * Handle any cleanups for dynamically-allocated parts of
 * the igp discriminator.
 *
 * For use by receiver code
 */
void zapi_fae_igp_discriminator_clean(
	struct zapi_fae_igp_discriminator *igp_discriminator)
{
	if (ZEBRA_ROUTE_ISIS == igp_discriminator->proto)
		XFREE(MTYPE_ZAPI_FAE_AREA_TAG,
		      igp_discriminator->proto_data.isis.area_tag);
}
