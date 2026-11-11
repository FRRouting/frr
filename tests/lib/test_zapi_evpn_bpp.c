// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EVPN bridge-port protection ZAPI codec tests.
 *
 * Copyright (C) 2026 Cisco Systems, Inc.
 */

#include <zebra.h>

#include "stream.h"
#include "vxlan.h"
#include "zclient.h"

#define BPP_PEER_ESI_OFFSET    0
#define BPP_PEER_TYPE_OFFSET   (BPP_PEER_ESI_OFFSET + sizeof(esi_t))
#define BPP_PEER_FAMILY_OFFSET (BPP_PEER_TYPE_OFFSET + sizeof(uint8_t))
#define BPP_PEER_ADDR_OFFSET   (BPP_PEER_FAMILY_OFFSET + sizeof(uint8_t))

static struct stream *clone_stream_bytes(const struct stream *source, size_t length)
{
	struct stream *copy = stream_new(length + 1);

	stream_put(copy, STREAM_DATA(source), length);
	return copy;
}

static void init_esi(esi_t *esi)
{
	size_t i;

	for (i = 0; i < sizeof(*esi); i++)
		esi->val[i] = i + 1;
}

static void init_peer(struct zapi_evpn_bpp_peer *peer, const char *vtep)
{
	const uint8_t rmac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 1 };

	memset(peer, 0, sizeof(*peer));
	init_esi(&peer->esi);
	peer->type = ZAPI_EVPN_BPP_PEER_L3;
	assert(str2ipaddr(vtep, &peer->vtep) == 0);
	memcpy(&peer->rmac, rmac, sizeof(rmac));
}

static void check_peer_truncation(const struct stream *encoded, bool add)
{
	struct zapi_evpn_bpp_peer decoded;
	struct stream *message;
	size_t length = stream_get_endp(encoded);
	size_t cut;

	for (cut = 0; cut < length; cut++) {
		message = clone_stream_bytes(encoded, cut);
		assert(zapi_evpn_bpp_peer_decode(message, &decoded, add) < 0);
		stream_free(message);
	}
}

static void check_peer_malformed(const struct stream *encoded, bool add, size_t offset,
				 size_t length)
{
	struct zapi_evpn_bpp_peer decoded;
	struct stream *message = clone_stream_bytes(encoded, stream_get_endp(encoded));

	memset(STREAM_DATA(message) + offset, 0, length);
	assert(zapi_evpn_bpp_peer_decode(message, &decoded, add) < 0);
	stream_free(message);
}

static void test_peer_codec(const char *vtep, size_t addrlen, bool add)
{
	struct zapi_evpn_bpp_peer peer;
	struct zapi_evpn_bpp_peer decoded;
	struct stream *encoded;
	struct stream *message;
	size_t expected_len = sizeof(esi_t) + 2 * sizeof(uint8_t) + addrlen + (add ? ETH_ALEN : 0);

	init_peer(&peer, vtep);
	encoded = stream_new(64);
	assert(zapi_evpn_bpp_peer_encode(encoded, &peer, add) == 0);
	assert(stream_get_endp(encoded) == expected_len);
	assert(!memcmp(STREAM_DATA(encoded), &peer.esi, sizeof(peer.esi)));
	assert(STREAM_DATA(encoded)[BPP_PEER_TYPE_OFFSET] == peer.type);
	assert(STREAM_DATA(encoded)[BPP_PEER_FAMILY_OFFSET] ==
	       (addrlen == IPV4_MAX_BYTELEN ? AF_INET : AF_INET6));
	assert(!memcmp(STREAM_DATA(encoded) + BPP_PEER_ADDR_OFFSET, &peer.vtep.ip, addrlen));
	if (add)
		assert(!memcmp(STREAM_DATA(encoded) + expected_len - ETH_ALEN, &peer.rmac,
			       ETH_ALEN));

	message = clone_stream_bytes(encoded, expected_len);
	assert(zapi_evpn_bpp_peer_decode(message, &decoded, add) == 0);
	assert(!memcmp(&decoded.esi, &peer.esi, sizeof(peer.esi)));
	assert(decoded.type == peer.type);
	assert(!ipaddr_cmp(&decoded.vtep, &peer.vtep));
	if (add)
		assert(!memcmp(&decoded.rmac, &peer.rmac, sizeof(peer.rmac)));
	else
		assert(is_zero_mac(&decoded.rmac));
	stream_free(message);

	message = clone_stream_bytes(encoded, expected_len);
	assert(zapi_evpn_bpp_peer_decode(message, &decoded, !add) < 0);
	stream_free(message);

	check_peer_truncation(encoded, add);

	message = clone_stream_bytes(encoded, expected_len);
	stream_putc(message, 0);
	assert(zapi_evpn_bpp_peer_decode(message, &decoded, add) < 0);
	stream_free(message);

	check_peer_malformed(encoded, add, BPP_PEER_TYPE_OFFSET, sizeof(uint8_t));
	check_peer_malformed(encoded, add, BPP_PEER_FAMILY_OFFSET, sizeof(uint8_t));
	check_peer_malformed(encoded, add, BPP_PEER_ADDR_OFFSET, addrlen);
	if (add)
		check_peer_malformed(encoded, add, expected_len - ETH_ALEN, ETH_ALEN);

	stream_free(encoded);
}

static void test_peer_encode_rejections(void)
{
	struct zapi_evpn_bpp_peer peer;
	struct stream *stream = stream_new(64);

	init_peer(&peer, "192.0.2.1");
	peer.type = 0;
	assert(zapi_evpn_bpp_peer_encode(stream, &peer, true) < 0);

	init_peer(&peer, "192.0.2.1");
	memset(&peer.vtep, 0, sizeof(peer.vtep));
	assert(zapi_evpn_bpp_peer_encode(stream, &peer, true) < 0);

	init_peer(&peer, "192.0.2.1");
	memset(&peer.rmac, 0, sizeof(peer.rmac));
	assert(zapi_evpn_bpp_peer_encode(stream, &peer, true) < 0);
	assert(zapi_evpn_bpp_peer_encode(stream, &peer, false) == 0);

	stream_free(stream);
}

static struct stream *encode_es_evi(const struct zapi_evpn_local_es_evi *evi)
{
	struct stream *encoded = stream_new(32);

	assert(zapi_evpn_local_es_evi_encode(encoded, evi) == 0);
	return encoded;
}

static void test_es_evi_codec(void)
{
	struct zapi_evpn_local_es_evi evi = { .l3vni = 100 };
	struct zapi_evpn_local_es_evi decoded;
	struct stream *encoded;
	struct stream *message;
	size_t expected_len = sizeof(esi_t) + sizeof(uint32_t);
	size_t cut;

	init_esi(&evi.esi);
	encoded = encode_es_evi(&evi);
	assert(stream_get_endp(encoded) == expected_len);

	message = clone_stream_bytes(encoded, expected_len);
	assert(zapi_evpn_local_es_evi_decode(message, &decoded) == 0);
	assert(!memcmp(&decoded.esi, &evi.esi, sizeof(evi.esi)));
	assert(decoded.l3vni == evi.l3vni);
	stream_free(message);

	for (cut = 0; cut < expected_len; cut++) {
		message = clone_stream_bytes(encoded, cut);
		assert(zapi_evpn_local_es_evi_decode(message, &decoded) < 0);
		stream_free(message);
	}

	message = clone_stream_bytes(encoded, expected_len);
	stream_putc(message, 0);
	assert(zapi_evpn_local_es_evi_decode(message, &decoded) < 0);
	stream_free(message);

	message = clone_stream_bytes(encoded, expected_len);
	memset(STREAM_DATA(message), 0, sizeof(esi_t));
	assert(zapi_evpn_local_es_evi_decode(message, &decoded) < 0);
	stream_free(message);

	message = clone_stream_bytes(encoded, expected_len);
	stream_putl_at(message, sizeof(esi_t), 0);
	assert(zapi_evpn_local_es_evi_decode(message, &decoded) < 0);
	stream_free(message);

	message = clone_stream_bytes(encoded, expected_len);
	stream_putl_at(message, sizeof(esi_t), VNI_MAX + 1);
	assert(zapi_evpn_local_es_evi_decode(message, &decoded) < 0);
	stream_free(message);

	stream_free(encoded);
}

static void test_es_evi_encode_rejections(void)
{
	struct zapi_evpn_local_es_evi evi = {};
	struct stream *stream = stream_new(32);

	evi.l3vni = 100;
	assert(zapi_evpn_local_es_evi_encode(stream, &evi) < 0);

	init_esi(&evi.esi);
	evi.l3vni = 0;
	assert(zapi_evpn_local_es_evi_encode(stream, &evi) < 0);

	evi.l3vni = VNI_MAX + 1;
	assert(zapi_evpn_local_es_evi_encode(stream, &evi) < 0);

	stream_free(stream);
}

int main(void)
{
	test_peer_codec("192.0.2.1", IPV4_MAX_BYTELEN, true);
	test_peer_codec("192.0.2.1", IPV4_MAX_BYTELEN, false);
	test_peer_codec("2001:db8::1", IPV6_MAX_BYTELEN, true);
	test_peer_codec("2001:db8::1", IPV6_MAX_BYTELEN, false);
	test_peer_encode_rejections();

	test_es_evi_codec();
	test_es_evi_encode_rejections();

	return 0;
}
