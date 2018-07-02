/* NHRP packet handling functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <netinet/if_ether.h>
#include "nhrpd.h"
#include "zbuf.h"
#include "thread.h"
#include "hash.h"

#include "nhrp_protocol.h"
#include "os.h"

struct nhrp_reqid_pool nhrp_packet_reqid;

static uint16_t family2proto(int family)
{
	switch (family) {
	case AF_INET:
		return ETH_P_IP;
	case AF_INET6:
		return ETH_P_IPV6;
	}
	return 0;
}

static int proto2family(uint16_t proto)
{
	switch (proto) {
	case ETH_P_IP:
		return AF_INET;
	case ETH_P_IPV6:
		return AF_INET6;
	}
	return AF_UNSPEC;
}

struct nhrp_packet_header *nhrp_packet_push(struct zbuf *zb, uint8_t type,
					    const union sockunion *src_nbma,
					    const union sockunion *src_proto,
					    const union sockunion *dst_proto)
{
	struct nhrp_packet_header *hdr;

	hdr = zbuf_push(zb, struct nhrp_packet_header);
	if (!hdr)
		return NULL;

	*hdr = (struct nhrp_packet_header){
		.afnum = htons(family2afi(sockunion_family(src_nbma))),
		.protocol_type =
			htons(family2proto(sockunion_family(src_proto))),
		.version = NHRP_VERSION_RFC2332,
		.type = type,
		.hop_count = 64,
		.src_nbma_address_len = sockunion_get_addrlen(src_nbma),
		.src_protocol_address_len = sockunion_get_addrlen(src_proto),
		.dst_protocol_address_len = sockunion_get_addrlen(dst_proto),
	};

	zbuf_put(zb, sockunion_get_addr(src_nbma), hdr->src_nbma_address_len);
	zbuf_put(zb, sockunion_get_addr(src_proto),
		 hdr->src_protocol_address_len);
	zbuf_put(zb, sockunion_get_addr(dst_proto),
		 hdr->dst_protocol_address_len);

	return hdr;
}

struct nhrp_packet_header *nhrp_packet_pull(struct zbuf *zb,
					    union sockunion *src_nbma,
					    union sockunion *src_proto,
					    union sockunion *dst_proto)
{
	struct nhrp_packet_header *hdr;

	hdr = zbuf_pull(zb, struct nhrp_packet_header);
	if (!hdr)
		return NULL;

	sockunion_set(src_nbma, afi2family(htons(hdr->afnum)),
		      zbuf_pulln(zb,
				 hdr->src_nbma_address_len
					 + hdr->src_nbma_subaddress_len),
		      hdr->src_nbma_address_len + hdr->src_nbma_subaddress_len);
	sockunion_set(src_proto, proto2family(htons(hdr->protocol_type)),
		      zbuf_pulln(zb, hdr->src_protocol_address_len),
		      hdr->src_protocol_address_len);
	sockunion_set(dst_proto, proto2family(htons(hdr->protocol_type)),
		      zbuf_pulln(zb, hdr->dst_protocol_address_len),
		      hdr->dst_protocol_address_len);

	return hdr;
}

uint16_t nhrp_packet_calculate_checksum(const uint8_t *pdu, uint16_t len)
{
	const uint16_t *pdu16 = (const uint16_t *)pdu;
	uint32_t csum = 0;
	int i;

	for (i = 0; i < len / 2; i++)
		csum += pdu16[i];
	if (len & 1)
		csum += htons(pdu[len - 1]);

	while (csum & 0xffff0000)
		csum = (csum & 0xffff) + (csum >> 16);

	return (~csum) & 0xffff;
}

void nhrp_packet_complete(struct zbuf *zb, struct nhrp_packet_header *hdr)
{
	unsigned short size;

	if (hdr->extension_offset)
		nhrp_ext_push(zb, hdr,
			      NHRP_EXTENSION_END
				      | NHRP_EXTENSION_FLAG_COMPULSORY);

	size = zb->tail - (uint8_t *)hdr;
	hdr->packet_size = htons(size);
	hdr->checksum = 0;
	hdr->checksum = nhrp_packet_calculate_checksum((uint8_t *)hdr, size);
}

struct nhrp_cie_header *nhrp_cie_push(struct zbuf *zb, uint8_t code,
				      const union sockunion *nbma,
				      const union sockunion *proto)
{
	struct nhrp_cie_header *cie;

	cie = zbuf_push(zb, struct nhrp_cie_header);
	*cie = (struct nhrp_cie_header){
		.code = code,
	};
	if (nbma) {
		cie->nbma_address_len = sockunion_get_addrlen(nbma);
		zbuf_put(zb, sockunion_get_addr(nbma), cie->nbma_address_len);
	}
	if (proto) {
		cie->protocol_address_len = sockunion_get_addrlen(proto);
		zbuf_put(zb, sockunion_get_addr(proto),
			 cie->protocol_address_len);
	}

	return cie;
}

struct nhrp_cie_header *nhrp_cie_pull(struct zbuf *zb,
				      struct nhrp_packet_header *hdr,
				      union sockunion *nbma,
				      union sockunion *proto)
{
	struct nhrp_cie_header *cie;

	cie = zbuf_pull(zb, struct nhrp_cie_header);
	if (!cie)
		return NULL;

	if (cie->nbma_address_len + cie->nbma_subaddress_len > 0) {
		sockunion_set(nbma, afi2family(htons(hdr->afnum)),
			      zbuf_pulln(zb,
					 cie->nbma_address_len
						 + cie->nbma_subaddress_len),
			      cie->nbma_address_len + cie->nbma_subaddress_len);
	} else {
		sockunion_family(nbma) = AF_UNSPEC;
	}

	if (cie->protocol_address_len) {
		sockunion_set(proto, proto2family(htons(hdr->protocol_type)),
			      zbuf_pulln(zb, cie->protocol_address_len),
			      cie->protocol_address_len);
	} else {
		sockunion_family(proto) = AF_UNSPEC;
	}

	return cie;
}

struct nhrp_extension_header *
nhrp_ext_push(struct zbuf *zb, struct nhrp_packet_header *hdr, uint16_t type)
{
	struct nhrp_extension_header *ext;
	ext = zbuf_push(zb, struct nhrp_extension_header);
	if (!ext)
		return NULL;

	if (!hdr->extension_offset)
		hdr->extension_offset =
			htons(zb->tail - (uint8_t *)hdr
			      - sizeof(struct nhrp_extension_header));

	*ext = (struct nhrp_extension_header){
		.type = htons(type), .length = 0,
	};
	return ext;
}

void nhrp_ext_complete(struct zbuf *zb, struct nhrp_extension_header *ext)
{
	ext->length = htons(zb->tail - (uint8_t *)ext
			    - sizeof(struct nhrp_extension_header));
}

struct nhrp_extension_header *nhrp_ext_pull(struct zbuf *zb,
					    struct zbuf *payload)
{
	struct nhrp_extension_header *ext;
	uint16_t plen;

	ext = zbuf_pull(zb, struct nhrp_extension_header);
	if (!ext)
		return NULL;

	plen = htons(ext->length);
	zbuf_init(payload, zbuf_pulln(zb, plen), plen, plen);
	return ext;
}

void nhrp_ext_request(struct zbuf *zb, struct nhrp_packet_header *hdr,
		      struct interface *ifp)
{
	/* Place holders for standard extensions */
	nhrp_ext_push(zb, hdr,
		      NHRP_EXTENSION_FORWARD_TRANSIT_NHS
			      | NHRP_EXTENSION_FLAG_COMPULSORY);
	nhrp_ext_push(zb, hdr,
		      NHRP_EXTENSION_REVERSE_TRANSIT_NHS
			      | NHRP_EXTENSION_FLAG_COMPULSORY);
	nhrp_ext_push(zb, hdr,
		      NHRP_EXTENSION_RESPONDER_ADDRESS
			      | NHRP_EXTENSION_FLAG_COMPULSORY);
}

int nhrp_ext_reply(struct zbuf *zb, struct nhrp_packet_header *hdr,
		   struct interface *ifp, struct nhrp_extension_header *ext,
		   struct zbuf *extpayload)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *ad = &nifp->afi[htons(hdr->afnum)];
	struct nhrp_extension_header *dst;
	struct nhrp_cie_header *cie;
	uint16_t type;

	type = htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
	if (type == NHRP_EXTENSION_END)
		return 0;

	dst = nhrp_ext_push(zb, hdr, htons(ext->type));
	if (!dst)
		goto err;

	switch (type) {
	case NHRP_EXTENSION_RESPONDER_ADDRESS:
		cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &nifp->nbma,
				    &ad->addr);
		if (!cie)
			goto err;
		cie->holding_time = htons(ad->holdtime);
		break;
	default:
		if (type & NHRP_EXTENSION_FLAG_COMPULSORY)
			goto err;
	/* fallthru */
	case NHRP_EXTENSION_FORWARD_TRANSIT_NHS:
	case NHRP_EXTENSION_REVERSE_TRANSIT_NHS:
		/* Supported compulsory extensions, and any
		 * non-compulsory that is not explicitly handled,
		 * should be just copied. */
		zbuf_copy(zb, extpayload, zbuf_used(extpayload));
		break;
	}
	nhrp_ext_complete(zb, dst);
	return 0;
err:
	zbuf_set_werror(zb);
	return -1;
}

static int nhrp_packet_recvraw(struct thread *t)
{
	int fd = THREAD_FD(t), ifindex;
	struct zbuf *zb;
	struct interface *ifp;
	struct nhrp_peer *p;
	union sockunion remote_nbma;
	uint8_t addr[64];
	size_t len, addrlen;

	thread_add_read(master, nhrp_packet_recvraw, 0, fd, NULL);

	zb = zbuf_alloc(1500);
	if (!zb)
		return 0;

	len = zbuf_size(zb);
	addrlen = sizeof(addr);
	if (os_recvmsg(zb->buf, &len, &ifindex, addr, &addrlen) < 0)
		goto err;

	zb->head = zb->buf;
	zb->tail = zb->buf + len;

	switch (addrlen) {
	case 4:
		sockunion_set(&remote_nbma, AF_INET, addr, addrlen);
		break;
	default:
		goto err;
	}

	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
	if (!ifp)
		goto err;

	p = nhrp_peer_get(ifp, &remote_nbma);
	if (!p)
		goto err;

	nhrp_peer_recv(p, zb);
	nhrp_peer_unref(p);
	return 0;

err:
	zbuf_free(zb);
	return 0;
}

int nhrp_packet_init(void)
{
	thread_add_read(master, nhrp_packet_recvraw, 0, os_socket(), NULL);
	return 0;
}
