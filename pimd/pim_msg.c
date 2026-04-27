// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_vty.h"
#include "pim_pim.h"
#include "pim_msg.h"
#include "pim_util.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_rpf.h"
#include "pim_register.h"
#include "pim_jp_agg.h"
#include "pim_oil.h"
#include "pim_dm.h"

void pim_msg_build_header(pim_addr src, pim_addr dst, uint8_t *pim_msg,
			  size_t pim_msg_size, uint8_t pim_msg_type,
			  bool no_fwd)
{
	struct pim_msg_header *header = (struct pim_msg_header *)pim_msg;
	struct iovec iov[2], *iovp = iov;

	/*
	 * The checksum for Registers is done only on the first 8 bytes of the
	 * packet, including the PIM header and the next 4 bytes, excluding the
	 * data packet portion
	 *
	 * for IPv6, the pseudoheader upper-level protocol length is also
	 * truncated, so let's just set it here before everything else.
	 */
	if (pim_msg_type == PIM_MSG_TYPE_REGISTER)
		pim_msg_size = PIM_MSG_REGISTER_LEN;

#if PIM_IPV == 6
	struct ipv6_ph phdr = {
		.src = src,
		.dst = dst,
		.ulpl = htonl(pim_msg_size),
		.next_hdr = IPPROTO_PIM,
	};

	iovp->iov_base = &phdr;
	iovp->iov_len = sizeof(phdr);
	iovp++;
#endif

	/*
	 * Write header
	 */
	header->ver = PIM_PROTO_VERSION;
	header->type = pim_msg_type;
	header->Nbit = no_fwd;
	header->reserved = 0;

	header->checksum = 0;
	iovp->iov_base = header;
	iovp->iov_len = pim_msg_size;
	iovp++;

	header->checksum = in_cksumv(iov, iovp - iov);
}

uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf, struct in_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	memcpy(buf + 2, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_UCAST_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf, struct in_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = '\0';			      /* reserved */
	buf[3] = 32;			      /* mask len */
	memcpy(buf + 4, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_GROUP_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_source(uint8_t *buf, struct in_addr addr,
					 uint8_t bits)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = bits;
	buf[3] = 32; /* mask len */
	memcpy(buf + 4, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_SOURCE_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv6_source(uint8_t *buf, struct in6_addr addr,
					 uint8_t bits)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = bits;
	buf[3] = 128; /* mask len */
	buf += 4;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

uint8_t *pim_msg_addr_encode_ipv6_ucast(uint8_t *buf, struct in6_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf += 2;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

uint8_t *pim_msg_addr_encode_ipv6_group(uint8_t *buf, struct in6_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = '\0';			      /* reserved */
	buf[3] = 128;			      /* mask len */
	buf += 4;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

#if PIM_IPV == 4
#define pim_msg_addr_encode(what) pim_msg_addr_encode_ipv4_##what
#else
#define pim_msg_addr_encode(what) pim_msg_addr_encode_ipv6_##what
#endif

uint8_t *pim_msg_addr_encode_ucast(uint8_t *buf, pim_addr addr)
{
	return pim_msg_addr_encode(ucast)(buf, addr);
}

uint8_t *pim_msg_addr_encode_group(uint8_t *buf, pim_addr addr)
{
	return pim_msg_addr_encode(group)(buf, addr);
}

uint8_t *pim_msg_addr_encode_source(uint8_t *buf, pim_addr addr, uint8_t bits)
{
	return pim_msg_addr_encode(source)(buf, addr, bits);
}
