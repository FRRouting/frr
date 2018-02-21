/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "if.h"

#include "pimd.h"
#include "pim_int.h"
#include "pim_tlv.h"
#include "pim_str.h"
#include "pim_msg.h"

uint8_t *pim_tlv_append_uint16(uint8_t *buf, const uint8_t *buf_pastend,
			       uint16_t option_type, uint16_t option_value)
{
	uint16_t option_len = 2;

	if ((buf + PIM_TLV_OPTION_SIZE(option_len)) > buf_pastend)
		return NULL;

	*(uint16_t *)buf = htons(option_type);
	buf += 2;
	*(uint16_t *)buf = htons(option_len);
	buf += 2;
	*(uint16_t *)buf = htons(option_value);
	buf += option_len;

	return buf;
}

uint8_t *pim_tlv_append_2uint16(uint8_t *buf, const uint8_t *buf_pastend,
				uint16_t option_type, uint16_t option_value1,
				uint16_t option_value2)
{
	uint16_t option_len = 4;

	if ((buf + PIM_TLV_OPTION_SIZE(option_len)) > buf_pastend)
		return NULL;

	*(uint16_t *)buf = htons(option_type);
	buf += 2;
	*(uint16_t *)buf = htons(option_len);
	buf += 2;
	*(uint16_t *)buf = htons(option_value1);
	buf += 2;
	*(uint16_t *)buf = htons(option_value2);
	buf += 2;

	return buf;
}

uint8_t *pim_tlv_append_uint32(uint8_t *buf, const uint8_t *buf_pastend,
			       uint16_t option_type, uint32_t option_value)
{
	uint16_t option_len = 4;

	if ((buf + PIM_TLV_OPTION_SIZE(option_len)) > buf_pastend)
		return NULL;

	*(uint16_t *)buf = htons(option_type);
	buf += 2;
	*(uint16_t *)buf = htons(option_len);
	buf += 2;
	pim_write_uint32(buf, option_value);
	buf += option_len;

	return buf;
}

#define ucast_ipv4_encoding_len (2 + sizeof(struct in_addr))
#define ucast_ipv6_encoding_len (2 + sizeof(struct in6_addr))

/*
 * An Encoded-Unicast address takes the following format:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Addr Family  | Encoding Type |     Unicast Address
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
 *
 *  Addr Family
 *       The PIM address family of the 'Unicast Address' field of this
 *       address.
 *
 *       Values 0-127 are as assigned by the IANA for Internet Address   *
 * Families in [7].  Values 128-250 are reserved to be assigned by
 *       the IANA for PIM-specific Address Families.  Values 251 though
 *       255 are designated for private use.  As there is no assignment
 *       authority for this space, collisions should be expected.
 *
 *  Encoding Type
 *       The type of encoding used within a specific Address Family.  The
 *       value '0' is reserved for this field and represents the native
 *       encoding of the Address Family.
 *
 *  Unicast Address
 *       The unicast address as represented by the given Address Family
 *       and Encoding Type.
 */
int pim_encode_addr_ucast(uint8_t *buf, struct prefix *p)
{
	switch (p->family) {
	case AF_INET:
		*(uint8_t *)buf =
			PIM_MSG_ADDRESS_FAMILY_IPV4; /* notice: AF_INET !=
							PIM_MSG_ADDRESS_FAMILY_IPV4
							*/
		++buf;
		*(uint8_t *)buf = 0; /* ucast IPv4 native encoding type (RFC
					4601: 4.9.1) */
		++buf;
		memcpy(buf, &p->u.prefix4, sizeof(struct in_addr));
		return ucast_ipv4_encoding_len;
		break;
	case AF_INET6:
		*(uint8_t *)buf = PIM_MSG_ADDRESS_FAMILY_IPV6;
		++buf;
		*(uint8_t *)buf = 0;
		++buf;
		memcpy(buf, &p->u.prefix6, sizeof(struct in6_addr));
		return ucast_ipv6_encoding_len;
		break;
	default:
		return 0;
		break;
	}
}

#define group_ipv4_encoding_len (4 + sizeof (struct in_addr))

/*
 * Encoded-Group addresses take the following format:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Addr Family  | Encoding Type |B| Reserved  |Z|  Mask Len     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Group multicast Address
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
 *
 *  Addr Family
 *       Described above.
 *
 *  Encoding Type
 *       Described above.
 *
 *  [B]idirectional PIM
 *       Indicates the group range should use Bidirectional PIM [13].
 *       For PIM-SM defined in this specification, this bit MUST be zero.
 *
 *  Reserved
 *       Transmitted as zero.  Ignored upon receipt.
 *
 *  Admin Scope [Z]one
 *       indicates the group range is an admin scope zone.  This is used
 *       in the Bootstrap Router Mechanism [11] only.  For all other
 *       purposes, this bit is set to zero and ignored on receipt.
 *
 *  Mask Len
 *       The Mask length field is 8 bits.  The value is the number of
 *       contiguous one bits that are left justified and used as a mask;
 *       when combined with the group address, it describes a range of
 *       groups.  It is less than or equal to the address length in bits
 *       for the given Address Family and Encoding Type.  If the message
 *       is sent for a single group, then the Mask length must equal the
 *       address length in bits for the given Address Family and Encoding
 *       Type (e.g., 32 for IPv4 native encoding, 128 for IPv6 native
 *       encoding).
 *
 *  Group multicast Address
 *       Contains the group address.
 */
int pim_encode_addr_group(uint8_t *buf, afi_t afi, int bidir, int scope,
			  struct in_addr group)
{
	uint8_t flags = 0;

	flags |= bidir << 8;
	flags |= scope;

	switch (afi) {
	case AFI_IP:
		*(uint8_t *)buf = PIM_MSG_ADDRESS_FAMILY_IPV4;
		++buf;
		*(uint8_t *)buf = 0;
		++buf;
		*(uint8_t *)buf = flags;
		++buf;
		*(uint8_t *)buf = 32;
		++buf;
		memcpy(buf, &group, sizeof(struct in_addr));
		return group_ipv4_encoding_len;
		break;
	default:
		return 0;
		break;
	}
}

uint8_t *pim_tlv_append_addrlist_ucast(uint8_t *buf, const uint8_t *buf_pastend,
				       struct list *ifconnected, int family)
{
	struct listnode *node;
	uint16_t option_len = 0;
	uint8_t *curr;
	size_t uel;

	node = listhead(ifconnected);

	/* Empty address list ? */
	if (!node) {
		return buf;
	}

	if (family == AF_INET)
		uel = ucast_ipv4_encoding_len;
	else
		uel = ucast_ipv6_encoding_len;

	/* Scan secondary address list */
	curr = buf + 4; /* skip T and L */
	for (; node; node = listnextnode(node)) {
		struct connected *ifc = listgetdata(node);
		struct prefix *p = ifc->address;
		int l_encode;

		if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
			continue;

		if ((curr + uel) > buf_pastend)
			return 0;

		if (p->family != family)
			continue;

		l_encode = pim_encode_addr_ucast(curr, p);
		curr += l_encode;
		option_len += l_encode;
	}

	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		zlog_debug(
			"%s: number of encoded secondary unicast IPv4 addresses: %zu",
			__PRETTY_FUNCTION__, option_len / uel);
	}

	if (option_len < 1) {
		/* Empty secondary unicast IPv4 address list */
		return buf;
	}

	/*
	 * Write T and L
	 */
	*(uint16_t *)buf = htons(PIM_MSG_OPTION_TYPE_ADDRESS_LIST);
	*(uint16_t *)(buf + 2) = htons(option_len);

	return curr;
}

static int check_tlv_length(const char *label, const char *tlv_name,
			    const char *ifname, struct in_addr src_addr,
			    int correct_len, int option_len)
{
	if (option_len != correct_len) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn(
			"%s: PIM hello %s TLV with incorrect value size=%d correct=%d from %s on interface %s",
			label, tlv_name, option_len, correct_len, src_str,
			ifname);
		return -1;
	}

	return 0;
}

static void check_tlv_redefinition_uint16(
	const char *label, const char *tlv_name, const char *ifname,
	struct in_addr src_addr, pim_hello_options options,
	pim_hello_options opt_mask, uint16_t new, uint16_t old)
{
	if (PIM_OPTION_IS_SET(options, opt_mask)) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn(
			"%s: PIM hello TLV redefined %s=%u old=%u from %s on interface %s",
			label, tlv_name, new, old, src_str, ifname);
	}
}

static void check_tlv_redefinition_uint32(
	const char *label, const char *tlv_name, const char *ifname,
	struct in_addr src_addr, pim_hello_options options,
	pim_hello_options opt_mask, uint32_t new, uint32_t old)
{
	if (PIM_OPTION_IS_SET(options, opt_mask)) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn(
			"%s: PIM hello TLV redefined %s=%u old=%u from %s on interface %s",
			label, tlv_name, new, old, src_str, ifname);
	}
}

static void check_tlv_redefinition_uint32_hex(
	const char *label, const char *tlv_name, const char *ifname,
	struct in_addr src_addr, pim_hello_options options,
	pim_hello_options opt_mask, uint32_t new, uint32_t old)
{
	if (PIM_OPTION_IS_SET(options, opt_mask)) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn(
			"%s: PIM hello TLV redefined %s=%08x old=%08x from %s on interface %s",
			label, tlv_name, new, old, src_str, ifname);
	}
}

int pim_tlv_parse_holdtime(const char *ifname, struct in_addr src_addr,
			   pim_hello_options *hello_options,
			   uint16_t *hello_option_holdtime, uint16_t option_len,
			   const uint8_t *tlv_curr)
{
	const char *label = "holdtime";

	if (check_tlv_length(__PRETTY_FUNCTION__, label, ifname, src_addr,
			     sizeof(uint16_t), option_len)) {
		return -1;
	}

	check_tlv_redefinition_uint16(
		__PRETTY_FUNCTION__, label, ifname, src_addr, *hello_options,
		PIM_OPTION_MASK_HOLDTIME, PIM_TLV_GET_HOLDTIME(tlv_curr),
		*hello_option_holdtime);

	PIM_OPTION_SET(*hello_options, PIM_OPTION_MASK_HOLDTIME);

	*hello_option_holdtime = PIM_TLV_GET_HOLDTIME(tlv_curr);

	return 0;
}

int pim_tlv_parse_lan_prune_delay(const char *ifname, struct in_addr src_addr,
				  pim_hello_options *hello_options,
				  uint16_t *hello_option_propagation_delay,
				  uint16_t *hello_option_override_interval,
				  uint16_t option_len, const uint8_t *tlv_curr)
{
	if (check_tlv_length(__PRETTY_FUNCTION__, "lan_prune_delay", ifname,
			     src_addr, sizeof(uint32_t), option_len)) {
		return -1;
	}

	check_tlv_redefinition_uint16(__PRETTY_FUNCTION__, "propagation_delay",
				      ifname, src_addr, *hello_options,
				      PIM_OPTION_MASK_LAN_PRUNE_DELAY,
				      PIM_TLV_GET_PROPAGATION_DELAY(tlv_curr),
				      *hello_option_propagation_delay);

	PIM_OPTION_SET(*hello_options, PIM_OPTION_MASK_LAN_PRUNE_DELAY);

	*hello_option_propagation_delay =
		PIM_TLV_GET_PROPAGATION_DELAY(tlv_curr);
	if (PIM_TLV_GET_CAN_DISABLE_JOIN_SUPPRESSION(tlv_curr)) {
		PIM_OPTION_SET(*hello_options,
			       PIM_OPTION_MASK_CAN_DISABLE_JOIN_SUPPRESSION);
	} else {
		PIM_OPTION_UNSET(*hello_options,
				 PIM_OPTION_MASK_CAN_DISABLE_JOIN_SUPPRESSION);
	}
	++tlv_curr;
	++tlv_curr;
	*hello_option_override_interval =
		PIM_TLV_GET_OVERRIDE_INTERVAL(tlv_curr);

	return 0;
}

int pim_tlv_parse_dr_priority(const char *ifname, struct in_addr src_addr,
			      pim_hello_options *hello_options,
			      uint32_t *hello_option_dr_priority,
			      uint16_t option_len, const uint8_t *tlv_curr)
{
	const char *label = "dr_priority";

	if (check_tlv_length(__PRETTY_FUNCTION__, label, ifname, src_addr,
			     sizeof(uint32_t), option_len)) {
		return -1;
	}

	check_tlv_redefinition_uint32(
		__PRETTY_FUNCTION__, label, ifname, src_addr, *hello_options,
		PIM_OPTION_MASK_DR_PRIORITY, PIM_TLV_GET_DR_PRIORITY(tlv_curr),
		*hello_option_dr_priority);

	PIM_OPTION_SET(*hello_options, PIM_OPTION_MASK_DR_PRIORITY);

	*hello_option_dr_priority = PIM_TLV_GET_DR_PRIORITY(tlv_curr);

	return 0;
}

int pim_tlv_parse_generation_id(const char *ifname, struct in_addr src_addr,
				pim_hello_options *hello_options,
				uint32_t *hello_option_generation_id,
				uint16_t option_len, const uint8_t *tlv_curr)
{
	const char *label = "generation_id";

	if (check_tlv_length(__PRETTY_FUNCTION__, label, ifname, src_addr,
			     sizeof(uint32_t), option_len)) {
		return -1;
	}

	check_tlv_redefinition_uint32_hex(__PRETTY_FUNCTION__, label, ifname,
					  src_addr, *hello_options,
					  PIM_OPTION_MASK_GENERATION_ID,
					  PIM_TLV_GET_GENERATION_ID(tlv_curr),
					  *hello_option_generation_id);

	PIM_OPTION_SET(*hello_options, PIM_OPTION_MASK_GENERATION_ID);

	*hello_option_generation_id = PIM_TLV_GET_GENERATION_ID(tlv_curr);

	return 0;
}

int pim_parse_addr_ucast(struct prefix *p, const uint8_t *buf, int buf_size)
{
	const int ucast_encoding_min_len = 3; /* 1 family + 1 type + 1 addr */
	const uint8_t *addr;
	const uint8_t *pastend;
	int family;
	int type;

	if (buf_size < ucast_encoding_min_len) {
		zlog_warn(
			"%s: unicast address encoding overflow: left=%d needed=%d",
			__PRETTY_FUNCTION__, buf_size, ucast_encoding_min_len);
		return -1;
	}

	addr = buf;
	pastend = buf + buf_size;

	family = *addr++;
	type = *addr++;

	if (type) {
		zlog_warn("%s: unknown unicast address encoding type=%d",
			  __PRETTY_FUNCTION__, type);
		return -2;
	}

	switch (family) {
	case PIM_MSG_ADDRESS_FAMILY_IPV4:
		if ((addr + sizeof(struct in_addr)) > pastend) {
			zlog_warn(
				"%s: IPv4 unicast address overflow: left=%zd needed=%zu",
				__PRETTY_FUNCTION__, pastend - addr,
				sizeof(struct in_addr));
			return -3;
		}

		p->family = AF_INET; /* notice: AF_INET !=
					PIM_MSG_ADDRESS_FAMILY_IPV4 */
		memcpy(&p->u.prefix4, addr, sizeof(struct in_addr));
		p->prefixlen = IPV4_MAX_PREFIXLEN;
		addr += sizeof(struct in_addr);

		break;
	case PIM_MSG_ADDRESS_FAMILY_IPV6:
		if ((addr + sizeof(struct in6_addr)) > pastend) {
			zlog_warn(
				"%s: IPv6 unicast address overflow: left=%zd needed %zu",
				__PRETTY_FUNCTION__, pastend - addr,
				sizeof(struct in6_addr));
			return -3;
		}

		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_PREFIXLEN;
		memcpy(&p->u.prefix6, addr, sizeof(struct in6_addr));
		addr += sizeof(struct in6_addr);

		break;
	default: {
		zlog_warn("%s: unknown unicast address encoding family=%d from",
			  __PRETTY_FUNCTION__, family);
		return -4;
	}
	}

	return addr - buf;
}

int pim_parse_addr_group(struct prefix_sg *sg, const uint8_t *buf, int buf_size)
{
	const int grp_encoding_min_len =
		4; /* 1 family + 1 type + 1 reserved + 1 addr */
	const uint8_t *addr;
	const uint8_t *pastend;
	int family;
	int type;
	int mask_len;

	if (buf_size < grp_encoding_min_len) {
		zlog_warn(
			"%s: group address encoding overflow: left=%d needed=%d",
			__PRETTY_FUNCTION__, buf_size, grp_encoding_min_len);
		return -1;
	}

	addr = buf;
	pastend = buf + buf_size;

	family = *addr++;
	type = *addr++;
	//++addr;
	++addr; /* skip b_reserved_z fields */
	mask_len = *addr++;

	switch (family) {
	case PIM_MSG_ADDRESS_FAMILY_IPV4:
		if (type) {
			zlog_warn(
				"%s: unknown group address encoding type=%d from",
				__PRETTY_FUNCTION__, type);
			return -2;
		}

		if ((addr + sizeof(struct in_addr)) > pastend) {
			zlog_warn(
				"%s: IPv4 group address overflow: left=%zd needed=%zu from",
				__PRETTY_FUNCTION__, pastend - addr,
				sizeof(struct in_addr));
			return -3;
		}

		memcpy(&sg->grp.s_addr, addr, sizeof(struct in_addr));

		addr += sizeof(struct in_addr);

		break;
	default: {
		zlog_warn(
			"%s: unknown group address encoding family=%d mask_len=%d from",
			__PRETTY_FUNCTION__, family, mask_len);
		return -4;
	}
	}

	return addr - buf;
}

int pim_parse_addr_source(struct prefix_sg *sg, uint8_t *flags,
			  const uint8_t *buf, int buf_size)
{
	const int src_encoding_min_len =
		4; /* 1 family + 1 type + 1 reserved + 1 addr */
	const uint8_t *addr;
	const uint8_t *pastend;
	int family;
	int type;
	int mask_len;

	if (buf_size < src_encoding_min_len) {
		zlog_warn(
			"%s: source address encoding overflow: left=%d needed=%d",
			__PRETTY_FUNCTION__, buf_size, src_encoding_min_len);
		return -1;
	}

	addr = buf;
	pastend = buf + buf_size;

	family = *addr++;
	type = *addr++;
	*flags = *addr++;
	mask_len = *addr++;

	if (type) {
		zlog_warn(
			"%s: unknown source address encoding type=%d: %02x%02x%02x%02x%02x%02x%02x%02x",
			__PRETTY_FUNCTION__, type, buf[0], buf[1], buf[2],
			buf[3], buf[4], buf[5], buf[6], buf[7]);
		return -2;
	}

	switch (family) {
	case PIM_MSG_ADDRESS_FAMILY_IPV4:
		if ((addr + sizeof(struct in_addr)) > pastend) {
			zlog_warn(
				"%s: IPv4 source address overflow: left=%zd needed=%zu",
				__PRETTY_FUNCTION__, pastend - addr,
				sizeof(struct in_addr));
			return -3;
		}

		memcpy(&sg->src, addr, sizeof(struct in_addr));

		/*
		   RFC 4601: 4.9.1  Encoded Source and Group Address Formats

		   Encoded-Source Address

		   The mask length MUST be equal to the mask length in bits for
		   the given Address Family and Encoding Type (32 for IPv4
		   native
		   and 128 for IPv6 native).  A router SHOULD ignore any
		   messages
		   received with any other mask length.
		*/
		if (mask_len != 32) {
			zlog_warn("%s: IPv4 bad source address mask: %d",
				  __PRETTY_FUNCTION__, mask_len);
			return -4;
		}

		addr += sizeof(struct in_addr);

		break;
	default: {
		zlog_warn(
			"%s: unknown source address encoding family=%d: %02x%02x%02x%02x%02x%02x%02x%02x",
			__PRETTY_FUNCTION__, family, buf[0], buf[1], buf[2],
			buf[3], buf[4], buf[5], buf[6], buf[7]);
		return -5;
	}
	}

	return addr - buf;
}

#define FREE_ADDR_LIST(hello_option_addr_list)                                 \
	{                                                                      \
		if (hello_option_addr_list) {                                  \
			list_delete_and_null(&hello_option_addr_list);         \
			hello_option_addr_list = 0;                            \
		}                                                              \
	}

int pim_tlv_parse_addr_list(const char *ifname, struct in_addr src_addr,
			    pim_hello_options *hello_options,
			    struct list **hello_option_addr_list,
			    uint16_t option_len, const uint8_t *tlv_curr)
{
	const uint8_t *addr;
	const uint8_t *pastend;

	zassert(hello_option_addr_list);

	/*
	  Scan addr list
	 */
	addr = tlv_curr;
	pastend = tlv_curr + option_len;
	while (addr < pastend) {
		struct prefix tmp;
		int addr_offset;

		/*
		  Parse ucast addr
		 */
		addr_offset = pim_parse_addr_ucast(&tmp, addr, pastend - addr);
		if (addr_offset < 1) {
			char src_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<src?>", src_addr, src_str,
				       sizeof(src_str));
			zlog_warn(
				"%s: pim_parse_addr_ucast() failure: from %s on %s",
				__PRETTY_FUNCTION__, src_str, ifname);
			FREE_ADDR_LIST(*hello_option_addr_list);
			return -1;
		}
		addr += addr_offset;

		/*
		  Debug
		 */
		if (PIM_DEBUG_PIM_TRACE) {
			switch (tmp.family) {
			case AF_INET: {
				char addr_str[INET_ADDRSTRLEN];
				char src_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", tmp.u.prefix4,
					       addr_str, sizeof(addr_str));
				pim_inet4_dump("<src?>", src_addr, src_str,
					       sizeof(src_str));
				zlog_debug(
					"%s: PIM hello TLV option: list_old_size=%d IPv4 address %s from %s on %s",
					__PRETTY_FUNCTION__,
					*hello_option_addr_list
						? ((int)listcount(
							  *hello_option_addr_list))
						: -1,
					addr_str, src_str, ifname);
			} break;
			case AF_INET6:
				break;
			default: {
				char src_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<src?>", src_addr, src_str,
					       sizeof(src_str));
				zlog_debug(
					"%s: PIM hello TLV option: list_old_size=%d UNKNOWN address family from %s on %s",
					__PRETTY_FUNCTION__,
					*hello_option_addr_list
						? ((int)listcount(
							  *hello_option_addr_list))
						: -1,
					src_str, ifname);
			}
			}
		}

		/*
		  Exclude neighbor's primary address if incorrectly included in
		  the secondary address list
		 */
		if (tmp.family == AF_INET) {
			if (tmp.u.prefix4.s_addr == src_addr.s_addr) {
				char src_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<src?>", src_addr, src_str,
					       sizeof(src_str));
				zlog_warn(
					"%s: ignoring primary address in secondary list from %s on %s",
					__PRETTY_FUNCTION__, src_str, ifname);
				continue;
			}
		}

		/*
		  Allocate list if needed
		 */
		if (!*hello_option_addr_list) {
			*hello_option_addr_list = list_new();
			if (!*hello_option_addr_list) {
				zlog_err(
					"%s %s: failure: hello_option_addr_list=list_new()",
					__FILE__, __PRETTY_FUNCTION__);
				return -2;
			}
			(*hello_option_addr_list)->del =
				(void (*)(void *))prefix_free;
		}

		/*
		  Attach addr to list
		 */
		{
			struct prefix *p;
			p = prefix_new();
			if (!p) {
				zlog_err("%s %s: failure: prefix_new()",
					 __FILE__, __PRETTY_FUNCTION__);
				FREE_ADDR_LIST(*hello_option_addr_list);
				return -3;
			}
			prefix_copy(p, &tmp);
			listnode_add(*hello_option_addr_list, p);
		}

	} /* while (addr < pastend) */

	/*
	  Mark hello option
	 */
	PIM_OPTION_SET(*hello_options, PIM_OPTION_MASK_ADDRESS_LIST);

	return 0;
}
