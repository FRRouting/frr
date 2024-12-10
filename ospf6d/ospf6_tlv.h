// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 Type Length Value.
 *
 */

#ifndef OSPF6_TLV_H
#define OSPF6_TLV_H

/*
 * Generic TLV (type, length, value) macros
 */
struct tlv_header {
	uint16_t type;	 /* Type of Value */
	uint16_t length; /* Length of Value portion only, in bytes */
};

#ifdef roundup
#define ROUNDUP(val, gran) roundup(val, gran)
#else /* roundup */
#define ROUNDUP(val, gran) (((val)-1 | (gran)-1) + 1)
#endif /* roundup */

#define TLV_HDR_SIZE (sizeof(struct tlv_header))

#define TLV_BODY_SIZE(tlvh) (ROUNDUP(ntohs((tlvh)->length), sizeof(uint32_t)))

#define TLV_SIZE(tlvh) ((uint32_t)(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh)))

#define TLV_HDR_NEXT(tlvh)                                                     \
	((struct tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh)))

/*
 * RFC 5187 - OSPFv3 Graceful Restart - Grace-LSA
 * Graceful restart predates Extended-LSA TLVs and IANA TLV register.
 */
/* Grace period TLV. */
#define TLV_GRACE_PERIOD_TYPE 1
#define TLV_GRACE_PERIOD_LENGTH 4
struct tlv_grace_period {
	struct tlv_header header;
	uint32_t interval;
};

/* Restart reason TLV. */
#define TLV_GRACE_RESTART_REASON_TYPE 2
#define TLV_GRACE_RESTART_REASON_LENGTH 1
struct tlv_grace_restart_reason {
	struct tlv_header header;
	uint8_t reason;
	uint8_t reserved[3];
};


#endif /* OSPF6_TLV_H */
