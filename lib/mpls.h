// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MPLS definitions
 * Copyright 2015 Cumulus Networks, Inc.
 */

#ifndef _QUAGGA_MPLS_H
#define _QUAGGA_MPLS_H

#include <zebra.h>
#include <vxlan.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MPLS_LABEL_MAX
#undef MPLS_LABEL_MAX
#endif

#define MPLS_LABEL_HELPSTR                                                     \
	"Specify label(s) for this route\nOne or more "                        \
	"labels in the range (16-1048575) separated by '/'\n"

/* Well-known MPLS label values (RFC 3032 etc). */
#define MPLS_LABEL_IPV4_EXPLICIT_NULL  0       /* [RFC3032] */
#define MPLS_LABEL_ROUTER_ALERT        1       /* [RFC3032] */
#define MPLS_LABEL_IPV6_EXPLICIT_NULL  2       /* [RFC3032] */
#define MPLS_LABEL_IMPLICIT_NULL       3       /* [RFC3032] */
#define MPLS_LABEL_ELI                 7       /* [RFC6790] */
#define MPLS_LABEL_GAL                 13      /* [RFC5586] */
#define MPLS_LABEL_OAM_ALERT           14      /* [RFC3429] */
#define MPLS_LABEL_EXTENSION           15      /* [RFC7274] */
#define MPLS_LABEL_MAX                 1048575
#define MPLS_LABEL_VALUE_MASK          0x000FFFFF
#define MPLS_LABEL_NONE                0xFFFFFFFF /* for internal use only */

/* Minimum and maximum label values */
#define MPLS_LABEL_RESERVED_MIN            0
#define MPLS_LABEL_RESERVED_MAX            15
#define MPLS_LABEL_UNRESERVED_MIN          16
#define MPLS_LABEL_UNRESERVED_MAX          1048575
#define MPLS_LABEL_BASE_ANY                0

/* Default min and max SRGB label range */
/* Even if the SRGB allows to manage different Label space between routers,
 * if an operator want to use the same SRGB for all its router, we must fix
 * a common range. However, Cisco start its SRGB at 16000 and Juniper ends
 * its SRGB at 16384 for OSPF. Thus, by fixing the minimum SRGB label to
 * 8000 we could deal with both Cisco and Juniper.
 */
#define MPLS_DEFAULT_MIN_SRGB_LABEL        8000
#define MPLS_DEFAULT_MAX_SRGB_LABEL        50000
#define MPLS_DEFAULT_MIN_SRGB_SIZE         5000
#define MPLS_DEFAULT_MAX_SRGB_SIZE         20000

/* Maximum # labels that can be pushed. */
#define MPLS_MAX_LABELS                    16

#define IS_MPLS_RESERVED_LABEL(label) (label <= MPLS_LABEL_RESERVED_MAX)

#define IS_MPLS_UNRESERVED_LABEL(label)                                        \
	(label >= MPLS_LABEL_UNRESERVED_MIN                                    \
	 && label <= MPLS_LABEL_UNRESERVED_MAX)

/* Definitions for a MPLS label stack entry (RFC 3032). This encodes the
 * label, EXP, BOS and TTL fields.
 */
typedef unsigned int mpls_lse_t;

#define MPLS_LS_LABEL_MASK             0xFFFFF000
#define MPLS_LS_LABEL_SHIFT            12
#define MPLS_LS_EXP_MASK               0x00000E00
#define MPLS_LS_EXP_SHIFT              9
#define MPLS_LS_S_MASK                 0x00000100
#define MPLS_LS_S_SHIFT                8
#define MPLS_LS_TTL_MASK               0x000000FF
#define MPLS_LS_TTL_SHIFT              0

#define MPLS_LABEL_VALUE(lse)                                                  \
	((lse & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT)
#define MPLS_LABEL_EXP(lse) ((lse & MPLS_LS_EXP_MASK) >> MPLS_LS_EXP_SHIFT)
#define MPLS_LABEL_BOS(lse) ((lse & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT)
#define MPLS_LABEL_TTL(lse) ((lse & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT)

#define IS_MPLS_LABEL_BOS(ls)          (MPLS_LABEL_BOS(ls) == 1)

#define MPLS_LABEL_LEN_BITS            20

/* MPLS label value as a 32-bit (mostly we only care about the label value). */
typedef unsigned int mpls_label_t;

struct mpls_label_stack {
	uint8_t num_labels;
	uint8_t reserved[3];
	mpls_label_t label[0]; /* 1 or more labels */
};

/* The MPLS explicit-null label is 0 which means when you memset a mpls_label_t
 * to zero you have set that variable to explicit-null which was probably not
 * your intent. The work-around is to use one bit to indicate if the
 * mpls_label_t has been set by the user. MPLS_INVALID_LABEL has this bit clear
 * so that we can use MPLS_INVALID_LABEL to initialize mpls_label_t variables.
 */
#define MPLS_INVALID_LABEL                 0xFFFDFFFF

/* LSP types. */
enum lsp_types_t {
	ZEBRA_LSP_NONE = 0,   /* No LSP. */
	ZEBRA_LSP_STATIC = 1, /* Static LSP. */
	ZEBRA_LSP_LDP = 2,    /* LDP LSP. */
	ZEBRA_LSP_BGP = 3,    /* BGP LSP. */
	ZEBRA_LSP_OSPF_SR = 4,/* OSPF Segment Routing LSP. */
	ZEBRA_LSP_ISIS_SR = 5,/* IS-IS Segment Routing LSP. */
	ZEBRA_LSP_SHARP = 6,  /* Identifier for test protocol */
	ZEBRA_LSP_SRTE = 7,   /* SR-TE LSP */
	ZEBRA_LSP_EVPN = 8,  /* EVPN VNI Label */
};

/* Functions for basic label operations. */

static inline void vni2label(vni_t vni, mpls_label_t *label)
{
	uint8_t *tag = (uint8_t *)label;

	assert(tag);

	tag[0] = (vni >> 16) & 0xFF;
	tag[1] = (vni >> 8) & 0xFF;
	tag[2] = vni & 0xFF;
}

static inline vni_t label2vni(const mpls_label_t *label)
{
	uint8_t *tag = (uint8_t *)label;
	vni_t vni;

	assert(tag);

	vni = ((uint32_t)*tag++ << 16);
	vni |= (uint32_t)*tag++ << 8;
	vni |= (uint32_t)(*tag & 0xFF);

	return vni;
}

/* Encode a label stack entry from fields; convert to network byte-order as
 * the Netlink interface expects MPLS labels to be in this format.
 */
static inline mpls_lse_t mpls_lse_encode(mpls_label_t label, uint32_t ttl,
					 uint32_t exp, uint32_t bos)
{
	mpls_lse_t lse;
	lse = htonl((label << MPLS_LS_LABEL_SHIFT) | (exp << MPLS_LS_EXP_SHIFT)
		    | (bos ? (1 << MPLS_LS_S_SHIFT) : 0)
		    | (ttl << MPLS_LS_TTL_SHIFT));
	return lse;
}

/* Extract the fields from a label stack entry after converting to host-byte
 * order. This is expected to be called only for messages received over the
 * Netlink interface.
 */
static inline void mpls_lse_decode(mpls_lse_t lse, mpls_label_t *label,
				   uint32_t *ttl, uint32_t *exp, uint32_t *bos)
{
	mpls_lse_t local_lse;

	local_lse = ntohl(lse);
	*label = MPLS_LABEL_VALUE(local_lse);
	*exp = MPLS_LABEL_EXP(local_lse);
	*bos = MPLS_LABEL_BOS(local_lse);
	*ttl = MPLS_LABEL_TTL(local_lse);
}

/* Invalid label index value (when used with BGP Prefix-SID). Should
 * match the BGP definition.
 */
#define MPLS_INVALID_LABEL_INDEX   0xFFFFFFFF

/* Printable string for labels (with consideration for reserved values). */
static inline char *label2str(mpls_label_t label, enum lsp_types_t type,
			      char *buf, size_t len)
{
	if (type == ZEBRA_LSP_EVPN) {
		snprintf(buf, len, "%u", label2vni(&label));
		return (buf);
	}

	switch (label) {
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
		strlcpy(buf, "IPv4 Explicit Null", len);
		return (buf);
	case MPLS_LABEL_ROUTER_ALERT:
		strlcpy(buf, "Router Alert", len);
		return (buf);
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		strlcpy(buf, "IPv6 Explicit Null", len);
		return (buf);
	case MPLS_LABEL_IMPLICIT_NULL:
		strlcpy(buf, "implicit-null", len);
		return (buf);
	case MPLS_LABEL_ELI:
		strlcpy(buf, "Entropy Label Indicator", len);
		return (buf);
	case MPLS_LABEL_GAL:
		strlcpy(buf, "Generic Associated Channel", len);
		return (buf);
	case MPLS_LABEL_OAM_ALERT:
		strlcpy(buf, "OAM Alert", len);
		return (buf);
	case MPLS_LABEL_EXTENSION:
		strlcpy(buf, "Extension", len);
		return (buf);
	default:
		if (label < 16)
			snprintf(buf, len, "Reserved (%u)", label);
		else
			snprintf(buf, len, "%u", label);
		return buf;
	}
}

/*
 * String to label conversion, labels separated by '/'.
 */
int mpls_str2label(const char *label_str, uint8_t *num_labels,
		   mpls_label_t *labels);

/* Generic string buffer for label-stack-to-str */
#define MPLS_LABEL_STRLEN 1024

/*
 * Label to string conversion, labels in string separated by '/'.
 */
char *mpls_label2str(uint8_t num_labels, const mpls_label_t *labels, char *buf,
		     int len, enum lsp_types_t type, int pretty);

#ifdef __cplusplus
}
#endif

#endif
