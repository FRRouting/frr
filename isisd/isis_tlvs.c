/*
 * IS-IS TLV Serializer/Deserializer
 *
 * Copyright (C) 2015,2017 Christian Franke
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include "md5.h"
#include "memory.h"
#include "stream.h"
#include "sbuf.h"

#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_common.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_te.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_TLV, "ISIS TLVs")
DEFINE_MTYPE_STATIC(ISISD, ISIS_SUBTLV, "ISIS Sub-TLVs")
DEFINE_MTYPE_STATIC(ISISD, ISIS_MT_ITEM_LIST, "ISIS MT Item Lists")

typedef int (*unpack_tlv_func)(enum isis_tlv_context context, uint8_t tlv_type,
			       uint8_t tlv_len, struct stream *s,
			       struct sbuf *log, void *dest, int indent);
typedef int (*pack_item_func)(struct isis_item *item, struct stream *s);
typedef void (*free_item_func)(struct isis_item *i);
typedef int (*unpack_item_func)(uint16_t mtid, uint8_t len, struct stream *s,
				struct sbuf *log, void *dest, int indent);
typedef void (*format_item_func)(uint16_t mtid, struct isis_item *i,
				 struct sbuf *buf, int indent);
typedef struct isis_item *(*copy_item_func)(struct isis_item *i);

struct tlv_ops {
	const char *name;
	unpack_tlv_func unpack;

	pack_item_func pack_item;
	free_item_func free_item;
	unpack_item_func unpack_item;
	format_item_func format_item;
	copy_item_func copy_item;
};

enum how_to_pack {
	ISIS_ITEMS,
	ISIS_MT_ITEMS,
};

struct pack_order_entry {
	enum isis_tlv_context context;
	enum isis_tlv_type type;
	enum how_to_pack how_to_pack;
	size_t what_to_pack;
};
#define PACK_ENTRY(t, h, w)                                                    \
	{                                                                      \
		.context = ISIS_CONTEXT_LSP, .type = ISIS_TLV_##t,             \
		.how_to_pack = (h),                                            \
		.what_to_pack = offsetof(struct isis_tlvs, w),                 \
	}

static struct pack_order_entry pack_order[] = {
	PACK_ENTRY(OLDSTYLE_REACH, ISIS_ITEMS, oldstyle_reach),
	PACK_ENTRY(LAN_NEIGHBORS, ISIS_ITEMS, lan_neighbor),
	PACK_ENTRY(LSP_ENTRY, ISIS_ITEMS, lsp_entries),
	PACK_ENTRY(EXTENDED_REACH, ISIS_ITEMS, extended_reach),
	PACK_ENTRY(MT_REACH, ISIS_MT_ITEMS, mt_reach),
	PACK_ENTRY(OLDSTYLE_IP_REACH, ISIS_ITEMS, oldstyle_ip_reach),
	PACK_ENTRY(OLDSTYLE_IP_REACH_EXT, ISIS_ITEMS, oldstyle_ip_reach_ext),
	PACK_ENTRY(IPV4_ADDRESS, ISIS_ITEMS, ipv4_address),
	PACK_ENTRY(IPV6_ADDRESS, ISIS_ITEMS, ipv6_address),
	PACK_ENTRY(EXTENDED_IP_REACH, ISIS_ITEMS, extended_ip_reach),
	PACK_ENTRY(MT_IP_REACH, ISIS_MT_ITEMS, mt_ip_reach),
	PACK_ENTRY(IPV6_REACH, ISIS_ITEMS, ipv6_reach),
	PACK_ENTRY(MT_IPV6_REACH, ISIS_MT_ITEMS, mt_ipv6_reach)};

/* This is a forward definition. The table is actually initialized
 * in at the bottom. */
static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX];

/* End of _ops forward definition. */

/* Prototypes */
static void append_item(struct isis_item_list *dest, struct isis_item *item);

/* Functions for Sub-TVL ??? IPv6 Source Prefix */

static struct prefix_ipv6 *copy_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p)
{
	if (!p)
		return NULL;

	struct prefix_ipv6 *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));
	rv->family = p->family;
	rv->prefixlen = p->prefixlen;
	memcpy(&rv->prefix, &p->prefix, sizeof(rv->prefix));
	return rv;
}

static void format_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p,
					     struct sbuf *buf, int indent)
{
	if (!p)
		return;

	char prefixbuf[PREFIX2STR_BUFFER];
	sbuf_push(buf, indent, "IPv6 Source Prefix: %s\n",
		  prefix2str(p, prefixbuf, sizeof(prefixbuf)));
}

static int pack_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p,
					  struct stream *s)
{
	if (!p)
		return 0;

	if (STREAM_WRITEABLE(s) < 3 + (unsigned)PSIZE(p->prefixlen))
		return 1;

	stream_putc(s, ISIS_SUBTLV_IPV6_SOURCE_PREFIX);
	stream_putc(s, 1 + PSIZE(p->prefixlen));
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->prefix, PSIZE(p->prefixlen));
	return 0;
}

static int unpack_subtlv_ipv6_source_prefix(enum isis_tlv_context context,
					    uint8_t tlv_type, uint8_t tlv_len,
					    struct stream *s, struct sbuf *log,
					    void *dest, int indent)
{
	struct isis_subtlvs *subtlvs = dest;
	struct prefix_ipv6 p = {
		.family = AF_INET6,
	};

	sbuf_push(log, indent, "Unpacking IPv6 Source Prefix Sub-TLV...\n");

	if (tlv_len < 1) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 1 or more bytes, got %" PRIu8 ")\n",
			  tlv_len);
		return 1;
	}

	p.prefixlen = stream_getc(s);
	if (p.prefixlen > 128) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv6\n",
			  p.prefixlen);
		return 1;
	}

	if (tlv_len != 1 + PSIZE(p.prefixlen)) {
		sbuf_push(
			log, indent,
			"TLV size differs from expected size for the prefixlen. "
			"(expected %u but got %" PRIu8 ")\n",
			1 + PSIZE(p.prefixlen), tlv_len);
		return 1;
	}

	stream_get(&p.prefix, s, PSIZE(p.prefixlen));

	if (subtlvs->source_prefix) {
		sbuf_push(
			log, indent,
			"WARNING: source prefix Sub-TLV present multiple times.\n");
		/* Ignore all but first occurrence of the source prefix Sub-TLV
		 */
		return 0;
	}

	subtlvs->source_prefix = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(p));
	memcpy(subtlvs->source_prefix, &p, sizeof(p));
	return 0;
}

/* Functions related to subtlvs */

static struct isis_subtlvs *isis_alloc_subtlvs(void)
{
	struct isis_subtlvs *result;

	result = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*result));

	return result;
}

static struct isis_subtlvs *copy_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return NULL;

	struct isis_subtlvs *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));

	rv->source_prefix =
		copy_subtlv_ipv6_source_prefix(subtlvs->source_prefix);
	return rv;
}

static void format_subtlvs(struct isis_subtlvs *subtlvs, struct sbuf *buf,
			   int indent)
{
	format_subtlv_ipv6_source_prefix(subtlvs->source_prefix, buf, indent);
}

static void isis_free_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return;

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs->source_prefix);

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs);
}

static int pack_subtlvs(struct isis_subtlvs *subtlvs, struct stream *s)
{
	int rv;
	size_t subtlv_len_pos = stream_get_endp(s);

	if (STREAM_WRITEABLE(s) < 1)
		return 1;

	stream_putc(s, 0); /* Put 0 as subtlvs length, filled in later */

	rv = pack_subtlv_ipv6_source_prefix(subtlvs->source_prefix, s);
	if (rv)
		return rv;

	size_t subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
	if (subtlv_len > 255)
		return 1;

	stream_putc_at(s, subtlv_len_pos, subtlv_len);
	return 0;
}

static int unpack_tlvs(enum isis_tlv_context context, size_t avail_len,
		       struct stream *stream, struct sbuf *log, void *dest,
		       int indent);

/* Functions related to TLVs 1 Area Addresses */

static struct isis_item *copy_item_area_address(struct isis_item *i)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;
	struct isis_area_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->len = addr->len;
	memcpy(rv->addr, addr->addr, addr->len);
	return (struct isis_item *)rv;
}

static void format_item_area_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, int indent)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;

	sbuf_push(buf, indent, "Area Address: %s\n",
		  isonet_print(addr->addr, addr->len));
}

static void free_item_area_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_area_address(struct isis_item *i, struct stream *s)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;

	if (STREAM_WRITEABLE(s) < (unsigned)1 + addr->len)
		return 1;
	stream_putc(s, addr->len);
	stream_put(s, addr->addr, addr->len);
	return 0;
}

static int unpack_item_area_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_area_address *rv = NULL;

	sbuf_push(log, indent, "Unpack area address...\n");
	if (len < 1) {
		sbuf_push(
			log, indent,
			"Not enough data left. (Expected 1 byte of address length, got %" PRIu8
			")\n",
			len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->len = stream_getc(s);

	if (len < 1 + rv->len) {
		sbuf_push(log, indent, "Not enough data left. (Expected %" PRIu8
				       " bytes of address, got %" PRIu8 ")\n",
			  rv->len, len - 1);
		goto out;
	}

	if (rv->len < 1 || rv->len > 20) {
		sbuf_push(log, indent,
			  "Implausible area address length %" PRIu8 "\n",
			  rv->len);
		goto out;
	}

	stream_get(rv->addr, s, rv->len);

	format_item_area_address(ISIS_MT_IPV4_UNICAST, (struct isis_item *)rv,
				 log, indent + 2);
	append_item(&tlvs->area_addresses, (struct isis_item *)rv);
	return 0;
out:
	XFREE(MTYPE_ISIS_TLV, rv);
	return 1;
}

/* Functions related to TLV 2 (Old-Style) IS Reach */
static struct isis_item *copy_item_oldstyle_reach(struct isis_item *i)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;
	struct isis_oldstyle_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->id, r->id, 7);
	rv->metric = r->metric;
	return (struct isis_item *)rv;
}

static void format_item_oldstyle_reach(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf, int indent)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;

	sbuf_push(buf, indent, "IS Reachability: %s (Metric: %" PRIu8 ")\n",
		  isis_format_id(r->id, 7), r->metric);
}

static void free_item_oldstyle_reach(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_oldstyle_reach(struct isis_item *i, struct stream *s)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;

	if (STREAM_WRITEABLE(s) < 11)
		return 1;

	stream_putc(s, r->metric);
	stream_putc(s, 0x80); /* delay metric - unsupported */
	stream_putc(s, 0x80); /* expense metric - unsupported */
	stream_putc(s, 0x80); /* error metric - unsupported */
	stream_put(s, r->id, 7);

	return 0;
}

static int unpack_item_oldstyle_reach(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack oldstyle reach...\n");
	if (len < 11) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 11 bytes of reach information, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_oldstyle_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->metric = stream_getc(s);
	if ((rv->metric & 0x3f) != rv->metric) {
		sbuf_push(log, indent, "Metric has unplausible format\n");
		rv->metric &= 0x3f;
	}
	stream_forward_getp(s, 3); /* Skip other metrics */
	stream_get(rv->id, s, 7);

	format_item_oldstyle_reach(mtid, (struct isis_item *)rv, log,
				   indent + 2);
	append_item(&tlvs->oldstyle_reach, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 6 LAN Neighbors */
static struct isis_item *copy_item_lan_neighbor(struct isis_item *i)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;
	struct isis_lan_neighbor *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->mac, n->mac, 6);
	return (struct isis_item *)rv;
}

static void format_item_lan_neighbor(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, int indent)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;

	sbuf_push(buf, indent, "LAN Neighbor: %s\n", isis_format_id(n->mac, 6));
}

static void free_item_lan_neighbor(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_lan_neighbor(struct isis_item *i, struct stream *s)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;

	if (STREAM_WRITEABLE(s) < 6)
		return 1;

	stream_put(s, n->mac, 6);

	return 0;
}

static int unpack_item_lan_neighbor(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack LAN neighbor...\n");
	if (len < 6) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 6 bytes of mac, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_lan_neighbor *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(rv->mac, s, 6);

	format_item_lan_neighbor(mtid, (struct isis_item *)rv, log, indent + 2);
	append_item(&tlvs->lan_neighbor, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 9 LSP Entry */
static struct isis_item *copy_item_lsp_entry(struct isis_item *i)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;
	struct isis_lsp_entry *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->rem_lifetime = e->rem_lifetime;
	memcpy(rv->id, e->id, sizeof(rv->id));
	rv->seqno = e->seqno;
	rv->checksum = e->checksum;

	return (struct isis_item *)rv;
}

static void format_item_lsp_entry(uint16_t mtid, struct isis_item *i,
				  struct sbuf *buf, int indent)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;

	sbuf_push(buf, indent, "LSP Entry: %s, seq 0x%08" PRIx32
		  ", cksum 0x%04" PRIx16 ", lifetime %" PRIu16 "s\n",
		  isis_format_id(e->id, 8), e->seqno, e->checksum,
		  e->rem_lifetime);
}

static void free_item_lsp_entry(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_lsp_entry(struct isis_item *i, struct stream *s)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;

	if (STREAM_WRITEABLE(s) < 16)
		return 1;

	stream_putw(s, e->rem_lifetime);
	stream_put(s, e->id, 8);
	stream_putl(s, e->seqno);
	stream_putw(s, e->checksum);

	return 0;
}

static int unpack_item_lsp_entry(uint16_t mtid, uint8_t len, struct stream *s,
				 struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack LSP entry...\n");
	if (len < 16) {
		sbuf_push(
			log, indent,
			"Not enough data left. (Expected 16 bytes of LSP info, got %" PRIu8,
			len);
		return 1;
	}

	struct isis_lsp_entry *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->rem_lifetime = stream_getw(s);
	stream_get(rv->id, s, 8);
	rv->seqno = stream_getl(s);
	rv->checksum = stream_getw(s);

	format_item_lsp_entry(mtid, (struct isis_item *)rv, log, indent + 2);
	append_item(&tlvs->lsp_entries, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLVs 22/222 Extended Reach/MT Reach */

static struct isis_item *copy_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;
	struct isis_extended_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->id, r->id, 7);
	rv->metric = r->metric;

	if (r->subtlvs && r->subtlv_len) {
		rv->subtlvs = XCALLOC(MTYPE_ISIS_TLV, r->subtlv_len);
		memcpy(rv->subtlvs, r->subtlvs, r->subtlv_len);
		rv->subtlv_len = r->subtlv_len;
	}

	return (struct isis_item *)rv;
}

static void format_item_extended_reach(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf, int indent)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;

	sbuf_push(buf, indent, "%s Reachability: %s (Metric: %u)",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT",
		  isis_format_id(r->id, 7), r->metric);
	if (mtid != ISIS_MT_IPV4_UNICAST)
		sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
	sbuf_push(buf, 0, "\n");

	if (r->subtlv_len && r->subtlvs)
		mpls_te_print_detail(buf, indent + 2, r->subtlvs, r->subtlv_len);
}

static void free_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *item = (struct isis_extended_reach *)i;
	XFREE(MTYPE_ISIS_TLV, item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_extended_reach(struct isis_item *i, struct stream *s)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;

	if (STREAM_WRITEABLE(s) < 11 + (unsigned)r->subtlv_len)
		return 1;
	stream_put(s, r->id, sizeof(r->id));
	stream_put3(s, r->metric);
	stream_putc(s, r->subtlv_len);
	stream_put(s, r->subtlvs, r->subtlv_len);
	return 0;
}

static int unpack_item_extended_reach(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_reach *rv = NULL;
	uint8_t subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->extended_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %s reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "extended" : "mt");

	if (len < 11) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 11 or more bytes, got %"
			  PRIu8 ")\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(rv->id, s, 7);
	rv->metric = stream_get3(s);
	subtlv_len = stream_getc(s);

	format_item_extended_reach(mtid, (struct isis_item *)rv, log,
				   indent + 2);

	if ((size_t)len < ((size_t)11) + subtlv_len) {
		sbuf_push(log, indent,
			  "Not enough data left for subtlv size %" PRIu8
			  ", there are only %" PRIu8 " bytes left.\n",
			  subtlv_len, len - 11);
		goto out;
	}

	sbuf_push(log, indent, "Storing %" PRIu8 " bytes of subtlvs\n",
		  subtlv_len);

	if (subtlv_len) {
		size_t subtlv_start = stream_get_getp(s);

		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_NE_REACH, subtlv_len, s,
				log, NULL, indent + 4)) {
			goto out;
		}

		stream_set_getp(s, subtlv_start);

		rv->subtlvs = XCALLOC(MTYPE_ISIS_TLV, subtlv_len);
		stream_get(rv->subtlvs, s, subtlv_len);
		rv->subtlv_len = subtlv_len;
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_extended_reach((struct isis_item *)rv);

	return 1;
}

/* Functions related to TLV 128 (Old-Style) IP Reach */
static struct isis_item *copy_item_oldstyle_ip_reach(struct isis_item *i)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;
	struct isis_oldstyle_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = r->metric;
	rv->prefix = r->prefix;
	return (struct isis_item *)rv;
}

static void format_item_oldstyle_ip_reach(uint16_t mtid, struct isis_item *i,
					  struct sbuf *buf, int indent)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	sbuf_push(buf, indent, "IP Reachability: %s (Metric: %" PRIu8 ")\n",
		  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)), r->metric);
}

static void free_item_oldstyle_ip_reach(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_oldstyle_ip_reach(struct isis_item *i, struct stream *s)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;

	if (STREAM_WRITEABLE(s) < 12)
		return 1;

	stream_putc(s, r->metric);
	stream_putc(s, 0x80); /* delay metric - unsupported */
	stream_putc(s, 0x80); /* expense metric - unsupported */
	stream_putc(s, 0x80); /* error metric - unsupported */
	stream_put(s, &r->prefix.prefix, 4);

	struct in_addr mask;
	masklen2ip(r->prefix.prefixlen, &mask);
	stream_put(s, &mask, sizeof(mask));

	return 0;
}

static int unpack_item_oldstyle_ip_reach(uint16_t mtid, uint8_t len,
					 struct stream *s, struct sbuf *log,
					 void *dest, int indent)
{
	sbuf_push(log, indent, "Unpack oldstyle ip reach...\n");
	if (len < 12) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 12 bytes of reach information, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_oldstyle_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->metric = stream_getc(s);
	if ((rv->metric & 0x7f) != rv->metric) {
		sbuf_push(log, indent, "Metric has unplausible format\n");
		rv->metric &= 0x7f;
	}
	stream_forward_getp(s, 3); /* Skip other metrics */
	rv->prefix.family = AF_INET;
	stream_get(&rv->prefix.prefix, s, 4);

	struct in_addr mask;
	stream_get(&mask, s, 4);
	rv->prefix.prefixlen = ip_masklen(mask);

	format_item_oldstyle_ip_reach(mtid, (struct isis_item *)rv, log,
				      indent + 2);
	append_item(dest, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 129 protocols supported */

static void copy_tlv_protocols_supported(struct isis_protocols_supported *src,
					 struct isis_protocols_supported *dest)
{
	if (!src->protocols || !src->count)
		return;
	dest->count = src->count;
	dest->protocols = XCALLOC(MTYPE_ISIS_TLV, src->count);
	memcpy(dest->protocols, src->protocols, src->count);
}

static void format_tlv_protocols_supported(struct isis_protocols_supported *p,
					   struct sbuf *buf, int indent)
{
	if (!p || !p->count || !p->protocols)
		return;

	sbuf_push(buf, indent, "Protocols Supported: ");
	for (uint8_t i = 0; i < p->count; i++) {
		sbuf_push(buf, 0, "%s%s", nlpid2str(p->protocols[i]),
			  (i + 1 < p->count) ? ", " : "");
	}
	sbuf_push(buf, 0, "\n");
}

static void free_tlv_protocols_supported(struct isis_protocols_supported *p)
{
	XFREE(MTYPE_ISIS_TLV, p->protocols);
}

static int pack_tlv_protocols_supported(struct isis_protocols_supported *p,
					struct stream *s)
{
	if (!p || !p->count || !p->protocols)
		return 0;

	if (STREAM_WRITEABLE(s) < (unsigned)(p->count + 2))
		return 1;

	stream_putc(s, ISIS_TLV_PROTOCOLS_SUPPORTED);
	stream_putc(s, p->count);
	stream_put(s, p->protocols, p->count);
	return 0;
}

static int unpack_tlv_protocols_supported(enum isis_tlv_context context,
					  uint8_t tlv_type, uint8_t tlv_len,
					  struct stream *s, struct sbuf *log,
					  void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking Protocols Supported TLV...\n");
	if (!tlv_len) {
		sbuf_push(log, indent, "WARNING: No protocols included\n");
		return 0;
	}
	if (tlvs->protocols_supported.protocols) {
		sbuf_push(
			log, indent,
			"WARNING: protocols supported TLV present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->protocols_supported.count = tlv_len;
	tlvs->protocols_supported.protocols = XCALLOC(MTYPE_ISIS_TLV, tlv_len);
	stream_get(tlvs->protocols_supported.protocols, s, tlv_len);

	format_tlv_protocols_supported(&tlvs->protocols_supported, log,
				       indent + 2);
	return 0;
}

/* Functions related to TLV 132 IPv4 Interface addresses */
static struct isis_item *copy_item_ipv4_address(struct isis_item *i)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;
	struct isis_ipv4_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->addr = a->addr;
	return (struct isis_item *)rv;
}

static void format_item_ipv4_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, int indent)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;
	char addrbuf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &a->addr, addrbuf, sizeof(addrbuf));
	sbuf_push(buf, indent, "IPv4 Interface Address: %s\n", addrbuf);
}

static void free_item_ipv4_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_ipv4_address(struct isis_item *i, struct stream *s)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;

	if (STREAM_WRITEABLE(s) < 4)
		return 1;

	stream_put(s, &a->addr, 4);

	return 0;
}

static int unpack_item_ipv4_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack IPv4 Interface address...\n");
	if (len < 4) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 4 bytes of IPv4 address, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_ipv4_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(&rv->addr, s, 4);

	format_item_ipv4_address(mtid, (struct isis_item *)rv, log, indent + 2);
	append_item(&tlvs->ipv4_address, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 232 IPv6 Interface addresses */
static struct isis_item *copy_item_ipv6_address(struct isis_item *i)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->addr = a->addr;
	return (struct isis_item *)rv;
}

static void format_item_ipv6_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, int indent)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	char addrbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &a->addr, addrbuf, sizeof(addrbuf));
	sbuf_push(buf, indent, "IPv6 Interface Address: %s\n", addrbuf);
}

static void free_item_ipv6_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_ipv6_address(struct isis_item *i, struct stream *s)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;

	if (STREAM_WRITEABLE(s) < 16)
		return 1;

	stream_put(s, &a->addr, 16);

	return 0;
}

static int unpack_item_ipv6_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack IPv6 Interface address...\n");
	if (len < 16) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 16 bytes of IPv6 address, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(&rv->addr, s, 16);

	format_item_ipv6_address(mtid, (struct isis_item *)rv, log, indent + 2);
	append_item(&tlvs->ipv6_address, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 229 MT Router information */
static struct isis_item *copy_item_mt_router_info(struct isis_item *i)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;
	struct isis_mt_router_info *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->overload = info->overload;
	rv->attached = info->attached;
	rv->mtid = info->mtid;
	return (struct isis_item *)rv;
}

static void format_item_mt_router_info(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf, int indent)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;

	sbuf_push(buf, indent, "MT Router Info: %s%s%s\n",
		  isis_mtid2str(info->mtid),
		  info->overload ? " Overload" : "",
		  info->attached ? " Attached" : "");
}

static void free_item_mt_router_info(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_mt_router_info(struct isis_item *i, struct stream *s)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;

	if (STREAM_WRITEABLE(s) < 2)
		return 1;

	uint16_t entry = info->mtid;

	if (info->overload)
		entry |= ISIS_MT_OL_MASK;
	if (info->attached)
		entry |= ISIS_MT_AT_MASK;

	stream_putw(s, entry);

	return 0;
}

static int unpack_item_mt_router_info(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack MT Router info...\n");
	if (len < 2) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 2 bytes of MT info, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_mt_router_info *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	uint16_t entry = stream_getw(s);
	rv->overload = entry & ISIS_MT_OL_MASK;
	rv->attached = entry & ISIS_MT_AT_MASK;
	rv->mtid = entry & ISIS_MT_MASK;

	format_item_mt_router_info(mtid, (struct isis_item *)rv, log,
				   indent + 2);
	append_item(&tlvs->mt_router_info, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 134 TE Router ID */

static struct in_addr *copy_tlv_te_router_id(const struct in_addr *id)
{
	if (!id)
		return NULL;

	struct in_addr *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	memcpy(rv, id, sizeof(*rv));
	return rv;
}

static void format_tlv_te_router_id(const struct in_addr *id, struct sbuf *buf,
				    int indent)
{
	if (!id)
		return;

	char addrbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, id, addrbuf, sizeof(addrbuf));
	sbuf_push(buf, indent, "TE Router ID: %s\n", addrbuf);
}

static void free_tlv_te_router_id(struct in_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, id);
}

static int pack_tlv_te_router_id(const struct in_addr *id, struct stream *s)
{
	if (!id)
		return 0;

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + sizeof(*id)))
		return 1;

	stream_putc(s, ISIS_TLV_TE_ROUTER_ID);
	stream_putc(s, 4);
	stream_put(s, id, 4);
	return 0;
}

static int unpack_tlv_te_router_id(enum isis_tlv_context context,
				   uint8_t tlv_type, uint8_t tlv_len,
				   struct stream *s, struct sbuf *log,
				   void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking TE Router ID TLV...\n");
	if (tlv_len != 4) {
		sbuf_push(log, indent, "WARNING: Length invalid\n");
		return 1;
	}

	if (tlvs->te_router_id) {
		sbuf_push(log, indent,
			  "WARNING: TE Router ID present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->te_router_id = XCALLOC(MTYPE_ISIS_TLV, 4);
	stream_get(tlvs->te_router_id, s, 4);
	format_tlv_te_router_id(tlvs->te_router_id, log, indent + 2);
	return 0;
}


/* Functions related to TLVs 135/235 extended IP reach/MT IP Reach */

static struct isis_item *copy_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	struct isis_extended_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = r->metric;
	rv->down = r->down;
	rv->prefix = r->prefix;

	return (struct isis_item *)rv;
}

static void format_item_extended_ip_reach(uint16_t mtid, struct isis_item *i,
					  struct sbuf *buf, int indent)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	sbuf_push(buf, indent, "%s IP Reachability: %s (Metric: %u)%s",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT",
		  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)), r->metric,
		  r->down ? " Down" : "");
	if (mtid != ISIS_MT_IPV4_UNICAST)
		sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
	sbuf_push(buf, 0, "\n");
}

static void free_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *item =
		(struct isis_extended_ip_reach *)i;
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_extended_ip_reach(struct isis_item *i, struct stream *s)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 5)
		return 1;
	stream_putl(s, r->metric);

	control = r->down ? ISIS_EXTENDED_IP_REACH_DOWN : 0;
	control |= r->prefix.prefixlen;
	stream_putc(s, control);

	if (STREAM_WRITEABLE(s) < (unsigned)PSIZE(r->prefix.prefixlen))
		return 1;
	stream_put(s, &r->prefix.prefix.s_addr, PSIZE(r->prefix.prefixlen));
	return 0;
}

static int unpack_item_extended_ip_reach(uint16_t mtid, uint8_t len,
					 struct stream *s, struct sbuf *log,
					 void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_ip_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->extended_ip_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_ip_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %s IPv4 reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "extended" : "mt");

	consume = 5;
	if (len < consume) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 5 or more bytes, got %" PRIu8 ")\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_EXTENDED_IP_REACH_DOWN);
	rv->prefix.family = AF_INET;
	rv->prefix.prefixlen = control & 0x3f;
	if (rv->prefix.prefixlen > 32) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv4\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent,
			  "Expected %u bytes of prefix, but only %u bytes available.\n",
			  PSIZE(rv->prefix.prefixlen), len - 5);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s_addr, s, PSIZE(rv->prefix.prefixlen));
	in_addr_t orig_prefix = rv->prefix.prefix.s_addr;
	apply_mask_ipv4(&rv->prefix);
	if (orig_prefix != rv->prefix.prefix.s_addr)
		sbuf_push(log, indent + 2,
			  "WARNING: Prefix had hostbits set.\n");
	format_item_extended_ip_reach(mtid, (struct isis_item *)rv, log,
				      indent + 2);

	if (control & ISIS_EXTENDED_IP_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected 1 byte of subtlv len, but no more data present.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2,
				  "  WARNING: subtlv bit is set, but there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected %" PRIu8
				  " bytes of subtlvs, but only %u bytes available.\n",
				  subtlv_len,
				  len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}
		sbuf_push(log, indent, "Skipping %" PRIu8 " bytes of subvls",
			  subtlv_len);
		stream_forward_getp(s, subtlv_len);
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_extended_ip_reach((struct isis_item *)rv);
	return 1;
}

/* Functions related to TLV 137 Dynamic Hostname */

static char *copy_tlv_dynamic_hostname(const char *hostname)
{
	if (!hostname)
		return NULL;

	return XSTRDUP(MTYPE_ISIS_TLV, hostname);
}

static void format_tlv_dynamic_hostname(const char *hostname, struct sbuf *buf,
					int indent)
{
	if (!hostname)
		return;

	sbuf_push(buf, indent, "Hostname: %s\n", hostname);
}

static void free_tlv_dynamic_hostname(char *hostname)
{
	XFREE(MTYPE_ISIS_TLV, hostname);
}

static int pack_tlv_dynamic_hostname(const char *hostname, struct stream *s)
{
	if (!hostname)
		return 0;

	uint8_t name_len = strlen(hostname);

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + name_len))
		return 1;

	stream_putc(s, ISIS_TLV_DYNAMIC_HOSTNAME);
	stream_putc(s, name_len);
	stream_put(s, hostname, name_len);
	return 0;
}

static int unpack_tlv_dynamic_hostname(enum isis_tlv_context context,
				       uint8_t tlv_type, uint8_t tlv_len,
				       struct stream *s, struct sbuf *log,
				       void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking Dynamic Hostname TLV...\n");
	if (!tlv_len) {
		sbuf_push(log, indent, "WARNING: No hostname included\n");
		return 0;
	}

	if (tlvs->hostname) {
		sbuf_push(log, indent,
			  "WARNING: Hostname present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->hostname = XCALLOC(MTYPE_ISIS_TLV, tlv_len + 1);
	stream_get(tlvs->hostname, s, tlv_len);
	tlvs->hostname[tlv_len] = '\0';

	bool sane = true;
	for (uint8_t i = 0; i < tlv_len; i++) {
		if ((unsigned char)tlvs->hostname[i] > 127
		    || !isprint((int)tlvs->hostname[i])) {
			sane = false;
			tlvs->hostname[i] = '?';
		}
	}
	if (!sane) {
		sbuf_push(
			log, indent,
			"WARNING: Hostname contained non-printable/non-ascii characters.\n");
	}

	return 0;
}

/* Functions related to TLVs 236/237 IPv6/MT-IPv6 reach */

static struct isis_item *copy_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	struct isis_ipv6_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->metric = r->metric;
	rv->down = r->down;
	rv->external = r->external;
	rv->prefix = r->prefix;
	rv->subtlvs = copy_subtlvs(r->subtlvs);

	return (struct isis_item *)rv;
}

static void format_item_ipv6_reach(uint16_t mtid, struct isis_item *i,
				   struct sbuf *buf, int indent)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	sbuf_push(buf, indent, "%sIPv6 Reachability: %s (Metric: %u)%s%s",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "" : "MT ",
		  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)),
		  r->metric,
		  r->down ? " Down" : "",
		  r->external ? " External" : "");
	if (mtid != ISIS_MT_IPV4_UNICAST)
		sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
	sbuf_push(buf, 0, "\n");

	if (r->subtlvs) {
		sbuf_push(buf, indent, "  Subtlvs:\n");
		format_subtlvs(r->subtlvs, buf, indent + 4);
	}
}

static void free_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *item = (struct isis_ipv6_reach *)i;

	isis_free_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_ipv6_reach(struct isis_item *i, struct stream *s)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 6)
		return 1;
	stream_putl(s, r->metric);

	control = r->down ? ISIS_IPV6_REACH_DOWN : 0;
	control |= r->external ? ISIS_IPV6_REACH_EXTERNAL : 0;
	control |= r->subtlvs ? ISIS_IPV6_REACH_SUBTLV : 0;

	stream_putc(s, control);
	stream_putc(s, r->prefix.prefixlen);

	if (STREAM_WRITEABLE(s) < (unsigned)PSIZE(r->prefix.prefixlen))
		return 1;
	stream_put(s, &r->prefix.prefix.s6_addr, PSIZE(r->prefix.prefixlen));

	if (r->subtlvs)
		return pack_subtlvs(r->subtlvs, s);

	return 0;
}

static int unpack_item_ipv6_reach(uint16_t mtid, uint8_t len, struct stream *s,
				  struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_ipv6_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->ipv6_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_ipv6_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %sIPv6 reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "" : "mt ");
	consume = 6;
	if (len < consume) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 6 or more bytes, got %"
			  PRIu8 ")\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_IPV6_REACH_DOWN);
	rv->external = (control & ISIS_IPV6_REACH_EXTERNAL);

	rv->prefix.family = AF_INET6;
	rv->prefix.prefixlen = stream_getc(s);
	if (rv->prefix.prefixlen > 128) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv6\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent,
			  "Expected %u bytes of prefix, but only %u bytes available.\n",
			  PSIZE(rv->prefix.prefixlen), len - 6);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s6_addr, s, PSIZE(rv->prefix.prefixlen));
	struct in6_addr orig_prefix = rv->prefix.prefix;
	apply_mask_ipv6(&rv->prefix);
	if (memcmp(&orig_prefix, &rv->prefix.prefix, sizeof(orig_prefix)))
		sbuf_push(log, indent + 2,
			  "WARNING: Prefix had hostbits set.\n");
	format_item_ipv6_reach(mtid, (struct isis_item *)rv, log, indent + 2);

	if (control & ISIS_IPV6_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected 1 byte of subtlv len, but no more data persent.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2,
				  "  WARNING: subtlv bit set, but there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected %" PRIu8
				  " bytes of subtlvs, but only %u bytes available.\n",
				  subtlv_len,
				  len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}

		rv->subtlvs = isis_alloc_subtlvs();
		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_IPV6_REACH, subtlv_len, s,
				log, rv->subtlvs, indent + 4)) {
			goto out;
		}
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_ipv6_reach((struct isis_item *)rv);
	return 1;
}

/* Functions related to TLV 10 Authentication */
static struct isis_item *copy_item_auth(struct isis_item *i)
{
	struct isis_auth *auth = (struct isis_auth *)i;
	struct isis_auth *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->type = auth->type;
	rv->length = auth->length;
	memcpy(rv->value, auth->value, sizeof(rv->value));
	return (struct isis_item *)rv;
}

static void format_item_auth(uint16_t mtid, struct isis_item *i,
			     struct sbuf *buf, int indent)
{
	struct isis_auth *auth = (struct isis_auth *)i;
	char obuf[768];

	sbuf_push(buf, indent, "Authentication:\n");
	switch (auth->type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		zlog_sanitize(obuf, sizeof(obuf), auth->value, auth->length);
		sbuf_push(buf, indent, "  Password: %s\n", obuf);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		for (unsigned int i = 0; i < 16; i++) {
			snprintf(obuf + 2 * i, sizeof(obuf) - 2 * i,
				 "%02" PRIx8, auth->value[i]);
		}
		sbuf_push(buf, indent, "  HMAC-MD5: %s\n", obuf);
		break;
	default:
		sbuf_push(buf, indent, "  Unknown (%" PRIu8 ")\n", auth->type);
		break;
	};
}

static void free_item_auth(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_auth(struct isis_item *i, struct stream *s)
{
	struct isis_auth *auth = (struct isis_auth *)i;

	if (STREAM_WRITEABLE(s) < 1)
		return 1;
	stream_putc(s, auth->type);

	switch (auth->type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		if (STREAM_WRITEABLE(s) < auth->length)
			return 1;
		stream_put(s, auth->passwd, auth->length);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		if (STREAM_WRITEABLE(s) < 16)
			return 1;
		auth->offset = stream_get_endp(s);
		stream_put(s, NULL, 16);
		break;
	default:
		return 1;
	}

	return 0;
}

static int unpack_item_auth(uint16_t mtid, uint8_t len, struct stream *s,
			    struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack Auth TLV...\n");
	if (len < 1) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 1 bytes of auth type, got %" PRIu8
			")\n",
			len);
		return 1;
	}

	struct isis_auth *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->type = stream_getc(s);
	rv->length = len - 1;

	if (rv->type == ISIS_PASSWD_TYPE_HMAC_MD5 && rv->length != 16) {
		sbuf_push(
			log, indent,
			"Unexpected auth length for HMAC-MD5 (expected 16, got %" PRIu8
			")\n",
			rv->length);
		XFREE(MTYPE_ISIS_TLV, rv);
		return 1;
	}

	rv->offset = stream_get_getp(s);
	stream_get(rv->value, s, rv->length);
	format_item_auth(mtid, (struct isis_item *)rv, log, indent + 2);
	append_item(&tlvs->isis_auth, (struct isis_item *)rv);
	return 0;
}

/* Functions relating to item TLVs */

static void init_item_list(struct isis_item_list *items)
{
	items->head = NULL;
	items->tail = &items->head;
	items->count = 0;
}

static struct isis_item *copy_item(enum isis_tlv_context context,
				   enum isis_tlv_type type,
				   struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->copy_item)
		return ops->copy_item(item);

	assert(!"Unknown item tlv type!");
	return NULL;
}

static void copy_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *src, struct isis_item_list *dest)
{
	struct isis_item *item;

	init_item_list(dest);

	for (item = src->head; item; item = item->next) {
		append_item(dest, copy_item(context, type, item));
	}
}

static void format_item(uint16_t mtid, enum isis_tlv_context context,
			enum isis_tlv_type type, struct isis_item *i,
			struct sbuf *buf, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->format_item) {
		ops->format_item(mtid, i, buf, indent);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void format_items_(uint16_t mtid, enum isis_tlv_context context,
			  enum isis_tlv_type type, struct isis_item_list *items,
			  struct sbuf *buf, int indent)
{
	struct isis_item *i;

	for (i = items->head; i; i = i->next)
		format_item(mtid, context, type, i, buf, indent);
}
#define format_items(...) format_items_(ISIS_MT_IPV4_UNICAST, __VA_ARGS__)

static void free_item(enum isis_tlv_context tlv_context,
		      enum isis_tlv_type tlv_type, struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[tlv_context][tlv_type];

	if (ops && ops->free_item) {
		ops->free_item(item);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void free_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *items)
{
	struct isis_item *item, *next_item;

	for (item = items->head; item; item = next_item) {
		next_item = item->next;
		free_item(context, type, item);
	}
}

static int pack_item(enum isis_tlv_context context, enum isis_tlv_type type,
		     struct isis_item *i, struct stream *s,
		     struct isis_tlvs **fragment_tlvs,
		     struct pack_order_entry *pe, uint16_t mtid)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->pack_item) {
		return ops->pack_item(i, s);
	}

	assert(!"Unknown item tlv type!");
	return 1;
}

static void add_item_to_fragment(struct isis_item *i, struct pack_order_entry *pe,
				 struct isis_tlvs *fragment_tlvs, uint16_t mtid)
{
	struct isis_item_list *l;

	if (pe->how_to_pack == ISIS_ITEMS) {
		l = (struct isis_item_list *)(((char *)fragment_tlvs) + pe->what_to_pack);
	} else {
		struct isis_mt_item_list *m;
		m = (struct isis_mt_item_list *)(((char *)fragment_tlvs) + pe->what_to_pack);
		l = isis_get_mt_items(m, mtid);
	}

	append_item(l, copy_item(pe->context, pe->type, i));
}

static int pack_items_(uint16_t mtid, enum isis_tlv_context context,
		       enum isis_tlv_type type, struct isis_item_list *items,
		       struct stream *s, struct isis_tlvs **fragment_tlvs,
		       struct pack_order_entry *pe,
		       struct isis_tlvs *(*new_fragment)(struct list *l),
		       struct list *new_fragment_arg)
{
	size_t len_pos, last_len, len;
	struct isis_item *item = NULL;
	int rv;

	if (!items->head)
		return 0;

top:
	if (STREAM_WRITEABLE(s) < 2)
		goto too_long;

	stream_putc(s, type);
	len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* Put 0 as length for now */

	if (context == ISIS_CONTEXT_LSP && IS_COMPAT_MT_TLV(type)
	    && mtid != ISIS_MT_IPV4_UNICAST) {
		if (STREAM_WRITEABLE(s) < 2)
			goto too_long;
		stream_putw(s, mtid);
	}

	if (context == ISIS_CONTEXT_LSP && type == ISIS_TLV_OLDSTYLE_REACH) {
		if (STREAM_WRITEABLE(s) < 1)
			goto too_long;
		stream_putc(s, 0); /* Virtual flag is set to 0 */
	}

	last_len = len = 0;
	for (item = item ? item : items->head; item; item = item->next) {
		rv = pack_item(context, type, item, s, fragment_tlvs, pe, mtid);
		if (rv)
			goto too_long;

		len = stream_get_endp(s) - len_pos - 1;

		/* Multiple auths don't go into one TLV, so always break */
		if (context == ISIS_CONTEXT_LSP && type == ISIS_TLV_AUTH) {
			item = item->next;
			break;
		}

		if (len > 255) {
			if (!last_len) /* strange, not a single item fit */
				return 1;
			/* drop last tlv, otherwise, its too long */
			stream_set_endp(s, len_pos + 1 + last_len);
			len = last_len;
			break;
		}

		if (fragment_tlvs)
			add_item_to_fragment(item, pe, *fragment_tlvs, mtid);

		last_len = len;
	}

	stream_putc_at(s, len_pos, len);
	if (item)
		goto top;

	return 0;
too_long:
	if (!fragment_tlvs)
		return 1;
	stream_reset(s);
	*fragment_tlvs = new_fragment(new_fragment_arg);
	goto top;
}
#define pack_items(...) pack_items_(ISIS_MT_IPV4_UNICAST, __VA_ARGS__)

static void append_item(struct isis_item_list *dest, struct isis_item *item)
{
	*dest->tail = item;
	dest->tail = &(*dest->tail)->next;
	dest->count++;
}

static int unpack_item(uint16_t mtid, enum isis_tlv_context context,
		       uint8_t tlv_type, uint8_t len, struct stream *s,
		       struct sbuf *log, void *dest, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][tlv_type];

	if (ops && ops->unpack_item)
		return ops->unpack_item(mtid, len, s, log, dest, indent);

	assert(!"Unknown item tlv type!");
	sbuf_push(log, indent, "Unknown item tlv type!\n");
	return 1;
}

static int unpack_tlv_with_items(enum isis_tlv_context context,
				 uint8_t tlv_type, uint8_t tlv_len,
				 struct stream *s, struct sbuf *log, void *dest,
				 int indent)
{
	size_t tlv_start;
	size_t tlv_pos;
	int rv;
	uint16_t mtid;

	tlv_start = stream_get_getp(s);
	tlv_pos = 0;

	if (context == ISIS_CONTEXT_LSP && IS_COMPAT_MT_TLV(tlv_type)) {
		if (tlv_len < 2) {
			sbuf_push(log, indent,
				  "TLV is too short to contain MTID\n");
			return 1;
		}
		mtid = stream_getw(s) & ISIS_MT_MASK;
		tlv_pos += 2;
		sbuf_push(log, indent, "Unpacking as MT %s item TLV...\n",
			  isis_mtid2str(mtid));
	} else {
		sbuf_push(log, indent, "Unpacking as item TLV...\n");
		mtid = ISIS_MT_IPV4_UNICAST;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_OLDSTYLE_REACH) {
		if (tlv_len - tlv_pos < 1) {
			sbuf_push(log, indent,
				  "TLV is too short for old style reach\n");
			return 1;
		}
		stream_forward_getp(s, 1);
		tlv_pos += 1;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_OLDSTYLE_IP_REACH) {
		struct isis_tlvs *tlvs = dest;
		dest = &tlvs->oldstyle_ip_reach;
	} else if (context == ISIS_CONTEXT_LSP
		   && tlv_type == ISIS_TLV_OLDSTYLE_IP_REACH_EXT) {
		struct isis_tlvs *tlvs = dest;
		dest = &tlvs->oldstyle_ip_reach_ext;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_MT_ROUTER_INFO) {
		struct isis_tlvs *tlvs = dest;
		tlvs->mt_router_info_empty = (tlv_pos >= (size_t)tlv_len);
	}

	while (tlv_pos < (size_t)tlv_len) {
		rv = unpack_item(mtid, context, tlv_type, tlv_len - tlv_pos, s,
				 log, dest, indent + 2);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(s) - tlv_start;
	}

	return 0;
}

/* Functions to manipulate mt_item_lists */

static int isis_mt_item_list_cmp(const struct isis_item_list *a,
				 const struct isis_item_list *b)
{
	if (a->mtid < b->mtid)
		return -1;
	if (a->mtid > b->mtid)
		return 1;
	return 0;
}

RB_PROTOTYPE(isis_mt_item_list, isis_item_list, mt_tree, isis_mt_item_list_cmp);
RB_GENERATE(isis_mt_item_list, isis_item_list, mt_tree, isis_mt_item_list_cmp);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m,
					 uint16_t mtid)
{
	struct isis_item_list *rv;

	rv = isis_lookup_mt_items(m, mtid);
	if (!rv) {
		rv = XCALLOC(MTYPE_ISIS_MT_ITEM_LIST, sizeof(*rv));
		init_item_list(rv);
		rv->mtid = mtid;
		RB_INSERT(isis_mt_item_list, m, rv);
	}

	return rv;
}

struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m,
					    uint16_t mtid)
{
	struct isis_item_list key = {.mtid = mtid};

	return RB_FIND(isis_mt_item_list, m, &key);
}

static void free_mt_items(enum isis_tlv_context context,
			  enum isis_tlv_type type, struct isis_mt_item_list *m)
{
	struct isis_item_list *n, *nnext;

	RB_FOREACH_SAFE (n, isis_mt_item_list, m, nnext) {
		free_items(context, type, n);
		RB_REMOVE(isis_mt_item_list, m, n);
		XFREE(MTYPE_ISIS_MT_ITEM_LIST, n);
	}
}

static void format_mt_items(enum isis_tlv_context context,
			    enum isis_tlv_type type,
			    struct isis_mt_item_list *m, struct sbuf *buf,
			    int indent)
{
	struct isis_item_list *n;

	RB_FOREACH (n, isis_mt_item_list, m) {
		format_items_(n->mtid, context, type, n, buf, indent);
	}
}

static int pack_mt_items(enum isis_tlv_context context, enum isis_tlv_type type,
			 struct isis_mt_item_list *m, struct stream *s,
			 struct isis_tlvs **fragment_tlvs,
			 struct pack_order_entry *pe,
			 struct isis_tlvs *(*new_fragment)(struct list *l),
			 struct list *new_fragment_arg)
{
	struct isis_item_list *n;

	RB_FOREACH (n, isis_mt_item_list, m) {
		int rv;

		rv = pack_items_(n->mtid, context, type, n, s, fragment_tlvs,
				 pe, new_fragment, new_fragment_arg);
		if (rv)
			return rv;
	}

	return 0;
}

static void copy_mt_items(enum isis_tlv_context context,
			  enum isis_tlv_type type,
			  struct isis_mt_item_list *src,
			  struct isis_mt_item_list *dest)
{
	struct isis_item_list *n;

	RB_INIT(isis_mt_item_list, dest);

	RB_FOREACH (n, isis_mt_item_list, src) {
		copy_items(context, type, n, isis_get_mt_items(dest, n->mtid));
	}
}

/* Functions related to tlvs in general */

struct isis_tlvs *isis_alloc_tlvs(void)
{
	struct isis_tlvs *result;

	result = XCALLOC(MTYPE_ISIS_TLV, sizeof(*result));

	init_item_list(&result->isis_auth);
	init_item_list(&result->area_addresses);
	init_item_list(&result->mt_router_info);
	init_item_list(&result->oldstyle_reach);
	init_item_list(&result->lan_neighbor);
	init_item_list(&result->lsp_entries);
	init_item_list(&result->extended_reach);
	RB_INIT(isis_mt_item_list, &result->mt_reach);
	init_item_list(&result->oldstyle_ip_reach);
	init_item_list(&result->oldstyle_ip_reach_ext);
	init_item_list(&result->ipv4_address);
	init_item_list(&result->ipv6_address);
	init_item_list(&result->extended_ip_reach);
	RB_INIT(isis_mt_item_list, &result->mt_ip_reach);
	init_item_list(&result->ipv6_reach);
	RB_INIT(isis_mt_item_list, &result->mt_ipv6_reach);

	return result;
}

struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs)
{
	struct isis_tlvs *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth,
		   &rv->isis_auth);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		   &tlvs->area_addresses, &rv->area_addresses);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
		   &tlvs->mt_router_info, &rv->mt_router_info);

	tlvs->mt_router_info_empty = rv->mt_router_info_empty;

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		   &tlvs->oldstyle_reach, &rv->oldstyle_reach);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		   &tlvs->lan_neighbor, &rv->lan_neighbor);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries,
		   &rv->lsp_entries);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->extended_reach, &rv->extended_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach,
		      &rv->mt_reach);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		   &tlvs->oldstyle_ip_reach, &rv->oldstyle_ip_reach);

	copy_tlv_protocols_supported(&tlvs->protocols_supported,
				     &rv->protocols_supported);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		   &tlvs->oldstyle_ip_reach_ext, &rv->oldstyle_ip_reach_ext);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS, &tlvs->ipv4_address,
		   &rv->ipv4_address);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS, &tlvs->ipv6_address,
		   &rv->ipv6_address);

	rv->te_router_id = copy_tlv_te_router_id(tlvs->te_router_id);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->extended_ip_reach, &rv->extended_ip_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
		      &tlvs->mt_ip_reach, &rv->mt_ip_reach);

	rv->hostname = copy_tlv_dynamic_hostname(tlvs->hostname);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach,
		   &rv->ipv6_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
		      &tlvs->mt_ipv6_reach, &rv->mt_ipv6_reach);

	return rv;
}

static void format_tlvs(struct isis_tlvs *tlvs, struct sbuf *buf, int indent)
{
	format_tlv_protocols_supported(&tlvs->protocols_supported, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth, buf,
		     indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		     &tlvs->area_addresses, buf, indent);

	if (tlvs->mt_router_info_empty) {
		sbuf_push(buf, indent, "MT Router Info: None\n");
	} else {
		format_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
			     &tlvs->mt_router_info, buf, indent);
	}

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		     &tlvs->oldstyle_reach, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		     &tlvs->lan_neighbor, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries,
		     buf, indent);

	format_tlv_dynamic_hostname(tlvs->hostname, buf, indent);
	format_tlv_te_router_id(tlvs->te_router_id, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		     &tlvs->extended_reach, buf, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach,
			buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		     &tlvs->oldstyle_ip_reach, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		     &tlvs->oldstyle_ip_reach_ext, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS,
		     &tlvs->ipv4_address, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS,
		     &tlvs->ipv6_address, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		     &tlvs->extended_ip_reach, buf, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
			&tlvs->mt_ip_reach, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach,
		     buf, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
			&tlvs->mt_ipv6_reach, buf, indent);
}

const char *isis_format_tlvs(struct isis_tlvs *tlvs)
{
	static struct sbuf buf;

	if (!sbuf_buf(&buf))
		sbuf_init(&buf, NULL, 0);

	sbuf_reset(&buf);
	format_tlvs(tlvs, &buf, 0);
	return sbuf_buf(&buf);
}

void isis_free_tlvs(struct isis_tlvs *tlvs)
{
	if (!tlvs)
		return;

	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		   &tlvs->area_addresses);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
		   &tlvs->mt_router_info);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		   &tlvs->oldstyle_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		   &tlvs->lan_neighbor);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->extended_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		   &tlvs->oldstyle_ip_reach);
	free_tlv_protocols_supported(&tlvs->protocols_supported);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		   &tlvs->oldstyle_ip_reach_ext);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS,
		   &tlvs->ipv4_address);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS,
		   &tlvs->ipv6_address);
	free_tlv_te_router_id(tlvs->te_router_id);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->extended_ip_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
		      &tlvs->mt_ip_reach);
	free_tlv_dynamic_hostname(tlvs->hostname);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
		      &tlvs->mt_ipv6_reach);

	XFREE(MTYPE_ISIS_TLV, tlvs);
}

static void add_padding(struct stream *s)
{
	while (STREAM_WRITEABLE(s)) {
		if (STREAM_WRITEABLE(s) == 1)
			break;
		uint32_t padding_len = STREAM_WRITEABLE(s) - 2;

		if (padding_len > 255) {
			if (padding_len == 256)
				padding_len = 254;
			else
				padding_len = 255;
		}

		stream_putc(s, ISIS_TLV_PADDING);
		stream_putc(s, padding_len);
		stream_put(s, NULL, padding_len);
	}
}

#define LSP_REM_LIFETIME_OFF 10
#define LSP_CHECKSUM_OFF 24
static void safe_auth_md5(struct stream *s, uint16_t *checksum,
			  uint16_t *rem_lifetime)
{
	memcpy(rem_lifetime, STREAM_DATA(s) + LSP_REM_LIFETIME_OFF,
	       sizeof(*rem_lifetime));
	memset(STREAM_DATA(s) + LSP_REM_LIFETIME_OFF, 0, sizeof(*rem_lifetime));
	memcpy(checksum, STREAM_DATA(s) + LSP_CHECKSUM_OFF, sizeof(*checksum));
	memset(STREAM_DATA(s) + LSP_CHECKSUM_OFF, 0, sizeof(*checksum));
}

static void restore_auth_md5(struct stream *s, uint16_t checksum,
			     uint16_t rem_lifetime)
{
	memcpy(STREAM_DATA(s) + LSP_REM_LIFETIME_OFF, &rem_lifetime,
	       sizeof(rem_lifetime));
	memcpy(STREAM_DATA(s) + LSP_CHECKSUM_OFF, &checksum, sizeof(checksum));
}

static void update_auth_hmac_md5(struct isis_auth *auth, struct stream *s,
				 bool is_lsp)
{
	uint8_t digest[16];
	uint16_t checksum, rem_lifetime;

	if (is_lsp)
		safe_auth_md5(s, &checksum, &rem_lifetime);

	memset(STREAM_DATA(s) + auth->offset, 0, 16);
	hmac_md5(STREAM_DATA(s), stream_get_endp(s), auth->passwd,
		 auth->plength, digest);
	memcpy(auth->value, digest, 16);
	memcpy(STREAM_DATA(s) + auth->offset, digest, 16);

	if (is_lsp)
		restore_auth_md5(s, checksum, rem_lifetime);
}

static void update_auth(struct isis_tlvs *tlvs, struct stream *s, bool is_lsp)
{
	struct isis_auth *auth_head = (struct isis_auth *)tlvs->isis_auth.head;

	for (struct isis_auth *auth = auth_head; auth; auth = auth->next) {
		if (auth->type == ISIS_PASSWD_TYPE_HMAC_MD5)
			update_auth_hmac_md5(auth, s, is_lsp);
	}
}

static int handle_pack_entry(struct pack_order_entry *pe,
			     struct isis_tlvs *tlvs, struct stream *stream,
			     struct isis_tlvs **fragment_tlvs,
			     struct isis_tlvs *(*new_fragment)(struct list *l),
			     struct list *new_fragment_arg)
{
	int rv;

	if (pe->how_to_pack == ISIS_ITEMS) {
		struct isis_item_list *l;
		l = (struct isis_item_list *)(((char *)tlvs)
					      + pe->what_to_pack);
		rv = pack_items(pe->context, pe->type, l, stream, fragment_tlvs,
				pe, new_fragment, new_fragment_arg);
	} else {
		struct isis_mt_item_list *l;
		l = (struct isis_mt_item_list *)(((char *)tlvs)
						 + pe->what_to_pack);
		rv = pack_mt_items(pe->context, pe->type, l, stream,
				   fragment_tlvs, pe, new_fragment,
				   new_fragment_arg);
	}

	return rv;
}

static int pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
		     struct isis_tlvs *fragment_tlvs,
		     struct isis_tlvs *(*new_fragment)(struct list *l),
		     struct list *new_fragment_arg)
{
	int rv;

	/* When fragmenting, don't add auth as it's already accounted for in the
	 * size we are given. */
	if (!fragment_tlvs) {
		rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth,
				stream, NULL, NULL, NULL, NULL);
		if (rv)
			return rv;
	}

	rv = pack_tlv_protocols_supported(&tlvs->protocols_supported, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		copy_tlv_protocols_supported(
			&tlvs->protocols_supported,
			&fragment_tlvs->protocols_supported);
	}

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
			&tlvs->area_addresses, stream, NULL, NULL, NULL, NULL);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
			   &tlvs->area_addresses,
			   &fragment_tlvs->area_addresses);
	}


	if (tlvs->mt_router_info_empty) {
		if (STREAM_WRITEABLE(stream) < 2)
			return 1;
		stream_putc(stream, ISIS_TLV_MT_ROUTER_INFO);
		stream_putc(stream, 0);
		if (fragment_tlvs)
			fragment_tlvs->mt_router_info_empty = true;
	} else {
		rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
				&tlvs->mt_router_info, stream, NULL, NULL, NULL,
				NULL);
		if (rv)
			return rv;
		if (fragment_tlvs) {
			copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
				   &tlvs->mt_router_info,
				   &fragment_tlvs->mt_router_info);
		}
	}

	rv = pack_tlv_dynamic_hostname(tlvs->hostname, stream);
	if (rv)
		return rv;
	if (fragment_tlvs)
		fragment_tlvs->hostname =
			copy_tlv_dynamic_hostname(tlvs->hostname);

	rv = pack_tlv_te_router_id(tlvs->te_router_id, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->te_router_id =
			copy_tlv_te_router_id(tlvs->te_router_id);
	}

	for (size_t pack_idx = 0; pack_idx < array_size(pack_order);
	     pack_idx++) {
		rv = handle_pack_entry(&pack_order[pack_idx], tlvs, stream,
				       fragment_tlvs ? &fragment_tlvs : NULL,
				       new_fragment, new_fragment_arg);

		if (rv)
			return rv;
	}

	return 0;
}

int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
		   size_t len_pointer, bool pad, bool is_lsp)
{
	int rv;

	rv = pack_tlvs(tlvs, stream, NULL, NULL, NULL);
	if (rv)
		return rv;

	if (pad)
		add_padding(stream);

	if (len_pointer != (size_t)-1) {
		stream_putw_at(stream, len_pointer, stream_get_endp(stream));
	}

	update_auth(tlvs, stream, is_lsp);

	return 0;
}

static struct isis_tlvs *new_fragment(struct list *l)
{
	struct isis_tlvs *rv = isis_alloc_tlvs();

	listnode_add(l, rv);
	return rv;
}

struct list *isis_fragment_tlvs(struct isis_tlvs *tlvs, size_t size)
{
	struct stream *dummy_stream = stream_new(size);
	struct list *rv = list_new();
	struct isis_tlvs *fragment_tlvs = new_fragment(rv);

	if (pack_tlvs(tlvs, dummy_stream, fragment_tlvs, new_fragment, rv)) {
		struct listnode *node;
		for (ALL_LIST_ELEMENTS_RO(rv, node, fragment_tlvs))
			isis_free_tlvs(fragment_tlvs);
		list_delete_and_null(&rv);
	}

	stream_free(dummy_stream);
	return rv;
}

static int unpack_tlv_unknown(enum isis_tlv_context context, uint8_t tlv_type,
			      uint8_t tlv_len, struct stream *s,
			      struct sbuf *log, int indent)
{
	stream_forward_getp(s, tlv_len);
	sbuf_push(log, indent,
		  "Skipping unknown TLV %" PRIu8 " (%" PRIu8 " bytes)\n",
		  tlv_type, tlv_len);
	return 0;
}

static int unpack_tlv(enum isis_tlv_context context, size_t avail_len,
		      struct stream *stream, struct sbuf *log, void *dest,
		      int indent)
{
	uint8_t tlv_type, tlv_len;
	const struct tlv_ops *ops;

	sbuf_push(log, indent, "Unpacking TLV...\n");

	if (avail_len < 2) {
		sbuf_push(
			log, indent + 2,
			"Available data %zu too short to contain a TLV header.\n",
			avail_len);
		return 1;
	}

	tlv_type = stream_getc(stream);
	tlv_len = stream_getc(stream);

	sbuf_push(log, indent + 2,
		  "Found TLV of type %" PRIu8 " and len %" PRIu8 ".\n",
		  tlv_type, tlv_len);

	if (avail_len < ((size_t)tlv_len) + 2) {
		sbuf_push(log, indent + 2,
			  "Available data %zu too short for claimed TLV len %" PRIu8 ".\n",
			  avail_len - 2, tlv_len);
		return 1;
	}

	ops = tlv_table[context][tlv_type];
	if (ops && ops->unpack) {
		return ops->unpack(context, tlv_type, tlv_len, stream, log,
				   dest, indent + 2);
	}

	return unpack_tlv_unknown(context, tlv_type, tlv_len, stream, log,
				  indent + 2);
}

static int unpack_tlvs(enum isis_tlv_context context, size_t avail_len,
		       struct stream *stream, struct sbuf *log, void *dest,
		       int indent)
{
	int rv;
	size_t tlv_start, tlv_pos;

	tlv_start = stream_get_getp(stream);
	tlv_pos = 0;

	sbuf_push(log, indent, "Unpacking %zu bytes of %s...\n", avail_len,
		  (context == ISIS_CONTEXT_LSP) ? "TLVs" : "sub-TLVs");

	while (tlv_pos < avail_len) {
		rv = unpack_tlv(context, avail_len - tlv_pos, stream, log, dest,
				indent + 2);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(stream) - tlv_start;
	}

	return 0;
}

int isis_unpack_tlvs(size_t avail_len, struct stream *stream,
		     struct isis_tlvs **dest, const char **log)
{
	static struct sbuf logbuf;
	int indent = 0;
	int rv;
	struct isis_tlvs *result;

	if (!sbuf_buf(&logbuf))
		sbuf_init(&logbuf, NULL, 0);

	sbuf_reset(&logbuf);
	if (avail_len > STREAM_READABLE(stream)) {
		sbuf_push(&logbuf, indent,
			  "Stream doesn't contain sufficient data. "
			  "Claimed %zu, available %zu\n",
			  avail_len, STREAM_READABLE(stream));
		return 1;
	}

	result = isis_alloc_tlvs();
	rv = unpack_tlvs(ISIS_CONTEXT_LSP, avail_len, stream, &logbuf, result,
			 indent);

	*log = sbuf_buf(&logbuf);
	*dest = result;

	return rv;
}

#define TLV_OPS(_name_, _desc_)                                                \
	static const struct tlv_ops tlv_##_name_##_ops = {                     \
		.name = _desc_, .unpack = unpack_tlv_##_name_,                 \
	}

#define ITEM_TLV_OPS(_name_, _desc_)                                           \
	static const struct tlv_ops tlv_##_name_##_ops = {                     \
		.name = _desc_,                                                \
		.unpack = unpack_tlv_with_items,                               \
									       \
		.pack_item = pack_item_##_name_,                               \
		.free_item = free_item_##_name_,                               \
		.unpack_item = unpack_item_##_name_,                           \
		.format_item = format_item_##_name_,                           \
		.copy_item = copy_item_##_name_}

#define SUBTLV_OPS(_name_, _desc_)                                             \
	static const struct tlv_ops subtlv_##_name_##_ops = {                  \
		.name = _desc_, .unpack = unpack_subtlv_##_name_,              \
	}

ITEM_TLV_OPS(area_address, "TLV 1 Area Addresses");
ITEM_TLV_OPS(oldstyle_reach, "TLV 2 IS Reachability");
ITEM_TLV_OPS(lan_neighbor, "TLV 6 LAN Neighbors");
ITEM_TLV_OPS(lsp_entry, "TLV 9 LSP Entries");
ITEM_TLV_OPS(auth, "TLV 10 IS-IS Auth");
ITEM_TLV_OPS(extended_reach, "TLV 22 Extended Reachability");
ITEM_TLV_OPS(oldstyle_ip_reach, "TLV 128/130 IP Reachability");
TLV_OPS(protocols_supported, "TLV 129 Protocols Supported");
ITEM_TLV_OPS(ipv4_address, "TLV 132 IPv4 Interface Address");
TLV_OPS(te_router_id, "TLV 134 TE Router ID");
ITEM_TLV_OPS(extended_ip_reach, "TLV 135 Extended IP Reachability");
TLV_OPS(dynamic_hostname, "TLV 137 Dynamic Hostname");
ITEM_TLV_OPS(mt_router_info, "TLV 229 MT Router Information");
ITEM_TLV_OPS(ipv6_address, "TLV 232 IPv6 Interface Address");
ITEM_TLV_OPS(ipv6_reach, "TLV 236 IPv6 Reachability");

SUBTLV_OPS(ipv6_source_prefix, "Sub-TLV 22 IPv6 Source Prefix");

static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX] = {
	[ISIS_CONTEXT_LSP] = {
		[ISIS_TLV_AREA_ADDRESSES] = &tlv_area_address_ops,
		[ISIS_TLV_OLDSTYLE_REACH] = &tlv_oldstyle_reach_ops,
		[ISIS_TLV_LAN_NEIGHBORS] = &tlv_lan_neighbor_ops,
		[ISIS_TLV_LSP_ENTRY] = &tlv_lsp_entry_ops,
		[ISIS_TLV_AUTH] = &tlv_auth_ops,
		[ISIS_TLV_EXTENDED_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_MT_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_OLDSTYLE_IP_REACH] = &tlv_oldstyle_ip_reach_ops,
		[ISIS_TLV_PROTOCOLS_SUPPORTED] = &tlv_protocols_supported_ops,
		[ISIS_TLV_OLDSTYLE_IP_REACH_EXT] = &tlv_oldstyle_ip_reach_ops,
		[ISIS_TLV_IPV4_ADDRESS] = &tlv_ipv4_address_ops,
		[ISIS_TLV_TE_ROUTER_ID] = &tlv_te_router_id_ops,
		[ISIS_TLV_EXTENDED_IP_REACH] = &tlv_extended_ip_reach_ops,
		[ISIS_TLV_MT_IP_REACH] = &tlv_extended_ip_reach_ops,
		[ISIS_TLV_DYNAMIC_HOSTNAME] = &tlv_dynamic_hostname_ops,
		[ISIS_TLV_MT_ROUTER_INFO] = &tlv_mt_router_info_ops,
		[ISIS_TLV_IPV6_ADDRESS] = &tlv_ipv6_address_ops,
		[ISIS_TLV_IPV6_REACH] = &tlv_ipv6_reach_ops,
		[ISIS_TLV_MT_IPV6_REACH] = &tlv_ipv6_reach_ops,
	},
	[ISIS_CONTEXT_SUBTLV_NE_REACH] = {},
	[ISIS_CONTEXT_SUBTLV_IP_REACH] = {},
	[ISIS_CONTEXT_SUBTLV_IPV6_REACH] = {
		[ISIS_SUBTLV_IPV6_SOURCE_PREFIX] = &subtlv_ipv6_source_prefix_ops,
	}
};

/* Accessor functions */

void isis_tlvs_add_auth(struct isis_tlvs *tlvs, struct isis_passwd *passwd)
{
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth);
	init_item_list(&tlvs->isis_auth);

	if (passwd->type == ISIS_PASSWD_TYPE_UNUSED)
		return;

	struct isis_auth *auth = XCALLOC(MTYPE_ISIS_TLV, sizeof(*auth));

	auth->type = passwd->type;

	auth->plength = passwd->len;
	memcpy(auth->passwd, passwd->passwd,
	       MIN(sizeof(auth->passwd), sizeof(passwd->passwd)));

	if (auth->type == ISIS_PASSWD_TYPE_CLEARTXT) {
		auth->length = passwd->len;
		memcpy(auth->value, passwd->passwd,
		       MIN(sizeof(auth->value), sizeof(passwd->passwd)));
	}

	append_item(&tlvs->isis_auth, (struct isis_item *)auth);
}

void isis_tlvs_add_area_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct area_addr *area_addr;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, area_addr)) {
		struct isis_area_address *a =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));

		a->len = area_addr->addr_len;
		memcpy(a->addr, area_addr->area_addr, 20);
		append_item(&tlvs->area_addresses, (struct isis_item *)a);
	}
}

void isis_tlvs_add_lan_neighbors(struct isis_tlvs *tlvs, struct list *neighbors)
{
	struct listnode *node;
	u_char *snpa;

	for (ALL_LIST_ELEMENTS_RO(neighbors, node, snpa)) {
		struct isis_lan_neighbor *n =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*n));

		memcpy(n->mac, snpa, 6);
		append_item(&tlvs->lan_neighbor, (struct isis_item *)n);
	}
}

void isis_tlvs_set_protocols_supported(struct isis_tlvs *tlvs,
				       struct nlpids *nlpids)
{
	tlvs->protocols_supported.count = nlpids->count;
	if (tlvs->protocols_supported.protocols)
		XFREE(MTYPE_ISIS_TLV, tlvs->protocols_supported.protocols);
	if (nlpids->count) {
		tlvs->protocols_supported.protocols =
			XCALLOC(MTYPE_ISIS_TLV, nlpids->count);
		memcpy(tlvs->protocols_supported.protocols, nlpids->nlpids,
		       nlpids->count);
	} else {
		tlvs->protocols_supported.protocols = NULL;
	}
}

void isis_tlvs_add_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid,
				  bool overload, bool attached)
{
	struct isis_mt_router_info *i = XCALLOC(MTYPE_ISIS_TLV, sizeof(*i));

	i->overload = overload;
	i->attached = attached;
	i->mtid = mtid;
	append_item(&tlvs->mt_router_info, (struct isis_item *)i);
}

void isis_tlvs_add_ipv4_address(struct isis_tlvs *tlvs, struct in_addr *addr)
{
	struct isis_ipv4_address *a = XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));
	a->addr = *addr;
	append_item(&tlvs->ipv4_address, (struct isis_item *)a);
}


void isis_tlvs_add_ipv4_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct prefix_ipv4 *ip_addr;
	unsigned int addr_count = 0;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, ip_addr)) {
		isis_tlvs_add_ipv4_address(tlvs, &ip_addr->prefix);
		addr_count++;
		if (addr_count >= 63)
			break;
	}
}

void isis_tlvs_add_ipv6_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct prefix_ipv6 *ip_addr;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, ip_addr)) {
		struct isis_ipv6_address *a =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));

		a->addr = ip_addr->prefix;
		append_item(&tlvs->ipv6_address, (struct isis_item *)a);
	}
}

typedef bool (*auth_validator_func)(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp);

static bool auth_validator_cleartxt(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp)
{
	return (auth->length == passwd->len
		&& !memcmp(auth->value, passwd->passwd, passwd->len));
}

static bool auth_validator_hmac_md5(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp)
{
	uint8_t digest[16];
	uint16_t checksum;
	uint16_t rem_lifetime;

	if (is_lsp)
		safe_auth_md5(stream, &checksum, &rem_lifetime);

	memset(STREAM_DATA(stream) + auth->offset, 0, 16);
	hmac_md5(STREAM_DATA(stream), stream_get_endp(stream), passwd->passwd,
		 passwd->len, digest);
	memcpy(STREAM_DATA(stream) + auth->offset, auth->value, 16);

	bool rv = !memcmp(digest, auth->value, 16);

	if (is_lsp)
		restore_auth_md5(stream, checksum, rem_lifetime);

	return rv;
}

static const auth_validator_func auth_validators[] = {
		[ISIS_PASSWD_TYPE_CLEARTXT] = auth_validator_cleartxt,
		[ISIS_PASSWD_TYPE_HMAC_MD5] = auth_validator_hmac_md5,
};

bool isis_tlvs_auth_is_valid(struct isis_tlvs *tlvs, struct isis_passwd *passwd,
			     struct stream *stream, bool is_lsp)
{
	/* If no auth is set, always pass authentication */
	if (!passwd->type)
		return true;

	/* If we don't known how to validate the auth, return invalid */
	if (passwd->type >= array_size(auth_validators)
	    || !auth_validators[passwd->type])
		return false;

	struct isis_auth *auth_head = (struct isis_auth *)tlvs->isis_auth.head;
	struct isis_auth *auth;
	for (auth = auth_head; auth; auth = auth->next) {
		if (auth->type == passwd->type)
			break;
	}

	/* If matching auth TLV could not be found, return invalid */
	if (!auth)
		return false;

	/* Perform validation and return result */
	return auth_validators[passwd->type](passwd, stream, auth, is_lsp);
}

bool isis_tlvs_area_addresses_match(struct isis_tlvs *tlvs,
				    struct list *addresses)
{
	struct isis_area_address *addr_head;

	addr_head = (struct isis_area_address *)tlvs->area_addresses.head;
	for (struct isis_area_address *addr = addr_head; addr;
	     addr = addr->next) {
		struct listnode *node;
		struct area_addr *a;

		for (ALL_LIST_ELEMENTS_RO(addresses, node, a)) {
			if (a->addr_len == addr->len
			    && !memcmp(a->area_addr, addr->addr, addr->len))
				return true;
		}
	}

	return false;
}

static void tlvs_area_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	if (adj->area_address_count != tlvs->area_addresses.count) {
		*changed = true;
		adj->area_address_count = tlvs->area_addresses.count;
		adj->area_addresses = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->area_addresses,
			adj->area_address_count * sizeof(*adj->area_addresses));
	}

	struct isis_area_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->area_addresses.count; i++) {
		if (!addr)
			addr = (struct isis_area_address *)
				       tlvs->area_addresses.head;
		else
			addr = addr->next;

		if (adj->area_addresses[i].addr_len == addr->len
		    && !memcmp(adj->area_addresses[i].area_addr, addr->addr,
			       addr->len)) {
			continue;
		}

		*changed = true;
		adj->area_addresses[i].addr_len = addr->len;
		memcpy(adj->area_addresses[i].area_addr, addr->addr, addr->len);
	}
}

static void tlvs_protocols_supported_to_adj(struct isis_tlvs *tlvs,
					    struct isis_adjacency *adj,
					    bool *changed)
{
	bool ipv4_supported = false, ipv6_supported = false;

	for (uint8_t i = 0; i < tlvs->protocols_supported.count; i++) {
		if (tlvs->protocols_supported.protocols[i] == NLPID_IP)
			ipv4_supported = true;
		if (tlvs->protocols_supported.protocols[i] == NLPID_IPV6)
			ipv6_supported = true;
	}

	struct nlpids reduced = {};

	if (ipv4_supported && ipv6_supported) {
		reduced.count = 2;
		reduced.nlpids[0] = NLPID_IP;
		reduced.nlpids[1] = NLPID_IPV6;
	} else if (ipv4_supported) {
		reduced.count = 1;
		reduced.nlpids[0] = NLPID_IP;
	} else if (ipv6_supported) {
		reduced.count = 1;
		reduced.nlpids[1] = NLPID_IPV6;
	} else {
		reduced.count = 0;
	}

	if (adj->nlpids.count == reduced.count
	    && !memcmp(adj->nlpids.nlpids, reduced.nlpids, reduced.count))
		return;

	*changed = true;
	adj->nlpids.count = reduced.count;
	memcpy(adj->nlpids.nlpids, reduced.nlpids, reduced.count);
}

static void tlvs_ipv4_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	if (adj->ipv4_address_count != tlvs->ipv4_address.count) {
		*changed = true;
		adj->ipv4_address_count = tlvs->ipv4_address.count;
		adj->ipv4_addresses = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->ipv4_addresses,
			adj->ipv4_address_count * sizeof(*adj->ipv4_addresses));
	}

	struct isis_ipv4_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->ipv4_address.count; i++) {
		if (!addr)
			addr = (struct isis_ipv4_address *)
				       tlvs->ipv4_address.head;
		else
			addr = addr->next;

		if (!memcmp(&adj->ipv4_addresses[i], &addr->addr,
			    sizeof(addr->addr)))
			continue;

		*changed = true;
		adj->ipv4_addresses[i] = addr->addr;
	}
}

static void tlvs_ipv6_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	if (adj->ipv6_address_count != tlvs->ipv6_address.count) {
		*changed = true;
		adj->ipv6_address_count = tlvs->ipv6_address.count;
		adj->ipv6_addresses = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->ipv6_addresses,
			adj->ipv6_address_count * sizeof(*adj->ipv6_addresses));
	}

	struct isis_ipv6_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->ipv6_address.count; i++) {
		if (!addr)
			addr = (struct isis_ipv6_address *)
				       tlvs->ipv6_address.head;
		else
			addr = addr->next;

		if (!memcmp(&adj->ipv6_addresses[i], &addr->addr,
			    sizeof(addr->addr)))
			continue;

		*changed = true;
		adj->ipv6_addresses[i] = addr->addr;
	}
}

void isis_tlvs_to_adj(struct isis_tlvs *tlvs, struct isis_adjacency *adj,
		      bool *changed)
{
	*changed = false;

	tlvs_area_addresses_to_adj(tlvs, adj, changed);
	tlvs_protocols_supported_to_adj(tlvs, adj, changed);
	tlvs_ipv4_addresses_to_adj(tlvs, adj, changed);
	tlvs_ipv6_addresses_to_adj(tlvs, adj, changed);
}

bool isis_tlvs_own_snpa_found(struct isis_tlvs *tlvs, uint8_t *snpa)
{
	struct isis_lan_neighbor *ne_head;

	ne_head = (struct isis_lan_neighbor *)tlvs->lan_neighbor.head;
	for (struct isis_lan_neighbor *ne = ne_head; ne; ne = ne->next) {
		if (!memcmp(ne->mac, snpa, ETH_ALEN))
			return true;
	}

	return false;
}

void isis_tlvs_add_lsp_entry(struct isis_tlvs *tlvs, struct isis_lsp *lsp)
{
	struct isis_lsp_entry *entry = XCALLOC(MTYPE_ISIS_TLV, sizeof(*entry));

	entry->rem_lifetime = lsp->hdr.rem_lifetime;
	memcpy(entry->id, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 2);
	entry->checksum = lsp->hdr.checksum;
	entry->seqno = lsp->hdr.seqno;
	entry->lsp = lsp;

	append_item(&tlvs->lsp_entries, (struct isis_item *)entry);
}

void isis_tlvs_add_csnp_entries(struct isis_tlvs *tlvs, uint8_t *start_id,
				uint8_t *stop_id, uint16_t num_lsps,
				dict_t *lspdb, struct isis_lsp **last_lsp)
{
	dnode_t *first = dict_lower_bound(lspdb, start_id);
	if (!first)
		return;

	dnode_t *last = dict_upper_bound(lspdb, stop_id);
	dnode_t *curr = first;

	isis_tlvs_add_lsp_entry(tlvs, first->dict_data);
	*last_lsp = first->dict_data;

	while (curr) {
		curr = dict_next(lspdb, curr);
		if (curr) {
			isis_tlvs_add_lsp_entry(tlvs, curr->dict_data);
			*last_lsp = curr->dict_data;
		}
		if (curr == last || tlvs->lsp_entries.count == num_lsps)
			break;
	}
}

void isis_tlvs_set_dynamic_hostname(struct isis_tlvs *tlvs,
				    const char *hostname)
{
	XFREE(MTYPE_ISIS_TLV, tlvs->hostname);
	if (hostname)
		tlvs->hostname = XSTRDUP(MTYPE_ISIS_TLV, hostname);
}

void isis_tlvs_set_te_router_id(struct isis_tlvs *tlvs,
				const struct in_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, tlvs->te_router_id);
	if (!id)
		return;
	tlvs->te_router_id = XCALLOC(MTYPE_ISIS_TLV, sizeof(*id));
	memcpy(tlvs->te_router_id, id, sizeof(*id));
}

void isis_tlvs_add_oldstyle_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint8_t metric)
{
	struct isis_oldstyle_ip_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv4(&r->prefix);
	append_item(&tlvs->oldstyle_ip_reach, (struct isis_item *)r);
}

void isis_tlvs_add_extended_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint32_t metric)
{
	struct isis_extended_ip_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv4(&r->prefix);
	append_item(&tlvs->extended_ip_reach, (struct isis_item *)r);
}

void isis_tlvs_add_ipv6_reach(struct isis_tlvs *tlvs, uint16_t mtid,
			      struct prefix_ipv6 *dest, uint32_t metric)
{
	struct isis_ipv6_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv6(&r->prefix);

	struct isis_item_list *l;
	l = (mtid == ISIS_MT_IPV4_UNICAST)
		    ? &tlvs->ipv6_reach
		    : isis_get_mt_items(&tlvs->mt_ipv6_reach, mtid);
	append_item(l, (struct isis_item *)r);
}

void isis_tlvs_add_oldstyle_reach(struct isis_tlvs *tlvs, uint8_t *id,
				  uint8_t metric)
{
	struct isis_oldstyle_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(r->id, id, sizeof(r->id));
	append_item(&tlvs->oldstyle_reach, (struct isis_item *)r);
}

void isis_tlvs_add_extended_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				  uint8_t *id, uint32_t metric,
				  uint8_t *subtlvs, uint8_t subtlv_len)
{
	struct isis_extended_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	memcpy(r->id, id, sizeof(r->id));
	r->metric = metric;
	if (subtlvs && subtlv_len) {
		r->subtlvs = XCALLOC(MTYPE_ISIS_TLV, subtlv_len);
		memcpy(r->subtlvs, subtlvs, subtlv_len);
		r->subtlv_len = subtlv_len;
	}

	struct isis_item_list *l;
	if (mtid == ISIS_MT_IPV4_UNICAST)
		l = &tlvs->extended_reach;
	else
		l = isis_get_mt_items(&tlvs->mt_reach, mtid);
	append_item(l, (struct isis_item *)r);
}

struct isis_mt_router_info *
isis_tlvs_lookup_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid)
{
	if (tlvs->mt_router_info_empty)
		return NULL;

	struct isis_mt_router_info *rv;
	for (rv = (struct isis_mt_router_info *)tlvs->mt_router_info.head; rv;
	     rv = rv->next) {
		if (rv->mtid == mtid)
			return rv;
	}

	return NULL;
}
