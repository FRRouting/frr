// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * "show ip ospf database opaque-area" stays within each received opaque
 * LSA: Extended Link, Extended Prefix, Traffic Engineering and Router
 * Information TLVs whose length claims more than the LSA holds are not
 * displayed.
 *
 * Each LSA is displayed twice: from an allocation of exactly its size (an
 * address sanitizer build reports any read past it), and from a buffer in
 * which it is followed by bytes that would display MARK if they were read
 * as part of the LSA.
 */

#include <zebra.h>

#include "lib/buffer.h"
#include "lib/privs.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ext.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_vty.h"

/* need these to link in libfrrospf */
struct event_loop *master;
struct zebra_privs_t ospfd_privs;

#define TEST_NAME "opaque-show: opaque LSA TLVs are displayed within the LSA"

/* 203.0.113.99, and its display */
#define MARK_ADDR 0xcb007163
#define MARK	  "203.0.113.99"

#define BODY_MAX 64

static void failed(const char *what, const char *out)
{
	printf("%s\n%s:\n%s\nfailed!\n", TEST_NAME, what, out ? out : "");
	exit(1);
}

static void put_tlv_hdr(uint8_t *p, uint16_t type, uint16_t len)
{
	struct tlv_header *tlvh = (struct tlv_header *)p;

	tlvh->type = htons(type);
	tlvh->length = htons(len);
}

static void put_addr(uint8_t *p, uint32_t addr)
{
	addr = htonl(addr);
	memcpy(p, &addr, sizeof(addr));
}

static char *show(struct ospf_lsa *lsa)
{
	struct vty *vty = vty_new();
	char *out;

	vty->type = VTY_TERM;
	show_opaque_info_detail(vty, lsa, NULL);
	out = buffer_getstr(vty->obuf);
	vty_close(vty);

	return out;
}

static void opaque_header_set(struct lsa_header *lsah, uint8_t opaque_type, size_t len)
{
	lsah->type = OSPF_OPAQUE_AREA_LSA;
	lsah->id.s_addr = htonl(SET_OPAQUE_LSID(opaque_type, 1));
	lsah->adv_router.s_addr = htonl(0x02020202);
	lsah->ls_seqnum = htonl(OSPF_INITIAL_SEQUENCE_NUMBER);
	lsah->length = htons(OSPF_LSA_HEADER_SIZE + len);
}

/*
 * Display an opaque LSA with the given body, followed in memory by the
 * given bytes, which are not part of the LSA: MARK must not be shown.
 */
static void check(const char *what, uint8_t opaque_type, const uint8_t *body, size_t len,
		  const uint8_t *after, size_t after_len)
{
	uint8_t buf[OSPF_LSA_HEADER_SIZE + 2 * BODY_MAX] = {};
	struct ospf_lsa lsa = {};
	struct ospf_lsa *exact;
	char *out;

	assert(len <= BODY_MAX && after_len <= BODY_MAX);

	exact = ospf_lsa_new_and_data(OSPF_LSA_HEADER_SIZE + len);
	opaque_header_set(exact->data, opaque_type, len);
	memcpy((uint8_t *)exact->data + OSPF_LSA_HEADER_SIZE, body, len);
	out = show(exact);
	ospf_lsa_discard(exact);
	if (strstr(out, MARK))
		failed(what, out);
	XFREE(MTYPE_TMP, out);

	lsa.data = (struct lsa_header *)buf;
	lsa.size = OSPF_LSA_HEADER_SIZE + len;
	opaque_header_set(lsa.data, opaque_type, len);
	memcpy(buf + OSPF_LSA_HEADER_SIZE, body, len);
	memcpy(buf + OSPF_LSA_HEADER_SIZE + len, after, after_len);
	out = show(&lsa);
	if (strstr(out, MARK))
		failed(what, out);
	XFREE(MTYPE_TMP, out);
}

/* A well-formed Extended Link LSA shows its Remote Interface Address */
static void test_ext_link_valid(void)
{
	uint8_t body[TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + TLV_HDR_SIZE +
		     EXT_SUBTLV_RMT_ITF_ADDR_SIZE] = {};
	struct ospf_lsa *lsa;
	char *out;

	put_tlv_hdr(body, EXT_TLV_LINK, sizeof(body) - TLV_HDR_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	put_tlv_hdr(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE, EXT_SUBTLV_RMT_ITF_ADDR,
		    EXT_SUBTLV_RMT_ITF_ADDR_SIZE);
	put_addr(body + 2 * TLV_HDR_SIZE + EXT_TLV_LINK_SIZE, MARK_ADDR);

	lsa = ospf_lsa_new_and_data(OSPF_LSA_HEADER_SIZE + sizeof(body));
	opaque_header_set(lsa->data, OPAQUE_TYPE_EXTENDED_LINK_LSA, sizeof(body));
	memcpy((uint8_t *)lsa->data + OSPF_LSA_HEADER_SIZE, body, sizeof(body));
	out = show(lsa);
	ospf_lsa_discard(lsa);
	if (!strstr(out, "Remote Interface Address Sub-TLV") || !strstr(out, MARK))
		failed("well-formed Extended Link TLV", out);
	XFREE(MTYPE_TMP, out);
}

/*
 * A well-formed Extended Link LSA with a label Adj-SID: its sub-TLV length
 * (7) is not a multiple of 4, so the Extended Link TLV length does not
 * count the padding of its last sub-TLV.
 */
static void test_ext_link_label_valid(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + EXT_SUBTLV_ADJ_SID_SIZE] = {};
	struct ext_subtlv_adj_sid *sid;
	struct ospf_lsa *lsa;
	char *out;

	put_tlv_hdr(body, EXT_TLV_LINK,
		    EXT_TLV_LINK_SIZE + TLV_HDR_SIZE + SID_LABEL_SIZE(EXT_SUBTLV_ADJ_SID_SIZE));
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	sid = (struct ext_subtlv_adj_sid *)(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE);
	put_tlv_hdr((uint8_t *)sid, EXT_SUBTLV_ADJ_SID, SID_LABEL_SIZE(EXT_SUBTLV_ADJ_SID_SIZE));
	sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG;
	sid->value = htonl(SET_LABEL(16123));

	lsa = ospf_lsa_new_and_data(OSPF_LSA_HEADER_SIZE + sizeof(body));
	opaque_header_set(lsa->data, OPAQUE_TYPE_EXTENDED_LINK_LSA, sizeof(body));
	memcpy((uint8_t *)lsa->data + OSPF_LSA_HEADER_SIZE, body, sizeof(body));
	out = show(lsa);
	ospf_lsa_discard(lsa);
	if (!strstr(out, "Label: 16123"))
		failed("well-formed label Adj-SID", out);
	XFREE(MTYPE_TMP, out);
}

/*
 * An empty Adj-SID sub-TLV in the last word of the LSA: its flags are past
 * the LSA (reported by an address sanitizer build).
 */
static void test_ext_link_empty_subtlv(void)
{
	uint8_t body[TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + TLV_HDR_SIZE] = {};
	uint8_t after[4] = { EXT_SUBTLV_LINK_ADJ_SID_VFLG };

	put_tlv_hdr(body, EXT_TLV_LINK, EXT_TLV_LINK_SIZE + TLV_HDR_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	put_tlv_hdr(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE, EXT_SUBTLV_ADJ_SID, 0);
	check("empty Adj-SID sub-TLV at the end of the LSA", OPAQUE_TYPE_EXTENDED_LINK_LSA, body,
	      sizeof(body), after, sizeof(after));
}

/*
 * An Extended Link TLV shorter than its fixed part. What follows it would
 * be its fixed part, then a Remote Interface Address sub-TLV showing MARK
 * and an unknown sub-TLV that ends any sub-TLV walk.
 */
static void test_ext_link_short(void)
{
	uint8_t body[TLV_HDR_SIZE] = {};
	uint8_t after[BODY_MAX] = {};
	uint8_t *p = after + EXT_TLV_LINK_SIZE;

	put_tlv_hdr(body, EXT_TLV_LINK, 0);
	put_tlv_hdr(p, EXT_SUBTLV_RMT_ITF_ADDR, EXT_SUBTLV_RMT_ITF_ADDR_SIZE);
	put_addr(p + TLV_HDR_SIZE, MARK_ADDR);
	p += TLV_HDR_SIZE + EXT_SUBTLV_RMT_ITF_ADDR_SIZE;
	/* ends the walk an unchecked 0 - EXT_TLV_LINK_SIZE length would make */
	put_tlv_hdr(p, 0x7fff,
		    0x10000 - EXT_TLV_LINK_SIZE - 2 * TLV_HDR_SIZE - EXT_SUBTLV_RMT_ITF_ADDR_SIZE);
	check("Extended Link TLV shorter than its fixed part", OPAQUE_TYPE_EXTENDED_LINK_LSA, body,
	      sizeof(body), after, p + TLV_HDR_SIZE - after);
}

/* An Extended Link TLV ending past the LSA, inside its last sub-TLV */
static void test_ext_link_past_end(void)
{
	uint8_t body[TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + TLV_HDR_SIZE] = {};
	uint8_t after[BODY_MAX] = {};

	put_tlv_hdr(body, EXT_TLV_LINK,
		    EXT_TLV_LINK_SIZE + TLV_HDR_SIZE + EXT_SUBTLV_RMT_ITF_ADDR_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	put_tlv_hdr(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE, EXT_SUBTLV_RMT_ITF_ADDR,
		    EXT_SUBTLV_RMT_ITF_ADDR_SIZE);
	put_addr(after, MARK_ADDR);
	check("Extended Link TLV running past the LSA", OPAQUE_TYPE_EXTENDED_LINK_LSA, body,
	      sizeof(body), after, 4);
}

/*
 * An Extended Prefix TLV shorter than its fixed part. What follows it would
 * be its fixed part with MARK as the prefix, then an unknown sub-TLV that
 * ends any sub-TLV walk.
 */
static void test_ext_prefix_short(void)
{
	uint8_t body[TLV_HDR_SIZE] = {};
	uint8_t after[BODY_MAX] = {};

	put_tlv_hdr(body, EXT_TLV_PREFIX, 0);
	put_addr(after + 4, MARK_ADDR);
	/* ends the walk an unchecked 0 - EXT_TLV_PREFIX_SIZE length would make */
	put_tlv_hdr(after + EXT_TLV_PREFIX_SIZE, 0x7fff,
		    0x10000 - EXT_TLV_PREFIX_SIZE - TLV_HDR_SIZE);
	check("Extended Prefix TLV shorter than its fixed part", OPAQUE_TYPE_EXTENDED_PREFIX_LSA,
	      body, sizeof(body), after, EXT_TLV_PREFIX_SIZE + TLV_HDR_SIZE);
}

/* A Traffic Engineering Router Address TLV whose value is past the LSA */
static void test_te_router_addr_past_end(void)
{
	uint8_t body[TLV_HDR_SIZE] = {};
	uint8_t after[4];

	put_tlv_hdr(body, TE_TLV_ROUTER_ADDR, TE_LINK_SUBTLV_DEF_SIZE);
	put_addr(after, MARK_ADDR);
	check("TE Router Address TLV running past the LSA", OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
	      body, sizeof(body), after, sizeof(after));
}

/* An empty Traffic Engineering Router Address TLV at the end of the LSA */
static void test_te_router_addr_empty(void)
{
	uint8_t body[TLV_HDR_SIZE] = {};
	uint8_t after[4];

	put_tlv_hdr(body, TE_TLV_ROUTER_ADDR, 0);
	put_addr(after, MARK_ADDR);
	check("empty TE Router Address TLV at the end of the LSA",
	      OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, body, sizeof(body), after, sizeof(after));
}

/* A Traffic Engineering Link sub-TLV whose value is past the LSA */
static void test_te_link_subtlv_past_end(void)
{
	uint8_t body[2 * TLV_HDR_SIZE] = {};
	uint8_t after[4];

	put_tlv_hdr(body, TE_TLV_LINK, TLV_HDR_SIZE);
	put_tlv_hdr(body + TLV_HDR_SIZE, TE_LINK_SUBTLV_LINK_ID, TE_LINK_SUBTLV_DEF_SIZE);
	put_addr(after, MARK_ADDR);
	check("TE Link sub-TLV running past the LSA", OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, body,
	      sizeof(body), after, sizeof(after));
}

/* A well-formed Router Information LSA shows its PCE Address */
static void test_ri_pce_address_valid(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + PCE_ADDRESS_IPV4_SIZE] = {};
	struct ospf_lsa *lsa;
	char *out;

	put_tlv_hdr(body, RI_TLV_PCE, TLV_HDR_SIZE + PCE_ADDRESS_IPV4_SIZE);
	put_tlv_hdr(body + TLV_HDR_SIZE, RI_PCE_SUBTLV_ADDRESS, PCE_ADDRESS_IPV4_SIZE);
	body[2 * TLV_HDR_SIZE + 1] = PCE_ADDRESS_IPV4;
	put_addr(body + 2 * TLV_HDR_SIZE + 4, MARK_ADDR);

	lsa = ospf_lsa_new_and_data(OSPF_LSA_HEADER_SIZE + sizeof(body));
	opaque_header_set(lsa->data, OPAQUE_TYPE_ROUTER_INFORMATION_LSA, sizeof(body));
	memcpy((uint8_t *)lsa->data + OSPF_LSA_HEADER_SIZE, body, sizeof(body));
	out = show(lsa);
	ospf_lsa_discard(lsa);
	if (!strstr(out, "PCE Address: " MARK))
		failed("well-formed PCE Address sub-TLV", out);
	XFREE(MTYPE_TMP, out);
}

/*
 * An empty PCE Address sub-TLV in the last word of the LSA: its address
 * type is past the LSA (reported by an address sanitizer build).
 */
static void test_ri_pce_address_empty(void)
{
	uint8_t body[2 * TLV_HDR_SIZE] = {};
	uint8_t after[PCE_ADDRESS_IPV4_SIZE] = { 0, PCE_ADDRESS_IPV4 };

	put_tlv_hdr(body, RI_TLV_PCE, TLV_HDR_SIZE);
	put_tlv_hdr(body + TLV_HDR_SIZE, RI_PCE_SUBTLV_ADDRESS, 0);
	put_addr(after + 4, MARK_ADDR);
	check("empty PCE Address sub-TLV at the end of the LSA",
	      OPAQUE_TYPE_ROUTER_INFORMATION_LSA, body, sizeof(body), after, sizeof(after));
}

int main(int argc, char **argv)
{
	master = event_master_create(NULL);
	cmd_init(1);
	vty_init(master, false);
	zlog_aux_init("NONE: ", LOG_ERR);
	vrf_init(NULL, NULL, NULL, NULL);
	ospf_master_init(master);
	ospf_vty_init();
	ospf_opaque_init();

	/* Router Information LSAs are displayed once it is registered */
	ospf_new_alloc(0, VRF_DEFAULT_NAME);
	ospf_router_info_update_sr(false, NULL);

	test_ext_link_valid();
	test_ext_link_label_valid();
	test_ext_link_short();
	test_ext_link_empty_subtlv();
	test_ext_link_past_end();
	test_ext_prefix_short();
	test_te_router_addr_past_end();
	test_te_router_addr_empty();
	test_te_link_subtlv_past_end();
	test_ri_pce_address_valid();
	test_ri_pce_address_empty();

	printf("%s\nOK\n", TEST_NAME);
	return 0;
}
