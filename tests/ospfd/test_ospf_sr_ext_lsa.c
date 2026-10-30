// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Segment Routing reads received Extended Link and Extended Prefix TLVs
 * within the LSA: the SIDs of well-formed TLVs are kept, and a TLV whose
 * length claims more than the LSA holds is not read.
 *
 * Each LSA is placed at the end of a page that is followed by an
 * inaccessible page, so any read past the LSA faults.
 */

#include <zebra.h>
#include <sys/mman.h>

#include "lib/privs.h"
#include "lib/vrf.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ext.h"
#include "ospfd/ospf_vty.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* need these to link in libfrrospf */
struct event_loop *master;
struct zebra_privs_t ospfd_privs;

#define TEST_NAME "sr-ext-lsa: Extended Link and Prefix TLVs are read within the LSA"

/* Advertising router of the LSAs, and the SIDs and prefix they carry */
#define ADV_ROUTER 0x02020202
#define ADJ_LABEL  16123
#define PREFIX	   0xc0000201
#define PREFIX_SID 10

static uint8_t *page_end;

static void failed(const char *what)
{
	printf("%s\n%s:\nfailed!\n", TEST_NAME, what);
	exit(1);
}

static void put_tlv_hdr(uint8_t *p, uint16_t type, uint16_t len)
{
	struct tlv_header *tlvh = (struct tlv_header *)p;

	tlvh->type = htons(type);
	tlvh->length = htons(len);
}

/* Give an opaque LSA with the given body, ending at page_end, to SR */
static void sr_update(uint8_t opaque_type, const uint8_t *body, size_t len)
{
	struct lsa_header *lsah;
	struct ospf_lsa lsa = {};

	lsah = (struct lsa_header *)(page_end - OSPF_LSA_HEADER_SIZE - len);
	memset(lsah, 0, OSPF_LSA_HEADER_SIZE);
	lsah->type = OSPF_OPAQUE_AREA_LSA;
	lsah->id.s_addr = htonl(SET_OPAQUE_LSID(opaque_type, 1));
	lsah->adv_router.s_addr = htonl(ADV_ROUTER);
	lsah->ls_seqnum = htonl(OSPF_INITIAL_SEQUENCE_NUMBER);
	lsah->length = htons(OSPF_LSA_HEADER_SIZE + len);
	memcpy((uint8_t *)lsah + OSPF_LSA_HEADER_SIZE, body, len);

	lsa.data = lsah;
	lsa.size = OSPF_LSA_HEADER_SIZE + len;
	if (opaque_type == OPAQUE_TYPE_EXTENDED_LINK_LSA)
		ospf_sr_ext_link_lsa_update(&lsa);
	else
		ospf_sr_ext_prefix_lsa_update(&lsa);
}

/* The SR node of the advertising router */
static struct sr_node *sr_node(void)
{
	struct in_addr rid = { .s_addr = htonl(ADV_ROUTER) };

	return ospf_sr_node_create(&rid);
}

/* The SR node holds only the link of test_ext_link_valid() */
static void check_link(const char *what)
{
	struct sr_node *srn = sr_node();
	struct sr_link *srl;

	if (listcount(srn->ext_link) != 1)
		failed(what);
	srl = listnode_head(srn->ext_link);
	if (srl->type != ADJ_SID || srl->sid[0] != ADJ_LABEL)
		failed(what);
}

/* The SR node holds only the prefix of test_ext_prefix_valid() */
static void check_prefix(const char *what)
{
	struct sr_node *srn = sr_node();
	struct sr_prefix *srp;

	if (listcount(srn->ext_prefix) != 1)
		failed(what);
	srp = listnode_head(srn->ext_prefix);
	if (srp->prefv4.prefix.s_addr != htonl(PREFIX) || srp->sid != PREFIX_SID)
		failed(what);
}

/*
 * A well-formed Extended Link TLV with a label Adj-SID, ending the LSA; its
 * length counts the padding of the sub-TLV, as ospfd sends it.
 */
static void test_ext_link_valid(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + EXT_SUBTLV_ADJ_SID_SIZE] = {};
	struct ext_subtlv_adj_sid *sid;

	put_tlv_hdr(body, EXT_TLV_LINK, sizeof(body) - TLV_HDR_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	sid = (struct ext_subtlv_adj_sid *)(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE);
	put_tlv_hdr((uint8_t *)sid, EXT_SUBTLV_ADJ_SID, SID_LABEL_SIZE(EXT_SUBTLV_ADJ_SID_SIZE));
	sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	sid->value = htonl(SET_LABEL(ADJ_LABEL));
	sr_update(OPAQUE_TYPE_EXTENDED_LINK_LSA, body, sizeof(body));
	check_link("well-formed Extended Link TLV");
}

/* An Extended Link TLV whose Link Data is past the LSA */
static void test_ext_link_past_end(void)
{
	uint8_t body[TLV_HDR_SIZE + EXT_TLV_LINK_SIZE - 4] = {};

	put_tlv_hdr(body, EXT_TLV_LINK, EXT_TLV_LINK_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	sr_update(OPAQUE_TYPE_EXTENDED_LINK_LSA, body, sizeof(body));
	check_link("Extended Link TLV running past the LSA");
}

/* An Extended Link TLV whose Adj-SID sub-TLV value is past the LSA */
static void test_ext_link_adj_sid_past_end(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + EXT_TLV_LINK_SIZE + EXT_SUBTLV_ADJ_SID_SIZE - 4] = {};

	put_tlv_hdr(body, EXT_TLV_LINK, EXT_TLV_LINK_SIZE + TLV_HDR_SIZE + EXT_SUBTLV_ADJ_SID_SIZE);
	body[TLV_HDR_SIZE] = 1; /* point-to-point */
	put_tlv_hdr(body + TLV_HDR_SIZE + EXT_TLV_LINK_SIZE, EXT_SUBTLV_ADJ_SID,
		    EXT_SUBTLV_ADJ_SID_SIZE);
	sr_update(OPAQUE_TYPE_EXTENDED_LINK_LSA, body, sizeof(body));
	check_link("Extended Link TLV with its Adj-SID past the LSA");
}

/* A well-formed Extended Prefix TLV with a Prefix-SID, ending the LSA */
static void test_ext_prefix_valid(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + EXT_TLV_PREFIX_SIZE + EXT_SUBTLV_PREFIX_SID_SIZE] = {};
	struct ext_tlv_prefix *pref = (struct ext_tlv_prefix *)body;
	struct ext_subtlv_prefix_sid *psid;

	put_tlv_hdr(body, EXT_TLV_PREFIX, sizeof(body) - TLV_HDR_SIZE);
	pref->pref_length = IPV4_MAX_BITLEN;
	pref->address.s_addr = htonl(PREFIX);
	psid = (struct ext_subtlv_prefix_sid *)(body + TLV_HDR_SIZE + EXT_TLV_PREFIX_SIZE);
	put_tlv_hdr((uint8_t *)psid, EXT_SUBTLV_PREFIX_SID, EXT_SUBTLV_PREFIX_SID_SIZE);
	psid->algorithm = SR_ALGORITHM_SPF;
	psid->value = htonl(PREFIX_SID);
	sr_update(OPAQUE_TYPE_EXTENDED_PREFIX_LSA, body, sizeof(body));
	check_prefix("well-formed Extended Prefix TLV");
}

/* An Extended Prefix TLV (another prefix) whose Prefix-SID value is past the LSA */
static void test_ext_prefix_sid_past_end(void)
{
	uint8_t body[2 * TLV_HDR_SIZE + EXT_TLV_PREFIX_SIZE + EXT_SUBTLV_PREFIX_SID_SIZE - 4] = {};
	struct ext_tlv_prefix *pref = (struct ext_tlv_prefix *)body;

	put_tlv_hdr(body, EXT_TLV_PREFIX,
		    EXT_TLV_PREFIX_SIZE + TLV_HDR_SIZE + EXT_SUBTLV_PREFIX_SID_SIZE);
	pref->pref_length = IPV4_MAX_BITLEN;
	pref->address.s_addr = htonl(PREFIX + 1);
	put_tlv_hdr(body + TLV_HDR_SIZE + EXT_TLV_PREFIX_SIZE, EXT_SUBTLV_PREFIX_SID,
		    EXT_SUBTLV_PREFIX_SID_SIZE);
	sr_update(OPAQUE_TYPE_EXTENDED_PREFIX_LSA, body, sizeof(body));
	check_prefix("Extended Prefix TLV with its Prefix-SID past the LSA");
}

int main(int argc, char **argv)
{
	long page_size = sysconf(_SC_PAGESIZE);
	uint8_t *pages;

	pages = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1,
		     0);
	if (pages == MAP_FAILED || mprotect(pages + page_size, page_size, PROT_NONE) != 0) {
		perror(TEST_NAME);
		return 1;
	}
	page_end = pages + page_size;

	master = event_master_create(NULL);
	cmd_init(1);
	zlog_aux_init("NONE: ", LOG_ERR);
	vrf_init(NULL, NULL, NULL, NULL);
	ospf_master_init(master);
	ospf_vty_init();
	/* also initializes the Segment Routing database */
	ospf_opaque_init();

	test_ext_link_valid();
	test_ext_link_past_end();
	test_ext_link_adj_sid_past_end();
	test_ext_prefix_valid();
	test_ext_prefix_sid_past_end();

	printf("%s\nOK\n", TEST_NAME);
	return 0;
}
