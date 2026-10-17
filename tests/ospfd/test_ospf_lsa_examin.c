// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Router-LSA length checks: the link blocks of a received Router-LSA must
 * fill its body exactly.
 */

#include "ospfd/ospf_packet.c"

struct event_loop *master;
struct zebra_privs_t ospfd_privs;

#define RLSA_MAX_LEN                                                                              \
	(OSPF_LSA_HEADER_SIZE + OSPF_ROUTER_LSA_MIN_SIZE + 3 * OSPF_ROUTER_LSA_LINK_SIZE +        \
	 OSPF_ROUTER_LSA_TOS_SIZE)

static int failed;

/* A Router-LSA with nlinks link blocks declaring declared links, the first
 * block with tos TOS metrics, its length extra bytes longer.
 */
static uint16_t router_lsa(uint8_t *buf, uint16_t nlinks, uint16_t declared, uint8_t tos, int extra)
{
	struct router_lsa *rlsa = (struct router_lsa *)buf;
	uint16_t len = OSPF_LSA_HEADER_SIZE + OSPF_ROUTER_LSA_MIN_SIZE +
		       nlinks * OSPF_ROUTER_LSA_LINK_SIZE + tos * OSPF_ROUTER_LSA_TOS_SIZE + extra;

	memset(buf, 0, RLSA_MAX_LEN);
	rlsa->header.type = OSPF_ROUTER_LSA;
	rlsa->header.length = htons(len);
	rlsa->links = htons(declared);
	rlsa->link[0].tos = tos;
	return len;
}

static void check(const char *name, uint16_t nlinks, uint16_t declared, uint8_t tos, int extra,
		  unsigned int expect)
{
	uint8_t buf[RLSA_MAX_LEN] __attribute__((aligned(4)));
	uint16_t len = router_lsa(buf, nlinks, declared, tos, extra);
	unsigned int ret = ospf_lsa_examin((struct lsa_header *)buf, len, 0);

	printf("%s: %s\n", name, ret == expect ? "OK" : "failed!");
	if (ret != expect)
		failed++;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	check("router-lsa: accept 2 links", 2, 2, 0, 0, MSG_OK);
	check("router-lsa: accept no links", 0, 0, 0, 0, MSG_OK);
	check("router-lsa: accept 2 links, one with a TOS metric", 2, 2, 1, 0, MSG_OK);
	check("router-lsa: reject 4 bytes after the links", 2, 2, 0, 4, MSG_NG);
	check("router-lsa: reject 8 bytes after the links", 2, 2, 0, 8, MSG_NG);
	check("router-lsa: reject 4 bytes and no links", 0, 0, 0, 4, MSG_NG);
	check("router-lsa: reject 4 bytes after a link with a TOS metric", 1, 1, 1, 4, MSG_NG);
	check("router-lsa: reject a truncated TOS metric", 1, 1, 1, -4, MSG_NG);
	check("router-lsa: reject a missing link", 1, 2, 0, 0, MSG_NG);
	check("router-lsa: reject a header only", 0, 0, 0, -4, MSG_NG);

	return failed;
}
