// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Grace-LSA show checks: "show ip ospf database opaque-link" walks the
 * grace LSA's TLVs within the LSA, stepping over unknown TLVs.
 *
 * Each LSA is followed in memory by bytes the test controls, so reading
 * past its end changes the output instead of depending on what follows
 * an allocation.
 */

#include <zebra.h>

#include "memory.h"
#include "privs.h"
#include "frrevent.h"
#include "buffer.h"
#include "command.h"
#include "vty.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_vty.h"

#define TEST_VALID	  "grace-lsa: show a valid grace LSA"
#define TEST_SHOW_UNKNOWN "grace-lsa: show steps over unknown TLVs"

#define BODY_MAX 256

struct event_loop *master;
struct zebra_privs_t ospfd_privs;

static void failed(const char *test, const char *why, const char *out)
{
	printf("%s\n%s\noutput:\n%s\nfailed!\n", test, why, out);
	exit(1);
}

/*
 * The output of "show ip ospf database opaque-link" for a grace LSA with
 * the given body, followed in memory by the given bytes, which are not
 * part of the LSA. The caller frees the result (MTYPE_TMP).
 */
static char *grace_lsa_show(const uint8_t *body, size_t len,
			    const uint8_t *after, size_t after_len)
{
	uint8_t buf[OSPF_LSA_HEADER_SIZE + BODY_MAX];
	struct lsa_header *lsah = (struct lsa_header *)buf;
	struct ospf_lsa lsa = {};
	struct vty *vty = vty_new();
	char *out;

	assert(len + after_len <= BODY_MAX);
	memset(buf, 0, sizeof(buf));
	lsah->type = OSPF_OPAQUE_LINK_LSA;
	lsah->id.s_addr = htonl(SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0));
	lsah->adv_router.s_addr = htonl(0x02020202);
	lsah->ls_seqnum = htonl(OSPF_INITIAL_SEQUENCE_NUMBER);
	lsah->length = htons(OSPF_LSA_HEADER_SIZE + len);
	memcpy(buf + OSPF_LSA_HEADER_SIZE, body, len);
	if (after_len)
		memcpy(buf + OSPF_LSA_HEADER_SIZE + len, after, after_len);

	lsa.data = lsah;
	lsa.size = OSPF_LSA_HEADER_SIZE + len;

	vty->type = VTY_TERM;
	show_opaque_info_detail(vty, &lsa, NULL);
	out = buffer_getstr(vty->obuf);
	vty_close(vty);

	return out;
}

static void test_valid(void)
{
	const uint8_t body[] = {
		0, 1, 0, 4, 0, 0, 0, 120, /* grace period 120 */
		0, 2, 0, 1, 1, 0, 0, 0,	  /* restart reason 1 */
	};
	char *out = grace_lsa_show(body, sizeof(body), NULL, 0);

	if (!strstr(out, "Grace period:120") || !strstr(out, "Restart reason:Software restart"))
		failed(TEST_VALID, "grace LSA fields not shown", out);
	XFREE(MTYPE_TMP, out);
	printf("%s\nOK\n", TEST_VALID);
}

static void test_show_unknown(void)
{
	/* Unknown TLVs take room in the LSA like any other. */
	const uint8_t body[] = {
		0, 9, 0, 0,		/* unknown TLV, length 0 */
		0, 9, 0, 0,		/* unknown TLV, length 0 */
		0, 2, 0, 1, 1, 0, 0, 0, /* restart reason 1 */
	};
	const uint8_t after[] = {
		0, 2, 0, 1, 2, 0, 0, 0, /* restart reason 2 */
	};
	char *out = grace_lsa_show(body, sizeof(body), after, sizeof(after));

	if (!strstr(out, "Restart reason:Software restart"))
		failed(TEST_SHOW_UNKNOWN, "restart reason in the LSA not shown", out);
	if (strstr(out, "Software reload/upgrade"))
		failed(TEST_SHOW_UNKNOWN, "TLV after the LSA shown", out);
	XFREE(MTYPE_TMP, out);
	printf("%s\nOK\n", TEST_SHOW_UNKNOWN);
}

int main(void)
{
	master = event_master_create(NULL);
	cmd_init(1);
	vty_init(master, false);
	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	ospf_vty_init();
	ospf_opaque_init();
	ospf_gr_helper_init();

	test_valid();
	test_show_unknown();

	ospf_gr_helper_stop();
	ospf_opaque_term();
	vty_terminate();
	cmd_terminate();
	event_master_free(master);
	return 0;
}
