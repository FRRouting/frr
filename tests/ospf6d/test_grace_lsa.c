// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Grace-LSA TLV checks: a Grace Period or Restart Reason TLV shorter than
 * its value is rejected rather than read past its end, and the show code
 * stays within the LSA and prints only known restart reasons.
 *
 * Each LSA is followed in memory by bytes the test controls, so reading
 * past its end changes the result instead of depending on what follows
 * an allocation.
 */

#include <zebra.h>

#include "memory.h"
#include "privs.h"
#include "frrevent.h"
#include "libospf.h"
#include "vty.h"
#include "json.h"

#include "ospf6d/ospf6_proto.h"
#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_neighbor.h"
#include "ospf6d/ospf6_tlv.h"
#include "ospf6d/ospf6_gr.h"
#include "ospf6d/ospf6d.h"

#define TEST_VALID	  "grace-lsa: valid grace period and restart reason"
#define TEST_PERIOD_SHORT "grace-lsa: empty grace period TLV before another TLV"
#define TEST_REASON_SHORT "grace-lsa: empty restart reason TLV before another TLV"
#define TEST_PERIOD_END	  "grace-lsa: empty grace period TLV at the end of the LSA"
#define TEST_SHOW_UNKNOWN "grace-lsa: show steps over an unknown TLV"
#define TEST_SHOW_REASON  "grace-lsa: show an unknown restart reason"

#define BODY_MAX 256

struct event_loop *master;
struct zebra_privs_t ospf6d_privs;

static struct ospf6 *ospf6;
static struct ospf6_neighbor *restarter;

static void failed(const char *test, const char *why)
{
	printf("%s\n%s\nfailed!\n", test, why);
	exit(1);
}

/*
 * A grace LSA in buf with the given body, followed by the given bytes,
 * which are not part of the LSA.
 */
static void grace_lsa(struct ospf6_lsa *lsa, uint8_t *buf, const uint8_t *body, size_t len,
		      const uint8_t *after, size_t after_len)
{
	struct ospf6_lsa_header *lsah = (struct ospf6_lsa_header *)buf;

	assert(len + after_len <= BODY_MAX);
	memset(buf, 0, OSPF6_LSA_HEADER_SIZE + BODY_MAX);
	lsah->type = htons(OSPF6_LSTYPE_GRACE_LSA);
	lsah->adv_router = htonl(0x02020202);
	lsah->seqnum = htonl(OSPF_INITIAL_SEQUENCE_NUMBER);
	lsah->length = htons(OSPF6_LSA_HEADER_SIZE + len);
	memcpy(buf + OSPF6_LSA_HEADER_SIZE, body, len);
	if (after_len)
		memcpy(buf + OSPF6_LSA_HEADER_SIZE + len, after, after_len);

	memset(lsa, 0, sizeof(*lsa));
	lsa->header = lsah;
}

/*
 * Process a grace LSA from a neighbor that is not FULL: an LSA whose TLVs
 * are accepted is rejected for the neighbor's state, a malformed one
 * before that.
 */
static bool grace_lsa_accepted(const uint8_t *body, size_t len, const uint8_t *after,
			       size_t after_len)
{
	uint8_t buf[OSPF6_LSA_HEADER_SIZE + BODY_MAX];
	struct ospf6_lsa lsa;
	int ret;

	grace_lsa(&lsa, buf, body, len, after, after_len);
	restarter->gr_helper_info.rejected_reason = OSPF6_HELPER_REJECTED_NONE;
	ret = ospf6_process_grace_lsa(ospf6, &lsa, restarter);

	assert(ret == OSPF6_GR_NOT_HELPER);
	return restarter->gr_helper_info.rejected_reason == OSPF6_HELPER_NOT_A_VALID_NEIGHBOUR;
}

/* The restart reason "show ipv6 ospf6 database ... json" prints. */
static void grace_lsa_show_reason(const uint8_t *body, size_t len, const uint8_t *after,
				  size_t after_len, char *reason, size_t reason_size)
{
	uint8_t buf[OSPF6_LSA_HEADER_SIZE + BODY_MAX];
	struct ospf6_lsa lsa;
	struct vty *vty = vty_new();
	json_object *json = json_object_new_array();
	json_object *jreason;

	vty->type = VTY_TERM;
	grace_lsa(&lsa, buf, body, len, after, after_len);
	ospf6_lsa_show(vty, &lsa, json, true);

	reason[0] = '\0';
	if (json_object_object_get_ex(json_object_array_get_idx(json, 0), "restartReason",
				      &jreason))
		strlcpy(reason, json_object_get_string(jreason), reason_size);

	json_object_free(json);
	vty_close(vty);
}

static void test_valid(void)
{
	const uint8_t body[] = {
		0, 1, 0, 4, 0, 0, 0, 120, /* grace period 120 */
		0, 2, 0, 1, 1, 0, 0, 0,	  /* restart reason 1 */
	};

	if (!grace_lsa_accepted(body, sizeof(body), NULL, 0))
		failed(TEST_VALID, "valid grace LSA rejected");
	printf("%s\nOK\n", TEST_VALID);
}

static void test_period_short(void)
{
	/*
	 * The grace period TLV has no value; the 4 bytes after its header
	 * are the next TLV's header, which reads as a valid interval.
	 */
	uint8_t body[4 + 4 + 120] = {
		0, 1, 0, 0,   /* grace period, length 0 */
		0, 0, 0, 120, /* unknown TLV, length 120 */
	};

	if (grace_lsa_accepted(body, sizeof(body), NULL, 0))
		failed(TEST_PERIOD_SHORT, "short grace period TLV accepted");
	printf("%s\nOK\n", TEST_PERIOD_SHORT);
}

static void test_reason_short(void)
{
	/* The reason byte is the next TLV's first byte. */
	const uint8_t body[] = {
		0, 1, 0, 4, 0, 0, 0, 120, /* grace period 120 */
		0, 2, 0, 0,		  /* restart reason, length 0 */
		1, 0, 0, 0,		  /* unknown TLV, length 0 */
	};

	if (grace_lsa_accepted(body, sizeof(body), NULL, 0))
		failed(TEST_REASON_SHORT, "short restart reason TLV accepted");
	printf("%s\nOK\n", TEST_REASON_SHORT);
}

static void test_period_end(void)
{
	/* The interval would be the 4 bytes after the LSA. */
	const uint8_t body[] = {
		0, 2, 0, 1, 1, 0, 0, 0, /* restart reason 1 */
		0, 1, 0, 0,		/* grace period, length 0 */
	};
	const uint8_t after[] = { 0, 0, 0, 120 };

	if (grace_lsa_accepted(body, sizeof(body), after, sizeof(after)))
		failed(TEST_PERIOD_END, "grace period read after the LSA");
	printf("%s\nOK\n", TEST_PERIOD_END);
}

static void test_show_unknown(void)
{
	/* An unknown TLV takes room in the LSA like any other. */
	const uint8_t body[] = {
		0, 9, 0, 4, 0, 0, 0, 0, /* unknown TLV, length 4 */
		0, 2, 0, 1, 1, 0, 0, 0, /* restart reason 1 */
	};
	const uint8_t after[] = {
		0, 2, 0, 1, 3, 0, 0, 0, /* restart reason 3 */
	};
	char reason[64];

	grace_lsa_show_reason(body, sizeof(body), after, sizeof(after), reason, sizeof(reason));
	if (strcmp(reason, "Software restart"))
		failed(TEST_SHOW_UNKNOWN, "TLV after the LSA shown");
	printf("%s\nOK\n", TEST_SHOW_UNKNOWN);
}

static void test_show_reason(void)
{
	const uint8_t body[] = {
		0, 2, 0, 1, 200, 0, 0, 0, /* restart reason 200 */
	};
	char reason[64];

	grace_lsa_show_reason(body, sizeof(body), NULL, 0, reason, sizeof(reason));
	if (strcmp(reason, "Unknown restart"))
		failed(TEST_SHOW_REASON, "unknown restart reason not shown as such");
	printf("%s\nOK\n", TEST_SHOW_REASON);
}

int main(void)
{
	master = event_master_create(NULL);
	ospf6_install_lsa_handler(&grace_lsa_handler);

	ospf6 = XCALLOC(MTYPE_TMP, sizeof(*ospf6));
	ospf6->router_id = htonl(0x01010101);
	ospf6->ospf6_helper_cfg.is_helper_supported = true;

	restarter = XCALLOC(MTYPE_TMP, sizeof(*restarter));
	restarter->state = OSPF6_NEIGHBOR_TWOWAY;
	restarter->router_id = htonl(0x02020202);
	strlcpy(restarter->name, "2.2.2.2", sizeof(restarter->name));

	test_valid();
	test_period_short();
	test_reason_short();
	test_period_end();
	test_show_unknown();
	test_show_reason();

	XFREE(MTYPE_TMP, restarter);
	XFREE(MTYPE_TMP, ospf6);
	event_master_free(master);
	return 0;
}
