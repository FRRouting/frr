// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * "show bgp attribute-info summary" counters.
 *
 * attr_show_all() counts, per attribute type, how many interned attributes
 * have that type's bit set in the 64-bit attr->flag. Only types 1-64 have a
 * flag bit, so types 65-255 must not be tested: shifting a 64-bit value by
 * 64 or more is undefined behaviour.
 *
 * Each case interns the given attributes in a child process, so that a
 * sanitizer abort or a crash fails only that case, and compares the
 * complete summary output.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "qobj.h"
#include "vty.h"
#include "privs.h"
#include "memory.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_network.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define MAX_ATTRS 3

#define F(t)	  ATTR_FLAG_BIT(BGP_ATTR_##t)
#define ALL_FLAGS UINT64_MAX

struct tcase {
	const char *description;
	enum kind kind;
	/* attr->flag of each interned attribute; each also gets a distinct
	 * MED so that they are interned separately
	 */
	uint64_t flags[MAX_ATTRS];
	int nattrs;
	const char *expected;
};

static const struct tcase cases[] = {
	/* counted once per attribute that has the type's bit */
	{ .description = "one attribute with origin, as-path and next-hop",
	  .kind = POSITIVE,
	  .flags = { F(ORIGIN) | F(AS_PATH) | F(NEXT_HOP) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " ORIGIN (1): 1\n"
		      " AS_PATH (2): 1\n"
		      " NEXT_HOP (3): 1\n" },
	{ .description = "two attributes, one with local-pref",
	  .kind = POSITIVE,
	  .flags = { F(ORIGIN) | F(LOCAL_PREF), F(ORIGIN) },
	  .nattrs = 2,
	  .expected = "Total attributes: 2\n"
		      "Attributes:\n"
		      " ORIGIN (1): 2\n"
		      " LOCAL_PREF (5): 1\n" },
	{ .description = "three attributes with the same types",
	  .kind = POSITIVE,
	  .flags = { F(ORIGIN) | F(AS_PATH), F(ORIGIN) | F(AS_PATH), F(ORIGIN) | F(AS_PATH) },
	  .nattrs = 3,
	  .expected = "Total attributes: 3\n"
		      "Attributes:\n"
		      " ORIGIN (1): 3\n"
		      " AS_PATH (2): 3\n" },
	{ .description = "optional types are counted",
	  .kind = POSITIVE,
	  .flags = { F(MULTI_EXIT_DISC) | F(COMMUNITIES) | F(LARGE_COMMUNITIES) | F(OTC) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " MULTI_EXIT_DISC (4): 1\n"
		      " COMMUNITY (8): 1\n"
		      " LARGE_COMMUNITY (32): 1\n"
		      " OTC (35): 1\n" },

	/* nothing to list */
	{ .description = "attribute with no flags is not counted",
	  .kind = NEGATIVE,
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n" },
	{ .description = "no attributes interned",
	  .kind = NEGATIVE,
	  .nattrs = 0,
	  .expected = "Total attributes: 0\n"
		      "Attributes:\n" },
	{ .description = "unnamed types 11-13 are not listed",
	  .kind = NEGATIVE,
	  .flags = { ATTR_FLAG_BIT(11) | ATTR_FLAG_BIT(12) | ATTR_FLAG_BIT(13) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n" },

	/* the ends of the flag bits, and of the named types */
	{ .description = "lowest type (ORIGIN, flag bit 1)",
	  .kind = BOUNDARY,
	  .flags = { ATTR_FLAG_BIT(1) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " ORIGIN (1): 1\n" },
	{ .description = "highest named type with a flag bit (PREFIX_SID)",
	  .kind = BOUNDARY,
	  .flags = { F(PREFIX_SID) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " PREFIX_SID (40): 1\n" },
	{ .description = "type 41, above the highest named type, is not listed",
	  .kind = BOUNDARY,
	  .flags = { ATTR_FLAG_BIT(41) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n" },
	{ .description = "flag bit 64 (unnamed type 64) is not listed",
	  .kind = BOUNDARY,
	  .flags = { ATTR_FLAG_BIT(64) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n" },

	/* every flag bit set: types above 64 have no bit, and must not be
	 * tested (shifting a 64-bit value by 64 or more is undefined)
	 */
	{ .description = "all 64 flag bits set",
	  .kind = CORNER,
	  .flags = { ALL_FLAGS },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " ORIGIN (1): 1\n"
		      " AS_PATH (2): 1\n"
		      " NEXT_HOP (3): 1\n"
		      " MULTI_EXIT_DISC (4): 1\n"
		      " LOCAL_PREF (5): 1\n"
		      " ATOMIC_AGGREGATE (6): 1\n"
		      " AGGREGATOR (7): 1\n"
		      " COMMUNITY (8): 1\n"
		      " ORIGINATOR_ID (9): 1\n"
		      " CLUSTER_LIST (10): 1\n"
		      " MP_REACH_NLRI (14): 1\n"
		      " MP_UNREACH_NLRI (15): 1\n"
		      " EXT_COMMUNITIES (16): 1\n"
		      " AS4_PATH (17): 1\n"
		      " AS4_AGGREGATOR (18): 1\n"
		      " PMSI_TUNNEL_ATTRIBUTE (22): 1\n"
		      " ENCAP (23): 1\n"
		      " IPV6_EXT_COMMUNITIES (25): 1\n"
		      " AIGP (26): 1\n"
		      " BGP-LS Attribute (29): 1\n"
		      " LARGE_COMMUNITY (32): 1\n"
		      " OTC (35): 1\n"
		      " Next Hop Dependent Characteristics (39): 1\n"
		      " PREFIX_SID (40): 1\n" },
	{ .description = "flag bits 1 and 64 only",
	  .kind = CORNER,
	  .flags = { ATTR_FLAG_BIT(1) | ATTR_FLAG_BIT(64) },
	  .nattrs = 1,
	  .expected = "Total attributes: 1\n"
		      "Attributes:\n"
		      " ORIGIN (1): 1\n" },
	{ .description = "all 64 flag bits set on three attributes",
	  .kind = CORNER,
	  .flags = { ALL_FLAGS, ALL_FLAGS, ALL_FLAGS },
	  .nattrs = 3,
	  .expected = "Total attributes: 3\n"
		      "Attributes:\n"
		      " ORIGIN (1): 3\n"
		      " AS_PATH (2): 3\n"
		      " NEXT_HOP (3): 3\n"
		      " MULTI_EXIT_DISC (4): 3\n"
		      " LOCAL_PREF (5): 3\n"
		      " ATOMIC_AGGREGATE (6): 3\n"
		      " AGGREGATOR (7): 3\n"
		      " COMMUNITY (8): 3\n"
		      " ORIGINATOR_ID (9): 3\n"
		      " CLUSTER_LIST (10): 3\n"
		      " MP_REACH_NLRI (14): 3\n"
		      " MP_UNREACH_NLRI (15): 3\n"
		      " EXT_COMMUNITIES (16): 3\n"
		      " AS4_PATH (17): 3\n"
		      " AS4_AGGREGATOR (18): 3\n"
		      " PMSI_TUNNEL_ATTRIBUTE (22): 3\n"
		      " ENCAP (23): 3\n"
		      " IPV6_EXT_COMMUNITIES (25): 3\n"
		      " AIGP (26): 3\n"
		      " BGP-LS Attribute (29): 3\n"
		      " LARGE_COMMUNITY (32): 3\n"
		      " OTC (35): 3\n"
		      " Next Hop Dependent Characteristics (39): 3\n"
		      " PREFIX_SID (40): 3\n" },
};

static int run_case(const struct tcase *tc)
{
	struct attr *interned[MAX_ATTRS] = {};
	char *out = NULL;
	size_t outlen = 0;
	struct vty *vty;
	int rc;

	for (int i = 0; i < tc->nattrs; i++) {
		struct attr attr = {};

		attr.med = i;
		attr.flag = tc->flags[i];
		interned[i] = bgp_attr_intern(&attr);
	}

	vty = vty_new();
	vty->type = VTY_SHELL;
	vty->of = open_memstream(&out, &outlen);
	attr_show_all(vty, true);
	fclose(vty->of);
	vty->of = NULL;

	printf("    got:\n%s", out);
	rc = strcmp(out, tc->expected) ? EXIT_MISMATCH : EXIT_MATCH;
	if (rc == EXIT_MISMATCH)
		printf("    expected:\n%s", tc->expected);

	free(out);
	vty_close(vty);
	for (int i = 0; i < tc->nattrs; i++)
		bgp_attr_unintern(&interned[i]);
	return rc;
}

/* waitpid(), retried if a signal interrupts it */
static int wait_child(pid_t pid, int *status)
{
	int rc;

	do {
		rc = waitpid(pid, status, 0);
	} while (rc < 0 && errno == EINTR);
	return rc;
}

static int run_table(const struct tcase *table, size_t n)
{
	int failures = 0;

	for (size_t i = 0; i < n; i++) {
		const struct tcase *tc = &table[i];
		char why[64] = "";
		int status;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		if (pid < 0)
			snprintfrr(why, sizeof(why), " (fork failed: %m)");
		else if (wait_child(pid, &status) < 0)
			snprintfrr(why, sizeof(why), " (waitpid failed: %m)");
		else if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH)
			snprintfrr(why, sizeof(why), " (wrong summary)");
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}
	return failures;
}

int main(void)
{
	int failures;

	qobj_init();
	cmd_init(0);
	master = event_master_create("test attr info");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_attr_init();

	printf("BGP attribute-info summary tests\n\n");
	failures = run_table(cases, array_size(cases));
	printf("\n%d of %zu cases failed\n", failures, array_size(cases));
	return failures ? 1 : 0;
}
