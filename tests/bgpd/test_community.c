// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Community attribute unit tests.
 */
#include <zebra.h>

#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_community.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;

/*
 * set_community_string() pre-computes the size of the cached com->str buffer.
 * A large set of numeric communities must not cause the rendered string to be
 * truncated, otherwise consumers that match against the string (e.g. expanded
 * community-lists, which run a regex over com->str) silently miss communities
 * that fall past the truncation point. A BGP peer could then hide a filtered
 * community (e.g. no-export) behind enough numerically-smaller padding
 * communities to evade a route-map match.
 */
static void test_large_community_not_truncated(void)
{
	const int npad = 800;
	struct community *com;
	char *input;
	size_t cap = (size_t)npad * 16 + 32;
	size_t off = 0;
	char *str;

	printf("large-community-not-truncated\n");

	input = XMALLOC(MTYPE_TMP, cap);

	/*
	 * 800 unique communities that each render as an 11-char token and sort
	 * numerically before no-export (0xFFFFFF01). 800 * 12 bytes well
	 * exceeds the historic BUFSIZ (8192) cap.
	 */
	for (int i = 0; i < npad; i++)
		off += snprintf(input + off, cap - off, "65534:%u ",
				(unsigned int)(10000 + i));

	/* The community an operator would filter on - sorts last. */
	snprintf(input + off, cap - off, "no-export");

	com = community_str2com(input);
	assert(com);

	str = community_str(com, false, false);

	printf("rendered string length: %zu (%d communities)\n", strlen(str),
	       com->size);

	if (strstr(str, "no-export") != NULL) {
		printf("OK\n");
	} else {
		printf("failed: no-export was truncated from the community string\n");
		failed++;
	}

	community_free(&com);
	XFREE(MTYPE_TMP, input);
}

int main(void)
{
	test_large_community_not_truncated();

	printf("failures: %d\n", failed);
	return failed;
}
