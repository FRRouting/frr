// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Router Capability TLV (242) encoding.
 *
 * Copyright (C) 2026 Dave Seddon
 *
 * A TLV carries at most 255 bytes of value. When the router capability
 * (Flex-Algo definitions with their admin groups, SRv6 capabilities) does
 * not fit, the encoder has to continue in another TLV 242 (RFC 7981
 * section 2). A sub-TLV that cannot fit in any TLV cannot be encoded at all.
 * Each emitted TLV must carry its real length, and the result must decode
 * back to what was encoded.
 *
 * A Flex-Algo definition that cannot be encoded must not be kept in the
 * router capability either: the local LSP copy would still carry it into
 * the local Flex-Algo election, while neighbours never receive it. So the
 * FADs kept locally must be exactly the ones that decode.
 *
 * The encoder refuses to start when the stream has less room than
 * isis_router_cap_tlv_size(), so every case packs again into a stream of
 * exactly the bytes written the first time: an estimate that counts a
 * sub-TLV the encoder leaves out fails there.
 *
 * Each case runs in a child process so that a crash fails only that case.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "memory.h"
#include "printfrr.h"
#include "stream.h"
#include "admin_group.h"
#include "flex_algo.h"

#include "isisd/isis_circuit.h"
#include "isisd/isis_tlvs.h"

#include "test_common.h"

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define MAX_FADS 8

/*
 * A Flex-Algo definition. Its FAD sub-TLV is 2 + 4 (fixed part) bytes, plus
 * 2 + 4 * words for each admin group with words > 0, plus 3 for flags.
 */
struct fad {
	uint8_t exclude_words, include_words;
	bool flags;
};

struct tcase {
	const char *description;
	enum kind kind;
	struct fad fads[MAX_FADS];
	uint8_t nfads;
	bool srv6;
	bool te_ipv6;	/* IPv6 TE Router ID sub-TLV: 18 more header bytes */
	bool same_algo; /* every FAD replaces the previous one (algorithm 128) */
	/* expected */
	int tlvs;	  /* TLV 242s emitted */
	int fads_decoded; /* also the FADs kept in the local router capability */
	bool srv6_decoded;
	/*
	 * Grow the first FAD past the limit after it was kept, bypassing
	 * isis_tlvs_set_router_capability_fad(): it counts as kept locally,
	 * but the encoder and the size estimate must leave it out.
	 */
	bool grow;
};

/*
 * Sizes (TLV value = 5 bytes router ID + flags, then sub-TLVs):
 *   {20, 0, flags} = 91, {15, 0, no flags} = 68, {16, 0, no flags} = 72
 *   {30, 30} = 250, the largest FAD that fits (5 + 250 = 255)
 *   {31, 30} = 254, too large for any TLV
 *   with the IPv6 TE Router ID the header is 23: {25, 30} = 230 fits,
 *   {26, 30} = 234 does not
 *   SRv6: capabilities 4 + algorithms 4 + MSD 4 = 12
 */
static const struct tcase tcases[] = {
	{ "one FAD with a one-word admin group", POSITIVE,
	  { { 1, 0, false } }, 1, false, false, false,
	  1, 1, false },
	{ "SRv6 capabilities only", POSITIVE,
	  { }, 0, true, false, false,
	  1, 0, true },
	{ "six largest FADs, one per TLV", POSITIVE,
	  { { 30, 30 }, { 30, 30 }, { 30, 30 }, { 30, 30 }, { 30, 30 }, { 30, 30 } },
	  6, false, false, false,
	  6, 6, false },
	{ "no FAD and no SR: bare router capability", NEGATIVE,
	  { }, 0, false, false, false,
	  1, 0, false },
	{ "FAD too large for any TLV is left out", NEGATIVE,
	  { { 31, 30 } }, 1, false, false, false,
	  1, 0, false },
	{ "FADs filling the TLV to exactly 255 bytes", BOUNDARY,
	  { { 20, 0, true }, { 20, 0, true }, { 15, 0, false } }, 3, false, false, false,
	  1, 3, false },
	{ "one admin-group word more than fits starts a second TLV", BOUNDARY,
	  { { 20, 0, true }, { 20, 0, true }, { 16, 0, false } }, 3, false, false, false,
	  2, 3, false },
	{ "largest FAD alone fills one TLV", BOUNDARY,
	  { { 30, 30 } }, 1, false, false, false,
	  1, 1, false },
	{ "SRv6 block after a full TLV goes into a second TLV", CORNER,
	  { { 20, 0, true }, { 20, 0, true }, { 15, 0, false } }, 3, true, false, false,
	  2, 3, true },
	{ "64-word admin group (sub-sub-TLV length 256) is left out", CORNER,
	  { { 64, 0 }, { 1, 0 } }, 2, false, false, false,
	  1, 1, false },
	{ "largest FAD that fits after the IPv6 TE Router ID", BOUNDARY,
	  { { 25, 30 } }, 1, false, true, false,
	  1, 1, false },
	{ "one word more than fits after the IPv6 TE Router ID is left out", NEGATIVE,
	  { { 26, 30 } }, 1, false, true, false,
	  1, 0, false },
	{ "FAD replaced by one too large for any TLV is not kept", CORNER,
	  { { 1, 0 }, { 31, 30 } }, 2, false, false, true,
	  1, 0, false },
	{ "FAD grown too large after it was kept is not encoded", CORNER,
	  { { 1, 0, false }, { 1, 0, false } }, 2, false, false, false,
	  1, 1, false, true },
};

static void admin_group_words(struct admin_group *ag, uint8_t words)
{
	admin_group_init(ag);
	/* bit 0 of the last word gives a bitmap of exactly that many words */
	if (words)
		admin_group_set(ag, 32 * (words - 1));
}

/* Walk the packed TLVs; every one must be a TLV 242 that ends in the buffer. */
static int count_tlvs(struct stream *s, bool *ok)
{
	size_t pos = 0, end = stream_get_endp(s);
	const uint8_t *data = STREAM_DATA(s);
	int n = 0;

	*ok = true;
	while (pos + 2 <= end) {
		if (data[pos] != ISIS_TLV_ROUTER_CAPABILITY) {
			printf("    offset %zu: TLV type %u, not 242\n", pos, data[pos]);
			*ok = false;
			return n;
		}
		pos += 2 + data[pos + 1];
		n++;
	}
	if (pos != end) {
		printf("    last TLV ends at %zu, data ends at %zu\n", pos, end);
		*ok = false;
	}
	return n;
}

static int run_case(const struct tcase *tc)
{
	uint8_t sysid[ISIS_SYS_ID_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	struct isis_tlvs *tlvs = isis_alloc_tlvs(), *out = NULL;
	struct isis_router_cap *rcap;
	struct stream *s = stream_new(8192), *exact;
	int ntlvs, nfads = 0, nlocal = 0, rc = EXIT_MATCH;
	const char *log;
	bool srv6, ok;

	rcap = isis_tlvs_init_router_capability(tlvs);
	inet_pton(AF_INET, "10.0.0.1", &rcap->router_id);
	if (tc->te_ipv6)
		inet_pton(AF_INET6, "2001:db8::1", &rcap->te_router_id_ipv6);

	for (int i = 0; i < tc->nfads; i++) {
		int algorithm = tc->same_algo ? 128 : 128 + i;
		struct flex_algo fa = {
			.algorithm = algorithm,
			.metric_type = MT_IGP,
			.calc_type = CALC_TYPE_SPF,
			.priority = 100,
			.flags = tc->fads[i].flags ? FAD_FLAG_M : 0,
		};

		admin_group_words(&fa.admin_group_exclude_any, tc->fads[i].exclude_words);
		admin_group_words(&fa.admin_group_include_any, tc->fads[i].include_words);
		admin_group_init(&fa.admin_group_include_all);
		isis_tlvs_set_router_capability_fad(tlvs, &fa, algorithm, sysid);
		admin_group_term(&fa.admin_group_exclude_any);
		admin_group_term(&fa.admin_group_include_any);
		admin_group_term(&fa.admin_group_include_all);
	}
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		if (rcap->fads[i])
			nlocal++;
	printf("    kept %d FAD(s) locally\n", nlocal);
	if (nlocal != tc->fads_decoded + tc->grow)
		rc = EXIT_MISMATCH;

	if (tc->grow) {
		struct flex_algo *fa = &rcap->fads[128]->fad;

		admin_group_term(&fa->admin_group_exclude_any);
		admin_group_term(&fa->admin_group_include_any);
		admin_group_words(&fa->admin_group_exclude_any, 31);
		admin_group_words(&fa->admin_group_include_any, 30);
	}

	if (tc->srv6) {
		rcap->srv6_cap.is_srv6_capable = true;
		rcap->algo[0] = SR_ALGORITHM_SPF;
		rcap->algo[1] = SR_ALGORITHM_STRICT_SPF;
		rcap->srv6_msd.max_seg_left_msd = 3;
	}

	if (isis_pack_tlvs(tlvs, s, (size_t)-1, false, false)) {
		printf("    pack failed\n");
		return EXIT_MISMATCH;
	}

	exact = stream_new(stream_get_endp(s));
	if (isis_pack_tlvs(tlvs, exact, (size_t)-1, false, false)) {
		printf("    pack into exactly %zu bytes failed\n", stream_get_endp(s));
		rc = EXIT_MISMATCH;
	}
	stream_free(exact);

	ntlvs = count_tlvs(s, &ok);
	printf("    %zu bytes, %d TLV 242%s\n", stream_get_endp(s), ntlvs,
	       ok ? "" : " (malformed)");
	if (!ok || ntlvs != tc->tlvs)
		rc = EXIT_MISMATCH;
	if (!ok)
		return rc;

	stream_set_getp(s, 0);
	if (isis_unpack_tlvs(STREAM_READABLE(s), s, &out, &log) || !out->router_cap) {
		printf("    unpack failed:\n%s\n", log);
		return EXIT_MISMATCH;
	}
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		if (out->router_cap->fads[i])
			nfads++;
	srv6 = out->router_cap->srv6_cap.is_srv6_capable;
	printf("    decoded %d FAD(s), SRv6 %s\n", nfads, srv6 ? "yes" : "no");
	if (nfads != tc->fads_decoded || srv6 != tc->srv6_decoded)
		rc = EXIT_MISMATCH;

	isis_free_tlvs(out);
	isis_free_tlvs(tlvs);
	stream_free(s);
	return rc;
}

int main(int argc, char **argv)
{
	int failures = 0;

	printf("IS-IS Router Capability TLV encoding tests\n\n");

	for (size_t i = 0; i < array_size(tcases); i++) {
		const struct tcase *tc = &tcases[i];
		char why[96] = "";
		int status;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH)
			snprintfrr(why, sizeof(why), " (expected %d TLV(s), %d FAD(s), SRv6 %s)",
				 tc->tlvs, tc->fads_decoded, tc->srv6_decoded ? "yes" : "no");
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}

	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
