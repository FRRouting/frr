// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#include "memory.h"
#include "sbuf.h"
#include "stream.h"
#include "frrevent.h"

#include "isisd/isis_circuit.h"
#include "isisd/isis_tlvs.h"

#include "test_common.h"

/*
 * #22820: a first extended-reach item whose sub-TLV area ends in two stray
 * bytes must not shift the parse of the following item.
 */
/* clang-format off */
static const uint8_t lsp_body[] = {
	0x16, 0x1e,			/* TLV type 22 (Ext Reach), length 30 */

	/* item 1 */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00,	/* neighbor id */
	0x00, 0x00, 0x0a,				/* metric 10 */
	0x08,						/* 8 bytes of sub-TLVs */
	0x03, 0x04, 0xde, 0xad, 0xbe, 0xef,		/* Admin Group sub-TLV (6 bytes) */
	0xff, 0xfe,					/* 2 bytes declared but not a sub-TLV */

	/* item 2 - must still parse as this exact neighbor */
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,	/* neighbor id */
	0x00, 0x00, 0x14,				/* metric 20 */
	0x00,						/* no sub-TLVs */
};
/* clang-format on */

/*
 * An LSP with one extended IS reachability whose only sub-TLV is an extended
 * admin group of n_words 32-bit words: the item takes 11 + 2 + 4 * n_words
 * bytes, plus 2 for the TLV header.
 */
static struct isis_tlvs *ext_reach_tlvs(size_t n_words)
{
	size_t item_len = 11 + 2 + 4 * n_words;
	struct stream *s = stream_new(2 + item_len);
	struct isis_tlvs *tlvs;
	const char *log;

	stream_putc(s, ISIS_TLV_EXTENDED_REACH);
	stream_putc(s, item_len);
	for (int i = 0; i < 7; i++)
		stream_putc(s, i + 1);
	stream_put3(s, 10);
	stream_putc(s, 2 + 4 * n_words);
	stream_putc(s, ISIS_SUBTLV_EXT_ADMIN_GRP);
	stream_putc(s, 4 * n_words);
	for (size_t i = 0; i < n_words; i++)
		stream_putl(s, 0xffffffff);
	stream_set_getp(s, 0);

	assert(isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log) == 0);
	stream_free(s);
	return tlvs;
}

/* How many fragments of size bytes the item packs into: 0 if it does not fit. */
static int fragments(size_t n_words, size_t size)
{
	struct isis_tlvs *tlvs = ext_reach_tlvs(n_words);
	struct list *frags = isis_fragment_tlvs(tlvs, size);
	struct isis_tlvs *frag;
	struct listnode *node;
	int count = 0;

	isis_free_tlvs(tlvs);
	if (!frags)
		return 0;
	for (ALL_LIST_ELEMENTS_RO(frags, node, frag)) {
		count += frag->extended_reach.count;
		isis_free_tlvs(frag);
	}
	list_delete(&frags);
	return count;
}

/*
 * An extended IS reachability is packed by its own size: it fits a fragment
 * with room for it and its TLV header, and is refused by one without, also
 * when it is larger than ISIS_SUBTLV_MAX_SIZE allows for.
 */
static void test_fragment_sizes(void)
{
	/* 77-byte item: needs 79 bytes with the header. */
	assert(fragments(16, 78) == 0);
	assert(fragments(16, 79) == 1);

	/* 213-byte item, beyond 11 + ISIS_SUBTLV_MAX_SIZE. */
	assert(fragments(50, 550) == 1);
	assert(fragments(50, 214) == 0);
	assert(fragments(50, 215) == 1);
	printf("fragment sizes OK\n");
}

int main(int argc, char **argv)
{
	static const uint8_t want_id[7] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	};
	struct stream *s = stream_new(sizeof(lsp_body));
	struct isis_extended_reach *first, *second;
	struct isis_tlvs *tlvs;
	const char *log;
	int rv;

	stream_put(s, lsp_body, sizeof(lsp_body));
	stream_set_getp(s, 0);

	rv = isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log);
	printf("unpack rv=%d\nlog:\n%s\n", rv, log);
	assert(rv == 0);

	assert(tlvs->extended_reach.count == 2);
	first = (struct isis_extended_reach *)tlvs->extended_reach.head;
	second = first->next;
	printf("second neighbor id %02x%02x.%02x%02x.%02x%02x.%02x\n", second->id[0], second->id[1],
	       second->id[2], second->id[3], second->id[4], second->id[5], second->id[6]);
	assert(memcmp(second->id, want_id, sizeof(want_id)) == 0);

	isis_free_tlvs(tlvs);
	stream_free(s);

	test_fragment_sizes();
	printf("OK\n");
	return 0;
}
