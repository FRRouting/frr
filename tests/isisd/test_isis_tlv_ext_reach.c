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
	printf("OK\n");
	return 0;
}
