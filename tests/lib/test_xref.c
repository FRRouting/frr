/*
 * xref tests
 * Copyright (C) 2020  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "xref.h"
#include "log.h"

/*
 * "lib/test_xref.c" (only 1 directory component included)
 * "logging call"
 * 0x00000003 (network byte order - LOG_ERR)
 * 0x00000000 (network byte order - EC / zero here)
 *
 * note there are no '\0' terminators included for the strings
 *
 * SHA256
 * => 71a65ce6e81517f642c8f55fb2af6f181f7df54357913b5b577aa61a663fdd4c
 *  & 0f -> 0x01      'H'
 *  & f001 -> 0x07    '7'
 *  &   3e -> 0x13    'K'
 *  &   c007 -> 0x12  'J'
 *  &     f8 -> 0x0b  'B'
 * etc.
 * (for reference: base32ch[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ")
 *
 * (bits are consumed starting with the lowest bit, and the first character
 * only consumes 4 bits and has the 5th bit at 1)
 */

static const char *expect_uid = "H7KJB-67TBH";
static bool test_logcall(void)
{
	zlog_err("logging call");

	return true;
}

static void check_xref(const struct xref *xref, bool *found, bool *error)
{
	const char *file = xref->file, *p;

	p = strrchr(file, '/');
	if (p)
		file = p + 1;

	if (strcmp(file, "test_xref.c"))
		return;
	if (xref->type != XREFT_LOGMSG)
		return;
	if (strcmp(xref->func, "test_logcall"))
		return;

	printf("xref: %s:%d %s() type=%d uid=%s\n",
	       xref->file, xref->line, xref->func, xref->type,
	       xref->xrefdata ? xref->xrefdata->uid : "--");

	if (*found) {
		printf("duplicate xref!\n");
		*error = true;
	}

	const struct xref_logmsg *logmsg;

	logmsg = container_of(xref, struct xref_logmsg, xref);
	if (strcmp(logmsg->fmtstring, "logging call")) {
		printf("log message mismatch!\n");
		*error = true;
	}
	if (logmsg->priority != LOG_ERR || logmsg->ec != 0) {
		printf("metadata mismatch!\n");
		*error = true;
	}

	*found = true;

	if (!xref->xrefdata) {
		printf("no unique ID?\n");
		*error = true;
		return;
	}

	if (strcmp(xref->xrefdata->uid, expect_uid)) {
		printf("unique ID mismatch, expected %s, got %s\n",
		       expect_uid, xref->xrefdata->uid);
		*error = true;
	}
}

static bool test_lookup(void)
{
	struct xref_block *xb;
	bool found = false, error = false;

	for (xb = xref_blocks; xb; xb = xb->next) {
		const struct xref * const *xrefp;

		for (xrefp = xb->start; xrefp < xb->stop; xrefp++) {
			const struct xref *xref = *xrefp;

			if (!xref)
				continue;

			check_xref(xref, &found, &error);
		}
	}
	return found && !error;
}

bool (*tests[])(void) = {
	test_lookup,
	test_logcall,
};

XREF_SETUP();

int main(int argc, char **argv)
{
	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	for (unsigned int i = 0; i < array_size(tests); i++)
		if (!tests[i]())
			return 1;
	return 0;
}
