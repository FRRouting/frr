// SPDX-License-Identifier: GPL-2.0-or-later
/* Simple stream test.
 *
 * Copyright (C) 2006 Sun Microsystems, Inc.
 */

#include <zebra.h>
#include <stream.h>
#include "frrevent.h"

#include "printfrr.h"

static unsigned long long ham = 0xdeadbeefdeadbeef;
struct event_loop *master;

static void print_stream(struct stream *s)
{
	size_t getp = stream_get_getp(s);

	printfrr("endp: %zu, readable: %zu, writeable: %zu\n",
		 stream_get_endp(s), STREAM_READABLE(s), STREAM_WRITEABLE(s));

	while (STREAM_READABLE(s))
		printfrr("0x%x ", stream_getc(s));

	printfrr("\n");

	/* put getp back to where it was */
	stream_set_getp(s, getp);
}

int main(void)
{
	struct stream *s;
	static const char str[] = "a medium-sized string";
	char buf[100];
	bool ret;

	s = stream_new(1024);

	stream_putc(s, ham);
	stream_putw(s, ham);
	stream_putl(s, ham);
	stream_putq(s, ham);

	print_stream(s);

	stream_resize_inplace(&s, stream_get_endp(s));

	print_stream(s);

	printfrr("c: 0x%hhx\n", stream_getc(s));
	printfrr("w: 0x%hx\n", stream_getw(s));
	printfrr("l: 0x%x\n", stream_getl(s));
	printfrr("q: 0x%" PRIx64 "\n", stream_getq(s));

	stream_reset(s);
	stream_resize_inplace(&s, 1024);

	stream_put_str(s, str);

	print_stream(s);

	/* Read into too-small buffer */
	ret = stream_get_str(s, buf, 10);
	assert(ret == false);
	assert(STREAM_READABLE(s) == 0);

	stream_reset(s);

	/* Read into valid buffer */
	stream_put_str(s, str);
	ret = stream_get_str(s, buf, sizeof(buf));

	printfrr("buf: %s\n", buf);

	stream_free(s);
	return 0;
}
