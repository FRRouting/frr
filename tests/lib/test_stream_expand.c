// SPDX-License-Identifier: GPL-2.0-or-later
/* Expandable stream write tests.
 *
 * stream_put() and stream_write() run CHECK_SIZE before checking whether
 * the stream may be expanded, so writes larger than the remaining space of
 * an expandable stream get truncated instead of growing the stream.
 */

#include <zebra.h>
#include <stream.h>
#include "frrevent.h"

#include "printfrr.h"

struct event_loop *master;

#define INITIAL_SIZE 10
#define WRITE_SIZE   20

static int failures;

static void report(const char *name, bool ok, struct stream *s, size_t expect_endp)
{
	printfrr("%s: size %zu endp %zu (expected endp %zu): %s\n", name, stream_get_size(s),
		 stream_get_endp(s), expect_endp, ok ? "OK" : "failed");
	if (!ok)
		failures++;
}

static void fill_pattern(uint8_t *data, size_t len, uint8_t seed)
{
	for (size_t i = 0; i < len; i++)
		data[i] = seed + i;
}

static void test_put_empty(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t data[WRITE_SIZE];
	bool ok;

	fill_pattern(data, sizeof(data), 0x10);
	stream_put(s, data, sizeof(data));

	ok = stream_get_endp(s) == WRITE_SIZE && stream_get_size(s) >= WRITE_SIZE &&
	     memcmp(STREAM_DATA(s), data, sizeof(data)) == 0;
	report("stream_put-expand-empty", ok, s, WRITE_SIZE);
	stream_free(s);
}

static void test_put_null_empty(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t zero[WRITE_SIZE] = {};
	bool ok;

	stream_put(s, NULL, WRITE_SIZE);

	ok = stream_get_endp(s) == WRITE_SIZE && stream_get_size(s) >= WRITE_SIZE &&
	     memcmp(STREAM_DATA(s), zero, sizeof(zero)) == 0;
	report("stream_put-null-expand-empty", ok, s, WRITE_SIZE);
	stream_free(s);
}

static void test_put_partial(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t data[WRITE_SIZE];
	bool ok;

	stream_putl(s, 0xdeadbeef);
	fill_pattern(data, sizeof(data), 0x20);
	stream_put(s, data, sizeof(data));

	ok = stream_get_endp(s) == 4 + WRITE_SIZE && stream_get_size(s) >= 4 + WRITE_SIZE &&
	     memcmp(STREAM_DATA(s) + 4, data, sizeof(data)) == 0;
	report("stream_put-expand-partial", ok, s, 4 + WRITE_SIZE);
	stream_free(s);
}

static void test_put_full(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t first[INITIAL_SIZE];
	uint8_t data[WRITE_SIZE];
	bool ok;

	fill_pattern(first, sizeof(first), 0x00);
	stream_put(s, first, sizeof(first));
	fill_pattern(data, sizeof(data), 0x30);
	stream_put(s, data, sizeof(data));

	ok = stream_get_endp(s) == INITIAL_SIZE + WRITE_SIZE &&
	     stream_get_size(s) >= INITIAL_SIZE + WRITE_SIZE &&
	     memcmp(STREAM_DATA(s) + INITIAL_SIZE, data, sizeof(data)) == 0;
	report("stream_put-expand-full", ok, s, INITIAL_SIZE + WRITE_SIZE);
	stream_free(s);
}

static void test_write_empty(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t data[WRITE_SIZE];
	size_t written;
	bool ok;

	fill_pattern(data, sizeof(data), 0x40);
	written = stream_write(s, data, sizeof(data));

	ok = written == WRITE_SIZE && stream_get_endp(s) == WRITE_SIZE &&
	     stream_get_size(s) >= WRITE_SIZE && memcmp(STREAM_DATA(s), data, sizeof(data)) == 0;
	printfrr("stream_write returned %zu (expected %d)\n", written, WRITE_SIZE);
	report("stream_write-expand-empty", ok, s, WRITE_SIZE);
	stream_free(s);
}

static void test_write_full(void)
{
	struct stream *s = stream_new_expandable(INITIAL_SIZE);
	uint8_t first[INITIAL_SIZE];
	uint8_t data[WRITE_SIZE];
	size_t written;
	bool ok;

	fill_pattern(first, sizeof(first), 0x00);
	stream_write(s, first, sizeof(first));
	fill_pattern(data, sizeof(data), 0x50);
	written = stream_write(s, data, sizeof(data));

	ok = written == WRITE_SIZE && stream_get_endp(s) == INITIAL_SIZE + WRITE_SIZE &&
	     stream_get_size(s) >= INITIAL_SIZE + WRITE_SIZE &&
	     memcmp(STREAM_DATA(s) + INITIAL_SIZE, data, sizeof(data)) == 0;
	printfrr("stream_write returned %zu (expected %d)\n", written, WRITE_SIZE);
	report("stream_write-expand-full", ok, s, INITIAL_SIZE + WRITE_SIZE);
	stream_free(s);
}

int main(void)
{
	test_put_empty();
	test_put_null_empty();
	test_put_partial();
	test_put_full();
	test_write_empty();
	test_write_full();

	return failures ? 1 : 0;
}
