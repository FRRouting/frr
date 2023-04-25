// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2004 Paul Jakma
 */

#include <zebra.h>
#include <memory.h>
#include <lib_vty.h>
#include <buffer.h>

struct event_loop *master;

int main(int argc, char **argv)
{
	struct buffer *b1, *b2;
	int n;
	char junk[3];
	char c = 'a';

	lib_cmd_init();

	if ((argc != 2) || (sscanf(argv[1], "%d%1s", &n, junk) != 1)) {
		fprintf(stderr, "Usage: %s <number of chars to simulate>\n",
			*argv);
		return 1;
	}

	b1 = buffer_new(0);
	b2 = buffer_new(1024);

	while (n-- > 0) {
		buffer_put(b1, &c, 1);
		buffer_put(b2, &c, 1);
		if (c++ == 'z')
			c = 'a';
		buffer_reset(b1);
		buffer_reset(b2);
	}
	buffer_free(b1);
	buffer_free(b2);
	return 0;
}
