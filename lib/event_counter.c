/*
 * Copyright (C) 2016 Christian Franke
 *
 * This file is part of Quagga.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, you can use, redistribute and/or modify it under the
 * following terms:
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "event_counter.h"

void event_counter_inc(struct event_counter *counter)
{
	counter->count++;
	counter->last = time(NULL);
}

const char *event_counter_format(const struct event_counter *counter)
{
	struct tm last_change_store;
	struct tm *last_change;
	char timebuf[sizeof("Thu, 01 Jan 1970 00:00:00 +0000")];
	static char rv[20 + sizeof("  last: ") + sizeof(timebuf)];

	last_change = localtime_r(&counter->last, &last_change_store);
	if (!last_change
	    || strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %T %z",
			last_change)
		       == 0) {
		strncpy(timebuf, "???", sizeof(timebuf));
	}

	snprintf(rv, sizeof(rv), "%5llu  last: %s", counter->count,
		 counter->last ? timebuf : "(never)");
	return rv;
}
