/*
 * frrscript unit tests
 * Copyright (C) 2021  Donald Lee
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

#include "lib/frrscript.h"

int main(int argc, char **argv)
{
	frrscript_init("./lib");

	struct frrscript *fs = frrscript_load("script1", NULL);
	long long a = 100, b = 200;
	int result = frrscript_call(fs, ("a", &a), ("b", &b));

	assert(result == 0);
	assert(a == 300);
	assert(b == 200);

	return 0;
}
