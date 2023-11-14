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
#include "lib/frrlua.h"

int main(int argc, char **argv)
{
	frrscript_init("./lib");
	struct frrscript *fs = frrscript_new("script1");
	int result;

	/* Positive testing */

	long long a = 100, b = 200;

	result = frrscript_load(fs, "foo", NULL);
	assert(result == 0);
	result = frrscript_call(fs, "foo", ("a", &a), ("b", &b));
	assert(result == 0);
	assert(a == 101);
	assert(b == 202);

	a = 100, b = 200;

	result = frrscript_load(fs, "bar", NULL);
	assert(result == 0);
	result = frrscript_call(fs, "bar", ("a", &a), ("b", &b));
	assert(result == 0);
	long long *cptr = frrscript_get_result(fs, "bar", "c", lua_tointegerp);

	/* a should not occur in the returned table in script */
	assert(a == 100);
	assert(b == 202);
	assert(*cptr == 303);
	XFREE(MTYPE_TMP, cptr);

	long long n = 5;

	result = frrscript_load(fs, "fact", NULL);
	assert(result == 0);
	result = frrscript_call(fs, "fact", ("n", &n));
	assert(result == 0);
	long long *ansptr =
		frrscript_get_result(fs, "fact", "ans", lua_tointegerp);
	assert(*ansptr == 120);
	XFREE(MTYPE_TMP, ansptr);

	/* Negative testing */

	/* Function does not exist in script file*/
	result = frrscript_load(fs, "does_not_exist", NULL);
	assert(result == 1);

	/* Function was not (successfully) loaded */
	result = frrscript_call(fs, "does_not_exist", ("a", &a), ("b", &b));
	assert(result == 1);

	/* Get result from a function that was not loaded */
	long long *llptr =
		frrscript_get_result(fs, "does_not_exist", "c", lua_tointegerp);
	assert(llptr == NULL);

	/* Function returns void */
	result = frrscript_call(fs, "bad_return1");
	assert(result == 1);

	/* Function returns number */
	result = frrscript_call(fs, "bad_return2");
	assert(result == 1);

	/* Get non-existent result from a function */
	result = frrscript_call(fs, "bad_return3");
	assert(result == 1);
	long long *cllptr =
		frrscript_get_result(fs, "bad_return3", "c", lua_tointegerp);
	assert(cllptr == NULL);

	/* Function throws exception */
	result = frrscript_call(fs, "bad_return4");
	assert(result == 1);

	frrscript_delete(fs);

	return 0;
}
