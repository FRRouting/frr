// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frrscript unit tests
 * Copyright (C) 2021  Donald Lee
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
	assert(b == 201);

	a = 100, b = 200;

	result = frrscript_load(fs, "bar", NULL);
	assert(result == 0);
	result = frrscript_call(fs, "bar", ("a", &a), ("b", &b));
	assert(result == 0);
	long long *cptr = frrscript_get_result(fs, "bar", "c", lua_tolonglongp);

	/* a should not occur in the returned table in script */
	assert(a == 100);
	assert(b == 201);
	assert(*cptr == 303);
	XFREE(MTYPE_SCRIPT_RES, cptr);

	long long n = 5;

	result = frrscript_load(fs, "fact", NULL);
	assert(result == 0);
	result = frrscript_call(fs, "fact", ("n", &n));
	assert(result == 0);
	long long *ansptr =
		frrscript_get_result(fs, "fact", "ans", lua_tolonglongp);
	assert(*ansptr == 120);

	/* check consecutive call + get_result without re-loading */
	n = 4;
	result = frrscript_call(fs, "fact", ("n", &n));
	assert(result == 0);
	ansptr = frrscript_get_result(fs, "fact", "ans", lua_tointegerp);
	assert(*ansptr == 24);

	XFREE(MTYPE_SCRIPT_RES, ansptr);

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
