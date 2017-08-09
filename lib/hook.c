/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "memory.h"
#include "hook.h"

DEFINE_MTYPE_STATIC(LIB, HOOK_ENTRY, "Hook entry")

void _hook_register(struct hook *hook, void *funcptr, void *arg, bool has_arg,
		    struct frrmod_runtime *module, const char *funcname)
{
	struct hookent *he = XCALLOC(MTYPE_HOOK_ENTRY, sizeof(*he));
	he->hookfn = funcptr;
	he->hookarg = arg;
	he->has_arg = has_arg;
	he->module = module;
	he->fnname = funcname;

	he->next = hook->entries;
	hook->entries = he;
}

void _hook_unregister(struct hook *hook, void *funcptr, void *arg, bool has_arg)
{
	struct hookent *he, **prev;

	for (prev = &hook->entries; (he = *prev) != NULL; prev = &he->next)
		if (he->hookfn == funcptr && he->hookarg == arg
		    && he->has_arg == has_arg) {
			*prev = he->next;
			XFREE(MTYPE_HOOK_ENTRY, he);
			break;
		}
}

/* For Emacs:          */
/* Local Variables:    */
/* indent-tabs-mode: t */
/* c-basic-offset: 8   */
/* End:                */
