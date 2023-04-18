// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "memory.h"
#include "hook.h"

DEFINE_MTYPE_STATIC(LIB, HOOK_ENTRY, "Hook entry");

void _hook_register(struct hook *hook, struct hookent *stackent, void *funcptr,
		    void *arg, bool has_arg, struct frrmod_runtime *module,
		    const char *funcname, int priority)
{
	struct hookent *he, **pos;

	if (!stackent->ent_used)
		he = stackent;
	else {
		he = XCALLOC(MTYPE_HOOK_ENTRY, sizeof(*he));
		he->ent_on_heap = true;
	}
	he->ent_used = true;
	he->hookfn = funcptr;
	he->hookarg = arg;
	he->has_arg = has_arg;
	he->module = module;
	he->fnname = funcname;
	he->priority = priority;

	for (pos = &hook->entries; *pos; pos = &(*pos)->next)
		if (hook->reverse ? (*pos)->priority < priority
				  : (*pos)->priority >= priority)
			break;

	he->next = *pos;
	*pos = he;
}

void _hook_unregister(struct hook *hook, void *funcptr, void *arg, bool has_arg)
{
	struct hookent *he, **prev;

	for (prev = &hook->entries; (he = *prev) != NULL; prev = &he->next)
		if (he->hookfn == funcptr && he->hookarg == arg
		    && he->has_arg == has_arg) {
			*prev = he->next;
			if (he->ent_on_heap)
				XFREE(MTYPE_HOOK_ENTRY, he);
			else
				memset(he, 0, sizeof(*he));
			break;
		}
}
